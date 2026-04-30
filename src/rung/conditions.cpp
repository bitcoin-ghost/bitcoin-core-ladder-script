// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// ============================================================================
// REVIEWER BLOCK — MLSC conditions, Merkle tree, proof verification
// ============================================================================
//
// PURPOSE
//   The MLSC (Merkle Ladder Script Conditions) consensus surface. Defines the
//   0xDF output format, leaf computation, Merkle tree, key-path tweak, and
//   proof serialisation.
//
// KEY SYMBOLS
//   IsMLSCScript / GetMLSCRoot / HasMLSCData
//     scriptPubKey classification — recognises 0xDF prefix with or without
//     a DATA_RETURN tail.
//   ComputeTxMLSCLeaf(cp_rung)
//     leaf = TaggedHash("LadderLeaf/v1", structural_template || value_commitment).
//   ComputeValueCommitment(rung, pubkeys)
//     SHA256(all condition field bytes || all pubkey bytes). Pubkeys are
//     fold-in-order — changing order changes the leaf.
//   BuildMerkleTree / VerifyMerklePath
//     Sorted-pair interior hashing, TaggedHash("LadderInternal/v1").
//     MLSC_EMPTY_LEAF (tagged all-zero) pads to the next power of 2.
//   ComputeTweakedConditionsRoot
//     Key-path tweak: output_pk = internal_pk + H(internal_pk || merkle_root)*G.
//     Tag: "LadderTweak/v1".
//   SerializeMLSCProof / DeserializeMLSCProof
//     Wire format for the proof witness stack element.
//
// LOAD-BEARING INVARIANTS
//   1. Tagged-hash domain strings are versioned (/v1). Changing any of them
//      splits consensus. Must match evaluator.cpp and pubkey.cpp exactly.
//   2. Interior hashing is SORTED-pair (smaller sibling first). This is NOT
//      the parity-based scheme used by BIP-340 taproot — Ladder paths are
//      commutative to save a direction bit per level.
//   3. Empty-leaf padding uses MLSC_EMPTY_LEAF (a specific tagged hash), not
//      raw zeros. Never substitute.
//   4. PUBKEY fields are stripped from block.fields during conditions
//      parsing and folded into value_commitment via rung_pks in POSITIONAL
//      ORDER (as they appear across block-then-field iteration). Changing
//      the iteration order changes the leaf → changes the root.
//   5. NUMERIC fields are normalised to 4-byte little-endian in
//      ComputeValueCommitment. Smaller NUMERIC fields are zero-padded; the
//      evaluator and RPC layer do the same.
//
// OPTIONAL / REMOVABLE
//   - SHARED proof mode is an optimisation for multi-input txs referencing
//     the same source UTXO. MERKLE_PATH is sufficient for single-input spends.
//   - revealed_mutation_targets (trailing proof field) is only needed for
//     cross-rung covenant mutations. Remove with RECURSE_MODIFIED targeting
//     non-self rungs if that scope is dropped.
//
// REFERENCES
//   Wire format: doc/ladder-script/TX_MLSC_SPEC.md
//   Reviewer guide: doc/ladder-script/REVIEW_GUIDE.md (Part 3, conditions section).
// ============================================================================

#include <rung/conditions.h>
#include <rung/serialize.h>

#include <crypto/sha256.h>
#include <pubkey.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>

namespace rung {

bool IsConditionDataType(RungDataType type)
{
    // PUBKEY / PUBKEY_COMMIT are witness-only: pubkeys fold into the
    // Merkle leaf, and attacker-chosen commitments don't belong in the
    // locking side of an output. SIGNATURE / PREIMAGE / SCRIPT_BODY are
    // the "proof" side, also witness-only.
    switch (type) {
    case RungDataType::HASH256:
    case RungDataType::HASH160:
    case RungDataType::NUMERIC:
    case RungDataType::SCHEME:
    case RungDataType::SPEND_INDEX:
    case RungDataType::DATA:
        return true;
    case RungDataType::PUBKEY_COMMIT:
    case RungDataType::PUBKEY:
    case RungDataType::SIGNATURE:
    case RungDataType::PREIMAGE:
    case RungDataType::SCRIPT_BODY:
    case RungDataType::MERKLE_PROOF:
        return false;
    }
    return false;
}

// 0xC1 inline-conditions stubs — always reject. See conditions.h.
namespace api {

bool IsRungConditionsScript(std::span<const uint8_t>)
{
    return false;
}

bool DeserializeRungConditions(std::span<const uint8_t>, RungConditions&, std::string& error)
{
    error = "inline conditions (0xC1) not supported — use MLSC (0xDF)";
    return false;
}

std::vector<uint8_t> SerializeRungConditions(const RungConditions&)
{
    return {};
}

}  // namespace api

bool ResolveTemplateReference(RungConditions& conditions,
                              const std::vector<RungConditions>& all_conditions,
                              std::string& error)
{
    if (!conditions.IsTemplateRef()) {
        error = "conditions do not have a template reference";
        return false;
    }

    const auto& ref = *conditions.template_ref;

    if (ref.input_index >= all_conditions.size()) {
        error = "template reference input_index out of range: " +
                std::to_string(ref.input_index) + " >= " +
                std::to_string(all_conditions.size());
        return false;
    }

    const auto& source = all_conditions[ref.input_index];

    // Source must not itself be a template reference (no chaining)
    if (source.IsTemplateRef()) {
        error = "template reference points to another template reference";
        return false;
    }

    // Copy conditions from source
    conditions.rungs = source.rungs;
    conditions.coil = source.coil;
    conditions.relays = source.relays;

    // Apply diffs
    for (const auto& diff : ref.diffs) {
        if (diff.rung_index >= conditions.rungs.size()) {
            error = "template diff rung_index out of range: " +
                    std::to_string(diff.rung_index);
            return false;
        }
        auto& rung = conditions.rungs[diff.rung_index];
        if (diff.block_index >= rung.blocks.size()) {
            error = "template diff block_index out of range: " +
                    std::to_string(diff.block_index);
            return false;
        }
        auto& block = rung.blocks[diff.block_index];
        if (diff.field_index >= block.fields.size()) {
            error = "template diff field_index out of range: " +
                    std::to_string(diff.field_index);
            return false;
        }

        // Replace the field (type must match for safety)
        if (block.fields[diff.field_index].type != diff.new_field.type) {
            error = "template diff type mismatch at rung " +
                    std::to_string(diff.rung_index) + " block " +
                    std::to_string(diff.block_index) + " field " +
                    std::to_string(diff.field_index) + ": expected " +
                    DataTypeName(block.fields[diff.field_index].type) +
                    ", got " + DataTypeName(diff.new_field.type);
            return false;
        }
        block.fields[diff.field_index] = diff.new_field;
    }

    // Clear template reference — conditions are now fully resolved
    conditions.template_ref.reset();
    return true;
}

// ============================================================================
// MLSC (Merkelized Ladder Script Conditions)
// ============================================================================

/**
 * BIP-341-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
 * The double-tag prefix provides domain separation — a hash computed with
 * one tag can never collide with a hash computed with a different tag,
 * preventing second-preimage attacks between leaf and internal nodes.
 */
static uint256 TaggedHash(const char* tag, const unsigned char* data, size_t len)
{
    unsigned char tag_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag), strlen(tag)).Finalize(tag_hash);

    // SHA256(SHA256(tag) || SHA256(tag) || data)
    CSHA256 hasher;
    hasher.Write(tag_hash, sizeof(tag_hash));
    hasher.Write(tag_hash, sizeof(tag_hash));
    hasher.Write(data, len);
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

/** Pre-computed tagged hashers for leaf and internal node domains (BIP-341 pattern). */
static CSHA256 InitTaggedHasher(const char* tag)
{
    unsigned char tag_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag), strlen(tag)).Finalize(tag_hash);
    CSHA256 hasher;
    hasher.Write(tag_hash, sizeof(tag_hash));
    hasher.Write(tag_hash, sizeof(tag_hash));
    return hasher;
}

static const CSHA256 LEAF_HASHER = InitTaggedHasher("LadderLeaf/v1");
static const CSHA256 INTERNAL_HASHER = InitTaggedHasher("LadderInternal/v1");
// v0.7: relay leaves are folded into the conditions_root tree. Distinct
// tagged-hash domain so a relay leaf can never alias a rung leaf even at
// matching block layouts.
static const CSHA256 RELAY_LEAF_HASHER = InitTaggedHasher("LadderRelayLeaf/v1");

/** Compute MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf/v1", "") at startup. */
static uint256 ComputeEmptyLeaf()
{
    return TaggedHash("LadderLeaf/v1", nullptr, 0);
}

const uint256 MLSC_EMPTY_LEAF = ComputeEmptyLeaf();

// MULTISIG v2 inner-pubkey-Merkle domain separation.
// Distinct tags ensure no cross-tree leaf collision: a 32-byte uint256 from the
// outer MLSC tree can never be misread as a 33-byte compressed pubkey under the
// inner-leaf hash, but explicit domain tags make this independent of byte-length.
static const CSHA256 MULTISIG_PUBKEY_HASHER  = InitTaggedHasher("LadderMultisigPubkey/v1");
static const CSHA256 MULTISIG_INTERNAL_HASHER = InitTaggedHasher("LadderMultisigInternal/v1");

// ACCUMULATOR v2 inner-tree domain separation. Leaves hash a 4-byte LE
// element_id (NOT free attacker bytes). Interior nodes hash sorted children
// like the MLSC tree but under their own domain tag.
static const CSHA256 ACCUMULATOR_LEAF_HASHER     = InitTaggedHasher("LadderAccumulatorLeaf/v1");
static const CSHA256 ACCUMULATOR_INTERIOR_HASHER = InitTaggedHasher("LadderAccumulatorInterior/v1");

/** Padding leaf for the inner pubkey tree (empty-input tagged hash). */
// v0.12 (audit 8b F13): empty-leaf padding uses a distinct tagged-hash
// domain so it cannot alias a real pubkey leaf even if FieldMinSize were
// ever loosened to permit 0-byte PUBKEYs. Today FieldMinSize(PUBKEY)=1
// blocks this from being exploitable, but the distinct domain is
// defence-in-depth.
static const uint256 MULTISIG_EMPTY_LEAF = TaggedHash("LadderMultisigPadding/v1", nullptr, 0);

/** Hash a single pubkey as an inner-tree leaf. */
static uint256 MultisigPubkeyLeaf(const std::vector<uint8_t>& pubkey)
{
    CSHA256 hasher = MULTISIG_PUBKEY_HASHER;
    hasher.Write(pubkey.data(), pubkey.size());
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

/** Sorted interior hash for the inner pubkey tree. */
static uint256 MultisigInterior(const uint256& a, const uint256& b)
{
    unsigned char children[32 + 32];
    if (memcmp(a.data(), b.data(), 32) <= 0) {
        memcpy(children, a.data(), 32);
        memcpy(children + 32, b.data(), 32);
    } else {
        memcpy(children, b.data(), 32);
        memcpy(children + 32, a.data(), 32);
    }
    CSHA256 hasher = MULTISIG_INTERNAL_HASHER;
    hasher.Write(children, sizeof(children));
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

namespace api {

bool IsMLSCScript(std::span<const uint8_t> script_pub_key)
{
    // 1 byte = compact MLSC from UTXO decompression (0xDF only, root recovered at spend time)
    // 33 bytes = full MLSC (0xDF + 32-byte root)
    // 34-73 bytes = MLSC with DATA_RETURN payload (max 40 bytes data)
    // Sizes 2-32 are invalid (not compact, not full)
    if (script_pub_key.empty() || script_pub_key[0] != RUNG_MLSC_PREFIX) return false;
    return script_pub_key.size() == 1 || (script_pub_key.size() >= 33 && script_pub_key.size() <= 73);
}

bool IsLadderScript(std::span<const uint8_t> script_pub_key)
{
    return IsMLSCScript(script_pub_key);
}

/** Check if this is a compact MLSC scriptPubKey (1-byte, root not embedded).
 *  The conditions_root must be recovered from the creating transaction. */
bool IsCompactMLSC(std::span<const uint8_t> script_pub_key)
{
    return script_pub_key.size() == 1 && script_pub_key[0] == RUNG_MLSC_PREFIX;
}

bool GetMLSCRoot(std::span<const uint8_t> script_pub_key, uint256& root_out)
{
    if (script_pub_key.size() < 33 || script_pub_key[0] != RUNG_MLSC_PREFIX) return false;
    memcpy(root_out.data(), script_pub_key.data() + 1, 32);
    return true;
}

std::vector<uint8_t> GetMLSCData(std::span<const uint8_t> script_pub_key)
{
    if (!IsMLSCScript(script_pub_key) || script_pub_key.size() <= 33) {
        return {};
    }
    return std::vector<uint8_t>(script_pub_key.begin() + 33, script_pub_key.end());
}

bool HasMLSCData(std::span<const uint8_t> script_pub_key)
{
    return IsMLSCScript(script_pub_key) && script_pub_key.size() > 33;
}

std::vector<uint8_t> CreateMLSCScript(const uint256& conditions_root)
{
    std::vector<uint8_t> result;
    result.push_back(RUNG_MLSC_PREFIX);
    result.insert(result.end(), conditions_root.begin(), conditions_root.end());
    return result;
}

std::vector<uint8_t> CreateMLSCScript(const uint256& conditions_root, const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> result;
    result.push_back(RUNG_MLSC_PREFIX);
    result.insert(result.end(), conditions_root.begin(), conditions_root.end());
    result.insert(result.end(), data.begin(), data.end());
    return result;
}

}  // namespace api

// v0.7: ComputeRungLeaf / ComputeCoilLeaf / ComputeRelayLeaf are retained as
// test-only helpers. The live consensus path uses TX_MLSC leaves (TaggedHash
// over structural template + value commitment) — see ComputeTxMLSCLeaf and
// ComputeTxMLSCRelayLeaf at the bottom of this file. These legacy helpers use
// the wire-format serialiser and produce DIFFERENT leaf hashes than consensus.
// New code must NOT call these.

uint256 ComputeRungLeaf(const Rung& rung,
                         const std::vector<std::vector<uint8_t>>& pubkeys)
{
    auto bytes = SerializeRungBlocks(rung, SerializationContext::CONDITIONS);
    CSHA256 hasher = LEAF_HASHER;
    hasher.Write(bytes.data(), bytes.size());
    for (const auto& pk : pubkeys) {
        hasher.Write(pk.data(), pk.size());
    }
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

uint256 ComputeCoilLeaf(const RungCoil& coil)
{
    auto bytes = SerializeCoilData(coil);
    CSHA256 hasher = LEAF_HASHER;
    hasher.Write(bytes.data(), bytes.size());
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

uint256 ComputeRelayLeaf(const Relay& relay,
                          const std::vector<std::vector<uint8_t>>& pubkeys)
{
    auto bytes = SerializeRelayBlocks(relay, SerializationContext::CONDITIONS);
    CSHA256 hasher = LEAF_HASHER;
    hasher.Write(bytes.data(), bytes.size());
    for (const auto& pk : pubkeys) {
        hasher.Write(pk.data(), pk.size());
    }
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

/** Compute a sorted interior Merkle node: TaggedHash("LadderInternal/v1", min(a,b) || max(a,b)). */
static uint256 MerkleInterior(const uint256& a, const uint256& b)
{
    unsigned char children[32 + 32];
    if (memcmp(a.data(), b.data(), 32) <= 0) {
        memcpy(children, a.data(), 32);
        memcpy(children + 32, b.data(), 32);
    } else {
        memcpy(children, b.data(), 32);
        memcpy(children + 32, a.data(), 32);
    }
    CSHA256 hasher = INTERNAL_HASHER; // copy pre-computed prefix
    hasher.Write(children, sizeof(children));
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

/** Next power of 2 >= n (for n > 0). */
static size_t NextPowerOf2(size_t n)
{
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

uint256 BuildMerkleTree(std::vector<uint256> leaves)
{
    if (leaves.empty()) return MLSC_EMPTY_LEAF;
    if (leaves.size() == 1) return leaves[0];

    // Pad to next power of 2
    size_t padded = NextPowerOf2(leaves.size());
    while (leaves.size() < padded) {
        leaves.push_back(MLSC_EMPTY_LEAF);
    }

    // Build tree bottom-up
    while (leaves.size() > 1) {
        std::vector<uint256> parents;
        parents.reserve(leaves.size() / 2);
        for (size_t i = 0; i < leaves.size(); i += 2) {
            parents.push_back(MerkleInterior(leaves[i], leaves[i + 1]));
        }
        leaves = std::move(parents);
    }

    return leaves[0];
}

std::vector<uint256> BuildMerklePath(std::vector<uint256> leaves, size_t target_index)
{
    if (leaves.size() <= 1) return {};

    // Pad to next power of 2
    size_t padded = NextPowerOf2(leaves.size());
    while (leaves.size() < padded) {
        leaves.push_back(MLSC_EMPTY_LEAF);
    }

    std::vector<uint256> path;
    size_t idx = target_index;

    // Build tree bottom-up, recording the sibling at each level
    while (leaves.size() > 1) {
        // Sibling is the other half of the pair
        size_t sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        if (sibling < leaves.size()) {
            path.push_back(leaves[sibling]);
        } else {
            path.push_back(MLSC_EMPTY_LEAF);
        }

        // Compute parent level
        std::vector<uint256> parents;
        parents.reserve(leaves.size() / 2);
        for (size_t i = 0; i < leaves.size(); i += 2) {
            parents.push_back(MerkleInterior(leaves[i], leaves[i + 1]));
        }
        leaves = std::move(parents);
        idx /= 2;
    }

    return path;
}

bool VerifyMerklePath(const uint256& leaf,
                      const std::vector<uint256>& path,
                      size_t total_leaves,
                      const uint256& expected_root,
                      std::string& error)
{
    if (total_leaves == 0) {
        error = "empty tree";
        return false;
    }
    if (total_leaves == 1) {
        if (!path.empty()) {
            error = "path should be empty for single-leaf tree";
            return false;
        }
        if (leaf != expected_root) {
            error = "single leaf does not match root: leaf=" + leaf.GetHex() + " root=" + expected_root.GetHex();
            return false;
        }
        return true;
    }

    size_t padded = NextPowerOf2(total_leaves);
    size_t expected_depth = 0;
    for (size_t p = padded; p > 1; p >>= 1) ++expected_depth;

    if (path.size() != expected_depth) {
        error = "path length " + std::to_string(path.size()) +
                " != expected depth " + std::to_string(expected_depth);
        return false;
    }

    // Walk up the tree: at each level, combine with sibling using sorted interior hash
    uint256 current = leaf;
    for (size_t i = 0; i < path.size(); ++i) {
        current = MerkleInterior(current, path[i]);
    }

    if (current != expected_root) {
        error = "computed root does not match expected root";
        return false;
    }

    return true;
}

uint256 ComputeMerkleRootFromPath(const uint256& leaf, const std::vector<uint256>& path)
{
    uint256 current = leaf;
    for (const auto& sibling : path) {
        current = MerkleInterior(current, sibling);
    }
    return current;
}

uint256 BuildPubkeyMerkleRoot(const std::vector<std::vector<uint8_t>>& pubkeys)
{
    if (pubkeys.empty()) return MULTISIG_EMPTY_LEAF;

    std::vector<uint256> leaves;
    leaves.reserve(pubkeys.size());
    for (const auto& pk : pubkeys) leaves.push_back(MultisigPubkeyLeaf(pk));

    if (leaves.size() == 1) return leaves[0];

    size_t padded = NextPowerOf2(leaves.size());
    while (leaves.size() < padded) leaves.push_back(MULTISIG_EMPTY_LEAF);

    while (leaves.size() > 1) {
        std::vector<uint256> parents;
        parents.reserve(leaves.size() / 2);
        for (size_t i = 0; i < leaves.size(); i += 2) {
            parents.push_back(MultisigInterior(leaves[i], leaves[i + 1]));
        }
        leaves = std::move(parents);
    }
    return leaves[0];
}

std::vector<uint256> BuildPubkeyMerkleProof(const std::vector<std::vector<uint8_t>>& pubkeys,
                                             size_t target_index)
{
    if (pubkeys.size() <= 1) return {};

    std::vector<uint256> leaves;
    leaves.reserve(pubkeys.size());
    for (const auto& pk : pubkeys) leaves.push_back(MultisigPubkeyLeaf(pk));

    size_t padded = NextPowerOf2(leaves.size());
    while (leaves.size() < padded) leaves.push_back(MULTISIG_EMPTY_LEAF);

    std::vector<uint256> path;
    size_t idx = target_index;
    while (leaves.size() > 1) {
        size_t sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        path.push_back(sibling < leaves.size() ? leaves[sibling] : MULTISIG_EMPTY_LEAF);

        std::vector<uint256> parents;
        parents.reserve(leaves.size() / 2);
        for (size_t i = 0; i < leaves.size(); i += 2) {
            parents.push_back(MultisigInterior(leaves[i], leaves[i + 1]));
        }
        leaves = std::move(parents);
        idx /= 2;
    }
    return path;
}

bool VerifyPubkeyMerkleProof(const std::vector<uint8_t>& pubkey,
                              const std::vector<uint256>& proof,
                              const uint256& expected_root,
                              std::string& error)
{
    if (proof.size() > MAX_MULTISIG_TREE_DEPTH) {
        error = "pubkey proof too deep: " + std::to_string(proof.size()) +
                " > MAX_MULTISIG_TREE_DEPTH (" +
                std::to_string(MAX_MULTISIG_TREE_DEPTH) + ")";
        return false;
    }
    uint256 current = MultisigPubkeyLeaf(pubkey);
    for (const auto& sibling : proof) current = MultisigInterior(current, sibling);
    if (current != expected_root) {
        error = "pubkey proof does not reach expected root";
        return false;
    }
    return true;
}

uint256 BuildAccumulatorLeaf(uint32_t element_id)
{
    uint8_t id_le[4] = {
        static_cast<uint8_t>(element_id & 0xFF),
        static_cast<uint8_t>((element_id >> 8) & 0xFF),
        static_cast<uint8_t>((element_id >> 16) & 0xFF),
        static_cast<uint8_t>((element_id >> 24) & 0xFF),
    };
    CSHA256 hasher = ACCUMULATOR_LEAF_HASHER;
    hasher.Write(id_le, sizeof(id_le));
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

uint256 BuildAccumulatorInterior(const uint256& a, const uint256& b)
{
    unsigned char children[32 + 32];
    if (memcmp(a.data(), b.data(), 32) <= 0) {
        memcpy(children, a.data(), 32);
        memcpy(children + 32, b.data(), 32);
    } else {
        memcpy(children, b.data(), 32);
        memcpy(children + 32, a.data(), 32);
    }
    CSHA256 hasher = ACCUMULATOR_INTERIOR_HASHER;
    hasher.Write(children, sizeof(children));
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

bool VerifyAccumulatorProof(uint32_t element_id,
                             const std::vector<uint8_t>& proof_bytes,
                             const uint256& expected_root,
                             std::string& error)
{
    if (element_id > MAX_ACCUMULATOR_ELEMENT_ID) {
        error = "accumulator element_id out of range: " + std::to_string(element_id);
        return false;
    }
    if (proof_bytes.size() % 32 != 0) {
        error = "accumulator proof length not a multiple of 32: " +
                std::to_string(proof_bytes.size());
        return false;
    }
    const size_t depth = proof_bytes.size() / 32;
    if (depth > MAX_ACCUMULATOR_PROOF_DEPTH) {
        error = "accumulator proof too deep: " + std::to_string(depth) +
                " > MAX_ACCUMULATOR_PROOF_DEPTH (" +
                std::to_string(MAX_ACCUMULATOR_PROOF_DEPTH) + ")";
        return false;
    }
    uint256 current = BuildAccumulatorLeaf(element_id);
    for (size_t i = 0; i < depth; ++i) {
        uint256 sibling;
        std::memcpy(sibling.data(), proof_bytes.data() + i * 32, 32);
        current = BuildAccumulatorInterior(current, sibling);
    }
    if (current != expected_root) {
        error = "accumulator proof does not reach expected root";
        return false;
    }
    return true;
}

std::optional<std::pair<uint256, bool>> ComputeTweakedConditionsRoot(
    const std::vector<uint8_t>& internal_pubkey_bytes,
    const uint256& merkle_root)
{
    if (internal_pubkey_bytes.size() != 32) return std::nullopt;
    XOnlyPubKey internal_key;
    std::copy(internal_pubkey_bytes.begin(), internal_pubkey_bytes.end(), internal_key.begin());
    if (!internal_key.IsFullyValid()) return std::nullopt;

    auto result = internal_key.CreateLadderTweak(&merkle_root);
    if (!result) return std::nullopt;

    uint256 tweaked;
    std::memcpy(tweaked.data(), result->first.data(), 32);
    return std::make_pair(tweaked, result->second);
}

uint256 ComputeConditionsRoot(const RungConditions& conditions,
                               const std::vector<std::vector<std::vector<uint8_t>>>& rung_pubkeys,
                               const std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys)
{
    // v0.7: thin wrapper around the canonical TX_MLSC root computation.
    // Builds CreationProofRung + CreationProofRelay structs, delegates to
    // `ComputeTxMLSCRoot(rungs, relays)`. Coil is structurally bound via
    // each rung leaf's template (no separate coil leaf in the tree).
    std::vector<CreationProofRung> cp_rungs;
    cp_rungs.reserve(conditions.rungs.size());
    for (size_t i = 0; i < conditions.rungs.size(); ++i) {
        const auto& pks = (i < rung_pubkeys.size()) ? rung_pubkeys[i]
                                                    : std::vector<std::vector<uint8_t>>{};
        CreationProofRung cp;
        for (const auto& blk : conditions.rungs[i].blocks) {
            cp.blocks.push_back({static_cast<uint16_t>(blk.type),
                                  static_cast<uint8_t>(blk.inverted ? 1 : 0)});
        }
        cp.relay_refs = conditions.rungs[i].relay_refs;
        cp.coil = conditions.coil;
        cp.value_commitment = ComputeValueCommitment(conditions.rungs[i], pks);
        cp_rungs.push_back(std::move(cp));
    }
    std::vector<CreationProofRelay> cp_relays;
    cp_relays.reserve(conditions.relays.size());
    for (size_t i = 0; i < conditions.relays.size(); ++i) {
        const auto& pks = (i < relay_pubkeys.size()) ? relay_pubkeys[i]
                                                     : std::vector<std::vector<uint8_t>>{};
        CreationProofRelay cp;
        for (const auto& blk : conditions.relays[i].blocks) {
            cp.blocks.push_back({static_cast<uint16_t>(blk.type),
                                  static_cast<uint8_t>(blk.inverted ? 1 : 0)});
        }
        cp.relay_refs = conditions.relays[i].relay_refs;
        // Relay value_commitment shape mirrors the rung: SHA256 of field values + pubkeys.
        // Reuse ComputeValueCommitment by constructing a temporary Rung wrapper —
        // both Rung and Relay carry `blocks`, and the helper only walks fields.
        Rung tmp;
        tmp.blocks = conditions.relays[i].blocks;
        cp.value_commitment = ComputeValueCommitment(tmp, pks);
        cp_relays.push_back(std::move(cp));
    }
    return ComputeTxMLSCRoot(cp_rungs, cp_relays);
}

bool DeserializeMLSCProof(const std::vector<uint8_t>& data, MLSCProof& proof, std::string& error)
{
    if (data.empty()) {
        error = "empty MLSC proof";
        return false;
    }

    DataStream ss{data};

    try {
        // Detect proof format: first byte 0x00 = new versioned format,
        // 0x01-0xFC = legacy format (CompactSize total_rungs, always >= 1).
        uint8_t first_byte = data[0];
        if (first_byte == 0x00) {
            // New versioned format: 0x00 + proof_mode + fields
            ss.ignore(1); // consume the 0x00 version prefix
            uint8_t mode_byte;
            ss >> mode_byte;
            if (mode_byte > static_cast<uint8_t>(MLSCProofMode::SHARED)) {
                error = "unknown MLSC proof mode: " + std::to_string(mode_byte);
                return false;
            }
            proof.proof_mode = static_cast<MLSCProofMode>(mode_byte);

            // SHARED mode: compact format — just source_input + rung_index + revealed rung
            if (proof.proof_mode == MLSCProofMode::SHARED) {
                // v0.14 (audit #10 F4): cap shared_source_input at uint16 max
                // before truncating. Pre-v0.14 this silently truncated wider
                // CompactSize values to uint16, so two distinct wire encodings
                // (e.g. 0x00 and 0xFE 0x00 0x00 0x01 0x00) decoded to the same
                // index. Conditions-side SIG doesn't cover the SHARED proof
                // wire encoding, so this enabled third-party wtxid malleation.
                uint64_t raw_src = ReadCompactSize(ss);
                if (raw_src > std::numeric_limits<uint16_t>::max()) {
                    error = "MLSC shared proof shared_source_input exceeds uint16 max";
                    return false;
                }
                proof.shared_source_input = static_cast<uint16_t>(raw_src);
                uint64_t total_rungs = ReadCompactSize(ss);
                uint64_t rung_index = ReadCompactSize(ss);
                if (total_rungs == 0 || total_rungs > MAX_RUNGS) {
                    error = "MLSC shared proof total_rungs out of range";
                    return false;
                }
                if (rung_index >= total_rungs) {
                    error = "MLSC shared proof rung_index out of range";
                    return false;
                }
                proof.total_rungs = static_cast<uint16_t>(total_rungs);
                proof.total_relays = 0;
                proof.rung_index = static_cast<uint16_t>(rung_index);

                uint64_t n_blocks = ReadCompactSize(ss);
                if (n_blocks == 0 || n_blocks > MAX_BLOCKS_PER_RUNG) {
                    error = "MLSC shared proof rung block count invalid";
                    return false;
                }
                uint8_t cond_ctx_s = static_cast<uint8_t>(SerializationContext::CONDITIONS);
                proof.revealed_rung.blocks.resize(n_blocks);
                for (uint64_t b = 0; b < n_blocks; ++b) {
                    std::string block_error;
                    if (!DeserializeBlock(ss, proof.revealed_rung.blocks[b], cond_ctx_s, block_error)) {
                        error = "MLSC shared proof rung: " + block_error;
                        return false;
                    }
                }
                uint64_t n_rung_refs = ReadCompactSize(ss);
                if (n_rung_refs > MAX_REQUIRES) {
                    error = "MLSC shared proof too many relay_refs";
                    return false;
                }
                // v0.11 (audit #7 #1): strict ascending unique. Same canonical
                // encoding requirement as the wire-format witness (v0.10 F-4).
                // Without this check the proof side re-opens the relay_refs
                // permutation channel since the merge step takes relay_refs
                // from the proof, not the wire form.
                proof.revealed_rung.relay_refs.resize(n_rung_refs);
                int64_t prev = -1;
                for (uint64_t ri = 0; ri < n_rung_refs; ++ri) {
                    uint64_t v = ReadCompactSize(ss);
                    if (static_cast<int64_t>(v) <= prev) {
                        error = "MLSC shared proof relay_refs not strict ascending";
                        return false;
                    }
                    prev = static_cast<int64_t>(v);
                    proof.revealed_rung.relay_refs[ri] = static_cast<uint16_t>(v);
                }
                return true;
            }
        } else {
            proof.proof_mode = MLSCProofMode::FULL_LEAVES;
        }

        uint64_t total_rungs = ReadCompactSize(ss);
        uint64_t total_relays = ReadCompactSize(ss);
        uint64_t rung_index = ReadCompactSize(ss);

        if (total_rungs == 0 || total_rungs > MAX_RUNGS) {
            error = "MLSC proof total_rungs out of range: " + std::to_string(total_rungs);
            return false;
        }
        if (total_relays > MAX_RELAYS) {
            error = "MLSC proof total_relays out of range: " + std::to_string(total_relays);
            return false;
        }
        if (rung_index >= total_rungs) {
            error = "MLSC proof rung_index out of range: " + std::to_string(rung_index) +
                    " >= " + std::to_string(total_rungs);
            return false;
        }

        proof.total_rungs = static_cast<uint16_t>(total_rungs);
        proof.total_relays = static_cast<uint16_t>(total_relays);
        proof.rung_index = static_cast<uint16_t>(rung_index);

        uint64_t n_blocks = ReadCompactSize(ss);
        if (n_blocks > MAX_BLOCKS_PER_RUNG) {
            error = "MLSC proof rung block count invalid: " + std::to_string(n_blocks);
            return false;
        }

        uint8_t cond_ctx = static_cast<uint8_t>(SerializationContext::CONDITIONS);

        if (n_blocks == 0) {
            error = "MLSC proof: compact rungs deprecated";
            return false;
        }

        proof.revealed_rung.blocks.resize(n_blocks);
        for (uint64_t b = 0; b < n_blocks; ++b) {
            std::string block_error;
            if (!DeserializeBlock(ss, proof.revealed_rung.blocks[b], cond_ctx, block_error)) {
                error = "MLSC proof rung: " + block_error;
                return false;
            }
        }

        // Read rung relay_refs
        uint64_t n_rung_refs = ReadCompactSize(ss);
        if (n_rung_refs > MAX_REQUIRES) {
            error = "MLSC proof too many rung relay_refs";
            return false;
        }
        // v0.11 (audit #7 #1): strict ascending unique on the proof-side
        // relay_refs. Wire format already enforces this (v0.10 F-4), but the
        // merge step takes relay_refs from the proof, not the wire — so a
        // permuted proof re-opens the F-4 channel without this check.
        proof.revealed_rung.relay_refs.resize(n_rung_refs);
        {
            int64_t prev = -1;
            for (uint64_t ri = 0; ri < n_rung_refs; ++ri) {
                uint64_t v = ReadCompactSize(ss);
                if (static_cast<int64_t>(v) <= prev) {
                    error = "MLSC proof rung relay_refs not strict ascending";
                    return false;
                }
                prev = static_cast<int64_t>(v);
                proof.revealed_rung.relay_refs[ri] = static_cast<uint16_t>(v);
            }
        }

        // Read revealed relays
        uint64_t n_revealed = ReadCompactSize(ss);
        if (n_revealed > total_relays) {
            error = "MLSC proof more revealed relays than total";
            return false;
        }
        proof.revealed_relays.resize(n_revealed);
        for (uint64_t rl = 0; rl < n_revealed; ++rl) {
            uint64_t relay_idx = ReadCompactSize(ss);
            if (relay_idx >= total_relays) {
                error = "MLSC proof relay index out of range";
                return false;
            }
            proof.revealed_relays[rl].first = static_cast<uint16_t>(relay_idx);

            uint64_t rnb = ReadCompactSize(ss);
            if (rnb == 0 || rnb > MAX_BLOCKS_PER_RUNG) {
                error = "MLSC proof relay block count invalid";
                return false;
            }
            Relay& relay = proof.revealed_relays[rl].second;
            relay.blocks.resize(rnb);
            for (uint64_t rb = 0; rb < rnb; ++rb) {
                std::string block_error;
                if (!DeserializeBlock(ss, relay.blocks[rb], cond_ctx, block_error)) {
                    error = "MLSC proof relay: " + block_error;
                    return false;
                }
            }

            // Read relay relay_refs
            uint64_t n_rrefs = ReadCompactSize(ss);
            if (n_rrefs > MAX_REQUIRES) {
                error = "MLSC proof relay too many relay_refs";
                return false;
            }
            // v0.11 (audit #7 #1): strict ascending unique — same canonical
            // encoding requirement as the wire-format relay deserialise.
            relay.relay_refs.resize(n_rrefs);
            {
                int64_t prev = -1;
                for (uint64_t rri = 0; rri < n_rrefs; ++rri) {
                    uint64_t v = ReadCompactSize(ss);
                    if (static_cast<int64_t>(v) <= prev) {
                        error = "MLSC proof relay relay_refs not strict ascending";
                        return false;
                    }
                    prev = static_cast<int64_t>(v);
                    relay.relay_refs[rri] = static_cast<uint16_t>(v);
                }
            }
        }

        // Read proof hashes
        uint64_t n_proofs = ReadCompactSize(ss);
        if (proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
            // Merkle path: ceil(log2(padded_size)) sibling hashes
            size_t total_leaves = total_rungs + total_relays + 1;
            size_t padded = 1;
            while (padded < total_leaves) padded <<= 1;
            size_t max_depth = 0;
            for (size_t p = padded; p > 1; p >>= 1) ++max_depth;
            if (n_proofs > max_depth) {
                error = "MLSC Merkle path too long: " + std::to_string(n_proofs) +
                        " > depth " + std::to_string(max_depth);
                return false;
            }
        } else {
            // Full leaves: max unrevealed = total_rungs - 1 + total_relays - revealed_relays
            size_t max_proofs = (total_rungs - 1) + (total_relays - n_revealed);
            if (n_proofs > max_proofs) {
                error = "MLSC proof too many proof hashes: " + std::to_string(n_proofs) +
                        " > " + std::to_string(max_proofs);
                return false;
            }
        }
        proof.proof_hashes.resize(n_proofs);
        for (uint64_t ph = 0; ph < n_proofs; ++ph) {
            ss.read(MakeWritableByteSpan(proof.proof_hashes[ph]));
        }

        // Optional: read revealed mutation targets (trailing field, backward-compatible)
        if (!ss.empty()) {
            uint64_t n_targets = ReadCompactSize(ss);
            if (n_targets > total_rungs) {
                error = "MLSC proof too many mutation targets: " + std::to_string(n_targets);
                return false;
            }
            proof.revealed_mutation_targets.resize(n_targets);
            for (uint64_t mt = 0; mt < n_targets; ++mt) {
                auto& target = proof.revealed_mutation_targets[mt];

                uint64_t mt_idx = ReadCompactSize(ss);
                if (mt_idx >= total_rungs) {
                    error = "MLSC proof mutation target index out of range";
                    return false;
                }
                target.idx = static_cast<uint16_t>(mt_idx);

                // Deserialize mutation target rung blocks
                uint64_t mt_blocks = ReadCompactSize(ss);
                if (mt_blocks == 0 || mt_blocks > MAX_BLOCKS_PER_RUNG) {
                    error = "MLSC proof mutation target block count invalid";
                    return false;
                }
                target.rung.blocks.resize(mt_blocks);
                for (uint64_t mb = 0; mb < mt_blocks; ++mb) {
                    std::string block_error;
                    if (!DeserializeBlock(ss, target.rung.blocks[mb], cond_ctx, block_error)) {
                        error = "MLSC proof mutation target: " + block_error;
                        return false;
                    }
                }

                // Read mutation target relay_refs
                uint64_t mt_refs = ReadCompactSize(ss);
                if (mt_refs > MAX_REQUIRES) {
                    error = "MLSC proof mutation target too many relay_refs";
                    return false;
                }
                // v0.11 (audit #7 #1): strict ascending unique — mutation
                // targets feed into BuildCPRung at evaluator.cpp via
                // VerifyMutatedLeaves; same canonical encoding required.
                target.rung.relay_refs.resize(mt_refs);
                {
                    int64_t prev = -1;
                    for (uint64_t mr = 0; mr < mt_refs; ++mr) {
                        uint64_t v = ReadCompactSize(ss);
                        if (static_cast<int64_t>(v) <= prev) {
                            error = "MLSC proof mutation target relay_refs not strict ascending";
                            return false;
                        }
                        prev = static_cast<int64_t>(v);
                        target.rung.relay_refs[mr] = static_cast<uint16_t>(v);
                    }
                }

                // Per-rung pubkey list. Matches the pubkey set folded
                // into the leaf at creation time so consensus can
                // recompute the leaf hash bit-exact. Empty for rungs
                // with no key-consuming blocks.
                uint64_t mt_n_pubkeys = ReadCompactSize(ss);
                // Hard cap: 16 pubkeys per rung (same as MAX_BLOCKS_PER_RUNG).
                if (mt_n_pubkeys > MAX_BLOCKS_PER_RUNG) {
                    error = "MLSC proof mutation target too many pubkeys";
                    return false;
                }
                target.pubkeys.resize(mt_n_pubkeys);
                for (uint64_t pk = 0; pk < mt_n_pubkeys; ++pk) {
                    uint64_t pk_len = ReadCompactSize(ss);
                    // Max pubkey size: FALCON-1024 at 1793 bytes.
                    if (pk_len > 1952) {
                        error = "MLSC proof mutation target pubkey too large: " +
                                std::to_string(pk_len);
                        return false;
                    }
                    target.pubkeys[pk].resize(pk_len);
                    if (pk_len > 0) {
                        ss.read(MakeWritableByteSpan(target.pubkeys[pk]));
                    }
                }
            }
        }

        if (!ss.empty()) {
            error = "trailing bytes in MLSC proof";
            return false;
        }

    } catch (const std::ios_base::failure& e) {
        error = std::string("MLSC proof deserialization failure: ") + e.what();
        return false;
    }

    return true;
}

std::vector<uint8_t> SerializeMLSCProof(const MLSCProof& proof)
{
    DataStream ss{};

    // New versioned format: prefix with 0x00 + proof_mode byte
    if (proof.proof_mode != MLSCProofMode::FULL_LEAVES) {
        ss << static_cast<uint8_t>(0x00); // version prefix
        ss << static_cast<uint8_t>(proof.proof_mode);

        // SHARED mode: compact format
        if (proof.proof_mode == MLSCProofMode::SHARED) {
            WriteCompactSize(ss, proof.shared_source_input);
            WriteCompactSize(ss, proof.total_rungs);
            WriteCompactSize(ss, proof.rung_index);
            auto rung_bytes = SerializeRungBlocks(proof.revealed_rung, SerializationContext::CONDITIONS);
            ss.write(MakeByteSpan(rung_bytes));
            std::vector<uint8_t> result(ss.size());
            ss.read(MakeWritableByteSpan(result));
            return result;
        }
    }

    WriteCompactSize(ss, proof.total_rungs);
    WriteCompactSize(ss, proof.total_relays);
    WriteCompactSize(ss, proof.rung_index);

    // Serialize revealed rung blocks using existing block serialization
    auto rung_bytes = SerializeRungBlocks(proof.revealed_rung, SerializationContext::CONDITIONS);
    ss.write(MakeByteSpan(rung_bytes));

    // Serialize revealed relays
    WriteCompactSize(ss, proof.revealed_relays.size());
    for (const auto& [relay_idx, relay] : proof.revealed_relays) {
        WriteCompactSize(ss, relay_idx);
        auto relay_bytes = SerializeRelayBlocks(relay, SerializationContext::CONDITIONS);
        ss.write(MakeByteSpan(relay_bytes));
    }

    // Serialize proof hashes
    WriteCompactSize(ss, proof.proof_hashes.size());
    for (const auto& hash : proof.proof_hashes) {
        ss.write(MakeByteSpan(hash));
    }

    // Serialize revealed mutation targets (optional trailing field).
    // Wire layout per target:
    //   idx (CompactSize)
    //   [SerializeRungBlocks: block_count, blocks, relay_ref_count, relay_refs]
    //   pubkey_count (CompactSize)
    //   [pubkey_len (CompactSize) + pubkey_bytes] * pubkey_count
    //
    // The pubkey list is the per-rung pubkey set folded into the
    // Merkle leaf at creation time. Consensus uses it to recompute
    // the leaf bit-exact when running covenant root comparisons on
    // the rung the mutation target reveals. Required for rungs with
    // SIG/key-consuming blocks; empty for QABI_SPEND/QABI_PRIME.
    if (!proof.revealed_mutation_targets.empty()) {
        WriteCompactSize(ss, proof.revealed_mutation_targets.size());
        for (const auto& target : proof.revealed_mutation_targets) {
            WriteCompactSize(ss, target.idx);
            auto mt_bytes = SerializeRungBlocks(target.rung, SerializationContext::CONDITIONS);
            ss.write(MakeByteSpan(mt_bytes));

            WriteCompactSize(ss, target.pubkeys.size());
            for (const auto& pk : target.pubkeys) {
                WriteCompactSize(ss, pk.size());
                if (!pk.empty()) {
                    ss.write(MakeByteSpan(pk));
                }
            }
        }
    }

    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

// v0.7: VerifyMLSCProof retained as a test-only helper that exercises the
// legacy full-MLSC leaf scheme + tree. Consensus does NOT call this — the
// live verifier (evaluator.cpp:1019-1049) inlines merkle-path/full-leaves
// verification using ComputeTxMLSCLeaf + ComputeTxMLSCRelayLeaf directly.
bool VerifyMLSCProof(const MLSCProof& proof,
                     const RungCoil& coil,
                     const uint256& expected_root,
                     const std::vector<std::vector<uint8_t>>& rung_pubkeys,
                     const std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys,
                     std::string& error,
                     MLSCVerifiedLeaves* verified_out)
{
    if (proof.proof_mode == MLSCProofMode::SHARED) {
        error = "SHARED proof mode must be resolved by the caller";
        return false;
    }
    // v0.8: tree = rung_leaves + relay_leaves (no coil leaf — coil structural
    // fields are bound via each rung leaf's template in the live TX_MLSC scheme).
    if (proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
        size_t total_leaves = proof.total_rungs + proof.total_relays;
        uint256 rung_leaf = ComputeRungLeaf(proof.revealed_rung, rung_pubkeys);
        std::string path_error;
        if (!VerifyMerklePath(rung_leaf, proof.proof_hashes, total_leaves, expected_root, path_error)) {
            error = "MERKLE_PATH verification failed: " + path_error;
            return false;
        }
        if (verified_out) {
            verified_out->root = expected_root;
            verified_out->rung_index = proof.rung_index;
            verified_out->total_rungs = proof.total_rungs;
            verified_out->total_relays = proof.total_relays;
            verified_out->leaves.resize(1);
            verified_out->leaves[0] = rung_leaf;
        }
        return true;
    }
    size_t total_leaves = proof.total_rungs + proof.total_relays;
    std::vector<uint256> leaves(total_leaves);
    std::vector<bool> revealed(total_leaves, false);
    leaves[proof.rung_index] = ComputeRungLeaf(proof.revealed_rung, rung_pubkeys);
    revealed[proof.rung_index] = true;
    for (size_t rl = 0; rl < proof.revealed_relays.size(); ++rl) {
        const auto& [relay_idx, relay] = proof.revealed_relays[rl];
        size_t leaf_idx = proof.total_rungs + relay_idx;
        if (leaf_idx >= total_leaves) {
            error = "revealed relay index out of range";
            return false;
        }
        const auto& rpks = (rl < relay_pubkeys.size()) ? relay_pubkeys[rl]
                                                      : std::vector<std::vector<uint8_t>>{};
        leaves[leaf_idx] = ComputeRelayLeaf(relay, rpks);
        revealed[leaf_idx] = true;
    }
    (void)coil; // v0.8: coil is structurally bound via rung leaf; no separate leaf.
    size_t proof_idx = 0;
    for (size_t i = 0; i < total_leaves; ++i) {
        if (!revealed[i]) {
            if (proof_idx >= proof.proof_hashes.size()) {
                error = "not enough proof hashes: need hash for leaf " + std::to_string(i);
                return false;
            }
            leaves[i] = proof.proof_hashes[proof_idx++];
        }
    }
    if (proof_idx != proof.proof_hashes.size()) {
        error = "excess proof hashes: used " + std::to_string(proof_idx) +
                " of " + std::to_string(proof.proof_hashes.size());
        return false;
    }
    for (const auto& target : proof.revealed_mutation_targets) {
        if (target.idx >= proof.total_rungs) {
            error = "mutation target rung_index out of range: " + std::to_string(target.idx);
            return false;
        }
        if (target.idx == proof.rung_index) {
            error = "mutation target same as revealed rung: " + std::to_string(target.idx);
            return false;
        }
        uint256 target_leaf = ComputeRungLeaf(target.rung, target.pubkeys);
        if (target_leaf != leaves[target.idx]) {
            error = "mutation target leaf mismatch at rung " + std::to_string(target.idx);
            return false;
        }
    }
    if (verified_out) {
        verified_out->leaves = leaves;
        verified_out->root = expected_root;
        verified_out->rung_index = proof.rung_index;
        verified_out->total_rungs = proof.total_rungs;
        verified_out->total_relays = proof.total_relays;
    }
    uint256 computed_root = BuildMerkleTree(std::move(leaves));
    if (computed_root != expected_root) {
        error = "MLSC Merkle root mismatch";
        return false;
    }
    return true;
}

// ============================================================================
// TX_MLSC: Transaction-Level Merkelised Ladder Script Conditions
// ============================================================================

std::vector<uint8_t> SerializeStructuralTemplate(const CreationProofRung& rung)
{
    std::vector<uint8_t> out;

    // n_blocks
    uint8_t n_blocks = static_cast<uint8_t>(rung.blocks.size());
    out.push_back(n_blocks);

    // Per block: block_type(2) + inverted(1)
    for (const auto& [block_type, inverted] : rung.blocks) {
        out.push_back(static_cast<uint8_t>(block_type & 0xFF));
        out.push_back(static_cast<uint8_t>((block_type >> 8) & 0xFF));
        out.push_back(inverted);
    }

    // v0.9 (R-1): n_relay_refs(1) + each ref(2 LE).
    // The rung leaf MUST commit to its relay dependencies; without this binding
    // a spender can drop relay_refs at spend time and skip relay enforcement.
    // Symmetric to SerializeRelayStructuralTemplate which already bound
    // relay.relay_refs since v0.7 (E-008).
    out.push_back(static_cast<uint8_t>(rung.relay_refs.size()));
    for (uint16_t r : rung.relay_refs) {
        out.push_back(static_cast<uint8_t>(r & 0xFF));
        out.push_back(static_cast<uint8_t>((r >> 8) & 0xFF));
    }

    // v0.8: Coil: type(1) + attestation(1) + scheme(1) + output_index(1)
    // (has_address byte removed alongside coil.address_hash; see E-009.)
    out.push_back(static_cast<uint8_t>(rung.coil.coil_type));
    out.push_back(static_cast<uint8_t>(rung.coil.attestation));
    out.push_back(static_cast<uint8_t>(rung.coil.scheme));
    out.push_back(rung.coil.output_index);

    return out;
}

uint256 ComputeTxMLSCLeaf(const CreationProofRung& rung)
{
    auto tmpl = SerializeStructuralTemplate(rung);
    CSHA256 hasher = LEAF_HASHER; // copy pre-computed TaggedHash("LadderLeaf/v1") prefix
    hasher.Write(tmpl.data(), tmpl.size());
    hasher.Write(rung.value_commitment.data(), 32);
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

std::vector<uint8_t> SerializeRelayStructuralTemplate(const CreationProofRelay& relay)
{
    std::vector<uint8_t> out;
    // n_blocks
    uint8_t n_blocks = static_cast<uint8_t>(relay.blocks.size());
    out.push_back(n_blocks);
    // Per block: block_type(2) + inverted(1)
    for (const auto& [block_type, inverted] : relay.blocks) {
        out.push_back(static_cast<uint8_t>(block_type & 0xFF));
        out.push_back(static_cast<uint8_t>((block_type >> 8) & 0xFF));
        out.push_back(inverted);
    }
    // n_relay_refs (1 byte; bounded by MAX_REQUIRES = 8)
    out.push_back(static_cast<uint8_t>(relay.relay_refs.size()));
    for (uint16_t r : relay.relay_refs) {
        out.push_back(static_cast<uint8_t>(r & 0xFF));
        out.push_back(static_cast<uint8_t>((r >> 8) & 0xFF));
    }
    return out;
}

uint256 ComputeTxMLSCRelayLeaf(const CreationProofRelay& relay)
{
    auto tmpl = SerializeRelayStructuralTemplate(relay);
    CSHA256 hasher = RELAY_LEAF_HASHER; // distinct domain from rung leaves
    hasher.Write(tmpl.data(), tmpl.size());
    hasher.Write(relay.value_commitment.data(), 32);
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

uint256 ComputeTxMLSCRoot(const std::vector<CreationProofRung>& rungs,
                          const std::vector<CreationProofRelay>& relays)
{
    // Tree leaves: rung_leaf[0..N-1] then relay_leaf[0..M-1]. Coil structural
    // fields are bound via each rung leaf's template (no separate coil leaf).
    std::vector<uint256> leaves;
    leaves.reserve(rungs.size() + relays.size());
    for (const auto& rung : rungs) {
        leaves.push_back(ComputeTxMLSCLeaf(rung));
    }
    for (const auto& relay : relays) {
        leaves.push_back(ComputeTxMLSCRelayLeaf(relay));
    }
    return BuildMerkleTree(std::move(leaves));
}

uint256 ComputeValueCommitment(const Rung& rung,
                                const std::vector<std::vector<uint8_t>>& pubkeys)
{
    CSHA256 hasher;

    // Hash all field values from all blocks in layout order.
    // NUMERIC fields are normalized to 4-byte LE to ensure consistent
    // value_commitment regardless of how the field was originally encoded
    // (1-byte hex vs 4-byte descriptor parser output).
    for (const auto& block : rung.blocks) {
        for (const auto& field : block.fields) {
            if (field.type == RungDataType::NUMERIC && field.data.size() < 4) {
                uint8_t padded[4] = {0, 0, 0, 0};
                memcpy(padded, field.data.data(), field.data.size());
                hasher.Write(padded, 4);
            } else {
                hasher.Write(field.data.data(), field.data.size());
            }
        }
    }

    // Append pubkeys (merkle_pub_key — same positional order as leaf computation)
    for (const auto& pk : pubkeys) {
        hasher.Write(pk.data(), pk.size());
    }

    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

} // namespace rung
