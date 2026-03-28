// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

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
    switch (type) {
    // PUBKEY_COMMIT removed from conditions — pubkeys folded into Merkle leaf
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
        return false;
    }
    return false;
}

// Inline conditions (0xC1) removed — all outputs must use MLSC (0xDF).
// These functions are retained for backward compatibility but always reject.

bool IsRungConditionsScript(const CScript&)
{
    return false; // Inline conditions removed
}

bool DeserializeRungConditions(const CScript&, RungConditions&, std::string& error)
{
    error = "inline conditions (0xC1) removed — use MLSC (0xDF)";
    return false;
}

CScript SerializeRungConditions(const RungConditions&)
{
    // Inline conditions removed — should never be called
    return CScript();
}

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
    // Compute SHA256(tag)
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

static const CSHA256 LEAF_HASHER = InitTaggedHasher("LadderLeaf");
static const CSHA256 INTERNAL_HASHER = InitTaggedHasher("LadderInternal");

/** Compute MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "") at startup. */
static uint256 ComputeEmptyLeaf()
{
    return TaggedHash("LadderLeaf", nullptr, 0);
}

const uint256 MLSC_EMPTY_LEAF = ComputeEmptyLeaf();

bool IsMLSCScript(const CScript& scriptPubKey)
{
    // 33 bytes = standard MLSC (0xDF + 32-byte root)
    // 34-73 bytes = MLSC with DATA_RETURN payload (max 40 bytes data)
    return scriptPubKey.size() >= 33 && scriptPubKey.size() <= 73 &&
           scriptPubKey[0] == RUNG_MLSC_PREFIX;
}

bool IsLadderScript(const CScript& scriptPubKey)
{
    return IsMLSCScript(scriptPubKey);
}

bool GetMLSCRoot(const CScript& scriptPubKey, uint256& root_out)
{
    if (!IsMLSCScript(scriptPubKey)) return false;
    memcpy(root_out.data(), scriptPubKey.data() + 1, 32);
    return true;
}

std::vector<uint8_t> GetMLSCData(const CScript& scriptPubKey)
{
    if (!IsMLSCScript(scriptPubKey) || scriptPubKey.size() <= 33) {
        return {};
    }
    return std::vector<uint8_t>(scriptPubKey.begin() + 33, scriptPubKey.end());
}

bool HasMLSCData(const CScript& scriptPubKey)
{
    return IsMLSCScript(scriptPubKey) && scriptPubKey.size() > 33;
}

CScript CreateMLSCScript(const uint256& conditions_root)
{
    CScript result;
    result.push_back(RUNG_MLSC_PREFIX);
    result.insert(result.end(), conditions_root.begin(), conditions_root.end());
    return result;
}

CScript CreateMLSCScript(const uint256& conditions_root, const std::vector<uint8_t>& data)
{
    CScript result;
    result.push_back(RUNG_MLSC_PREFIX);
    result.insert(result.end(), conditions_root.begin(), conditions_root.end());
    result.insert(result.end(), data.begin(), data.end());
    return result;
}

uint256 ComputeRungLeaf(const Rung& rung,
                         const std::vector<std::vector<uint8_t>>& pubkeys)
{
    auto bytes = SerializeRungBlocks(rung, SerializationContext::CONDITIONS);
    CSHA256 hasher = LEAF_HASHER; // copy pre-computed prefix
    hasher.Write(bytes.data(), bytes.size());
    // merkle_pub_key: append pubkeys in positional order
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
    // merkle_pub_key: append pubkeys in positional order
    for (const auto& pk : pubkeys) {
        hasher.Write(pk.data(), pk.size());
    }
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

/** Compute a sorted interior Merkle node: TaggedHash("LadderInternal", min(a,b) || max(a,b)). */
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
            error = "single leaf does not match root";
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
    // Leaf order: [rung_leaf[0..N-1], relay_leaf[0..M-1], coil_leaf]
    std::vector<uint256> leaves;
    leaves.reserve(conditions.rungs.size() + conditions.relays.size() + 1);

    for (size_t i = 0; i < conditions.rungs.size(); ++i) {
        const auto& pks = (i < rung_pubkeys.size()) ? rung_pubkeys[i] : std::vector<std::vector<uint8_t>>{};
        leaves.push_back(ComputeRungLeaf(conditions.rungs[i], pks));
    }
    for (size_t i = 0; i < conditions.relays.size(); ++i) {
        const auto& pks = (i < relay_pubkeys.size()) ? relay_pubkeys[i] : std::vector<std::vector<uint8_t>>{};
        leaves.push_back(ComputeRelayLeaf(conditions.relays[i], pks));
    }
    leaves.push_back(ComputeCoilLeaf(conditions.coil));

    return BuildMerkleTree(leaves);
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
                proof.shared_source_input = static_cast<uint16_t>(ReadCompactSize(ss));
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

                // Deserialize revealed rung blocks
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
                proof.revealed_rung.relay_refs.resize(n_rung_refs);
                for (uint64_t ri = 0; ri < n_rung_refs; ++ri) {
                    proof.revealed_rung.relay_refs[ri] = static_cast<uint16_t>(ReadCompactSize(ss));
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

        // Deserialize revealed rung condition blocks
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

        // Deserialize rung blocks via shared DeserializeBlock (CONDITIONS context)
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
        proof.revealed_rung.relay_refs.resize(n_rung_refs);
        for (uint64_t ri = 0; ri < n_rung_refs; ++ri) {
            proof.revealed_rung.relay_refs[ri] = static_cast<uint16_t>(ReadCompactSize(ss));
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

            // Deserialize relay blocks via shared DeserializeBlock (CONDITIONS context)
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
            relay.relay_refs.resize(n_rrefs);
            for (uint64_t rri = 0; rri < n_rrefs; ++rri) {
                relay.relay_refs[rri] = static_cast<uint16_t>(ReadCompactSize(ss));
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
                uint64_t mt_idx = ReadCompactSize(ss);
                if (mt_idx >= total_rungs) {
                    error = "MLSC proof mutation target index out of range";
                    return false;
                }
                proof.revealed_mutation_targets[mt].first = static_cast<uint16_t>(mt_idx);

                // Deserialize mutation target rung blocks
                uint64_t mt_blocks = ReadCompactSize(ss);
                if (mt_blocks == 0 || mt_blocks > MAX_BLOCKS_PER_RUNG) {
                    error = "MLSC proof mutation target block count invalid";
                    return false;
                }
                Rung& mt_rung = proof.revealed_mutation_targets[mt].second;
                mt_rung.blocks.resize(mt_blocks);
                for (uint64_t mb = 0; mb < mt_blocks; ++mb) {
                    std::string block_error;
                    if (!DeserializeBlock(ss, mt_rung.blocks[mb], cond_ctx, block_error)) {
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
                mt_rung.relay_refs.resize(mt_refs);
                for (uint64_t mr = 0; mr < mt_refs; ++mr) {
                    mt_rung.relay_refs[mr] = static_cast<uint16_t>(ReadCompactSize(ss));
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

    // Serialize revealed mutation targets (optional trailing field)
    if (!proof.revealed_mutation_targets.empty()) {
        WriteCompactSize(ss, proof.revealed_mutation_targets.size());
        for (const auto& [mt_idx, mt_rung] : proof.revealed_mutation_targets) {
            WriteCompactSize(ss, mt_idx);
            auto mt_bytes = SerializeRungBlocks(mt_rung, SerializationContext::CONDITIONS);
            ss.write(MakeByteSpan(mt_bytes));
        }
    }

    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

bool VerifyMLSCProof(const MLSCProof& proof,
                     const RungCoil& coil,
                     const uint256& expected_root,
                     const std::vector<std::vector<uint8_t>>& rung_pubkeys,
                     const std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys,
                     std::string& error,
                     MLSCVerifiedLeaves* verified_out,
                     const std::vector<std::vector<std::vector<uint8_t>>>& mutation_target_pubkeys)
{
    // SHARED mode must be handled by the caller (evaluator) — not this function
    if (proof.proof_mode == MLSCProofMode::SHARED) {
        error = "SHARED proof mode must be resolved by the caller";
        return false;
    }

    // MERKLE_PATH mode: O(log N) sibling hashes from leaf to root
    if (proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
        size_t total_leaves = proof.total_rungs + proof.total_relays + 1;
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

    // FULL_LEAVES mode: all unrevealed leaf hashes provided
    // Total leaves: total_rungs + total_relays + 1 (coil)
    size_t total_leaves = proof.total_rungs + proof.total_relays + 1;

    // Build the leaf array
    std::vector<uint256> leaves(total_leaves);

    // Track which leaves are revealed vs proof
    std::vector<bool> revealed(total_leaves, false);

    // Rung leaf: the revealed rung goes at rung_index (with merkle_pub_key pubkeys)
    leaves[proof.rung_index] = ComputeRungLeaf(proof.revealed_rung, rung_pubkeys);
    revealed[proof.rung_index] = true;

    // Revealed relay leaves: relays start at index total_rungs
    for (size_t rl = 0; rl < proof.revealed_relays.size(); ++rl) {
        const auto& [relay_idx, relay] = proof.revealed_relays[rl];
        size_t leaf_idx = proof.total_rungs + relay_idx;
        if (leaf_idx >= total_leaves - 1) { // -1 because last leaf is coil
            error = "revealed relay index out of range";
            return false;
        }
        const auto& rpks = (rl < relay_pubkeys.size()) ? relay_pubkeys[rl] : std::vector<std::vector<uint8_t>>{};
        leaves[leaf_idx] = ComputeRelayLeaf(relay, rpks);
        revealed[leaf_idx] = true;
    }

    // Coil leaf: always last
    leaves[total_leaves - 1] = ComputeCoilLeaf(coil);
    revealed[total_leaves - 1] = true;

    // Fill unrevealed leaves with proof hashes (in order)
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

    // Verify mutation target leaves: for each revealed mutation target,
    // compute its leaf and check it matches the leaf at that rung index.
    for (size_t mt = 0; mt < proof.revealed_mutation_targets.size(); ++mt) {
        const auto& [target_idx, target_rung] = proof.revealed_mutation_targets[mt];
        if (target_idx >= proof.total_rungs) {
            error = "mutation target rung_index out of range: " + std::to_string(target_idx);
            return false;
        }
        if (target_idx == proof.rung_index) {
            error = "mutation target same as revealed rung: " + std::to_string(target_idx);
            return false;
        }
        const auto& mt_pks = (mt < mutation_target_pubkeys.size()) ?
            mutation_target_pubkeys[mt] : std::vector<std::vector<uint8_t>>{};
        uint256 target_leaf = ComputeRungLeaf(target_rung, mt_pks);
        if (target_leaf != leaves[target_idx]) {
            error = "mutation target leaf mismatch at rung " + std::to_string(target_idx);
            return false;
        }
    }

    // Populate verified_out before moving leaves
    if (verified_out) {
        verified_out->leaves = leaves; // copy before move
        verified_out->root = expected_root;
        verified_out->rung_index = proof.rung_index;
        verified_out->total_rungs = proof.total_rungs;
        verified_out->total_relays = proof.total_relays;
    }

    // Build Merkle tree and compare
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

    // Coil: type(1) + attestation(1) + scheme(1) + output_index(1) + has_address(1)
    out.push_back(static_cast<uint8_t>(rung.coil.coil_type));
    out.push_back(static_cast<uint8_t>(rung.coil.attestation));
    out.push_back(static_cast<uint8_t>(rung.coil.scheme));
    out.push_back(rung.coil.output_index);
    out.push_back(rung.coil.address_hash.empty() ? 0x00 : 0x01);

    return out;
}

uint256 ComputeTxMLSCLeaf(const CreationProofRung& rung)
{
    auto tmpl = SerializeStructuralTemplate(rung);
    CSHA256 hasher = LEAF_HASHER; // copy pre-computed TaggedHash("LadderLeaf") prefix
    hasher.Write(tmpl.data(), tmpl.size());
    hasher.Write(rung.value_commitment.data(), 32);
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

uint256 ComputeTxMLSCRoot(const std::vector<CreationProofRung>& rungs)
{
    std::vector<uint256> leaves;
    leaves.reserve(rungs.size());
    for (const auto& rung : rungs) {
        leaves.push_back(ComputeTxMLSCLeaf(rung));
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
                // Normalize to 4-byte LE
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
