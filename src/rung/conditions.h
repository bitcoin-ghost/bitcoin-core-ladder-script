// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_CONDITIONS_H
#define BITCOIN_RUNG_CONDITIONS_H

#include <rung/types.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rung {

/** Legacy prefix byte for inline conditions (removed — always rejected).
 *  Retained as a constant for test code that verifies rejection. */
static constexpr uint8_t RUNG_CONDITIONS_PREFIX = 0xc1;

/** Magic prefix byte identifying a scriptPubKey as MLSC (Merkelised Ladder Script Conditions).
 *  Output format: 0xDF + conditions_root(32 bytes) = 33-byte scriptPubKey.
 *  Full conditions are revealed only at spend time in the witness.
 *  This is the ONLY accepted output format. Inline conditions (0xC1) are removed. */
static constexpr uint8_t RUNG_MLSC_PREFIX = 0xdf;

/** Nothing-up-my-sleeve constant for empty Merkle tree leaf padding.
 *  = SHA256("LADDER_EMPTY_LEAF"). Cannot collide with valid serialized rung/coil/relay data. */
extern const uint256 MLSC_EMPTY_LEAF;

/** A single field-level diff in a template reference. */
struct TemplateDiff {
    uint16_t rung_index;   //!< Which rung in the inherited conditions
    uint16_t block_index;  //!< Which block within that rung
    uint16_t field_index;  //!< Which field within that block
    RungField new_field;   //!< Replacement field data
};

/** Template reference: conditions inherited from another input with optional diffs. */
struct TemplateReference {
    uint32_t input_index;               //!< Which input's conditions to inherit
    std::vector<TemplateDiff> diffs;    //!< Field-level patches to apply
};

/** Rung conditions = the "locking" side of a v4 output.
 *  Stored in scriptPubKey with the same wire format as a LadderWitness
 *  but containing only condition data types (HASH256, HASH160, NUMERIC,
 *  SCHEME, SPEND_INDEX) — never PUBKEY, PUBKEY_COMMIT, SIGNATURE,
 *  or PREIMAGE. Public keys are folded into the Merkle leaf hash
 *  (merkle_pub_key) to prevent arbitrary data embedding.
 *
 *  When template_ref is set, n_rungs was 0 on the wire — conditions
 *  are inherited from the referenced input with diffs applied.
 *  Resolution happens in VerifyRungTx after all inputs' conditions
 *  are deserialized. */
struct RungConditions {
    std::vector<Rung> rungs;
    RungCoil coil;               //!< Output coil (per-output, serialized with conditions)
    std::vector<Relay> relays;   //!< Relay definitions (shared condition sets)
    std::optional<TemplateReference> template_ref; //!< Template inheritance reference (if set, rungs are empty until resolved)
    std::optional<uint256> conditions_root; //!< MLSC: Merkle root from UTXO (set for 0xDF outputs)

    bool IsEmpty() const { return rungs.empty() && !template_ref.has_value() && !conditions_root.has_value(); }
    bool IsTemplateRef() const { return template_ref.has_value(); }
    bool IsMLSC() const { return conditions_root.has_value(); }
};

// Inline conditions (0xC1) removed. These stubs always return false.
bool IsRungConditionsScript(const CScript& scriptPubKey);
bool DeserializeRungConditions(const CScript& scriptPubKey, RungConditions& out, std::string& error);
CScript SerializeRungConditions(const RungConditions& conditions);

/** Resolve a template reference: copy conditions from the referenced input
 *  and apply field-level diffs.
 *  @param[in,out] conditions  The conditions with template_ref set (rungs empty).
 *                              On success, rungs/coil/relays are populated from
 *                              the referenced input and template_ref is cleared.
 *  @param[in]     all_conditions  All deserialized conditions for the transaction's inputs.
 *  @param[out]    error       Error message on failure.
 *  @return true on success. */
bool ResolveTemplateReference(RungConditions& conditions,
                              const std::vector<RungConditions>& all_conditions,
                              std::string& error);

/** Check whether a data type is allowed in conditions (locking side).
 *  SIGNATURE and PREIMAGE are witness-only and not permitted. */
bool IsConditionDataType(RungDataType type);

// Backward-compatible alias
inline bool IsConditionFieldType(RungDataType type) { return IsConditionDataType(type); }

// ============================================================================
// MLSC (Merkelized Ladder Script Conditions)
// ============================================================================

/** Check if scriptPubKey is an MLSC output (0xDF prefix).
 *  Accepts both full (33+ bytes: 0xDF + root) and compact (1 byte: 0xDF only, from UTXO decompression). */
bool IsMLSCScript(const CScript& scriptPubKey);

/** Check if scriptPubKey is a Ladder Script output (MLSC 0xDF). */
bool IsLadderScript(const CScript& scriptPubKey);

/** Check if this is a compact MLSC scriptPubKey (1 byte, root not embedded).
 *  The conditions_root must be recovered from the creating transaction. */
bool IsCompactMLSC(const CScript& scriptPubKey);

/** Extract the 32-byte conditions root from a full MLSC scriptPubKey.
 *  Returns false for compact (1-byte) MLSC — use block database lookup instead. */
bool GetMLSCRoot(const CScript& scriptPubKey, uint256& root_out);

/** Extract the DATA_RETURN payload from an MLSC scriptPubKey (bytes after the root).
 *  Returns empty vector if no data is appended (standard 33-byte MLSC). */
std::vector<uint8_t> GetMLSCData(const CScript& scriptPubKey);

/** Check if an MLSC scriptPubKey has a DATA_RETURN payload appended. */
bool HasMLSCData(const CScript& scriptPubKey);

/** Create an MLSC scriptPubKey: 0xDF + conditions_root. */
CScript CreateMLSCScript(const uint256& conditions_root);

/** Create an MLSC scriptPubKey with DATA_RETURN payload: 0xDF + conditions_root + data.
 *  Data must be 1-80 bytes. */
CScript CreateMLSCScript(const uint256& conditions_root, const std::vector<uint8_t>& data);

/** Compute the SHA256 leaf hash for a single rung (blocks + relay_refs + pubkeys).
 *  merkle_pub_key: pubkeys are appended to the leaf in positional order,
 *  walked left-to-right across key-consuming blocks using PubkeyCountForBlock(). */
uint256 ComputeRungLeaf(const Rung& rung,
                         const std::vector<std::vector<uint8_t>>& pubkeys = {});

/** Compute the SHA256 leaf hash for coil metadata. */
uint256 ComputeCoilLeaf(const RungCoil& coil);

/** Compute the SHA256 leaf hash for a relay (blocks + relay_refs + pubkeys). */
uint256 ComputeRelayLeaf(const Relay& relay,
                          const std::vector<std::vector<uint8_t>>& pubkeys = {});

/** Build a binary Merkle tree from an arbitrary set of leaves.
 *  Pads to next power of 2 with MLSC_EMPTY_LEAF.
 *  Interior hashing: sort children lexicographically, then SHA256(0x01 || left || right).
 *  @return the Merkle root. */
uint256 BuildMerkleTree(std::vector<uint256> leaves);

/** Build a Merkle path (sibling hashes from leaf to root) for a target leaf.
 *  The tree uses sorted interior nodes, so no direction bits are needed.
 *  @param leaves        The full leaf array (will be padded to next power of 2)
 *  @param target_index  Index of the target leaf
 *  @return vector of sibling hashes, one per tree level (bottom to top). */
std::vector<uint256> BuildMerklePath(std::vector<uint256> leaves, size_t target_index);

/** Verify a Merkle path against an expected root.
 *  Uses sorted interior nodes — no direction bits needed.
 *  @param leaf           The leaf hash to verify
 *  @param path           Sibling hashes from leaf to root
 *  @param total_leaves   Number of leaves before padding (for depth computation)
 *  @param expected_root  The expected Merkle root
 *  @param error          Error message on failure
 *  @return true if the path verifies correctly. */
bool VerifyMerklePath(const uint256& leaf,
                      const std::vector<uint256>& path,
                      size_t total_leaves,
                      const uint256& expected_root,
                      std::string& error);

/** Compute a Ladder Script tweaked conditions root for key-path spending.
 *  tweaked_key = internal_pubkey + H_LadderTweak(internal_pubkey || merkle_root) * G
 *  @return (tweaked x-only key as uint256, parity) or nullopt on failure. */
std::optional<std::pair<uint256, bool>> ComputeTweakedConditionsRoot(
    const std::vector<uint8_t>& internal_pubkey_bytes,
    const uint256& merkle_root);

/** Compute the Merkle root from a leaf and its path (without checking against an expected root).
 *  Uses sorted interior nodes. */
uint256 ComputeMerkleRootFromPath(const uint256& leaf, const std::vector<uint256>& path);

/** Compute the MLSC conditions root for a complete set of conditions.
 *  Leaf order: [rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf].
 *  @param rung_pubkeys   Per-rung pubkey lists (outer index = rung index)
 *  @param relay_pubkeys  Per-relay pubkey lists (outer index = relay index) */
uint256 ComputeConditionsRoot(const RungConditions& conditions,
                               const std::vector<std::vector<std::vector<uint8_t>>>& rung_pubkeys = {},
                               const std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys = {});

/** Verified leaf array from VerifyMLSCProof — enables leaf-centric covenant checks.
 *  Instead of recomputing the Merkle root from conditions (which requires all rungs'
 *  pubkeys including unrevealed ones), covenant evaluators copy this array, mutate
 *  the relevant leaf, rebuild the tree, and compare against the output root. */
struct MLSCVerifiedLeaves {
    std::vector<uint256> leaves;  //!< Full leaf array (rungs + relays + coil)
    uint256 root;                 //!< Verified conditions root
    uint16_t rung_index;          //!< Which leaf is the revealed rung
    uint16_t total_rungs;         //!< Number of rung leaves
    uint16_t total_relays;        //!< Number of relay leaves
};

/** Proof mode for MLSC spending proofs. */
enum class MLSCProofMode : uint8_t {
    FULL_LEAVES = 0x00,  //!< Legacy: all unrevealed leaf hashes (O(N) witness size)
    MERKLE_PATH = 0x01,  //!< Sibling hashes from leaf to root (O(log N) witness size)
    SHARED      = 0x02,  //!< References another input's proof from the same source tx
};

/** MLSC spending proof — revealed conditions + Merkle proof hashes.
 *  Carried in witness stack[1] when spending an MLSC (0xDF) output. */
struct MLSCProof {
    uint16_t total_rungs;      //!< Total number of rungs in the original conditions
    uint16_t total_relays;     //!< Total number of relays in the original conditions
    uint16_t rung_index;       //!< Which rung leaf is being revealed (0-based)
    Rung revealed_rung;        //!< Condition blocks for the revealed rung
    std::vector<std::pair<uint16_t, Relay>> revealed_relays; //!< (relay_index, condition blocks) for each revealed relay
    std::vector<uint256> proof_hashes; //!< FULL_LEAVES: unrevealed leaf hashes. MERKLE_PATH: sibling hashes from leaf to root. SHARED: empty.
    MLSCProofMode proof_mode{MLSCProofMode::FULL_LEAVES}; //!< Proof format
    uint16_t shared_source_input{0}; //!< SHARED mode: input index carrying the full proof for the same source tx
    std::vector<std::pair<uint16_t, Rung>> revealed_mutation_targets; //!< (rung_index, condition blocks) for cross-rung mutation targets (optional, backward-compatible)
};

/** Deserialize an MLSC proof from witness stack element bytes. */
bool DeserializeMLSCProof(const std::vector<uint8_t>& data, MLSCProof& proof, std::string& error);

/** Serialize an MLSC proof to bytes (for witness stack element). */
std::vector<uint8_t> SerializeMLSCProof(const MLSCProof& proof);

/** Verify an MLSC Merkle proof against a conditions root.
 *  Reconstructs the full leaf array from revealed data + proof hashes, builds the tree,
 *  and checks the computed root matches the expected root.
 *  @param[in]  proof           The deserialized MLSC proof
 *  @param[in]  coil            The coil from the spending witness (always revealed)
 *  @param[in]  expected_root   The conditions_root from the UTXO
 *  @param[in]  rung_pubkeys    Pubkeys for the revealed rung (from witness, bound by Merkle proof)
 *  @param[in]  relay_pubkeys   Per-relay pubkey lists for revealed relays
 *  @param[out] error           Error message on failure
 *  @param[out] verified_out    If non-null, receives the verified leaf array for covenant checks
 *  @param[in]  mutation_target_pubkeys  Per-mutation-target pubkey lists (for cross-rung leaf computation)
 *  @return true if the Merkle proof verifies correctly. */
bool VerifyMLSCProof(const MLSCProof& proof,
                     const RungCoil& coil,
                     const uint256& expected_root,
                     const std::vector<std::vector<uint8_t>>& rung_pubkeys,
                     const std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys,
                     std::string& error,
                     MLSCVerifiedLeaves* verified_out = nullptr,
                     const std::vector<std::vector<std::vector<uint8_t>>>& mutation_target_pubkeys = {});

// ============================================================================
// TX_MLSC (Transaction-Level Merkelised Ladder Script Conditions)
// ============================================================================

/** A single rung in the creation proof — structural template + opaque value commitment.
 *  The structural template (block types, inverted flags, coil) is validated at block
 *  acceptance. The value_commitment = SHA256(field_values || pubkeys) is opaque —
 *  a hash output, not attacker-chosen data.
 *
 *  Together they form the leaf: TaggedHash("LadderLeaf", template || value_commitment). */
struct CreationProofRung {
    std::vector<std::pair<uint16_t, uint8_t>> blocks;  //!< Per-block: (block_type, inverted)
    RungCoil coil;                                      //!< Coil including output_index
    uint256 value_commitment;                           //!< SHA256(field_values || pubkeys)
};

/** Serialize a structural template (block types + inverted flags + coil) for leaf hashing.
 *  Used at spend time to reconstruct rung leaves from witness data. */
std::vector<uint8_t> SerializeStructuralTemplate(const CreationProofRung& rung);

/** Compute a TX_MLSC leaf from a rung's structural template + value commitment.
 *  leaf = TaggedHash("LadderLeaf", structural_template || value_commitment)
 *  Used at both creation (by RPC) and spend time (by evaluator). */
uint256 ComputeTxMLSCLeaf(const CreationProofRung& rung);

/** Compute the TX_MLSC conditions root from a set of rung leaves.
 *  Builds a Merkle tree using sorted interior nodes. */
uint256 ComputeTxMLSCRoot(const std::vector<CreationProofRung>& rungs);

/** Compute a value_commitment for a rung: SHA256(field_values || pubkeys).
 *  Used by RPC commands when building conditions and by the evaluator
 *  when verifying spend-time Merkle proofs. */
uint256 ComputeValueCommitment(const Rung& rung,
                                const std::vector<std::vector<uint8_t>>& pubkeys);

} // namespace rung

#endif // BITCOIN_RUNG_CONDITIONS_H
