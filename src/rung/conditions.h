// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_CONDITIONS_H
#define BITCOIN_RUNG_CONDITIONS_H

#include <rung/api.h>
#include <rung/types.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rung {

/** 0xC1 inline-conditions prefix. The feature is gone; the constant stays
 *  so the rejection tests in rung_tests can assert that every entry point
 *  still refuses it. */
static constexpr uint8_t RUNG_CONDITIONS_PREFIX = 0xc1;

/** Magic prefix byte for MLSC (Merkelised Ladder Script Conditions)
 *  scriptPubKeys: 0xDF || conditions_root(32). The only supported v4
 *  output format. Full conditions are revealed at spend time in the witness. */
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

// 0xC1 inline-conditions stubs — always reject. Used only by the
// regression tests in rung_tests that pin "0xC1 is rejected everywhere".
// These + the MLSC predicates below live in rung::api to match api.h.
// Library-internal code can `using namespace rung::api;` at file scope.
namespace api {
bool IsRungConditionsScript(std::span<const uint8_t> script_pub_key);
bool DeserializeRungConditions(std::span<const uint8_t> script_pub_key, RungConditions& out, std::string& error);
std::vector<uint8_t> SerializeRungConditions(const RungConditions& conditions);
}  // namespace api

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

/** MLSC scriptPubKey marker: full or compact MLSC outputs all start with this
 *  byte. (`0xDF` was chosen to be in the upper-half of the byte space, well
 *  away from any existing OP_* opcode.) */
inline constexpr uint8_t MLSC_MARKER = 0xDF;

/** Synthetic-root coin marker: per-tx synthetic UTXO entries at
 *  `(txid, MLSC_ROOT_VOUT = 0xFFFFFFFF)` carry the 32-byte conditions_root
 *  prefixed with this byte. Distinct from `MLSC_MARKER` (`0xDF`) so the
 *  standard UTXO compressor does not strip the root from the synthetic
 *  entry. Defined in one place so any divergence between the writer
 *  (`coins.cpp`) and the reader (`validation.cpp`) is a compile-time
 *  collision rather than a silent runtime drift. */
inline constexpr uint8_t MLSC_SYNTHETIC_MARKER = 0xDE;

namespace api {

/** Check if scriptPubKey is an MLSC output (0xDF prefix).
 *  Accepts both full (33+ bytes: 0xDF + root) and compact (1 byte: 0xDF only, from UTXO decompression). */
bool IsMLSCScript(std::span<const uint8_t> script_pub_key);

/** Check if scriptPubKey is a Ladder Script output (MLSC 0xDF). */
bool IsLadderScript(std::span<const uint8_t> script_pub_key);

/** Check if this is a compact MLSC scriptPubKey (1 byte, root not embedded).
 *  The conditions_root must be recovered from the creating transaction. */
bool IsCompactMLSC(std::span<const uint8_t> script_pub_key);

/** Extract the 32-byte conditions root from a full MLSC scriptPubKey.
 *  Returns false for compact (1-byte) MLSC — use block database lookup instead. */
bool GetMLSCRoot(std::span<const uint8_t> script_pub_key, uint256& root_out);

/** Extract the DATA_RETURN payload from an MLSC scriptPubKey (bytes after the root).
 *  Returns empty vector if no data is appended (standard 33-byte MLSC). */
std::vector<uint8_t> GetMLSCData(std::span<const uint8_t> script_pub_key);

/** Check if an MLSC scriptPubKey has a DATA_RETURN payload appended. */
bool HasMLSCData(std::span<const uint8_t> script_pub_key);

/** Create an MLSC scriptPubKey: 0xDF + conditions_root. Returns raw bytes. */
std::vector<uint8_t> CreateMLSCScript(const uint256& conditions_root);

/** Create an MLSC scriptPubKey with DATA_RETURN payload: 0xDF + conditions_root + data.
 *  Data must be 1-80 bytes. Returns raw bytes. */
std::vector<uint8_t> CreateMLSCScript(const uint256& conditions_root, const std::vector<uint8_t>& data);

}  // namespace api

// v0.7: ComputeRungLeaf / ComputeCoilLeaf / ComputeRelayLeaf are retained as
// test-only helpers. They use the legacy serialised-blocks leaf scheme and do
// NOT participate in consensus — the live verifier uses ComputeTxMLSCLeaf and
// ComputeTxMLSCRelayLeaf (TaggedHash over structural template + value
// commitment). Consensus paths must NOT call these. Tests in rung_tests.cpp
// pin the legacy helpers' determinism + tree behaviour.
uint256 ComputeRungLeaf(const Rung& rung,
                         const std::vector<std::vector<uint8_t>>& pubkeys = {});
uint256 ComputeCoilLeaf(const RungCoil& coil);
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

/** MULTISIG v2 inner-pubkey Merkle helpers (BIP-XXXX §MULTISIG).
 *
 *  The inner tree commits to an ordered list of pubkeys at fund time so that
 *  signers can later reveal only the K pubkeys whose signatures are required,
 *  preventing the K<N data-embedding bypass. Unrevealed slots cost nothing
 *  on-chain; revealed slots carry one MERKLE_PROOF (≤128 B) each.
 *
 *  Hash domains (separated from the outer MLSC tree to prevent any cross-tree
 *  collision attack):
 *    leaf:     TaggedHash("LadderMultisigPubkey/v1",   pubkey_bytes)
 *    interior: TaggedHash("LadderMultisigInternal/v1", min(a,b) || max(a,b))
 *
 *  Padding leaf is the empty-input tagged hash of the leaf domain. */

/** Build the inner pubkey-Merkle root over a positional pubkey list.
 *  Pads to the next power of 2 with the multisig-specific empty-leaf hash. */
uint256 BuildPubkeyMerkleRoot(const std::vector<std::vector<uint8_t>>& pubkeys);

/** Build the Merkle path (sibling hashes from leaf to root) for the pubkey
 *  at the given index within the positional list. */
std::vector<uint256> BuildPubkeyMerkleProof(const std::vector<std::vector<uint8_t>>& pubkeys,
                                             size_t target_index);

/** Verify that `pubkey` is committed to by `expected_root` via `proof`.
 *  Proof length encodes tree depth (0 ≤ depth ≤ MAX_MULTISIG_TREE_DEPTH).
 *  An empty proof indicates a single-leaf tree (leaf must equal root).
 *  Errors set `error` and return false. */
bool VerifyPubkeyMerkleProof(const std::vector<uint8_t>& pubkey,
                              const std::vector<uint256>& proof,
                              const uint256& expected_root,
                              std::string& error);

/** ACCUMULATOR v2 helpers (BIP-XXXX §ACCUMULATOR).
 *
 *  Set-membership proofs over an inner Merkle tree where leaves are
 *  domain-separated tagged hashes of a small structured payload (the
 *  element id). This eliminates the legacy v1 shape in which both leaf and
 *  sibling hashes were free 32-byte attacker-chosen blobs (~288 B per spend).
 *
 *  Hash domains:
 *    leaf:     TaggedHash("LadderAccumulatorLeaf/v1",     element_id_LE)
 *    interior: TaggedHash("LadderAccumulatorInterior/v1", min(a,b) || max(a,b))
 *
 *  Sorted-children interior nodes — same convention as the legacy shape but
 *  domain-separated from MLSC and inner-pubkey trees so cross-tree collisions
 *  are impossible. */

/** Compute the leaf hash for the element with the given id. */
uint256 BuildAccumulatorLeaf(uint32_t element_id);

/** Sorted interior hash for the accumulator tree. */
uint256 BuildAccumulatorInterior(const uint256& a, const uint256& b);

/** Verify that the element with the given id is committed to by `expected_root`
 *  via the proof bytes (concatenated 32-byte sibling hashes, depth ≤
 *  MAX_ACCUMULATOR_PROOF_DEPTH). */
bool VerifyAccumulatorProof(uint32_t element_id,
                             const std::vector<uint8_t>& proof_bytes,
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
 *  Convenience wrapper around `ComputeTxMLSCRoot`: builds CreationProofRung +
 *  CreationProofRelay structs from the supplied conditions and delegates.
 *  Leaf order: [rung[0..N-1], relay[0..M-1]] (coil is structurally bound via
 *  rung leaf templates — does not appear separately).
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

/** A revealed cross-rung mutation target — carries the full content of
 *  another rung in the original conditions tree. Covenant blocks that
 *  need to reason about the whole tree (QABI_PRIME's check 5, cross-
 *  rung RECURSE_MODIFIED mutations) use this to access rungs other
 *  than the one being spent.
 *
 *  `pubkeys` carries the same per-rung pubkey list that was folded
 *  into the leaf at creation time. Required for any rung with
 *  key-consuming blocks (SIG, etc.) — without it the consensus-time
 *  leaf recomputation would produce a different hash than the real
 *  tree and covenant checks would fail. Empty for rungs with no
 *  key-consuming blocks (e.g. QABI_SPEND, QABI_PRIME). */
struct MLSCMutationTarget {
    uint16_t idx;
    Rung rung;
    std::vector<std::vector<uint8_t>> pubkeys;
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
    std::vector<MLSCMutationTarget> revealed_mutation_targets; //!< Cross-rung mutation targets with full content + pubkeys
};

/** Deserialize an MLSC proof from witness stack element bytes. */
bool DeserializeMLSCProof(const std::vector<uint8_t>& data, MLSCProof& proof, std::string& error);

/** Serialize an MLSC proof to bytes (for witness stack element). */
std::vector<uint8_t> SerializeMLSCProof(const MLSCProof& proof);

// v0.7: VerifyMLSCProof retained as a test-only helper that exercises the
// legacy full-MLSC leaf scheme + tree (ComputeRungLeaf / ComputeRelayLeaf /
// ComputeCoilLeaf). Consensus does NOT call this — the live verifier inlines
// MERKLE_PATH/FULL_LEAVES against ComputeTxMLSCLeaf + ComputeTxMLSCRelayLeaf
// (see evaluator.cpp:1019-1049).
bool VerifyMLSCProof(const MLSCProof& proof,
                     const RungCoil& coil,
                     const uint256& expected_root,
                     const std::vector<std::vector<uint8_t>>& rung_pubkeys,
                     const std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys,
                     std::string& error,
                     MLSCVerifiedLeaves* verified_out = nullptr);

// ============================================================================
// TX_MLSC (Transaction-Level Merkelised Ladder Script Conditions)
// ============================================================================

/** A single rung in the creation proof — structural template + opaque value commitment.
 *  The structural template (block types, inverted flags, coil) is validated at block
 *  acceptance. The value_commitment = SHA256(field_values || pubkeys) is opaque —
 *  a hash output, not attacker-chosen data.
 *
 *  Together they form the leaf: TaggedHash("LadderLeaf/v1", template || value_commitment). */
struct CreationProofRung {
    std::vector<std::pair<uint16_t, uint8_t>> blocks;  //!< Per-block: (block_type, inverted)
    RungCoil coil;                                      //!< Coil including output_index
    uint256 value_commitment;                           //!< SHA256(field_values || pubkeys)
};

/** A single relay in the creation proof — symmetric to CreationProofRung but without coil.
 *  Leaf: TaggedHash("LadderRelayLeaf/v1", template || value_commitment).
 *  v0.7: relay leaves are now folded into the conditions_root alongside rung leaves,
 *  closing E-008 (KEY_REF_SIG could previously dereference any spender-supplied relay). */
struct CreationProofRelay {
    std::vector<std::pair<uint16_t, uint8_t>> blocks;       //!< Per-block: (block_type, inverted)
    std::vector<uint16_t> relay_refs;                       //!< Bound transitive relay deps
    uint256 value_commitment;                               //!< SHA256(field_values || pubkeys)
};

/** Serialize a structural template (block types + inverted flags + coil) for leaf hashing.
 *  Used at spend time to reconstruct rung leaves from witness data. */
std::vector<uint8_t> SerializeStructuralTemplate(const CreationProofRung& rung);

/** Serialize a relay's structural template (block types + inverted flags + relay_refs). */
std::vector<uint8_t> SerializeRelayStructuralTemplate(const CreationProofRelay& relay);

/** Compute a TX_MLSC leaf from a rung's structural template + value commitment.
 *  leaf = TaggedHash("LadderLeaf/v1", structural_template || value_commitment)
 *  Used at both creation (by RPC) and spend time (by evaluator). */
uint256 ComputeTxMLSCLeaf(const CreationProofRung& rung);

/** Compute a TX_MLSC relay leaf.
 *  leaf = TaggedHash("LadderRelayLeaf/v1", relay_template || value_commitment) */
uint256 ComputeTxMLSCRelayLeaf(const CreationProofRelay& relay);

/** Compute the TX_MLSC conditions root from rung leaves and (optionally) relay leaves.
 *  v0.7: relay leaves participate in the tree to close the KEY_REF_SIG relay-swap bug.
 *  Tree leaf order: [rung[0..N-1], relay[0..M-1]]. */
uint256 ComputeTxMLSCRoot(const std::vector<CreationProofRung>& rungs,
                          const std::vector<CreationProofRelay>& relays = {});

/** Compute a value_commitment for a rung: SHA256(field_values || pubkeys).
 *  Used by RPC commands when building conditions and by the evaluator
 *  when verifying spend-time Merkle proofs. */
uint256 ComputeValueCommitment(const Rung& rung,
                                const std::vector<std::vector<uint8_t>>& pubkeys);

} // namespace rung

#endif // BITCOIN_RUNG_CONDITIONS_H
