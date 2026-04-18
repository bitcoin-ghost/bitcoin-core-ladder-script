// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

#ifndef BITCOIN_RUNG_API_H
#define BITCOIN_RUNG_API_H

// ============================================================================
// libladder public API
// ============================================================================
//
// This header is the ONLY interface that Bitcoin Core uses to call into
// the Ladder Script library. Everything that isn't declared here is a
// library internal. A BIP that specifies Ladder Script normatively
// references the symbols in this file; reviewers who want to understand
// what the library does read this header first and follow links from here.
//
// Design rules:
//
//   1. This header MUST NOT include any Bitcoin Core type (CTransaction,
//      CTxOut, CScript, CAmount, BaseSignatureChecker, PrecomputedTransactionData,
//      CPubKey, CKey, XOnlyPubKey, uint256 from <uint256.h>, etc.). Every
//      external type crosses the boundary as a byte span, a primitive, or
//      an adapter struct defined here.
//
//   2. The library never touches global state that lives in Bitcoin Core
//      (chainstate, mempool, net, wallet, RPC server). Anything it needs
//      from Core comes in via a callback (LadderSigChecker,
//      LadderBlockAccessor) or an explicitly-passed value.
//
//   3. Each block type lives in its own translation unit under
//      src/rung/blocks/, exporting a void register_XYZ_block() function
//      that the host calls from ladder_init() at startup. A block that
//      is compiled out never registers; transactions using that block
//      are rejected with LADDER_ERR_UNKNOWN_BLOCK_TYPE. This is what
//      makes selective activation possible: a BIP sub-proposal can be
//      declined by disabling its blocks, and the Core integration is
//      unchanged.
//
//   4. The header uses C++ style (namespaces, references, virtual classes
//      for callbacks). A narrow extern "C" wrapper will be added later
//      for language bindings, in the libsecp256k1 pattern. The C++ here
//      is deliberately conservative: no templates at the ABI surface, no
//      exceptions, no STL containers in function signatures.
//
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

// Forward declaration: RungField is library-internal (rung/types.h).
// Appears in LadderBlockDescriptor callbacks because those fire inside
// the library after deserialisation. Hosts never construct RungField.
namespace rung { struct RungField; }

namespace rung::api {

// ============================================================================
// Section 1: error codes
// ============================================================================
//
// The library has its own error enum. Bitcoin Core's SCRIPT_ERR_* is not
// visible here. The Core-side shim translates LadderScriptError to
// SCRIPT_ERR_* when interfacing with the Core interpreter.

enum class LadderScriptError : uint32_t {
    OK = 0,

    // Dispatch / structural
    UNKNOWN_BLOCK_TYPE,           // A block in the witness is not registered
    UNKNOWN_ERROR,                // Catch-all (avoid; prefer specific)
    WITNESS_PROGRAM_WITNESS_EMPTY,
    WITNESS_MALFORMED,
    WITNESS_UNEXPECTED_SIZE,
    NON_MLSC_SCRIPT,              // Evaluator called on non-MLSC output

    // Serialisation
    CONDITIONS_DESERIALISE_FAILED,
    PROOF_DESERIALISE_FAILED,
    FIELD_TYPE_INVALID,
    FIELD_SIZE_INVALID,
    FIELD_COUNT_INVALID,

    // Merkle / MLSC
    MERKLE_PATH_MISMATCH,
    MLSC_ROOT_MISMATCH,
    MLSC_ROOT_UNAVAILABLE,        // block accessor could not fetch root
    MLSC_LEAF_MISMATCH,

    // Signature / crypto
    SIGNATURE_INVALID,
    SIGNATURE_SIZE_INVALID,
    SCHNORR_SIG_SIZE,
    PUBKEY_INVALID,

    // Locktimes
    LOCKTIME_FAILED,
    SEQUENCE_FAILED,
    NEGATIVE_LOCKTIME,

    // Covenants / introspection
    CTV_HASH_MISMATCH,
    OUTPUT_CHECK_FAILED,
    INPUT_COUNT_FAILED,
    OUTPUT_COUNT_FAILED,
    WEIGHT_LIMIT_FAILED,
    EPOCH_GATE_FAILED,

    // PQ signatures
    PQ_SCHEME_DISABLED,           // Library built without the requested scheme
    PQ_SIGNATURE_INVALID,

    // QABIO
    QABI_DISABLED,                // Library built without LADDER_ENABLE_QABIO
    QABI_PRIME_INVALID,
    QABI_SPEND_INVALID,
    QABI_AGGREGATED_SIG_INVALID,

    // Policy (not consensus; returned by IsStandardRungTx etc.)
    POLICY_BAD_TX,
    POLICY_NON_STANDARD,

    // Evaluator
    EVAL_FALSE,                   // Rung evaluated to UNSATISFIED
    EVAL_NO_RUNG_SATISFIED,       // No rung in the ladder was satisfied
};

const char* LadderScriptErrorName(LadderScriptError err);

// ============================================================================
// Section 2: adapter types — byte-span views over Core types
// ============================================================================
//
// These are non-owning views. Lifetime is the caller's responsibility. The
// Core-side shim layer (see src/rung_shims.cpp) constructs these from
// CTransaction / CScript / etc. and passes them to library functions.

// A scriptPubKey / witness-byte view. For MLSC outputs, this is a 1-, 33-, or
// 34–73-byte buffer (0xDF prefix + conditions_root + optional DATA_RETURN).
struct LadderScript {
    const uint8_t* data{nullptr};
    size_t size{0};

    constexpr LadderScript() = default;
    constexpr LadderScript(const uint8_t* d, size_t s) : data(d), size(s) {}

    std::span<const uint8_t> as_span() const { return {data, size}; }
};

// One element of a witness stack.
struct LadderWitnessElement {
    const uint8_t* data{nullptr};
    size_t size{0};
};

// The full witness stack for one input.
struct LadderWitnessStack {
    const LadderWitnessElement* elements{nullptr};
    size_t count{0};
};

// A previous-output reference (txid + vout index).
struct LadderOutPoint {
    uint8_t txid[32]{};   // byte-for-byte txid (internal order — not display order)
    uint32_t n{0};
};

// One input of a transaction.
struct LadderInputView {
    LadderOutPoint prevout;
    LadderScript script_sig;          // typically empty for v4
    LadderWitnessStack witness;
    uint32_t sequence{0};
};

// One output.
struct LadderOutputView {
    int64_t value{0};                 // amount in satoshis
    LadderScript script_pub_key;
};

// A transaction as a set of byte views.
//
// The caller provides txid/wtxid if already known; otherwise the library
// computes them as needed (ComputeTxMLSCRoot path depends on stable txid).
struct LadderTxView {
    int32_t version{0};
    uint32_t lock_time{0};

    const LadderInputView* inputs{nullptr};
    size_t input_count{0};

    const LadderOutputView* outputs{nullptr};
    size_t output_count{0};

    // Precomputed identity hashes. nullptr if the caller hasn't computed
    // them; the library will compute internally if needed. Having them
    // cached makes repeated evaluations (same tx, multiple inputs) cheap.
    const uint8_t* txid{nullptr};     // 32 bytes or nullptr
    const uint8_t* wtxid{nullptr};    // 32 bytes or nullptr

    // QABIO extension: the per-tx serialised QABI batch block, if any.
    // Empty (data=nullptr, size=0) for non-QABIO v4 transactions.
    const uint8_t* qabi_block{nullptr};
    size_t qabi_block_size{0};
};

// ============================================================================
// Section 3: precomputed transaction data
// ============================================================================
//
// The Core PrecomputedTransactionData computes several SHA256 summaries of
// the transaction up front so that every input's sighash doesn't rebuild
// them from scratch. The library accepts byte-span pointers to those
// summaries; if nullptr, it will compute on demand (but that is slow for
// multi-input transactions).

struct LadderPrecomputedTxData {
    const uint8_t* hash_prevouts_sha256{nullptr};      // 32 bytes
    const uint8_t* hash_sequences_sha256{nullptr};     // 32 bytes
    const uint8_t* hash_outputs_sha256{nullptr};       // 32 bytes
    const uint8_t* hash_spent_amounts_sha256{nullptr}; // 32 bytes
    // Note: ladder sighash does NOT consume hash_spent_scripts_sha256
    // (that is BIP341 territory); the field is omitted here.
    bool ladder_ready{false};  // all four pointers above are valid and computed
};

// ============================================================================
// Section 4: callbacks into the host (Core-side)
// ============================================================================
//
// The two places where libladder genuinely needs state the caller owns.
// Everything else is pure-functional over bytes.

// Signature verification. The host (Core) wraps its BaseSignatureChecker
// in an adapter that implements this interface. Test harnesses and fuzzers
// provide mocks. The library never sees Core's signature checker directly.
class LadderSigChecker {
public:
    virtual ~LadderSigChecker() = default;

    // ECDSA (BIP66-style). sig includes the 1-byte sighash suffix.
    virtual bool CheckECDSASignature(
        std::span<const uint8_t> sig,
        std::span<const uint8_t> pubkey,
        std::span<const uint8_t, 32> sighash) const = 0;

    // Schnorr (BIP340). sig is 64 bytes or 65 bytes (with sighash byte).
    virtual bool CheckSchnorrSignature(
        std::span<const uint8_t> sig,
        std::span<const uint8_t> pubkey,
        std::span<const uint8_t, 32> sighash) const = 0;

    // Locktime / sequence checks. These read state the library doesn't have
    // (current block height / MTP vs the tx's nLockTime). Host-provided.
    virtual bool CheckLockTime(uint32_t lock_time) const = 0;
    virtual bool CheckSequence(uint32_t sequence) const = 0;
};

// MLSC root recovery. The consensus invariant in src/compressor.cpp
// requires that at spend time, we recover the creating transaction's
// conditions_root from block storage. Only the host (Core, with a block
// index) knows how to do this. Stateless verifiers (library fuzzers,
// libbitcoinkernel-style paths) provide a mock or refuse to validate
// v4 spends.
class LadderBlockAccessor {
public:
    virtual ~LadderBlockAccessor() = default;

    // Given a UTXO's creating txid, produce the conditions_root field
    // from that tx's TX_MLSC layout. Returns false if the tx can't be
    // located (pruned without undo data, snapshot boundary, etc.).
    virtual bool FetchConditionsRoot(
        std::span<const uint8_t, 32> txid,
        uint8_t root_out[32]) const = 0;
};

// ============================================================================
// Section 5: opaque cache handles
// ============================================================================
//
// These exist for performance (shared-proof mode within a transaction,
// QABIO aggregated-sig memoisation). Opaque to the host — library owns
// the memory. Created once per transaction / block by the host, passed
// through each per-input VerifyRungTx call, destroyed at the end.

// Caches: currently library-internal std::map<Txid, ...> aliases defined
// in rung/evaluator.h. Converting them to genuine opaque handles (so api.h
// is independent of uint256/Txid/Core types) is deferred to a later phase
// — see libladder-extraction-notes.md for the interim representation.
// For now, callers pass pointers to the library-internal types directly.

// ============================================================================
// Section 6: evaluation context
// ============================================================================

struct LadderEvalContext {
    int32_t block_height{0};
    uint32_t flags{0};  // script verification flags (bit-compatible with SCRIPT_VERIFY_*)

    const LadderPrecomputedTxData* precomputed{nullptr};
    const LadderSigChecker* sig_checker{nullptr};
    const LadderBlockAccessor* block_accessor{nullptr};

    // Caches — see note in Section 5. Typed as void* in api.h for now;
    // library-internal code casts back to rung::SharedTreeCache* /
    // rung::QABOSigCache*. A later phase will make these truly opaque.
    void* shared_tree_cache{nullptr};
    void* qabo_sig_cache{nullptr};
};

// ============================================================================
// Section 7: block registry
// ============================================================================
//
// This is the per-block modularity point. Each block type is a translation
// unit under src/rung/blocks/ that defines:
//
//   - a static LadderBlockDescriptor
//   - a static evaluate() function matching LadderBlockEvalFn
//   - a static validate_fields() function matching LadderBlockValidateFn
//   - an exported void register_<block>_block() function that calls
//     ladder_register_block(&descriptor)
//
// ladder_init() (defined in src/rung/block_registry.cpp) calls each
// register_*_block() in turn, guarded by #ifdef LADDER_ENABLE_<BLOCK>.
// A block that isn't compiled in never registers; the library returns
// UNKNOWN_BLOCK_TYPE for any transaction that uses it.
//
// This gives per-block compile-time selectivity: if a BIP reviewer objects
// to, say, ANCHOR_ORACLE, we ship a build with -DLADDER_ENABLE_ANCHOR_ORACLE=OFF
// and the library's registry simply doesn't know about that block. The Core
// integration doesn't change.
//
// Required-for-consensus-base blocks are described as "required" in their
// CMakeLists.txt entry — disabling them is a build error, not a silent
// reduction.

// RungField is defined in rung/types.h (library-internal). Forward declared
// at file scope above. Block eval/validate callbacks receive the parsed
// RungField form because that's what exists inside the library after
// deserialisation.

enum class LadderEvalResult : uint8_t {
    SATISFIED,
    UNSATISFIED,
    EVAL_ERROR,
};

using LadderBlockEvalFn = LadderEvalResult (*)(
    const ::rung::RungField* fields,
    size_t field_count,
    const LadderEvalContext& ctx,
    LadderScriptError* error_out);

using LadderBlockValidateFn = bool (*)(
    const ::rung::RungField* fields,
    size_t field_count,
    LadderScriptError* error_out);

// Capability bits advertised per block (for introspection, not consensus).
namespace block_cap {
    constexpr uint32_t KEY_CONSUMING   = 1 << 0;  // contains a SIG-family block
    constexpr uint32_t INVERTIBLE      = 1 << 1;  // supports contact inversion
    constexpr uint32_t COVENANT        = 1 << 2;  // binds future-tx shape
    constexpr uint32_t STATEFUL        = 1 << 3;  // PLC block with hidden state
    constexpr uint32_t PQ              = 1 << 4;  // uses liboqs
    constexpr uint32_t INTROSPECTION   = 1 << 5;  // reads current-tx shape
    constexpr uint32_t RECURSIVE       = 1 << 6;  // RECURSE_* family
    constexpr uint32_t QABIO           = 1 << 7;  // QABI_PRIME / QABI_SPEND
}

struct LadderBlockDescriptor {
    uint16_t type_code;              // canonical consensus type code (stable across BIPs)
    const char* name;                // display name ("SIG", "CSV", ...)
    uint8_t min_fields;
    uint8_t max_fields;
    uint32_t capability_flags;       // any of block_cap::*
    LadderBlockEvalFn evaluate;
    LadderBlockValidateFn validate_fields;
};

// Called once per block from ladder_init(). Returns false if the block
// type_code is already registered (registration is idempotent in debug
// builds, fatal in release).
bool ladder_register_block(const LadderBlockDescriptor* desc);

// Lookup by type code. Returns nullptr if not registered (which, during
// consensus evaluation, is the primary "unknown block" signal).
const LadderBlockDescriptor* ladder_lookup_block(uint16_t type_code);

// Introspection — how many blocks are registered in this build.
size_t ladder_registered_block_count();

// Enumeration for RPC / tooling. Returns descriptors in undefined order.
// iter starts at nullptr; out-of-range when returned value is nullptr.
const LadderBlockDescriptor* ladder_enumerate_blocks(
    const LadderBlockDescriptor* iter);

// ============================================================================
// Section 8: library initialisation
// ============================================================================
//
// Call once at process startup before any other library entry point.
// Idempotent. Thread-safe. Populates the block registry with every block
// whose translation unit was compiled in.

void ladder_init();

// Inverse of ladder_init, primarily for test fixtures that want a clean
// registry per run. In production, library lifetime == process lifetime.
void ladder_shutdown();

// ============================================================================
// Section 9: consensus-critical entry points
// ============================================================================
//
// Eight functions + two opaque cache types. This is the BIP-reviewable
// surface. Everything above exists to support these.

// Verify one input of a v4 transaction. Returns true iff the input is valid
// (all rung evaluations line up, signatures check, proofs verify). Called
// per-input by the host after dispatch (see src/rung/api.h comment on
// dispatch in VerifyRungTx).
//
// The host MUST only call this for inputs whose spent output is an MLSC
// scriptPubKey. Calling it otherwise returns NON_MLSC_SCRIPT (safety net).
bool VerifyRungTx(
    const LadderTxView& tx,
    size_t input_index,
    const LadderOutputView& spent_output,
    const LadderEvalContext& ctx,
    LadderScriptError* error_out);

// Transaction-level consensus checks (output structure, creation-proof
// sanity, TX_MLSC layout, QABIO priming rules). Run once per v4 tx,
// separately from per-input VerifyRungTx, because it must fire even on
// v4 txs whose inputs are all standard P2WPKH/P2TR (wallet-funded bootstrap).
bool CheckRungTxLevel(
    const LadderTxView& tx,
    uint32_t flags,
    std::string& error_out);

// Is this scriptPubKey an MLSC output of any form (compact, full, or with
// DATA_RETURN suffix)? Dispatch predicate — used by Core's CScriptCheck
// to decide whether to route to VerifyRungTx or VerifyScript.
bool IsMLSCScript(const LadderScript& script_pub_key);

// Is this the 1-byte "compact" MLSC form (root recovered from block data)?
bool IsCompactMLSC(const LadderScript& script_pub_key);

// Alias for IsMLSCScript; kept for readability at call sites where the
// question is "should this output be treated as Ladder Script?" rather than
// specifically "is this MLSC-shaped?".
bool IsLadderScript(const LadderScript& script_pub_key);

// Policy (non-consensus): is this a standard, relay-eligible Ladder tx?
bool IsStandardRungTx(
    const LadderTxView& tx,
    std::string& reason_out);

// Policy: does this tx contain a QABI_PRIME block? (Used for mempool
// replacement rules — priming txs have special RBD semantics.)
bool IsQABIPrimingTx(const LadderTxView& tx);

// Policy: does new_tx validly replace old_tx under QABIO-specific
// replace-by-descendant-of-prime rules?
bool IsValidRBDReplacement(
    const LadderTxView& new_tx,
    const LadderTxView& old_tx,
    std::string& reason_out);

// ============================================================================
// End of libladder public API
// ============================================================================

}  // namespace rung::api

#endif  // BITCOIN_RUNG_API_H
