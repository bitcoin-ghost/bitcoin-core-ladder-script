// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_EVALUATOR_H
#define BITCOIN_RUNG_EVALUATOR_H

#include <rung/conditions.h>
#include <rung/types.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script_error.h>

#include <consensus/amount.h>
#include <primitives/transaction_identifier.h>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <uint256.h>
#include <unordered_set>

class CTransaction;
class CTxOut;

namespace rung {

// Ladder-native Eval*Block functions take the adapter sig checker
// (`rung::api::LadderSigChecker` in `rung/api.h`, implemented Core-side by
// `rung::CoreLadderSigChecker` in `rung_shims.h`). Legacy P2* wrapper
// blocks stay on Core's `BaseSignatureChecker` because they verify legacy
// / SegWit / Taproot sighashes, not Ladder sighash.

// QABIO support types (BIP-YYYY). Gated on ENABLE_QABIO so the base
// Ladder Script evaluator has no QABIO-specific machinery when the
// extension is disabled.
//
// QABOSigCache is deliberately kept as a complete type in both builds
// (an empty struct when disabled) so that RungEvalContext's pointer
// member and VerifyRungTx's parameter keep identical signatures
// regardless of the flag. Callers pass nullptr when the extension is
// off, the evaluator's QABIO code paths are all #ifdef'd out, and no
// QABIO-specific headers (qabi.h, shared_ptr<QABIBlock>, unordered_set)
// leak into non-QABIO builds.
#ifdef ENABLE_QABIO

struct QABIBlock;  // fwd decl — full definition in rung/qabi.h

/** Hash functor for uint256 values inside unordered containers.
 *
 *  SaltedUint256Hasher has const members, which disables move-assignment
 *  and prevents its use as a hasher for std::unordered_set fields inside
 *  move-assignable containers. This trivial hasher has no state, so it
 *  supports all the assignment operations we need.
 *
 *  uint256 values used in QABI are themselves SHA-256 digests
 *  (participant_id = SHA256(pubkey), etc.) so their bytes are already
 *  uniformly distributed. Reading the first 8 bytes directly gives a
 *  perfectly good hash with zero CPU cost. */
struct QABIUint256Hasher {
    size_t operator()(const uint256& h) const noexcept {
        size_t out;
        std::memcpy(&out, h.data(), sizeof(out));
        return out;
    }
};

/** Per-tx cached state for a QABIO batch verification.
 *
 *  Within a single QABIO tx, every primed input checks the SAME tx-level
 *  state. Four of the nine QABI_SPEND checks depend only on tx-level
 *  state (not per-input state), so their results are identical across
 *  every primed input and can be computed once, cached, and reused:
 *
 *    (4) SHA256(tx.qabi_block) == committed_root — per-input committed_root
 *        differs, but the computed root is tx-level. Cache the hash.
 *    (5) ParseQABIBlock(tx.qabi_block) — same parse each time. Cache the
 *        parsed block.
 *    (8) tx.vout bit-exact equal to parsed.outputs — both are tx-level,
 *        so the comparison's result is tx-level. Cache the bool.
 *    (9) FalconVerify(coordinator_pubkey, sighash, aggregated_sig) — all
 *        three inputs are tx-level. Cache the bool.
 *
 *  Remaining per-input work (checks 1, 2, 3, 6, 7) is genuinely per-input
 *  (primed state, expiry, preimage, expiry binding, identity match) and
 *  must run for every input.
 *
 *  On large batches (N=1000+) this cache collapses the per-input cost
 *  from ~7.5 ms to ~1.5 ms — a ~5× speedup on the bottleneck operations.
 *  The cached parsed block is owned via std::shared_ptr so multiple
 *  readers borrow without copying. */
struct QABOVerifiedEntry {
    bool sig_ok{false};                           //!< FALCON verify result
    uint256 computed_root;                        //!< SHA256 of tx.qabi_block
    std::shared_ptr<const QABIBlock> parsed;      //!< ParseQABIBlock result
    bool vout_matches_outputs{false};             //!< tx.vout == parsed.outputs
    //! Hash-indexed set of block.entries[*].participant_id values. Built
    //! once per tx during the cache-miss path so check 7 (identity
    //! lookup) becomes O(1) per input instead of O(N). Shared across
    //! readers via the enclosing shared_ptr on parsed. Collapses total
    //! identity-check work from O(N²) to O(N) per QABIO tx.
    std::unordered_set<uint256, QABIUint256Hasher> entries_set;
};

/** Per-tx cache of verified QABIO state, keyed by sighash. */
using QABOSigCache = std::map<uint256, QABOVerifiedEntry>;

#else // ENABLE_QABIO

/** Empty placeholder so RungEvalContext and VerifyRungTx signatures
 *  stay stable regardless of whether QABIO is compiled in. Callers
 *  always pass nullptr when the extension is disabled. */
struct QABOSigCache {};

#endif // ENABLE_QABIO

/** Extended evaluation context for block types that need transaction data.
 *  Provides transaction and amount data needed by covenant, anchor,
 *  recursion, and PLC evaluators. */
struct RungEvalContext {
    const api::LadderTxView* tx{nullptr};  //!< The spending transaction (adapter view)
    //! BIP 141 transaction weight, populated by the host (Core shim computes
    //! `GetTransactionWeight(CTransaction)` and the library-entry shim
    //! forwards from `api::LadderEvalContext::tx_weight`). Consumed by
    //! anchor / PLC / governance blocks that need weight or vsize =
    //! (tx_weight + 3) / 4. Zero if the caller didn't populate it, in which
    //! case weight-dependent blocks fail closed.
    int64_t tx_weight{0};
    //! Precomputed sighash mid-state (hash_prevouts, hash_sequences, etc.).
    //! Used by library-internal sighash computation in `VerifySigWithScheme` /
    //! `EvalPQSig`. Nullable — test stubs without a real tx set this to
    //! nullptr and the sighash path falls back to an all-zero hash (the mock
    //! checker ignores the hash bytes anyway). In production
    //! `VerifyRungTx` always populates this before dispatching.
    const api::LadderPrecomputedTxData* precomputed{nullptr};
    uint32_t input_index{0};               //!< Index of the input being evaluated
    int64_t input_amount{0};               //!< Amount of the UTXO being spent (satoshis)
    int64_t output_amount{0};              //!< Amount of the output being created (for AMOUNT_LOCK)
    int32_t block_height{0};               //!< Current block height (for RECURSE_UNTIL)
    const api::LadderOutputView* spending_output{nullptr}; //!< Output being created (for recursion covenant checks)
    const RungConditions* input_conditions{nullptr}; //!< Input conditions (for recursion covenant comparison)
    const api::LadderOutputView* spent_outputs{nullptr}; //!< All spent outputs in the tx (for COSIGN cross-input checks)
    size_t spent_output_count{0};                        //!< Count for spent_outputs above
    const std::vector<Relay>* relays{nullptr};         //!< Relay definitions (for KEY_REF_SIG resolution)
    const std::vector<uint16_t>* rung_relay_refs{nullptr}; //!< Current rung's relay_refs (KEY_REF_SIG validation)
    const std::vector<std::vector<std::vector<uint8_t>>>* rung_pubkeys{nullptr}; //!< Per-rung pubkey lists for Merkle leaf (merkle_pub_key)
    const MLSCVerifiedLeaves* verified_leaves{nullptr}; //!< Verified leaf array from VerifyMLSCProof (leaf-centric covenant checks)
    const MLSCProof* mlsc_proof{nullptr}; //!< MLSC proof (for cross-rung mutation target access)
    QABOSigCache* qabo_sig_cache{nullptr}; //!< Optional per-tx cache: caches the FALCON QABO sig verify result so subsequent inputs of the same QABIO tx skip the expensive verify call
};

/** Result of evaluating a single block or rung. */
enum class EvalResult {
    SATISFIED,           //!< All conditions met
    UNSATISFIED,         //!< Conditions not met (valid but fails)
    ERROR,               //!< Malformed block (consensus failure)
    UNKNOWN_BLOCK_TYPE,  //!< Unknown block type (treated as unsatisfied for forward compat)
};

/** Apply inversion to an eval result.
 *  SATISFIED↔UNSATISFIED, ERROR unchanged, UNKNOWN_BLOCK_TYPE inverted → SATISFIED. */
EvalResult ApplyInversion(EvalResult raw, bool inverted);

// Signature evaluators — Ladder-native blocks, adapter-typed sig checker.
// Sig-bearing evaluators take a RungEvalContext so they can compute the
// Ladder sighash via `api::SignatureHashLadder`. Timelock-only evaluators
// (CSV / CLTV / CSV_TIME / CLTV_TIME) don't need it.
EvalResult EvalSigBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalMultisigBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalHashPreimageBlock(const RungBlock& block);
EvalResult EvalHash160PreimageBlock(const RungBlock& block);
EvalResult EvalCSVBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker);
EvalResult EvalCSVTimeBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker);
EvalResult EvalCLTVBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker);
EvalResult EvalCLTVTimeBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker);
EvalResult EvalAdaptorSigBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalMusigThresholdBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalTaggedHashBlock(const RungBlock& block);
EvalResult EvalHashGuardedBlock(const RungBlock& block);

// Covenant evaluators
EvalResult EvalCTVBlock(const RungBlock& block, const RungEvalContext& ctx);

namespace api {
/** BIP-119 CheckTemplateVerify template hash. Reads only the fields exposed
 *  on the adapter view (version, lock_time, per-input script_sig and sequence,
 *  per-output value and script_pub_key). Idempotent, side-effect free. */
uint256 ComputeCTVHash(const LadderTxView& tx, uint32_t input_index);
}  // namespace api

EvalResult EvalVaultLockBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalAmountLockBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalAnchorBlock(const RungBlock& block);
EvalResult EvalAnchorChannelBlock(const RungBlock& block);
EvalResult EvalAnchorPoolBlock(const RungBlock& block);
EvalResult EvalAnchorReserveBlock(const RungBlock& block);
EvalResult EvalAnchorSealBlock(const RungBlock& block);
EvalResult EvalAnchorOracleBlock(const RungBlock& block);

// Recursion evaluators
EvalResult EvalRecurseSameBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalRecurseModifiedBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalRecurseUntilBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalRecurseCountBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalRecurseSplitBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalRecurseDecayBlock(const RungBlock& block, const RungEvalContext& ctx);

// PLC evaluators
EvalResult EvalHysteresisFeeBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalHysteresisValueBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalTimerContinuousBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalTimerOffDelayBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalLatchSetBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalLatchResetBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalCounterDownBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalCounterPresetBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalCounterUpBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalCompareBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalSequencerBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalOneShotBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalRateLimitBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalCosignBlock(const RungBlock& block, const RungEvalContext& ctx);

// Compound evaluators (multi-block patterns in single block)
EvalResult EvalTimelockedSigBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalHTLCBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalHashSigBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalPTLCBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalCLTVSigBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});
EvalResult EvalTimelockedMultisigBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const RungEvalContext& ctx = {});

// Legacy evaluators (wrapped Bitcoin transaction types). These keep Core's
// BaseSignatureChecker because they verify against Core's legacy / SegWit /
// Taproot sighash. The P2SH / P2WSH / P2TR_SCRIPT wrappers also take the
// adapter `sig_checker` so they can recurse into inner Ladder-native blocks
// via EvalBlock.
EvalResult EvalP2PKLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalP2PKHLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalP2SHLegacyBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const BaseSignatureChecker& legacy_checker, SigVersion sigversion, ScriptExecutionData& execdata, const RungEvalContext& ctx, int depth = 0);
EvalResult EvalP2WPKHLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalP2WSHLegacyBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const BaseSignatureChecker& legacy_checker, SigVersion sigversion, ScriptExecutionData& execdata, const RungEvalContext& ctx, int depth = 0);
EvalResult EvalP2TRLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalP2TRScriptLegacyBlock(const RungBlock& block, const api::LadderSigChecker& sig_checker, const BaseSignatureChecker& legacy_checker, SigVersion sigversion, ScriptExecutionData& execdata, const RungEvalContext& ctx, int depth = 0);

// Governance evaluators (transaction-level constraints)
EvalResult EvalEpochGateBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalWeightLimitBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalInputCountBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalOutputCountBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalRelativeValueBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalAccumulatorBlock(const RungBlock& block);
EvalResult EvalOutputCheckBlock(const RungBlock& block, const RungEvalContext& ctx);

/** Evaluate a single block by dispatching to the appropriate evaluator.
 *  Ladder-native blocks use `sig_checker` (adapter-typed). Legacy P2*
 *  wrapper blocks use `legacy_checker` + `sigversion` + `execdata` — they
 *  verify Core's legacy / SegWit / Taproot sighash, not Ladder sighash. */
EvalResult EvalBlock(const RungBlock& block,
                     const api::LadderSigChecker& sig_checker,
                     const BaseSignatureChecker& legacy_checker,
                     SigVersion sigversion,
                     ScriptExecutionData& execdata,
                     const RungEvalContext& ctx = {},
                     int depth = 0);

/** Evaluate all relays in order, caching results.
 *  Relays are evaluated index 0 first; each relay checks its relay_refs
 *  against already-cached results before evaluating its own blocks. */
bool EvalRelays(const std::vector<Relay>& relays,
                const api::LadderSigChecker& sig_checker,
                const BaseSignatureChecker& legacy_checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx,
                std::vector<EvalResult>& relay_results_out);

/** Evaluate a single rung: all blocks must return SATISFIED (AND logic).
 *  If relay_results is non-null, checks rung.relay_refs against relay results first. */
EvalResult EvalRung(const Rung& rung,
                    const api::LadderSigChecker& sig_checker,
                    const BaseSignatureChecker& legacy_checker,
                    SigVersion sigversion,
                    ScriptExecutionData& execdata,
                    const RungEvalContext& ctx = {},
                    const std::vector<EvalResult>* relay_results = nullptr);

/** Evaluate a complete ladder: first satisfied rung wins (OR logic).
 *  Evaluates relays first, then passes results to each rung.
 *  @param[out] satisfied_rung_out  If non-null and a rung is satisfied, set to the rung index. */
bool EvalLadder(const LadderWitness& ladder,
                const api::LadderSigChecker& sig_checker,
                const BaseSignatureChecker& legacy_checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx = {},
                size_t* satisfied_rung_out = nullptr);

/** Rung verification flags (use high bits to avoid collision with SCRIPT_VERIFY_* flags). */
static constexpr unsigned int RUNG_VERIFY_MLSC_ONLY = (1U << 28); //!< Reject 0xC1 inline conditions (mainnet)

/** Cache entry for same-source proof sharing. */
struct SharedTreeEntry {
    uint256 root;                   //!< Verified conditions_root
    std::vector<uint256> leaves;    //!< All leaf hashes in the tree (for leaf membership check)
};

/** Cache for same-source proof sharing: maps source txid to verified tree data.
 *  When multiple inputs reference the same source tx, subsequent inputs can use
 *  SHARED proof mode — but must still prove their leaf is in the cached tree. */
using SharedTreeCache = std::map<Txid, SharedTreeEntry>;

/** Tx-level consensus checks for v4 RUNG_TX transactions.
 *
 *  Runs ONCE per v4 tx, regardless of input types. Must be called before
 *  per-input script verification so that wallet-funded v4 txs (where
 *  the spent input is a standard Bitcoin output, not MLSC) still have
 *  their tx-level rung rules enforced.
 *
 *  Enforces:
 *   - Output format (ValidateRungOutputs: MLSC-only, at most one DATA_RETURN, dust)
 *   - Per-tx PREIMAGE/SCRIPT_BODY field count limit
 *
 *  Returns true on success. On failure, populates `error` with a human
 *  readable reason; caller maps to SCRIPT_ERR_UNKNOWN_ERROR or similar.
 *
 *  Declared in rung/api.h (adapter-typed; rung::api::CheckRungTxLevel /
 *  rung::api::ValidateRungOutputs). CTransaction-taking wrappers live in
 *  rung_shims.h and forward via LadderTxViewBuilder. */

/** Top-level verification entry point for v4 RUNG_TX transactions.
 *  TX_MLSC: validates creation proof, verifies spend proof against shared tree,
 *  checks coil.output_index matches spent output.
 *  @param shared_cache  Optional cache for same-source proof sharing. */
bool VerifyRungTx(const CTransaction& tx,
                  unsigned int nIn,
                  const CTxOut& spent_output,
                  unsigned int flags,
                  const BaseSignatureChecker& checker,
                  const PrecomputedTransactionData& txdata,
                  ScriptError* serror,
                  int32_t block_height = 0,
                  SharedTreeCache* shared_cache = nullptr,
                  QABOSigCache* qabo_sig_cache = nullptr);

} // namespace rung

#endif // BITCOIN_RUNG_EVALUATOR_H
