// Copyright (c) 2026 The Bitcoin Ghost developers
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
#include <map>
#include <string>
#include <uint256.h>

class CTransaction;
class CTxOut;

namespace rung {

/** Batch Schnorr signature verifier.
 *  Collects (sighash, pubkey, signature) tuples during evaluation and verifies
 *  them all in a single batch after all inputs pass. Falls back to individual
 *  verification if batch verification is not available.
 *
 *  Half-aggregation support: entries with aggregated=true contain only R (32 bytes).
 *  Verification uses the transaction-level aggregated_s value. */
struct BatchVerifier {
    struct Entry {
        uint256 sighash;
        XOnlyPubKey pubkey;
        std::vector<unsigned char> sig; //!< R||s (64 bytes) for INLINE, R only (32 bytes) for AGGREGATE
        bool aggregated{false};         //!< If true, sig is R only; s comes from aggregated_sig
    };
    std::vector<Entry> entries;
    bool active{false};
    std::vector<unsigned char> aggregated_s; //!< 32-byte aggregated s value from transaction

    /** Add a verification entry to the batch. */
    void Add(const uint256& sighash, const XOnlyPubKey& pk, std::span<const unsigned char> sig, bool agg = false) {
        Entry e;
        e.sighash = sighash;
        e.pubkey = pk;
        e.sig.assign(sig.begin(), sig.end());
        e.aggregated = agg;
        entries.push_back(std::move(e));
    }

    /** Batch verify all entries. Returns true if all signatures are valid.
     *  For aggregated entries, uses half-aggregation verification with aggregated_s. */
    bool Verify() const;

    /** On batch failure, find the index of the first invalid entry.
     *  Returns -1 if all entries are individually valid (shouldn't happen). */
    int FindFailure() const;
};

/** Signature checker that wraps an existing checker and adds rung conditions context.
 *  When CheckSchnorrSignature is called with SigVersion::LADDER, it computes
 *  SignatureHashLadder instead of SignatureHashSchnorr. */
class LadderSignatureChecker : public DeferringSignatureChecker
{
private:
    const RungConditions& m_conditions;
    const PrecomputedTransactionData& m_txdata;
    const CTransaction& m_tx;
    unsigned int m_nIn;
    BatchVerifier* m_batch{nullptr}; //!< If non-null, defer verification to batch

public:
    LadderSignatureChecker(const BaseSignatureChecker& checker,
                           const RungConditions& conditions,
                           const PrecomputedTransactionData& txdata,
                           const CTransaction& tx,
                           unsigned int nIn,
                           BatchVerifier* batch = nullptr)
        : DeferringSignatureChecker(checker),
          m_conditions(conditions),
          m_txdata(txdata),
          m_tx(tx),
          m_nIn(nIn),
          m_batch(batch) {}

    bool CheckSchnorrSignature(std::span<const unsigned char> sig,
                               std::span<const unsigned char> pubkey,
                               SigVersion sigversion,
                               ScriptExecutionData& execdata,
                               ScriptError* serror = nullptr) const override;

    /** Compute the ladder sighash for PQ signature verification.
     *  @param[in]  hash_type  Sighash type (SIGHASH_DEFAULT=0, etc.)
     *  @param[out] hash_out   The computed sighash
     *  @return true on success */
    bool ComputeSighash(uint8_t hash_type, uint256& hash_out) const;
};

/** Extended evaluation context for block types that need transaction data.
 *  Provides transaction and amount data needed by covenant, anchor,
 *  recursion, and PLC evaluators. */
struct RungEvalContext {
    const CTransaction* tx{nullptr};       //!< The spending transaction (for CTV template verification)
    uint32_t input_index{0};               //!< Index of the input being evaluated
    CAmount input_amount{0};               //!< Amount of the UTXO being spent
    CAmount output_amount{0};              //!< Amount of the output being created (for AMOUNT_LOCK)
    int32_t block_height{0};               //!< Current block height (for RECURSE_UNTIL)
    const CTxOut* spending_output{nullptr}; //!< Output script being created (for recursion covenant checks)
    const RungConditions* input_conditions{nullptr}; //!< Input conditions (for recursion covenant comparison)
    const std::vector<CTxOut>* spent_outputs{nullptr}; //!< All spent outputs in the tx (for COSIGN cross-input checks)
    const std::vector<Relay>* relays{nullptr};         //!< Relay definitions (for KEY_REF_SIG resolution)
    const std::vector<uint16_t>* rung_relay_refs{nullptr}; //!< Current rung's relay_refs (KEY_REF_SIG validation)
    const std::vector<std::vector<std::vector<uint8_t>>>* rung_pubkeys{nullptr}; //!< Per-rung pubkey lists for Merkle leaf (merkle_pub_key)
    const MLSCVerifiedLeaves* verified_leaves{nullptr}; //!< Verified leaf array from VerifyMLSCProof (leaf-centric covenant checks)
    const MLSCProof* mlsc_proof{nullptr}; //!< MLSC proof (for cross-rung mutation target access)
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

// Signature evaluators
EvalResult EvalSigBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalMultisigBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalHashPreimageBlock(const RungBlock& block);
EvalResult EvalHash160PreimageBlock(const RungBlock& block);
EvalResult EvalCSVBlock(const RungBlock& block, const BaseSignatureChecker& checker);
EvalResult EvalCSVTimeBlock(const RungBlock& block, const BaseSignatureChecker& checker);
EvalResult EvalCLTVBlock(const RungBlock& block, const BaseSignatureChecker& checker);
EvalResult EvalCLTVTimeBlock(const RungBlock& block, const BaseSignatureChecker& checker);
EvalResult EvalAdaptorSigBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalMusigThresholdBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalTaggedHashBlock(const RungBlock& block);
EvalResult EvalHashGuardedBlock(const RungBlock& block);

// Covenant evaluators
EvalResult EvalCTVBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalVaultLockBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
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
EvalResult EvalTimelockedSigBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalHTLCBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalHashSigBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalPTLCBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalCLTVSigBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalTimelockedMultisigBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);

// Legacy evaluators (wrapped Bitcoin transaction types)
EvalResult EvalP2PKLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalP2PKHLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalP2SHLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, const RungEvalContext& ctx, int depth = 0);
EvalResult EvalP2WPKHLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalP2WSHLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, const RungEvalContext& ctx, int depth = 0);
EvalResult EvalP2TRLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata);
EvalResult EvalP2TRScriptLegacyBlock(const RungBlock& block, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, const RungEvalContext& ctx, int depth = 0);

// Governance evaluators (transaction-level constraints)
EvalResult EvalEpochGateBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalWeightLimitBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalInputCountBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalOutputCountBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalRelativeValueBlock(const RungBlock& block, const RungEvalContext& ctx);
EvalResult EvalAccumulatorBlock(const RungBlock& block);
EvalResult EvalOutputCheckBlock(const RungBlock& block, const RungEvalContext& ctx);

/** Evaluate a single block by dispatching to the appropriate evaluator. */
EvalResult EvalBlock(const RungBlock& block,
                     const BaseSignatureChecker& checker,
                     SigVersion sigversion,
                     ScriptExecutionData& execdata,
                     const RungEvalContext& ctx = {},
                     int depth = 0);

/** Evaluate all relays in order, caching results.
 *  Relays are evaluated index 0 first; each relay checks its relay_refs
 *  against already-cached results before evaluating its own blocks. */
bool EvalRelays(const std::vector<Relay>& relays,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx,
                std::vector<EvalResult>& relay_results_out);

/** Evaluate a single rung: all blocks must return SATISFIED (AND logic).
 *  If relay_results is non-null, checks rung.relay_refs against relay results first. */
EvalResult EvalRung(const Rung& rung,
                    const BaseSignatureChecker& checker,
                    SigVersion sigversion,
                    ScriptExecutionData& execdata,
                    const RungEvalContext& ctx = {},
                    const std::vector<EvalResult>* relay_results = nullptr);

/** Evaluate a complete ladder: first satisfied rung wins (OR logic).
 *  Evaluates relays first, then passes results to each rung.
 *  @param[out] satisfied_rung_out  If non-null and a rung is satisfied, set to the rung index. */
bool EvalLadder(const LadderWitness& ladder,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx = {},
                size_t* satisfied_rung_out = nullptr);

/** Compute the BIP-119 CTV template hash for a transaction at a given input index. */
uint256 ComputeCTVHash(const CTransaction& tx, uint32_t input_index);

/** Rung verification flags (use high bits to avoid collision with SCRIPT_VERIFY_* flags). */
static constexpr unsigned int RUNG_VERIFY_MLSC_ONLY = (1U << 28); //!< Reject 0xC1 inline conditions (mainnet)

/** @deprecated Legacy per-output MLSC output validation.
 *  TX_MLSC validates conditions at spend time via Merkle proof (no creation proof).
 *  Retained for recursive covenant evaluators (RECURSE_SAME, RECURSE_MODIFIED,
 *  RECURSE_DECAY) which verify output conditions match expected roots. */
bool ValidateRungOutputs(const CTransaction& tx, unsigned int flags, std::string& error);

/** Cache entry for same-source proof sharing. */
struct SharedTreeEntry {
    uint256 root;                   //!< Verified conditions_root
    std::vector<uint256> leaves;    //!< All leaf hashes in the tree (for leaf membership check)
};

/** Cache for same-source proof sharing: maps source txid to verified tree data.
 *  When multiple inputs reference the same source tx, subsequent inputs can use
 *  SHARED proof mode — but must still prove their leaf is in the cached tree. */
using SharedTreeCache = std::map<Txid, SharedTreeEntry>;

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
                  SharedTreeCache* shared_cache = nullptr);

} // namespace rung

#endif // BITCOIN_RUNG_EVALUATOR_H
