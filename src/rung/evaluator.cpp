// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// ============================================================================
// REVIEWER BLOCK — Ladder Script evaluator (consensus entry point)
// ============================================================================
//
// PURPOSE
//   Top-level validation for v4 (RUNG_TX) inputs spending MLSC outputs. This
//   file is the single seam Core dispatches into from validation.cpp.
//
// KEY SYMBOLS
//   VerifyRungTx(tx, input_idx, spent_output, ctx, error_out)
//     The only public entry point. Handles key-path (1-elem witness),
//     script-path (2 or 3 elem witness), per-tx checks (run on first input).
//   EvalLadder / EvalRung / EvalBlock
//     OR / AND / type-dispatch primitives for script-path evaluation.
//   CheckLadderTweakRaw
//     Key-path tweak verification via libsecp256k1's xonly_pubkey_tweak_add_check.
//     MUST match XOnlyPubKey::ComputeLadderTweakHash in src/pubkey.cpp byte-for-byte.
//   ValidateRungOutputs
//     Per-tx rule: every output must be MLSC (0xDF) or MLSC+DATA_RETURN,
//     max 1 DATA_RETURN, dust threshold applies.
//   ExtractBlockPubkeys
//     Reads the first N PUBKEY fields from each block's witness, where N =
//     PubkeyCountForBlock. The ordering matches what fund-time ComputeValueCommitment
//     folded into the Merkle leaf; deviating breaks root reconstruction.
//
// LOAD-BEARING INVARIANTS (must not change without consensus analysis)
//   1. Unknown block types return UNSATISFIED (not ERROR) in the non-inverted
//      case — this is the soft-fork-friendly forward-compat behaviour (mirrors
//      Taproot's unknown-leaf-version semantics). Inverted UNKNOWN becomes
//      ERROR via ApplyInversion (fail-closed on "NOT unknown").
//   2. Every rejected spend returns false AND sets error_out. Never return
//      true on an error path.
//   3. Per-tx checks (ValidateRungOutputs, creation proof, PREIMAGE count)
//      run on the first input before per-input evaluation.
//   4. LadderTweak/v1 tagged hash must be computed identically in both
//      CheckLadderTweakRaw (here) and ComputeLadderTweakHash (pubkey.cpp).
//      Any divergence splits the network.
//   5. Merkle proof verification is byte-strict: VerifyMerklePath rejects
//      path-length mismatches, FULL_LEAVES rejects wrong leaf count.
//
// OPTIONAL / REMOVABLE
//   - Diagnostic LogPrintf calls on fail paths are debugging aids, not
//     consensus-critical. Can be removed or gated behind a log category.
//   - SHARED proof mode (cached-tree cross-input reference) is an optimisation
//     — MERKLE_PATH and FULL_LEAVES are the minimum set.
//   - QABIO/QABI_SPEND handling (gated by #ifdef LADDER_ENABLE_QABIO) is
//     scoped to that feature; removing QABIO excises it entirely.
//
// TEST COVERAGE
//   Boost: build/bin/test_bitcoin --run_test=rung_tests (517 cases).
//   Functional: feature_rung_tx.py, feature_rung_p2p.py, feature_rung_legacy.py.
//   End-to-end: tools/test-presets.py (56 presets, all paths exercised).
//
// REFERENCES
//   Library reviewer guide: doc/ladder-script/REVIEW_GUIDE.md (Part 3,
//   "src/rung/evaluator.{h,cpp}" section).
// ============================================================================

#include <rung/evaluator.h>
#include <rung/block_dispatch.h>
#include <rung/block_helpers.h>
#include <rung/conditions.h>
#include <rung/pq_verify.h>
#include <rung/qabi.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung_shims.h>  // Core↔library boundary adapters

#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <optional>

namespace rung {
using namespace api;  // Bring libladder public API (span-based) into file scope

// Tagged hash for the Ladder-style x-only key tweak. Must match
// `XOnlyPubKey::ComputeLadderTweakHash` in src/pubkey.cpp byte-for-byte —
// consensus divergence on this tag would split the network.
static const HashWriter HASHER_LADDERTWEAK{TaggedHash("LadderTweak/v1")};

// Ladder tweak verification using raw libsecp256k1 — the library keeps this
// self-contained rather than depending on Core's `XOnlyPubKey`. Returns true
// iff output_pk == internal_pk + H(internal_pk || merkle_root) * G with the
// given y-parity.
static bool CheckLadderTweakRaw(const unsigned char output_pk[32],
                                const unsigned char internal_pk[32],
                                const uint256& merkle_root,
                                int parity)
{
    secp256k1_xonly_pubkey internal_key;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &internal_key, internal_pk)) {
        return false;
    }
    HashWriter h{HASHER_LADDERTWEAK};
    h.write(std::as_bytes(std::span<const unsigned char>{internal_pk, 32}));
    h.write(std::as_bytes(std::span<const unsigned char>{merkle_root.begin(), 32}));
    uint256 tweak = h.GetSHA256();
    return secp256k1_xonly_pubkey_tweak_add_check(secp256k1_context_static,
                                                  output_pk, parity,
                                                  &internal_key, tweak.begin());
}

// Per-block evaluators live in src/rung/blocks/*.cpp; each TU self-registers
// via `register_<family>_blocks()` called from block_registry.cpp.

// ============================================================================
// Block dispatch
// ============================================================================

EvalResult EvalBlock(const RungBlock& block,
                     const api::LadderSigChecker& sig_checker,
                     const BaseSignatureChecker& legacy_checker,
                     SigVersion sigversion,
                     ScriptExecutionData& execdata,
                     const RungEvalContext& ctx,
                     int depth)
{
    ladder_init();  // no-op after the first call

    // Defense in depth: reject inverted key-consuming blocks.
    if (block.inverted && !IsInvertibleBlockType(block.type)) {
        return EvalResult::ERROR;
    }

    BlockEvaluator fn = LookupBlockEvaluator(block.type);
    if (!fn) {
        // Not registered. Pre-soft-fork nodes must treat unknown block types as
        // UNSATISFIED (forward-compat — newer BIPs can add block types, and old
        // nodes see those spends as anyone-can-spend at the Ladder layer).
        // ApplyInversion flips UNKNOWN to ERROR, which is the correct behaviour
        // for an inverted unknown block: "unknown must not satisfy".
        return ApplyInversion(EvalResult::UNKNOWN_BLOCK_TYPE, block.inverted);
    }

    const BlockDispatchContext dctx{sig_checker, legacy_checker, sigversion,
                                     execdata, ctx, depth};
    return ApplyInversion(fn(block, dctx), block.inverted);
}

bool EvalRelays(const std::vector<Relay>& relays,
                const api::LadderSigChecker& sig_checker,
                const BaseSignatureChecker& legacy_checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx,
                std::vector<EvalResult>& relay_results_out)
{
    relay_results_out.resize(relays.size(), EvalResult::UNSATISFIED);

    for (size_t i = 0; i < relays.size(); ++i) {
        const auto& relay = relays[i];

        // Check relay_refs: all required relays must be SATISFIED
        bool requires_met = true;
        for (uint16_t req : relay.relay_refs) {
            if (req >= i || relay_results_out[req] != EvalResult::SATISFIED) {
                requires_met = false;
                break;
            }
        }

        if (!requires_met) {
            relay_results_out[i] = EvalResult::UNSATISFIED;
            continue;
        }

        // Evaluate relay blocks (AND logic, same as a rung)
        if (relay.blocks.empty()) {
            relay_results_out[i] = EvalResult::ERROR;
            return false;
        }

        // Set relay context so KEY_REF_SIG blocks in relays can resolve references
        RungEvalContext relay_ctx = ctx;
        relay_ctx.relays = &relays;
        relay_ctx.rung_relay_refs = relay.relay_refs.empty() ? nullptr : &relay.relay_refs;

        EvalResult relay_result = EvalResult::SATISFIED;
        for (const auto& block : relay.blocks) {
            EvalResult result = EvalBlock(block, sig_checker, legacy_checker, sigversion, execdata, relay_ctx);
            if (result != EvalResult::SATISFIED) {
                relay_result = result;
                break;
            }
        }

        if (relay_result == EvalResult::ERROR) {
            return false;
        }
        relay_results_out[i] = relay_result;
    }
    return true;
}

EvalResult EvalRung(const Rung& rung,
                    const api::LadderSigChecker& sig_checker,
                    const BaseSignatureChecker& legacy_checker,
                    SigVersion sigversion,
                    ScriptExecutionData& execdata,
                    const RungEvalContext& ctx,
                    const std::vector<EvalResult>* relay_results)
{
    if (rung.blocks.empty()) {
        return EvalResult::ERROR;
    }

    // Check relay_refs: all required relays must be SATISFIED
    if (relay_results && !rung.relay_refs.empty()) {
        for (uint16_t req : rung.relay_refs) {
            if (req >= relay_results->size() || (*relay_results)[req] != EvalResult::SATISFIED) {
                return EvalResult::UNSATISFIED;
            }
        }
    }

    for (const auto& block : rung.blocks) {
        EvalResult result = EvalBlock(block, sig_checker, legacy_checker, sigversion, execdata, ctx);
        if (result != EvalResult::SATISFIED) {
            return result;
        }
    }
    return EvalResult::SATISFIED;
}

bool EvalLadder(const LadderWitness& ladder,
                const api::LadderSigChecker& sig_checker,
                const BaseSignatureChecker& legacy_checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx,
                size_t* satisfied_rung_out)
{
    if (ladder.IsEmpty()) {
        return false;
    }

    // Evaluate relays first, cache results
    std::vector<EvalResult> relay_results;
    if (!ladder.relays.empty()) {
        if (!EvalRelays(ladder.relays, sig_checker, legacy_checker, sigversion, execdata, ctx, relay_results)) {
            return false;
        }
    }

    // First satisfied rung wins (OR logic across rungs)
    const std::vector<EvalResult>* relay_ptr = relay_results.empty() ? nullptr : &relay_results;
    RungEvalContext rung_ctx = ctx;
    if (!ladder.relays.empty()) {
        rung_ctx.relays = &ladder.relays;
    }
    for (size_t r = 0; r < ladder.rungs.size(); ++r) {
        const auto& rung = ladder.rungs[r];
        rung_ctx.rung_relay_refs = rung.relay_refs.empty() ? nullptr : &rung.relay_refs;
        EvalResult result = EvalRung(rung, sig_checker, legacy_checker, sigversion, execdata, rung_ctx, relay_ptr);
        if (result == EvalResult::SATISFIED) {
            if (satisfied_rung_out) *satisfied_rung_out = r;
            return true;
        }
    }
    return false;
}

/** Merge conditions (from spent output) with witness (from input).
 *  For each rung/block, the conditions provide the "locks" (pubkeys, hashes, timelocks)
 *  and the witness provides the "keys" (signatures, preimages). The merged result
 *  has all fields from both, which EvalLadder can then evaluate.
 *
 *  The witness must have the same rung/block structure as the conditions.
 *  The inverted flag is taken from conditions (witness doesn't override). */
static bool MergeConditionsAndWitness(const RungConditions& conditions,
                                       const LadderWitness& witness,
                                       LadderWitness& merged,
                                       std::string& error)
{
    if (conditions.rungs.size() != witness.rungs.size()) {
        error = "rung count mismatch: conditions=" + std::to_string(conditions.rungs.size()) +
                " witness=" + std::to_string(witness.rungs.size());
        return false;
    }

    merged.rungs.resize(conditions.rungs.size());
    merged.coil = conditions.coil;
    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
        const auto& cond_rung = conditions.rungs[r];
        const auto& wit_rung = witness.rungs[r];

        if (cond_rung.blocks.size() != wit_rung.blocks.size()) {
            error = "block count mismatch in rung " + std::to_string(r);
            return false;
        }

        merged.rungs[r].blocks.resize(cond_rung.blocks.size());
        merged.rungs[r].rung_id = cond_rung.rung_id;
        merged.rungs[r].relay_refs = cond_rung.relay_refs; // relay_refs come from conditions

        for (size_t b = 0; b < cond_rung.blocks.size(); ++b) {
            const auto& cond_block = cond_rung.blocks[b];
            const auto& wit_block = wit_rung.blocks[b];

            if (cond_block.type != wit_block.type) {
                error = "block type mismatch in rung " + std::to_string(r) +
                        " block " + std::to_string(b);
                return false;
            }

            // Merge: all condition fields first, then all witness fields.
            // v0.10 (F-8): cap post-merge field count. Per-side fields are
            // already capped at MAX_FIELDS_PER_BLOCK = 16 by deserialise,
            // but the merge step combines them and order-sensitive
            // evaluators see the combined array. MULTISIG / TIMELOCKED_MULTISIG
            // legitimately produce up to 3K + conds = 48 + 4 = 52 fields, so
            // honour the wider cap from `MAX_MULTISIG_WITNESS_FIELDS`.
            auto& merged_block = merged.rungs[r].blocks[b];
            merged_block.type = cond_block.type;
            merged_block.inverted = cond_block.inverted; // inverted comes from conditions
            const size_t merged_count = cond_block.fields.size() + wit_block.fields.size();
            const bool is_multisig = (cond_block.type == RungBlockType::MULTISIG ||
                                       cond_block.type == RungBlockType::TIMELOCKED_MULTISIG);
            const size_t cap = is_multisig
                ? (MAX_FIELDS_PER_BLOCK + MAX_MULTISIG_WITNESS_FIELDS)
                : (2 * MAX_FIELDS_PER_BLOCK);
            if (merged_count > cap) {
                error = "merged field count exceeds cap in rung " +
                        std::to_string(r) + " block " + std::to_string(b);
                return false;
            }
            merged_block.fields.insert(merged_block.fields.end(),
                                       cond_block.fields.begin(), cond_block.fields.end());
            merged_block.fields.insert(merged_block.fields.end(),
                                       wit_block.fields.begin(), wit_block.fields.end());
        }
    }

    // Merge relays: conditions provide locks, witness provides keys
    if (conditions.relays.size() != witness.relays.size()) {
        error = "relay count mismatch: conditions=" + std::to_string(conditions.relays.size()) +
                " witness=" + std::to_string(witness.relays.size());
        return false;
    }
    merged.relays.resize(conditions.relays.size());
    for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
        const auto& cond_relay = conditions.relays[rl];
        const auto& wit_relay = witness.relays[rl];

        if (cond_relay.blocks.size() != wit_relay.blocks.size()) {
            error = "block count mismatch in relay " + std::to_string(rl);
            return false;
        }

        merged.relays[rl].blocks.resize(cond_relay.blocks.size());
        merged.relays[rl].relay_refs = cond_relay.relay_refs; // relay_refs come from conditions

        for (size_t b = 0; b < cond_relay.blocks.size(); ++b) {
            const auto& cond_block = cond_relay.blocks[b];
            const auto& wit_block = wit_relay.blocks[b];

            if (cond_block.type != wit_block.type) {
                error = "block type mismatch in relay " + std::to_string(rl) +
                        " block " + std::to_string(b);
                return false;
            }

            auto& merged_block = merged.relays[rl].blocks[b];
            merged_block.type = cond_block.type;
            merged_block.inverted = cond_block.inverted;
            merged_block.fields.insert(merged_block.fields.end(),
                                       cond_block.fields.begin(), cond_block.fields.end());
            merged_block.fields.insert(merged_block.fields.end(),
                                       wit_block.fields.begin(), wit_block.fields.end());
        }
    }

    return true;
}

/** Resolve a witness reference: copy rungs/relays from the referenced input's
 *  witness and apply field-level diffs. Coil is already populated (always fresh).
 *  @param[in,out] witness     The witness with witness_ref set (rungs/relays empty).
 *                              On success, rungs/relays are populated and witness_ref cleared.
 *  @param[in]     tx          The spending transaction.
 *  @param[in]     nIn         Current input index.
 *  @param[out]    error       Error message on failure.
 *  @return true on success. */
static bool ResolveWitnessReference(LadderWitness& witness,
                                    const api::LadderTxView& tx,
                                    size_t nIn,
                                    std::string& error)
{
    if (!witness.IsWitnessRef()) {
        error = "witness does not have a witness reference";
        return false;
    }

    const auto& ref = *witness.witness_ref;

    // Forward-only: source must be a lower-indexed input (prevents cycles)
    if (ref.input_index >= nIn) {
        error = "witness reference must be forward-only: input_index " +
                std::to_string(ref.input_index) + " >= current " + std::to_string(nIn);
        return false;
    }

    // Deserialize the source input's witness
    const auto& source_wit = tx.inputs[ref.input_index].witness;
    if (source_wit.count == 0) {
        error = "witness reference source input " + std::to_string(ref.input_index) +
                " has empty witness";
        return false;
    }

    // Copy the first element bytes into a std::vector for the deserialiser.
    std::vector<uint8_t> src_bytes(source_wit.elements[0].data,
                                    source_wit.elements[0].data + source_wit.elements[0].size);

    LadderWitness source_ladder;
    std::string deser_error;
    if (!DeserializeLadderWitness(src_bytes, source_ladder, deser_error)) {
        error = "witness reference source deserialization failed: " + deser_error;
        return false;
    }

    // No chaining: source must not itself be a witness reference
    if (source_ladder.IsWitnessRef()) {
        error = "witness reference points to another witness reference (no chaining)";
        return false;
    }

    // Copy rungs and relays from source
    witness.rungs = source_ladder.rungs;
    witness.relays = source_ladder.relays;
    // Coil is already populated fresh from deserialization — do NOT copy

    // Apply diffs
    for (size_t d = 0; d < ref.diffs.size(); ++d) {
        const auto& diff = ref.diffs[d];

        if (diff.rung_index >= witness.rungs.size()) {
            error = "witness diff rung_index out of range: " +
                    std::to_string(diff.rung_index) + " at diff " + std::to_string(d);
            return false;
        }
        auto& rung = witness.rungs[diff.rung_index];

        if (diff.block_index >= rung.blocks.size()) {
            error = "witness diff block_index out of range: " +
                    std::to_string(diff.block_index) + " at diff " + std::to_string(d);
            return false;
        }
        auto& block = rung.blocks[diff.block_index];

        if (diff.field_index >= block.fields.size()) {
            error = "witness diff field_index out of range: " +
                    std::to_string(diff.field_index) + " at diff " + std::to_string(d);
            return false;
        }

        // Type must match source field type
        if (block.fields[diff.field_index].type != diff.new_field.type) {
            error = "witness diff type mismatch at rung " +
                    std::to_string(diff.rung_index) + " block " +
                    std::to_string(diff.block_index) + " field " +
                    std::to_string(diff.field_index) + ": expected " +
                    DataTypeName(block.fields[diff.field_index].type) +
                    ", got " + DataTypeName(diff.new_field.type);
            return false;
        }

        block.fields[diff.field_index] = diff.new_field;
    }

    // Clear witness reference — witness is now fully resolved
    witness.witness_ref.reset();
    return true;
}


namespace api {

bool ValidateRungOutputs(const LadderTxView& tx, std::string& error)
{
    size_t data_return_count = 0;
    size_t spendable_mlsc_count = 0;

    for (size_t i = 0; i < tx.output_count; ++i) {
        const auto spk = tx.outputs[i].script_pub_key.as_span();
        const int64_t value = tx.outputs[i].value;

        // MLSC output: 0xDF + 32 bytes (+ optional DATA_RETURN payload)
        if (IsMLSCScript(spk)) {
            // MLSC with DATA_RETURN payload (> 33 bytes)
            if (HasMLSCData(spk)) {
                data_return_count++;
                // Must be zero-value (unspendable)
                if (value != 0) {
                    error = "output " + std::to_string(i) + ": DATA_RETURN output must have zero value";
                    return false;
                }
            } else {
                // Consensus dust threshold: non-DATA_RETURN outputs must carry
                // minimum value to prevent UTXO set bloat and cheap spam.
                if (value < MIN_RUNG_OUTPUT_VALUE) {
                    error = "output " + std::to_string(i) + ": value " +
                            std::to_string(value) + " below minimum " +
                            std::to_string(MIN_RUNG_OUTPUT_VALUE);
                    return false;
                }
                spendable_mlsc_count++;
            }
            continue;
        }

        // Only MLSC (0xDF) outputs are accepted in v4. Everything else
        // (OP_RETURN, P2TR, P2WPKH, 0xC1, arbitrary data) is rejected.
        error = "output " + std::to_string(i) + ": non-Ladder Script output rejected in v4 transaction";
        return false;
    }

    // Only one DATA_RETURN output allowed per transaction
    if (data_return_count > 1) {
        error = "too many DATA_RETURN outputs: " + std::to_string(data_return_count) + " (max 1)";
        return false;
    }

    // Stage 3 audit (F16): the chainstate synthetic root entry stores a
    // uint16_t refcount counting unspent non-DATA_RETURN MLSC outputs from
    // the creating tx (`coins.cpp:AddCoins`). A v4 tx with > 65535
    // spendable outputs would silently wrap the refcount at write time:
    // refcount==0 short-circuits before the synthetic entry is ever
    // written, leaving every output with no recoverable conditions_root
    // and effectively unspendable. Block weight (~4M WU) doesn't bound
    // this — a dense v4 tx fits ~50k+ outputs in a single block, well
    // past the wrap point. Reject at consensus so an honest signer can't
    // accidentally burn funds and a malicious miner can't mine an
    // unrecoverable-UTXO chunk. The legacy 33-byte synthetic format had
    // no refcount and would have been unaffected; the v0.13 35-byte
    // format with the refcount field needs this cap. Cap held inside
    // the standard relay envelope for forward compatibility — future
    // chainstate-format bumps to wider refcounts can relax it.
    if (spendable_mlsc_count > std::numeric_limits<uint16_t>::max()) {
        error = "v4 tx has too many spendable MLSC outputs: " +
                std::to_string(spendable_mlsc_count) + " > " +
                std::to_string(std::numeric_limits<uint16_t>::max()) +
                " (synthetic root refcount cap)";
        return false;
    }

    return true;
}

} // namespace api

/** Extract pubkeys from witness blocks positionally (merkle_pub_key).
 *  Walks blocks left-to-right, collecting PUBKEY fields based on
 *  PubkeyCountForBlock() for each block type. */
static std::vector<std::vector<uint8_t>> ExtractBlockPubkeys(const std::vector<RungBlock>& blocks)
{
    std::vector<std::vector<uint8_t>> pubkeys;
    for (const auto& block : blocks) {
        size_t count = PubkeyCountForBlock(block.type, block);
        if (count == 0) continue;
        auto pks = FindAllFields(block, RungDataType::PUBKEY);
        for (size_t i = 0; i < count && i < pks.size(); ++i) {
            pubkeys.push_back(pks[i]->data);
        }
    }
    return pubkeys;
}

/** Count PREIMAGE/SCRIPT_BODY fields across MLSC-spending inputs in a tx.
 *  Deserialises each MLSC input's ladder witness to count preimage-bearing
 *  fields. Bootstrap inputs (P2WPKH/P2WSH/P2TR etc) are excluded —
 *  v0.10 tightened from "all inputs" so a crafted bootstrap
 *  witness can't fake-deserialise as a fake QABI ladder and bypass caps.
 *  Returns total count; callers reject if > MAX_PREIMAGE_FIELDS_PER_TX. */
/** Count PREIMAGE/SCRIPT_BODY fields in a single deserialized witness. */
static size_t CountWitnessPreimageFields(const LadderWitness& lw)
{
    size_t total = 0;
    for (const auto& rung : lw.rungs) {
        for (const auto& block : rung.blocks) {
            // QABI_SPEND preimages are exempt from the per-tx spam limit:
            // their count is already bounded by the qabi_block entry count
            // (max STANDARD_RELAY_MAX_N), and the preimage is consensus-
            // validated against the auth chain — not arbitrary data.
            if (block.type == RungBlockType::QABI_SPEND) continue;
            for (const auto& field : block.fields) {
                if (field.type == RungDataType::PREIMAGE ||
                    field.type == RungDataType::SCRIPT_BODY) {
                    total++;
                }
            }
        }
    }
    for (const auto& relay : lw.relays) {
        for (const auto& block : relay.blocks) {
            for (const auto& field : block.fields) {
                if (field.type == RungDataType::PREIMAGE ||
                    field.type == RungDataType::SCRIPT_BODY) {
                    total++;
                }
            }
        }
    }
    return total;
}

/** v0.10 (F-2): is input `i` an MLSC-spending input?
 *  The per-tx counters and gates only inspect element[0] of inputs whose
 *  spent output is an MLSC scriptPubKey (`0xDF || 32-byte root [|| data]`).
 *  Bootstrap inputs (P2WPKH/P2WSH/P2TR/etc) can carry any bytes in their
 *  witness stack and must not contribute to v4 consensus checks — otherwise
 *  a P2WSH `OP_DROP OP_TRUE` script with a crafted first stack element
 *  bypasses every per-tx cap (T-1, T-2, E-003, ACCUMULATOR cap, etc).
 *
 *  Caller MUST pass a non-null spent_outputs of length tx.input_count.
 *  The validator layer (validation.cpp) and per-input verifier (VerifyRungTx)
 *  both repopulate spent_outputs unconditionally before invoking
 *  CheckRungTxLevel — but if a future code path forgets, this helper
 *  returning false would silently zero out preimage / script_body /
 *  accumulator caps (the loops over zero items would be cap-non-enforcing).
 *  CheckRungTxLevel guards against that with an explicit nullptr check;
 *  this helper preserves the same behaviour as a defence-in-depth. */
static bool IsMLSCSpendingInput(const LadderOutputView* spent_outputs,
                                 size_t spent_output_count,
                                 size_t i)
{
    if (!spent_outputs || i >= spent_output_count) return false;
    return rung::api::IsMLSCScript(spent_outputs[i].script_pub_key.as_span());
}

/** Count PREIMAGE/SCRIPT_BODY fields in a witness, including any diff entries
 *  carried by a diff witness (`witness_ref`). v0.10 (F-3): pre-fix, diffs were
 *  not counted, allowing each diff input to overlay 2 PREIMAGE/SCRIPT_BODY
 *  source positions with fresh attacker bytes that contributed 0 to the
 *  per-tx cap — multi-input embedding multiplier. */
static size_t CountWitnessPreimageFieldsWithDiffs(const LadderWitness& lw)
{
    size_t total = CountWitnessPreimageFields(lw);
    if (lw.witness_ref) {
        for (const auto& diff : lw.witness_ref->diffs) {
            if (diff.new_field.type == RungDataType::PREIMAGE ||
                diff.new_field.type == RungDataType::SCRIPT_BODY) {
                ++total;
            }
        }
    }
    return total;
}

/** Count PREIMAGE/SCRIPT_BODY fields across MLSC inputs in a transaction.
 *  v0.10 (F-2/F-3): filter to MLSC-spending inputs, also walk diff entries. */
static size_t CountTxPreimageFields(const LadderTxView& tx,
                                     const LadderOutputView* spent_outputs,
                                     size_t spent_output_count)
{
    size_t total = 0;
    for (size_t i = 0; i < tx.input_count; ++i) {
        if (!IsMLSCSpendingInput(spent_outputs, spent_output_count, i)) continue;
        const auto& witness = tx.inputs[i].witness;
        if (witness.count < 2 || witness.count > 3) continue;

        const auto& stack0 = witness.elements[0];
        std::vector<uint8_t> bytes(stack0.data, stack0.data + stack0.size);

        LadderWitness lw;
        std::string err;
        if (!DeserializeLadderWitness(bytes, lw, err)) continue;

        total += CountWitnessPreimageFieldsWithDiffs(lw);
    }
    return total;
}

/** Count SCRIPT_BODY-only fields across MLSC inputs in a transaction (v0.7).
 *  v0.10 (F-2/F-3): filter to MLSC-spending inputs, also count diff entries. */
static size_t CountTxScriptBodyFields(const LadderTxView& tx,
                                       const LadderOutputView* spent_outputs,
                                       size_t spent_output_count)
{
    size_t total = 0;
    for (size_t i = 0; i < tx.input_count; ++i) {
        if (!IsMLSCSpendingInput(spent_outputs, spent_output_count, i)) continue;
        const auto& witness = tx.inputs[i].witness;
        if (witness.count < 2 || witness.count > 3) continue;
        const auto& stack0 = witness.elements[0];
        std::vector<uint8_t> bytes(stack0.data, stack0.data + stack0.size);
        LadderWitness lw;
        std::string err;
        if (!DeserializeLadderWitness(bytes, lw, err)) continue;
        for (const auto& rung : lw.rungs) {
            for (const auto& block : rung.blocks) {
                for (const auto& field : block.fields) {
                    if (field.type == RungDataType::SCRIPT_BODY) ++total;
                }
            }
        }
        for (const auto& relay : lw.relays) {
            for (const auto& block : relay.blocks) {
                for (const auto& field : block.fields) {
                    if (field.type == RungDataType::SCRIPT_BODY) ++total;
                }
            }
        }
        if (lw.witness_ref) {
            for (const auto& diff : lw.witness_ref->diffs) {
                if (diff.new_field.type == RungDataType::SCRIPT_BODY) ++total;
            }
        }
    }
    return total;
}

/** v0.9 (T-1/T-2) + v0.10 (F-2): do any MLSC inputs carry QABI block types?
 *  QABI_SPEND / QABI_PRIME consume `tx.qabi_block`; QABI_SPEND additionally
 *  expects a `tx.aggregated_sig`. PQ_BATCH does not use either, but we
 *  include it for forward-compat with the QABIO family. v0.10 filters to
 *  MLSC-spending inputs — pre-v0.10, a crafted bootstrap input could fake
 *  the appearance of a QABI input and re-open the T-1 / T-2 channels. */
struct TxQABIShape {
    bool has_any{false};
    bool has_qabi_spend{false};
};

static TxQABIShape ScanTxQABIInputs(const LadderTxView& tx,
                                     const LadderOutputView* spent_outputs,
                                     size_t spent_output_count)
{
    TxQABIShape shape;
    auto note = [&](RungBlockType t) {
        if (t == RungBlockType::QABI_SPEND) {
            shape.has_qabi_spend = true;
            shape.has_any = true;
        } else if (t == RungBlockType::QABI_PRIME ||
                   t == RungBlockType::PQ_BATCH) {
            shape.has_any = true;
        }
    };
    for (size_t i = 0; i < tx.input_count; ++i) {
        if (!IsMLSCSpendingInput(spent_outputs, spent_output_count, i)) continue;
        const auto& witness = tx.inputs[i].witness;
        if (witness.count < 2 || witness.count > 3) continue;
        const auto& stack0 = witness.elements[0];
        std::vector<uint8_t> bytes(stack0.data, stack0.data + stack0.size);
        LadderWitness lw;
        std::string err;
        if (!DeserializeLadderWitness(bytes, lw, err)) continue;
        for (const auto& rung : lw.rungs) {
            for (const auto& block : rung.blocks) note(block.type);
        }
        for (const auto& relay : lw.relays) {
            for (const auto& block : relay.blocks) note(block.type);
        }
    }
    return shape;
}

/** Count ACCUMULATOR blocks across MLSC inputs in a transaction (v0.6).
 *  v0.10 (F-2): filter to MLSC-spending inputs. */
static size_t CountTxAccumulatorBlocks(const LadderTxView& tx,
                                        const LadderOutputView* spent_outputs,
                                        size_t spent_output_count)
{
    size_t total = 0;
    for (size_t i = 0; i < tx.input_count; ++i) {
        if (!IsMLSCSpendingInput(spent_outputs, spent_output_count, i)) continue;
        const auto& witness = tx.inputs[i].witness;
        if (witness.count < 2 || witness.count > 3) continue;
        const auto& stack0 = witness.elements[0];
        std::vector<uint8_t> bytes(stack0.data, stack0.data + stack0.size);
        LadderWitness lw;
        std::string err;
        if (!DeserializeLadderWitness(bytes, lw, err)) continue;
        for (const auto& rung : lw.rungs) {
            for (const auto& block : rung.blocks) {
                if (block.type == RungBlockType::ACCUMULATOR) ++total;
            }
        }
        for (const auto& relay : lw.relays) {
            for (const auto& block : relay.blocks) {
                if (block.type == RungBlockType::ACCUMULATOR) ++total;
            }
        }
    }
    return total;
}

namespace api {

bool CheckRungTxLevel(const LadderTxView& tx,
                      const LadderOutputView* spent_outputs,
                      size_t spent_output_count,
                      std::string& error)
{
    // v0.11: require spent_outputs to be present whenever the
    // tx has any inputs. The per-tx counters silently treat inputs as
    // non-MLSC when spent_outputs is null, which would skip every per-tx
    // cap. Production callers (validation.cpp:2406, evaluator's input-0
    // safety net) always pass the populated vector — so the only way to
    // hit this branch is a future code path that forgets to wire it up,
    // and we want that to fail loud instead of silently zeroing the caps.
    //
    // v0.13: coinbase exception — coinbase has a
    // single null-prevout input and no real spent_outputs; the per-tx
    // counters trivially see zero MLSC inputs and validate nothing
    // beyond the output format and qabi_block / aggregated_sig gating.
    // Detect coinbase by tx.input_count == 1 AND null prevout txid +
    // n == 0xFFFFFFFF (the canonical coinbase prevout).
    bool is_coinbase = (tx.input_count == 1 && tx.inputs &&
        tx.inputs[0].prevout.n == 0xFFFFFFFF);
    if (is_coinbase) {
        // ok if both is_coinbase
        for (int z = 0; z < 32; ++z) {
            if (tx.inputs[0].prevout.txid[z] != 0) { is_coinbase = false; break; }
        }
    }
    if (tx.input_count > 0 && !is_coinbase &&
        (spent_outputs == nullptr || spent_output_count != tx.input_count)) {
        error = "TX_MLSC: tx-level check requires spent_outputs of equal length to inputs";
        return false;
    }

    // Consensus: validate all outputs are valid Ladder Script format.
    // Ensures only MLSC (0xDF) outputs, max 1 DATA_RETURN, dust threshold.
    if (!ValidateRungOutputs(tx, error)) {
        return false;
    }

    // Consensus: PREIMAGE/SCRIPT_BODY field count across MLSC inputs.
    if (CountTxPreimageFields(tx, spent_outputs, spent_output_count) > MAX_PREIMAGE_FIELDS_PER_TX) {
        error = "TX_MLSC: per-tx preimage field count exceeds limit";
        return false;
    }

    // Consensus (v0.7): SCRIPT_BODY-only sub-cap inside the combined limit.
    // Closes E-003 (2 × 80 B SCRIPT_BODY > 112 B/tx claim).
    if (CountTxScriptBodyFields(tx, spent_outputs, spent_output_count) > MAX_SCRIPT_BODY_FIELDS_PER_TX) {
        error = "TX_MLSC: per-tx SCRIPT_BODY field count exceeds limit";
        return false;
    }

    // Consensus (v0.6): ACCUMULATOR block count across MLSC inputs.
    if (CountTxAccumulatorBlocks(tx, spent_outputs, spent_output_count) > MAX_ACCUMULATOR_BLOCKS_PER_TX) {
        error = "TX_MLSC: per-tx ACCUMULATOR block count exceeds limit";
        return false;
    }

    // Consensus (v0.9, T-1/T-2; v0.10 F-2/F-5): tx-level QABI fields gating.
    //   - When no MLSC input carries QABI_SPEND/QABI_PRIME/PQ_BATCH:
    //       qabi_block MUST be empty.
    //       aggregated_sig MUST be empty.
    //   - When at least one MLSC input is QABI_SPEND:
    //       aggregated_sig MUST be exactly 666 bytes (the FALCON-512
    //       coordinator signature size). Pre-v0.10 the deserialiser
    //       allowed any 1..665 of attacker bytes here; the QABI_SPEND
    //       evaluator only checks the field size after dispatch.
    //   - When QABI is present but no QABI_SPEND input (only QABI_PRIME /
    //     PQ_BATCH):
    //       aggregated_sig MUST be empty (no consumer).
    auto qabi = ScanTxQABIInputs(tx, spent_outputs, spent_output_count);
    if (!qabi.has_any) {
        if (tx.qabi_block_size > 0) {
            error = "TX_MLSC: tx.qabi_block must be empty when no QABI input is present";
            return false;
        }
        if (tx.aggregated_sig_size > 0) {
            error = "TX_MLSC: tx.aggregated_sig must be empty when no QABI input is present";
            return false;
        }
    } else if (qabi.has_qabi_spend) {
        // v0.14: aggregated_sig is now variable-length
        // (1..QABI_AGGREGATED_SIG_MAX). Pre-v0.14 required exactly 666 B
        // and signers padded with zeros — the trailing padding was a
        // 0-66 B/tx coordinator-side channel. v0.14 wire-format carries
        // the actual FALCON-512 sig bytes (variable length per BIP-FALCON);
        // liboqs rejects malformed sig lengths internally.
        if (tx.aggregated_sig_size > 666) {
            error = "TX_MLSC: tx.aggregated_sig exceeds maximum FALCON-512 size";
            return false;
        }
    } else {
        if (tx.aggregated_sig_size > 0) {
            error = "TX_MLSC: tx.aggregated_sig must be empty when no QABI_SPEND input is present";
            return false;
        }
    }

    return true;
}

} // namespace api

namespace api {

bool VerifyRungTx(
    const LadderTxView& tx,
    size_t input_index,
    const LadderOutputView& spent_output,
    const LadderEvalContext& ctx,
    LadderScriptError* error_out,
    std::string* error_message_out)
{
    // `fail` (no-message) is the bulk path — most rejections are
    // structural and the LadderScriptError code is enough. `fail_msg`
    // captures a human-readable string for the rejections that have
    // one (deserialiser parse_err strings, witness-merge failures,
    // tx-level check messages). Operator-friendliness only — same
    // intent as the DecodeHexTx patch but at the script-verify layer.
    auto fail = [&](LadderScriptError code) -> bool {
        if (error_out) *error_out = code;
        return false;
    };
    auto fail_msg = [&](LadderScriptError code, std::string_view msg) -> bool {
        if (error_out) *error_out = code;
        if (error_message_out && error_message_out->empty() && !msg.empty()) {
            *error_message_out = std::string(msg);
        }
        return false;
    };

    if (input_index >= tx.input_count) return fail(LadderScriptError::UNKNOWN_ERROR);
    if (!ctx.sig_checker)              return fail(LadderScriptError::UNKNOWN_ERROR);
    if (!ctx.precomputed)              return fail(LadderScriptError::UNKNOWN_ERROR);

    // Per-transaction checks: only run on first input (same result for all).
    // Note: for wallet-funded v4 txs (where input 0 is a standard P2WPKH/P2TR
    // spend), VerifyRungTx is never called — the tx-level checks in
    // CheckRungTxLevel must be invoked separately by the tx-level validator
    // so the rules apply regardless of input types. The call here is a
    // safety net for pure-MLSC txs (redundant but harmless when
    // CheckRungTxLevel has already run).
    if (input_index == 0) {
        std::string tx_error;
        // VerifyRungTx is only called for MLSC inputs, so spent_outputs from
        // ctx.precomputed is the correct source of truth for IsMLSCScript
        // filtering inside CheckRungTxLevel. May be nullptr if the host
        // didn't pre-populate; CheckRungTxLevel fails-closed in that case.
        const LadderOutputView* spent_outs = ctx.precomputed
            ? ctx.precomputed->spent_outputs : nullptr;
        const size_t spent_count = ctx.precomputed
            ? ctx.precomputed->spent_output_count : 0;
        if (!CheckRungTxLevel(tx, spent_outs, spent_count, tx_error)) {
            LogPrintf("TX_MLSC tx-level check failed: %s\n", tx_error);
            return fail_msg(LadderScriptError::UNKNOWN_ERROR,
                            "TX_MLSC tx-level: " + tx_error);
        }
    }

    const auto& witness = tx.inputs[input_index].witness;

    // Witness stack size determines spending path:
    //   1 element  = key-path spend (signature only)
    //   2 elements = script-path, no tweak check (LadderWitness + MLSCProof)
    //   3 elements = script-path with tweak (LadderWitness + MLSCProof + internal_pubkey)
    if (witness.count == 0 || witness.count > 3) {
        return fail(LadderScriptError::WITNESS_PROGRAM_WITNESS_EMPTY);
    }

    // ================================================================
    // Dispatch invariant — defense in depth.
    //
    // VerifyRungTx must only ever be called for inputs spending an MLSC
    // scriptPubKey (0xDF prefix). The actual dispatch lives in
    // src/validation.cpp (CScriptCheck::operator()), gated by:
    //   tx.version == RUNG_TX_VERSION && IsMLSCScript(spent_pk)
    //
    // That gate makes ladder-vs-taproot witness "mixing" structurally
    // impossible: P2TR (OP_1 + 32B) and MLSC (0xDF + 32B) have disjoint
    // scriptPubKey prefixes, so a single input is dispatched to exactly
    // one parser based on the spent output, never both. The witness
    // stack is interpreted by the parser the dispatch chose; ladder
    // bytes never reach the taproot interpreter and vice versa.
    //
    // This check is the safety net: if a future refactor changes the
    // dispatch in validation.cpp, ladder code still refuses to evaluate
    // a non-MLSC scriptPubKey instead of silently mis-interpreting the
    // witness as ladder. Do not weaken or remove without auditing
    // every call site of VerifyRungTx.
    // ================================================================
    if (!IsMLSCScript(spent_output.script_pub_key.as_span())) {
        LogPrintf("VerifyRungTx called on non-MLSC scriptPubKey — dispatch invariant violated\n");
        return fail(LadderScriptError::NON_MLSC_SCRIPT);
    }
    // Defense in depth: MLSC outputs carrying a DATA_RETURN payload
    // (scriptPubKey 34-73 bytes, 0xDF prefix + root + data) are marked
    // IsUnspendable() by Core and are not tracked in the UTXO set, so this
    // path should be unreachable in practice. Reject explicitly in case a
    // future CScript refactor changes the IsUnspendable rule.
    if (HasMLSCData(spent_output.script_pub_key.as_span())) {
        LogPrintf("VerifyRungTx called on MLSC+DATA_RETURN output — unspendable\n");
        return fail(LadderScriptError::NON_MLSC_SCRIPT);
    }

    // Local helpers to turn adapter witness elements into byte spans.
    auto wit_span = [&](size_t i) -> std::span<const uint8_t> {
        return {witness.elements[i].data, witness.elements[i].size};
    };
    auto wit_vec = [&](size_t i) -> std::vector<uint8_t> {
        const auto& e = witness.elements[i];
        return std::vector<uint8_t>(e.data, e.data + e.size);
    };

    // Convert the prevout txid at input `i` to a library Txid.
    auto prevout_txid = [&](size_t i) -> Txid {
        uint256 u;
        std::memcpy(u.data(), tx.inputs[i].prevout.txid, 32);
        return Txid::FromUint256(u);
    };

    auto* shared_cache   = static_cast<SharedTreeCache*>(ctx.shared_tree_cache);
    auto* shared_cache_mutex = static_cast<std::mutex*>(ctx.shared_tree_cache_mutex);
    auto* qabo_sig_cache = static_cast<QABOSigCache*>(ctx.qabo_sig_cache);
    auto* qabo_sig_cache_mutex = static_cast<std::mutex*>(ctx.qabo_sig_cache_mutex);
    auto* pq_batch_cache = static_cast<PQBatchCache*>(ctx.pq_batch_cache);
    auto* pq_batch_cache_mutex = static_cast<std::mutex*>(ctx.pq_batch_cache_mutex);

    // ================================================================
    // KEY-PATH SPEND: witness = [signature]
    // Verify Schnorr signature directly against the output's conditions_root
    // treated as an x-only public key. No conditions revealed, no Merkle proof.
    // ================================================================
    if (witness.count == 1) {
        uint256 conditions_root;
        if (!GetMLSCRoot(spent_output.script_pub_key.as_span(), conditions_root)) {
            return fail(LadderScriptError::UNKNOWN_ERROR);
        }

        auto sig_full = wit_span(0);
        if (sig_full.size() != 64 && sig_full.size() != 65) {
            return fail(LadderScriptError::SCHNORR_SIG_SIZE);
        }

        // Extract sighash type from trailing byte (BIP341 convention).
        uint8_t hashtype = SIGHASH_DEFAULT;
        std::vector<uint8_t> sig_data(sig_full.begin(), sig_full.end());
        if (sig_data.size() == 65) {
            hashtype = sig_data.back();
            sig_data.pop_back();
            if (hashtype == SIGHASH_DEFAULT) {
                return fail(LadderScriptError::UNKNOWN_ERROR);
            }
        }

        // Compute key-path sighash (no conditions commitment).
        uint256 sighash;
        if (!SignatureHashLadderKeyPath(*ctx.precomputed, tx, input_index,
                                          hashtype, sighash)) {
            return fail(LadderScriptError::UNKNOWN_ERROR);
        }

        // Verify Schnorr signature against the output key (conditions_root
        // interpreted as an x-only pubkey). Delegated to the host's sig
        // checker — the library never handles XOnlyPubKey.
        std::span<const uint8_t, 32> sighash_span{sighash.data(), 32};
        std::span<const uint8_t, 32> pubkey_span{conditions_root.data(), 32};
        std::span<const uint8_t> sig_span{sig_data.data(), sig_data.size()};
        if (!ctx.sig_checker->CheckSchnorrSignature(sig_span, pubkey_span, sighash_span)) {
            return fail(LadderScriptError::SIGNATURE_INVALID);
        }

        return true;
    }

    // ================================================================
    // SCRIPT-PATH SPEND: witness = [LadderWitness, MLSCProof] or
    //                               [LadderWitness, MLSCProof, internal_pubkey]
    // ================================================================
    const std::vector<uint8_t> witness_bytes = wit_vec(0);

    LadderWitness witness_ladder;
    std::string deser_error;
    if (!DeserializeLadderWitness(witness_bytes, witness_ladder, deser_error)) {
        return fail_msg(LadderScriptError::WITNESS_MALFORMED,
                        "ladder witness deserialise: " + deser_error);
    }

    // Resolve witness references if needed (diff witness mode)
    if (witness_ladder.IsWitnessRef()) {
        std::string ref_error;
        if (!ResolveWitnessReference(witness_ladder, tx, input_index, ref_error)) {
            return fail(LadderScriptError::WITNESS_MALFORMED);
        }
    }

    RungConditions conditions;
    bool has_conditions = false;
    std::vector<std::vector<std::vector<uint8_t>>> eval_rung_pubkeys;
    MLSCVerifiedLeaves verified_leaves_data;
    MLSCProof mlsc_proof;

    {
        // ================================================================
        // MLSC path: conditions come from witness, not scriptPubKey
        // ================================================================
        uint256 conditions_root;
        if (!GetMLSCRoot(spent_output.script_pub_key.as_span(), conditions_root)) {
            return fail(LadderScriptError::MLSC_ROOT_UNAVAILABLE);
        }

        // stack[0] = LadderWitness (already deserialized above)
        // stack[1] = MLSCProof (revealed conditions + Merkle proof hashes)
        // (exact stack size already enforced at entry)

        // Deserialize MLSC proof from stack[1]
        const std::vector<uint8_t> proof_bytes = wit_vec(1);
        std::string proof_error;
        if (!DeserializeMLSCProof(proof_bytes, mlsc_proof, proof_error)) {
            LogPrintf("MLSC proof deserialization failed: %s\n", proof_error);
            return fail_msg(LadderScriptError::PROOF_DESERIALISE_FAILED,
                            "MLSC proof: " + proof_error);
        }

        // SHARED proof mode: validate against a previously verified input from the same source tx
        if (mlsc_proof.proof_mode == MLSCProofMode::SHARED) {
            if (!shared_cache) {
                LogPrintf("MLSC shared proof: no cache available\n");
                return fail(LadderScriptError::UNKNOWN_ERROR);
            }
            uint16_t src_idx = mlsc_proof.shared_source_input;
            if (src_idx >= input_index) {
                LogPrintf("MLSC shared proof: source_input %u >= current input %zu (must reference earlier input)\n",
                          src_idx, input_index);
                return fail(LadderScriptError::UNKNOWN_ERROR);
            }
            // Verify same source tx
            if (std::memcmp(tx.inputs[src_idx].prevout.txid,
                            tx.inputs[input_index].prevout.txid, 32) != 0) {
                LogPrintf("MLSC shared proof: source input %u has different prevout hash\n", src_idx);
                return fail(LadderScriptError::UNKNOWN_ERROR);
            }
            // Look up the verified root from the source input.
            // v0.13: mutex-protected — anchor writes
            // by other workers are immediately visible.
            uint256 cached_root;
            bool cached_found = false;
            {
                std::optional<std::unique_lock<std::mutex>> lk;
                if (shared_cache_mutex) lk.emplace(*shared_cache_mutex);
                auto it = shared_cache->find(prevout_txid(src_idx));
                if (it != shared_cache->end()) {
                    cached_root = it->second.root;
                    cached_found = true;
                }
            }
            if (!cached_found) {
                LogPrintf("MLSC shared proof: source input %u not in cache\n", src_idx);
                return fail(LadderScriptError::UNKNOWN_ERROR);
            }
            if (cached_root != conditions_root) {
                LogPrintf("MLSC shared proof: cached root mismatch\n");
                return fail(LadderScriptError::MLSC_ROOT_MISMATCH);
            }
            // Root matches. Leaf membership is checked below after pubkey extraction.
        }

        // Single rung rule: standard spends reveal exactly 1 rung
        if (witness_ladder.rungs.size() != 1) {
            return fail(LadderScriptError::UNKNOWN_ERROR);
        }

        // Extract pubkeys from witness for merkle_pub_key leaf computation
        std::vector<std::vector<uint8_t>> rung_pks;
        if (!witness_ladder.rungs.empty()) {
            rung_pks = ExtractBlockPubkeys(witness_ladder.rungs[0].blocks);
        }
        std::vector<std::vector<std::vector<uint8_t>>> relay_pks;
        for (const auto& [relay_idx, relay] : mlsc_proof.revealed_relays) {
            // Find the corresponding witness relay to extract pubkeys
            if (relay_idx < witness_ladder.relays.size()) {
                relay_pks.push_back(ExtractBlockPubkeys(witness_ladder.relays[relay_idx].blocks));
            } else {
                relay_pks.push_back({});
            }
        }

        // Mutation target pubkeys now travel inline inside each
        // MLSCMutationTarget — no parallel vector needed here.

        // Verify Merkle proof: TX_MLSC leaf = TaggedHash(template || value_commitment)
        std::string verify_error;

        // Build CreationProofRung from the revealed rung + witness data.
        // v0.9 (R-1): relay_refs flow into the structural template so a
        // spender cannot drop relay dependencies at spend time.
        CreationProofRung cp_rung;
        for (const auto& block : mlsc_proof.revealed_rung.blocks) {
            cp_rung.blocks.push_back({
                static_cast<uint16_t>(block.type),
                static_cast<uint8_t>(block.inverted ? 1 : 0)
            });
        }
        cp_rung.relay_refs = mlsc_proof.revealed_rung.relay_refs;
        cp_rung.coil = witness_ladder.coil;
        cp_rung.value_commitment = ComputeValueCommitment(
            mlsc_proof.revealed_rung, rung_pks);

        // Compute leaf (needed for rung evaluation even in SHARED mode)
        uint256 my_leaf = ComputeTxMLSCLeaf(cp_rung);

        // SHARED proofs: root was validated via cache. Now verify leaf membership —
        // the revealed rung's leaf must exist in the cached tree's leaf set.
        // v0.13: mutex-protected cache access.
        if (mlsc_proof.proof_mode == MLSCProofMode::SHARED) {
            std::vector<uint256> cached_leaves;
            {
                std::optional<std::unique_lock<std::mutex>> lk;
                if (shared_cache_mutex) lk.emplace(*shared_cache_mutex);
                auto cache_it = shared_cache->find(prevout_txid(input_index));
                if (cache_it == shared_cache->end()) {
                    return fail(LadderScriptError::UNKNOWN_ERROR);
                }
                cached_leaves = cache_it->second.leaves;
            }
            bool leaf_found = false;
            for (const auto& cached_leaf : cached_leaves) {
                if (cached_leaf == my_leaf) {
                    leaf_found = true;
                    break;
                }
            }
            if (!leaf_found) {
                LogPrintf("MLSC shared proof: leaf not found in cached tree\n");
                return fail(LadderScriptError::MLSC_LEAF_MISMATCH);
            }
        } else if (witness.count == 3) {
            // Compute raw Merkle root from proof, then verify tweak
            uint256 computed_merkle_root;
            if (mlsc_proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
                computed_merkle_root = ComputeMerkleRootFromPath(my_leaf, mlsc_proof.proof_hashes);
            } else {
                // v0.7: tree includes relay leaves at positions [N..N+M-1].
                size_t total_leaves = mlsc_proof.total_rungs + mlsc_proof.total_relays;
                if (total_leaves > MAX_RUNGS + MAX_RELAYS) {
                    LogPrintf("MLSC proof: total_leaves %zu exceeds maximum\n", total_leaves);
                    return fail(LadderScriptError::UNKNOWN_ERROR);
                }
                std::vector<uint256> leaves(total_leaves);
                std::vector<bool> revealed(total_leaves, false);
                leaves[mlsc_proof.rung_index] = my_leaf;
                revealed[mlsc_proof.rung_index] = true;
                // Recompute revealed relay leaves at their committed positions.
                for (size_t rl = 0; rl < mlsc_proof.revealed_relays.size(); ++rl) {
                    const auto& [relay_idx, relay] = mlsc_proof.revealed_relays[rl];
                    size_t leaf_idx = static_cast<size_t>(mlsc_proof.total_rungs) + relay_idx;
                    if (leaf_idx >= total_leaves) {
                        LogPrintf("MLSC proof: revealed_relay index out of range\n");
                        return fail(LadderScriptError::MERKLE_PATH_MISMATCH);
                    }
                    CreationProofRelay cp_relay;
                    for (const auto& blk : relay.blocks) {
                        cp_relay.blocks.push_back({static_cast<uint16_t>(blk.type),
                                                    static_cast<uint8_t>(blk.inverted ? 1 : 0)});
                    }
                    cp_relay.relay_refs = relay.relay_refs;
                    std::vector<std::vector<uint8_t>> rpks =
                        (relay_idx < witness_ladder.relays.size())
                            ? ExtractBlockPubkeys(witness_ladder.relays[relay_idx].blocks)
                            : std::vector<std::vector<uint8_t>>{};
                    Rung tmp; tmp.blocks = relay.blocks;
                    cp_relay.value_commitment = ComputeValueCommitment(tmp, rpks);
                    leaves[leaf_idx] = ComputeTxMLSCRelayLeaf(cp_relay);
                    revealed[leaf_idx] = true;
                }
                size_t ph_idx = 0;
                for (size_t i = 0; i < total_leaves; ++i) {
                    if (revealed[i]) continue;
                    if (ph_idx >= mlsc_proof.proof_hashes.size()) {
                        LogPrintf("MLSC proof failed: not enough proof hashes\n");
                        return fail(LadderScriptError::MERKLE_PATH_MISMATCH);
                    }
                    leaves[i] = mlsc_proof.proof_hashes[ph_idx++];
                }
                computed_merkle_root = BuildMerkleTree(std::move(leaves));
            }

            // Verify tweak: conditions_root == internal_pubkey + H(internal_pubkey || merkle_root) * G.
            auto internal_pk_span = wit_span(2);
            if (internal_pk_span.size() != 32) {
                LogPrintf("MLSC tweak: internal pubkey must be 32 bytes\n");
                return fail(LadderScriptError::PUBKEY_INVALID);
            }
            if (!CheckLadderTweakRaw(conditions_root.data(), internal_pk_span.data(),
                                     computed_merkle_root, 0) &&
                !CheckLadderTweakRaw(conditions_root.data(), internal_pk_span.data(),
                                     computed_merkle_root, 1)) {
                LogPrintf("MLSC tweak verification failed\n");
                return fail(LadderScriptError::MLSC_ROOT_MISMATCH);
            }
        } else {
            // 2-element witness: verify the Merkle proof directly against conditions_root
            // (no tweak — the output was created without an internal_pubkey).
            // v0.7: tree includes relay leaves at positions [N..N+M-1].
            size_t total_leaves = mlsc_proof.total_rungs + mlsc_proof.total_relays;
            if (total_leaves > MAX_RUNGS + MAX_RELAYS) {
                LogPrintf("MLSC proof: total_leaves %zu exceeds maximum\n", total_leaves);
                return fail(LadderScriptError::UNKNOWN_ERROR);
            }
            if (mlsc_proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
                std::string path_error;
                if (!VerifyMerklePath(my_leaf, mlsc_proof.proof_hashes,
                                      total_leaves, conditions_root, path_error)) {
                    LogPrintf("MLSC Merkle path verification failed: %s\n", path_error.c_str());
                    return fail_msg(LadderScriptError::MERKLE_PATH_MISMATCH,
                                    "MLSC Merkle path: " + path_error);
                }
            } else {
                std::vector<uint256> leaves(total_leaves);
                std::vector<bool> revealed(total_leaves, false);
                leaves[mlsc_proof.rung_index] = my_leaf;
                revealed[mlsc_proof.rung_index] = true;
                // Recompute revealed relay leaves at their committed positions.
                for (size_t rl = 0; rl < mlsc_proof.revealed_relays.size(); ++rl) {
                    const auto& [relay_idx, relay] = mlsc_proof.revealed_relays[rl];
                    size_t leaf_idx = static_cast<size_t>(mlsc_proof.total_rungs) + relay_idx;
                    if (leaf_idx >= total_leaves) {
                        LogPrintf("MLSC proof: revealed_relay index out of range\n");
                        return fail(LadderScriptError::MERKLE_PATH_MISMATCH);
                    }
                    CreationProofRelay cp_relay;
                    for (const auto& blk : relay.blocks) {
                        cp_relay.blocks.push_back({static_cast<uint16_t>(blk.type),
                                                    static_cast<uint8_t>(blk.inverted ? 1 : 0)});
                    }
                    cp_relay.relay_refs = relay.relay_refs;
                    std::vector<std::vector<uint8_t>> rpks =
                        (relay_idx < witness_ladder.relays.size())
                            ? ExtractBlockPubkeys(witness_ladder.relays[relay_idx].blocks)
                            : std::vector<std::vector<uint8_t>>{};
                    Rung tmp; tmp.blocks = relay.blocks;
                    cp_relay.value_commitment = ComputeValueCommitment(tmp, rpks);
                    leaves[leaf_idx] = ComputeTxMLSCRelayLeaf(cp_relay);
                    revealed[leaf_idx] = true;
                }
                size_t ph_idx = 0;
                for (size_t i = 0; i < total_leaves; ++i) {
                    if (revealed[i]) continue;
                    if (ph_idx >= mlsc_proof.proof_hashes.size()) {
                        LogPrintf("MLSC proof failed: not enough proof hashes\n");
                        return fail(LadderScriptError::MERKLE_PATH_MISMATCH);
                    }
                    leaves[i] = mlsc_proof.proof_hashes[ph_idx++];
                }
                uint256 computed_root = BuildMerkleTree(std::move(leaves));
                if (computed_root != conditions_root) {
                    LogPrintf("MLSC root mismatch: computed %s != expected %s\n",
                              computed_root.GetHex(), conditions_root.GetHex());
                    return fail_msg(LadderScriptError::MLSC_ROOT_MISMATCH,
                                    "MLSC root mismatch: computed " +
                                        computed_root.GetHex().substr(0, 16) +
                                        " != expected " +
                                        conditions_root.GetHex().substr(0, 16));
                }
            }
        }

        // Verify coil.output_index matches the output being spent
        uint32_t spent_vout = tx.inputs[input_index].prevout.n;
        if (witness_ladder.coil.output_index != spent_vout) {
            LogPrintf("coil.output_index %u != spent vout %u\n",
                      witness_ladder.coil.output_index, spent_vout);
            return fail(LadderScriptError::UNKNOWN_ERROR);
        }

        // Populate verified_leaves_data for recursive covenant blocks.
        // For FULL_LEAVES mode, we can reconstruct the full leaf array.
        // For MERKLE_PATH mode, store the leaf + path for covenant root recomputation.
        verified_leaves_data.root = conditions_root;
        verified_leaves_data.rung_index = mlsc_proof.rung_index;
        verified_leaves_data.total_rungs = mlsc_proof.total_rungs;
        verified_leaves_data.total_relays = mlsc_proof.total_relays;
        // Store the verified leaf at rung_index + all proof hashes as the leaf set.
        // Covenant blocks use this to swap a leaf and recompute the root.
        if (mlsc_proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
            // For Merkle path mode: store just the verified leaf.
            // Covenant recomputation uses ComputeMerkleRootFromPath(new_leaf, proof_hashes).
            verified_leaves_data.leaves.resize(1);
            verified_leaves_data.leaves[0] = my_leaf;
        } else if (mlsc_proof.proof_mode != MLSCProofMode::SHARED) {
            // FULL_LEAVES mode: reconstruct the full leaf array
            verified_leaves_data.leaves.resize(mlsc_proof.total_rungs);
            verified_leaves_data.leaves[mlsc_proof.rung_index] = my_leaf;
            size_t ph = 0;
            for (size_t i = 0; i < mlsc_proof.total_rungs; ++i) {
                if (i != mlsc_proof.rung_index && ph < mlsc_proof.proof_hashes.size()) {
                    verified_leaves_data.leaves[i] = mlsc_proof.proof_hashes[ph++];
                }
            }
        }

        // Populate shared tree cache for same-source proof sharing.
        // Store root + all leaf hashes so SHARED proofs can verify leaf membership.
        if (shared_cache && mlsc_proof.proof_mode != MLSCProofMode::SHARED) {
            SharedTreeEntry entry;
            entry.root = conditions_root;
            entry.leaves = verified_leaves_data.leaves;
            // v0.13: mutex-protected write so anchor
            // entries are immediately visible to other workers' SHARED-proof
            // reads — eliminates the parallel-snapshot race.
            std::optional<std::unique_lock<std::mutex>> lk;
            if (shared_cache_mutex) lk.emplace(*shared_cache_mutex);
            (*shared_cache)[prevout_txid(input_index)] = std::move(entry);
        }

        // Build RungConditions from MLSC proof. conditions.rungs is
        // kept at exactly 1 rung (the revealed one) so it stays 1:1
        // with witness_ladder.rungs for MergeConditionsAndWitness.
        // Cross-rung covenant checks (QABI_PRIME) read the full tree
        // indirectly via ctx.mlsc_proof->revealed_mutation_targets.
        conditions.rungs.push_back(mlsc_proof.revealed_rung);
        conditions.coil = witness_ladder.coil;
        conditions.conditions_root = conditions_root; // For sighash computation

        // Build relay vector: allocate for total_relays, fill in revealed ones
        conditions.relays.resize(mlsc_proof.total_relays);
        for (const auto& [relay_idx, relay] : mlsc_proof.revealed_relays) {
            if (relay_idx < conditions.relays.size()) {
                conditions.relays[relay_idx] = relay;
            }
        }

        has_conditions = true;

        // Save per-rung pubkeys for covenant root comparison
        eval_rung_pubkeys.push_back(rung_pks);

    } // end MLSC block

    // Build evaluation context for covenant, anchor, recursion, and PLC blocks.
    RungEvalContext eval_ctx;
    eval_ctx.tx = &tx;
    eval_ctx.tx_weight = ctx.tx_weight;
    eval_ctx.precomputed = ctx.precomputed;
    eval_ctx.input_index = static_cast<uint32_t>(input_index);
    eval_ctx.input_amount = spent_output.value;
    eval_ctx.block_height = ctx.block_height;
    // v0.10 (F-7): coil.output_index must address a real output. Pre-v0.10
    // an out-of-range index silently fell back to outputs[0], which masked
    // creator errors and could feed a covenant evaluator the wrong output.
    // The leaf binds output_index (per O-1) so honest creators commit
    // to a valid value at fund time; tampered/oversized values fail-closed.
    {
        uint32_t coil_out_idx = witness_ladder.coil.output_index;
        if (coil_out_idx >= tx.output_count) {
            return fail(LadderScriptError::UNKNOWN_ERROR);
        }
        eval_ctx.output_amount = tx.outputs[coil_out_idx].value;
        eval_ctx.spending_output = &tx.outputs[coil_out_idx];
    }
    if (has_conditions) {
        eval_ctx.input_conditions = &conditions;
    }
    if (!eval_rung_pubkeys.empty()) {
        eval_ctx.rung_pubkeys = &eval_rung_pubkeys;
    }
    if (has_conditions) {
        eval_ctx.verified_leaves = &verified_leaves_data;
        eval_ctx.mlsc_proof = &mlsc_proof;
    }
    if (ctx.precomputed->spent_output_count > 0) {
        eval_ctx.spent_outputs = ctx.precomputed->spent_outputs;
        eval_ctx.spent_output_count = ctx.precomputed->spent_output_count;
    }
    // Plumb the QABO sig cache through so QABI_SPEND can short-circuit
    // duplicate FALCON verifications across primed inputs of the same tx.
    eval_ctx.qabo_sig_cache = qabo_sig_cache;
    // Plumb the PQ_BATCH cache so non-anchor inputs with matching HASH256
    // commits can validate from cache after the anchor has verified once.
    eval_ctx.pq_batch_cache = pq_batch_cache;
    // v0.13: plumb cache mutexes so the evaluator can lock for both
    // reads and writes — eliminates parallel-snapshot races for both
    // PQ_BATCH and SharedTreeCache.
    eval_ctx.pq_batch_cache_mutex = pq_batch_cache_mutex;
    eval_ctx.shared_tree_cache_mutex = shared_cache_mutex;
    // v0.14: plumb QABO sig cache mutex too — last cache
    // to migrate off the snapshot/merge pattern. Reads/writes inside
    // EvalQABISpendBlock now lock against this directly.
    eval_ctx.qabo_sig_cache_mutex = qabo_sig_cache_mutex;
    // v0.14 follow-up (#136): pipe the optional eval-layer error string
    // through. Block evaluators (EvalQABISpendBlock, EvalHTLC, etc.)
    // write here on UNSATISFIED; we surface it via the api-level
    // error_message_out when nothing earlier (witness/proof/merge deser)
    // already populated it.
    eval_ctx.error_message_out = error_message_out;

    // EvalLadder also needs a `BaseSignatureChecker&` for the legacy P2*
    // wrapper family. Fetch it from the opaque ctx field; fall back to a
    // default-constructed checker (all four methods return false) when the
    // host didn't provide one and the spend uses no legacy wrappers.
    static BaseSignatureChecker kFallbackLegacyChecker{};
    const BaseSignatureChecker& legacy_checker =
        ctx.legacy_sig_checker
            ? *static_cast<const BaseSignatureChecker*>(ctx.legacy_sig_checker)
            : kFallbackLegacyChecker;

    LadderWitness eval_ladder;
    ScriptExecutionData execdata;

    if (has_conditions) {
        // Merge conditions with witness.
        std::string merge_error;
        if (!MergeConditionsAndWitness(conditions, witness_ladder, eval_ladder, merge_error)) {
            return fail_msg(LadderScriptError::WITNESS_MALFORMED,
                            "merge conditions+witness: " + merge_error);
        }

        if (!EvalLadder(eval_ladder, *ctx.sig_checker, legacy_checker,
                        SigVersion::LADDER, execdata, eval_ctx)) {
            return fail(LadderScriptError::UNKNOWN_ERROR);
        }
    } else {
        // Bootstrap spend: v4 tx spending a v1/v2 UTXO.
        if (!EvalLadder(witness_ladder, *ctx.sig_checker, legacy_checker,
                        SigVersion::LADDER, execdata, eval_ctx)) {
            return fail(LadderScriptError::UNKNOWN_ERROR);
        }
    }

    return true;
}

} // namespace api

// Core-typed entry point — builds the adapter views, constructs a
// `CoreLadderSigChecker`, packages a `LadderEvalContext`, then forwards to
// `rung::api::VerifyRungTx`. `ScriptError*` translation matches the prior
// error surface (the Core validator only distinguishes a handful of codes,
// so coarse mapping is sufficient).
bool VerifyRungTx(const CTransaction& tx,
                  unsigned int nIn,
                  const CTxOut& spent_output,
                  unsigned int flags,
                  const BaseSignatureChecker& checker,
                  const PrecomputedTransactionData& txdata,
                  ScriptError* serror,
                  int32_t block_height,
                  SharedTreeCache* shared_cache,
                  QABOSigCache* qabo_sig_cache,
                  PQBatchCache* pq_batch_cache,
                  std::mutex* pq_batch_cache_mutex,
                  std::mutex* shared_cache_mutex,
                  std::mutex* qabo_sig_cache_mutex,
                  std::string* error_message_out)
{
    LadderTxViewBuilder tx_view_builder(tx);
    LadderPrecomputedBuilder precomputed_builder(txdata);
    api::LadderOutputView spent_view;
    spent_view.value = spent_output.nValue;
    spent_view.script_pub_key = {spent_output.scriptPubKey.data(),
                                  spent_output.scriptPubKey.size()};

    CoreLadderSigChecker sig_checker(checker);

    api::LadderEvalContext adapter_ctx;
    adapter_ctx.block_height = block_height;
    adapter_ctx.flags = flags;
    adapter_ctx.tx_weight = GetTransactionWeight(tx);
    adapter_ctx.precomputed = &precomputed_builder.view;
    adapter_ctx.sig_checker = &sig_checker;
    adapter_ctx.shared_tree_cache = shared_cache;
    adapter_ctx.shared_tree_cache_mutex = shared_cache_mutex;
    adapter_ctx.qabo_sig_cache = qabo_sig_cache;
    adapter_ctx.qabo_sig_cache_mutex = qabo_sig_cache_mutex;
    adapter_ctx.pq_batch_cache = pq_batch_cache;
    adapter_ctx.pq_batch_cache_mutex = pq_batch_cache_mutex;
    adapter_ctx.legacy_sig_checker = const_cast<BaseSignatureChecker*>(&checker);
    // v0.14 follow-up (#136): propagate the eval-layer error channel
    // so block evaluators (EvalQABISpendBlock, EvalHTLC, etc.) can
    // populate it on UNSATISFIED returns. api::VerifyRungTx unifies
    // this with the deser-layer error_message_out param.
    adapter_ctx.error_message_out = error_message_out;

    api::LadderScriptError err = api::LadderScriptError::OK;
    if (!api::VerifyRungTx(tx_view_builder.view, static_cast<size_t>(nIn),
                            spent_view, adapter_ctx, &err, error_message_out)) {
        if (serror) {
            switch (err) {
            case api::LadderScriptError::WITNESS_PROGRAM_WITNESS_EMPTY:
                *serror = SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY; break;
            case api::LadderScriptError::SCHNORR_SIG_SIZE:
                *serror = SCRIPT_ERR_SCHNORR_SIG_SIZE; break;
            case api::LadderScriptError::SIGNATURE_INVALID:
                *serror = SCRIPT_ERR_SCHNORR_SIG; break;
            default:
                *serror = SCRIPT_ERR_UNKNOWN_ERROR; break;
            }
        }
        return false;
    }
    return true;
}

// ============================================================================
// Block-type dispatch registry
// ============================================================================
//
// Each Ladder block family exports a `register_<family>_blocks()` function
// below. `ladder_init()` calls them all at first use. The goal is selective
// compilation: a host that wants to ship a reduced block set (BIP sub-
// proposal opt-out, fuzz harness, kernel library, etc.) defines the
// corresponding `LADDER_NO_<FAMILY>` macro and that family is stripped from
// the build. Block types whose evaluators never register behave as
// UNKNOWN_BLOCK_TYPE at dispatch time — the same forward-compat semantics
// used for genuinely unknown block types.

namespace {
// RungBlockType is a uint16_t enum (rung/types.h), using values up to at
// least 0x0A02 (QABI_SPEND). A 65536-slot direct-lookup array costs ~512 KB
// of BSS and amortises to a single load per dispatch — cheaper than a hash
// map for a hot consensus path.
std::array<BlockEvaluator, 0x10000> g_block_registry{};
} // namespace

void RegisterBlock(RungBlockType type, BlockEvaluator fn)
{
    g_block_registry[static_cast<uint16_t>(type)] = fn;
}

BlockEvaluator LookupBlockEvaluator(RungBlockType type)
{
    return g_block_registry[static_cast<uint16_t>(type)];
}

// ---- Family: signature ----
#ifndef LADDER_NO_SIG
#else
void register_sig_blocks() {}
#endif

// ---- Family: timelock ----
#ifndef LADDER_NO_TIMELOCK
#else
void register_timelock_blocks() {}
#endif

// ---- Family: hash ----
#ifndef LADDER_NO_HASH
#else
void register_hash_blocks() {}
#endif

// ---- Family: covenant ----
#ifndef LADDER_NO_COVENANT
#else
void register_covenant_blocks() {}
#endif

// ---- Family: anchor ----
#ifndef LADDER_NO_ANCHOR
#else
void register_anchor_blocks() {}
#endif

// ---- Family: recursion ----
#ifndef LADDER_NO_RECURSION
#else
void register_recursion_blocks() {}
#endif

// ---- Family: PLC (hysteresis / timer / latch / counter / compare / sequencer / one-shot / rate-limit / cosign) ----
#ifndef LADDER_NO_PLC
#else
void register_plc_blocks() {}
#endif

// ---- Family: compound (combinations of sig + timelock + hash in one block) ----
#ifndef LADDER_NO_COMPOUND
#else
void register_compound_blocks() {}
#endif

// ---- Family: governance (tx-level constraints) ----
#ifndef LADDER_NO_GOVERNANCE
#else
void register_governance_blocks() {}
#endif

// ---- Family: legacy P2* wrappers ----
#ifndef LADDER_NO_LEGACY
#else
void register_legacy_blocks() {}
#endif

// ---- Family: QABIO (BIP-YYYY) ----
#ifdef ENABLE_QABIO
#else
#endif

namespace api {
void ladder_init()
{
    static const bool initialised = []() {
        register_sig_blocks();
        register_timelock_blocks();
        register_hash_blocks();
        register_covenant_blocks();
        register_anchor_blocks();
        register_recursion_blocks();
        register_plc_blocks();
        register_compound_blocks();
        register_governance_blocks();
        register_legacy_blocks();
#ifdef ENABLE_QABIO
        register_qabi_blocks();
#else
        register_qabi_stub();
#endif
        return true;
    }();
    (void)initialised;
}

}  // namespace api

} // namespace rung
