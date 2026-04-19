// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: recursion.
// Evaluators + registry function. The top-level dispatcher calls each
// registered evaluator via `rung::LookupBlockEvaluator`.

#include <rung/block_dispatch.h>
#include <rung/block_helpers.h>
#include <rung/evaluator.h>

#include <rung/conditions.h>
#include <rung/pq_verify.h>
#include <rung/qabi.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung_shims.h>

#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>

namespace rung {
using namespace api;

EvalResult EvalRecurseSameBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Verify output carries identical rung conditions as input
    const RungField* max_depth = FindField(block, RungDataType::NUMERIC);
    if (!max_depth) {
        return EvalResult::ERROR;
    }
    auto depth_opt = ReadNumeric(*max_depth);
    if (!depth_opt || *depth_opt <= 0) {
        return EvalResult::UNSATISFIED;
    }

    // Leaf-centric: output root must equal input root (identity)
    if (ctx.verified_leaves) {
        if (!ctx.spending_output) return EvalResult::ERROR;
        if (!OutputRootMatchesInput(*ctx.spending_output, *ctx.verified_leaves)) {
            return EvalResult::UNSATISFIED;
        }
    } else if (ctx.input_conditions) {
        if (!ctx.spending_output) return EvalResult::ERROR;
        // Fallback: compare MLSC roots directly
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
            return EvalResult::UNSATISFIED;
        }
        std::vector<std::vector<std::vector<uint8_t>>> pks;
        if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
        if (output_root != ComputeConditionsRootMLSC(*ctx.input_conditions, pks)) {
            return EvalResult::UNSATISFIED;
        }
    }
    // No covenant context available — structural check passed (depth > 0)
    return EvalResult::SATISFIED;
}

EvalResult EvalRecurseModifiedBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    int64_t max_depth;
    std::vector<MutationSpec> mutations;
    if (!ParseMutationSpecs(numerics, max_depth, mutations)) {
        return EvalResult::ERROR;
    }
    if (max_depth <= 0) {
        return EvalResult::UNSATISFIED;
    }
    return VerifyMutatedLeaves(ctx, mutations);
}

EvalResult EvalRecurseUntilBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    const RungField* until_height_field = FindField(block, RungDataType::NUMERIC);
    if (!until_height_field) {
        return EvalResult::ERROR;
    }
    auto until_height_opt = ReadNumeric(*until_height_field);
    if (!until_height_opt) {
        return EvalResult::ERROR;
    }
    int64_t until_height = *until_height_opt;
    // Use tx nLockTime as height proxy (like CLTV — consensus ensures tx can't
    // be included before nLockTime). If nLockTime >= until_height, covenant terminates.
    int64_t effective_height = ctx.block_height;
    if (ctx.tx && ctx.tx->lock_time < LOCKTIME_THRESHOLD) {
        effective_height = std::max(effective_height, static_cast<int64_t>(ctx.tx->lock_time));
    }
    if (effective_height >= until_height) {
        return EvalResult::SATISFIED;
    }
    // Before until_height: must re-encumber output with same conditions
    // Leaf-centric: output root must equal input root (identity)
    if (ctx.verified_leaves && ctx.spending_output) {
        if (!OutputRootMatchesInput(*ctx.spending_output, *ctx.verified_leaves)) {
            return EvalResult::UNSATISFIED;
        }
    } else if (ctx.input_conditions && ctx.spending_output) {
        // Fallback: compare MLSC roots directly
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
            return EvalResult::UNSATISFIED;
        }
        std::vector<std::vector<std::vector<uint8_t>>> pks;
        if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
        if (output_root != ComputeConditionsRootMLSC(*ctx.input_conditions, pks)) {
            return EvalResult::UNSATISFIED;
        }
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalRecurseCountBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    const RungField* max_count = FindField(block, RungDataType::NUMERIC);
    if (!max_count) {
        return EvalResult::ERROR;
    }
    auto count_opt = ReadNumeric(*max_count);
    if (!count_opt) {
        return EvalResult::ERROR;
    }
    int64_t count = *count_opt;
    if (count == 0) {
        return EvalResult::SATISFIED; // countdown reached zero — covenant terminates
    }
    if (count < 0) {
        // Malformed: countdown values are always non-negative. Rejecting
        // here also prevents signed-overflow UB on `cur - 1` below if `cur`
        // were `INT64_MIN`.
        return EvalResult::ERROR;
    }
    // Count > 0: output must re-encumber with count-1.
    if (ctx.input_conditions && ctx.spending_output) {
        if (ctx.input_conditions->rungs.empty()) return EvalResult::UNSATISFIED;

        // Build the decremented rung
        Rung mutated = ctx.input_conditions->rungs[0];
        bool found = false;
        for (auto& blk : mutated.blocks) {
            if (blk.type == RungBlockType::RECURSE_COUNT) {
                for (auto& f : blk.fields) {
                    if (f.type == RungDataType::NUMERIC) {
                        auto cur = ReadNumeric(f);
                        if (!cur || *cur <= 0) return EvalResult::ERROR;
                        WriteNumericField(f, *cur - 1);
                        found = true;
                        break;
                    }
                }
                if (found) break;
            }
        }
        if (!found) return EvalResult::UNSATISFIED;

        if (ctx.verified_leaves) {
            // Leaf-centric: recompute only the mutated leaf, rebuild tree
            std::vector<std::vector<uint8_t>> rung_pks;
            if (ctx.rung_pubkeys && !ctx.rung_pubkeys->empty()) {
                rung_pks = (*ctx.rung_pubkeys)[0];
            }
            auto cp = BuildCPRung(mutated, rung_pks, ctx.input_conditions->coil);
            uint256 new_leaf = ComputeTxMLSCLeaf(cp);
            uint256 expected_root = ComputeExpectedRoot(*ctx.verified_leaves,
                                                         ctx.verified_leaves->rung_index, new_leaf);
            uint256 output_root;
            if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
                return EvalResult::UNSATISFIED;
            }
            if (output_root != expected_root) {
                return EvalResult::UNSATISFIED;
            }
        } else {
            // Fallback: build full conditions with decremented rung, compare root
            RungConditions expected = *ctx.input_conditions;
            expected.rungs[0] = mutated;
            std::vector<std::vector<std::vector<uint8_t>>> pks;
            if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
            uint256 output_root;
            if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
                return EvalResult::UNSATISFIED;
            }
            if (output_root != ComputeConditionsRootMLSC(expected, pks)) {
                return EvalResult::UNSATISFIED;
            }
        }
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalRecurseSplitBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }
    auto max_splits_opt = ReadNumeric(*numerics[0]);
    auto min_split_sats_opt = ReadNumeric(*numerics[1]);
    if (!max_splits_opt || !min_split_sats_opt) {
        return EvalResult::ERROR;
    }
    int64_t max_splits = *max_splits_opt;
    int64_t min_split_sats = *min_split_sats_opt;
    if (max_splits <= 0 || min_split_sats < 0) {
        return EvalResult::UNSATISFIED;
    }

    // Decrement max_splits, recompute root, compare outputs.
    if (ctx.tx && ctx.input_conditions) {
        if (ctx.input_conditions->rungs.empty()) return EvalResult::UNSATISFIED;

        // Build the decremented rung
        Rung mutated = ctx.input_conditions->rungs[0];
        for (auto& blk : mutated.blocks) {
            if (blk.type == RungBlockType::RECURSE_SPLIT) {
                for (auto& f : blk.fields) {
                    if (f.type == RungDataType::NUMERIC) {
                        auto cur = ReadNumeric(f);
                        if (!cur) return EvalResult::ERROR;
                        WriteNumericField(f, *cur - 1);
                        break; // first NUMERIC is max_splits
                    }
                }
            }
        }

        // Compute expected root via leaf-centric or fallback path
        uint256 expected_root;
        if (ctx.verified_leaves) {
            // Leaf-centric: replace only the revealed rung's leaf, rebuild tree
            std::vector<std::vector<uint8_t>> rung_pks;
            if (ctx.rung_pubkeys && !ctx.rung_pubkeys->empty()) {
                rung_pks = (*ctx.rung_pubkeys)[0];
            }
            auto cp = BuildCPRung(mutated, rung_pks, ctx.input_conditions->coil);
            uint256 new_leaf = ComputeTxMLSCLeaf(cp);
            expected_root = ComputeExpectedRoot(*ctx.verified_leaves,
                                                ctx.verified_leaves->rung_index, new_leaf);
        } else {
            // Fallback: build full conditions with decremented rung
            RungConditions expected = *ctx.input_conditions;
            expected.rungs[0] = mutated;
            std::vector<std::vector<std::vector<uint8_t>>> pks;
            if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
            expected_root = ComputeConditionsRootMLSC(expected, pks);
        }

        int64_t total_output = 0;
        for (size_t voi = 0; voi < ctx.tx->output_count; ++voi) {
            const auto& vout = ctx.tx->outputs[voi];
            // DATA_RETURN outputs (value == 0) are exempt from covenant checks
            if (vout.value == 0) continue;
            if (vout.value < min_split_sats) {
                return EvalResult::UNSATISFIED;
            }
            total_output += vout.value;
            // Every spendable output must be MLSC with the expected root
            uint256 out_root;
            if (!GetMLSCRoot(vout.script_pub_key.as_span(), out_root)) {
                return EvalResult::UNSATISFIED; // non-MLSC output breaks covenant
            }
            if (out_root != expected_root) {
                return EvalResult::UNSATISFIED;
            }
        }
        // Value conservation: total outputs must not exceed input
        if (total_output > ctx.input_amount) {
            return EvalResult::UNSATISFIED;
        }
    } else if (ctx.output_amount > 0 && ctx.output_amount < min_split_sats) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalRecurseDecayBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    int64_t max_depth;
    std::vector<MutationSpec> mutations;
    if (!ParseMutationSpecs(numerics, max_depth, mutations)) {
        return EvalResult::ERROR;
    }
    if (max_depth <= 0) {
        return EvalResult::UNSATISFIED;
    }
    // Decay: negate deltas (output = input - decay_per_step)
    for (auto& m : mutations) {
        m.delta = -m.delta;
    }
    return VerifyMutatedLeaves(ctx, mutations);
}

void register_recursion_blocks()
{
    RegisterBlock(RungBlockType::RECURSE_SAME, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseSameBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_MODIFIED, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseModifiedBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_UNTIL, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseUntilBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_COUNT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseCountBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_SPLIT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseSplitBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_DECAY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseDecayBlock(b, d.ctx);
    });
}

} // namespace rung
