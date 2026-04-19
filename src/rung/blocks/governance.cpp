// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: governance.
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

EvalResult EvalEpochGateBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // EPOCH_GATE: spending allowed only within periodic windows.
    // Fields: NUMERIC[0] = epoch_size (blocks per epoch),
    //         NUMERIC[1] = window_size (blocks within epoch where spending is allowed)
    // Gate opens at block_height % epoch_size < window_size
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    auto epoch_size_opt = ReadNumeric(*numerics[0]);
    auto window_size_opt = ReadNumeric(*numerics[1]);
    if (!epoch_size_opt || !window_size_opt) {
        return EvalResult::ERROR;
    }
    int64_t epoch_size = *epoch_size_opt;
    int64_t window_size = *window_size_opt;
    if (epoch_size <= 0 || window_size <= 0 || window_size > epoch_size) {
        return EvalResult::ERROR;
    }

    int64_t position = ctx.block_height % epoch_size;
    if (position < window_size) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalWeightLimitBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // WEIGHT_LIMIT: max transaction weight
    // Fields: NUMERIC = max weight units (1 WU = 4 bytes for non-witness, 1 byte for witness)
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) return EvalResult::ERROR;

    auto max_weight_opt = ReadNumeric(*numeric_field);
    if (!max_weight_opt || *max_weight_opt <= 0) return EvalResult::ERROR;
    int64_t max_weight = *max_weight_opt;

    if (ctx.tx_weight <= 0) return EvalResult::ERROR; // fail-safe: no tx weight

    if (ctx.tx_weight <= max_weight) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalInputCountBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // INPUT_COUNT: bounds on number of inputs in spending tx
    // Fields: NUMERIC[0] = min_inputs, NUMERIC[1] = max_inputs
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    auto min_inputs_opt = ReadNumeric(*numerics[0]);
    auto max_inputs_opt = ReadNumeric(*numerics[1]);
    if (!min_inputs_opt || !max_inputs_opt) {
        return EvalResult::ERROR;
    }
    int64_t min_inputs = *min_inputs_opt;
    int64_t max_inputs = *max_inputs_opt;
    if (min_inputs < 0 || max_inputs < 0 || min_inputs > max_inputs) {
        return EvalResult::ERROR;
    }

    if (!ctx.tx) return EvalResult::ERROR;

    int64_t count = static_cast<int64_t>(ctx.tx->input_count);
    if (count >= min_inputs && count <= max_inputs) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalOutputCountBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // OUTPUT_COUNT: bounds on number of outputs in spending tx
    // Fields: NUMERIC[0] = min_outputs, NUMERIC[1] = max_outputs
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    auto min_outputs_opt = ReadNumeric(*numerics[0]);
    auto max_outputs_opt = ReadNumeric(*numerics[1]);
    if (!min_outputs_opt || !max_outputs_opt) {
        return EvalResult::ERROR;
    }
    int64_t min_outputs = *min_outputs_opt;
    int64_t max_outputs = *max_outputs_opt;
    if (min_outputs < 0 || max_outputs < 0 || min_outputs > max_outputs) {
        return EvalResult::ERROR;
    }

    if (!ctx.tx) return EvalResult::ERROR;

    int64_t count = static_cast<int64_t>(ctx.tx->output_count);
    if (count >= min_outputs && count <= max_outputs) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalRelativeValueBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // RELATIVE_VALUE: output must be within a ratio of input value
    // Fields: NUMERIC[0] = numerator, NUMERIC[1] = denominator
    // Satisfied when: output_amount * denominator >= input_amount * numerator
    // Example: 9/10 means output must be >= 90% of input (anti-fee-siphon)
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    auto numerator_opt = ReadNumeric(*numerics[0]);
    auto denominator_opt = ReadNumeric(*numerics[1]);
    if (!numerator_opt || !denominator_opt) return EvalResult::ERROR;
    int64_t numerator = *numerator_opt;
    int64_t denominator = *denominator_opt;
    if (numerator < 0 || denominator <= 0) return EvalResult::ERROR;
    // Reject numerator / denominator outside uint32. The cross-division below
    // relies on `(a % n) * d` staying inside int64; that holds only when n
    // and d each fit in 32 bits. Without this guard an 8-byte NUMERIC with
    // a large value triggers signed-overflow UB and a consensus split between
    // platforms that wrap differently.
    if (numerator > 0xFFFFFFFFLL || denominator > 0xFFFFFFFFLL) {
        return EvalResult::ERROR;
    }

    // Compare output_amount * denominator >= input_amount * numerator without overflow.
    // Both sides can exceed int64_t range (amounts up to ~2.1e15, num/denom up to ~2^32).
    // Use portable overflow-safe comparison via cross-division.
    //
    // For non-negative values: a*b >= c*d ⟺ (a/d) > (c/b) OR
    //   ((a/d) == (c/b) AND (a%d)*b >= (c%b)*d)
    // But the remainder products can still overflow. Instead, decompose into
    // quotient + remainder comparison that stays within 64 bits.
    //
    // Simplification: since denominator > 0 and numerator >= 0, we can compare
    // output_amount / numerator_part >= input_amount / denominator_part.
    // But edge cases (numerator=0) need special handling.
    if (numerator == 0) {
        // 0 >= 0 always true (output * denom >= input * 0 = 0)
        return EvalResult::SATISFIED;
    }
    // Both numerator > 0 and denominator > 0 at this point.
    // Compare: output_amount * denominator >= input_amount * numerator
    // Rearrange: output_amount / numerator >= input_amount / denominator
    //   with careful remainder handling to avoid truncation errors.
    int64_t lhs_quot = ctx.output_amount / numerator;
    int64_t rhs_quot = ctx.input_amount / denominator;
    if (lhs_quot > rhs_quot) return EvalResult::SATISFIED;
    if (lhs_quot < rhs_quot) return EvalResult::UNSATISFIED;
    // Quotients equal — compare remainders: (a%n)*d vs (c%d)*n
    // These remainders are bounded: a%n < n, c%d < d.
    // So (a%n)*d < n*d and (c%d)*n < d*n — both < n*d which fits in int64_t
    // when n and d are each < 2^32 (NUMERIC fields are max 4 bytes = 2^32).
    int64_t lhs_rem = (ctx.output_amount % numerator) * denominator;
    int64_t rhs_rem = (ctx.input_amount % denominator) * numerator;
    if (lhs_rem >= rhs_rem) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalAccumulatorBlock(const RungBlock& block)
{
    // ACCUMULATOR: Merkle set membership proof
    // Conditions fields: HASH256[0] = merkle_root
    // Witness fields: HASH256[1..N] = merkle_proof (sibling hashes from leaf to root)
    //                 HASH256[N+1] = leaf_hash (the element being proven)
    // Proof verification: hash leaf with siblings bottom-up, compare to root.
    auto hashes = FindAllFields(block, RungDataType::HASH256);
    if (hashes.size() < 3) return EvalResult::ERROR; // root + at least 1 proof node + leaf
    if (hashes.size() > 10) return EvalResult::ERROR; // root + max 8 proof nodes + leaf

    const RungField* root_field = hashes[0];
    const RungField* leaf_field = hashes[hashes.size() - 1];
    if (root_field->data.size() != 32 || leaf_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute Merkle path: start from leaf, hash with each sibling
    // Convention: if computed_hash < sibling, hash(computed || sibling), else hash(sibling || computed)
    unsigned char current[32];
    memcpy(current, leaf_field->data.data(), 32);

    for (size_t i = 1; i < hashes.size() - 1; ++i) {
        const auto& sibling = hashes[i]->data;
        if (sibling.size() != 32) return EvalResult::ERROR;

        unsigned char combined[64];
        if (memcmp(current, sibling.data(), 32) < 0) {
            memcpy(combined, current, 32);
            memcpy(combined + 32, sibling.data(), 32);
        } else {
            memcpy(combined, sibling.data(), 32);
            memcpy(combined + 32, current, 32);
        }
        CSHA256().Write(combined, 64).Finalize(current);
    }

    if (memcmp(current, root_field->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalOutputCheckBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // OUTPUT_CHECK: per-output value and script constraint
    // Conditions fields: NUMERIC(output_index) + NUMERIC(min_sats) + NUMERIC(max_sats) + HASH256(script_hash)
    // script_hash = all zeros means "skip script check"
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 3) return EvalResult::ERROR;

    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    if (!hash_field || hash_field->data.size() != 32) return EvalResult::ERROR;

    auto output_index_opt = ReadNumeric(*numerics[0]);
    auto min_sats_opt = ReadNumeric(*numerics[1]);
    auto max_sats_opt = ReadNumeric(*numerics[2]);

    if (!output_index_opt || !min_sats_opt || !max_sats_opt) return EvalResult::ERROR;
    int64_t output_index = *output_index_opt;
    int64_t min_sats = *min_sats_opt;
    int64_t max_sats = *max_sats_opt;
    if (output_index < 0 || min_sats < 0 || max_sats < 0) return EvalResult::ERROR;
    if (min_sats > max_sats) return EvalResult::ERROR;

    if (!ctx.tx) return EvalResult::ERROR;

    // Bounds check
    if (static_cast<size_t>(output_index) >= ctx.tx->output_count) {
        return EvalResult::UNSATISFIED;
    }

    const auto& vout = ctx.tx->outputs[static_cast<size_t>(output_index)];

    // Value check
    if (vout.value < min_sats || vout.value > max_sats) {
        return EvalResult::UNSATISFIED;
    }

    // Script check (skip if hash is all zeros)
    static const std::vector<uint8_t> zero_hash(32, 0x00);
    if (hash_field->data != zero_hash) {
        const auto spk = vout.script_pub_key.as_span();
        unsigned char computed[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(spk.data(), spk.size()).Finalize(computed);
        if (memcmp(computed, hash_field->data.data(), 32) != 0) {
            return EvalResult::UNSATISFIED;
        }
    }

    return EvalResult::SATISFIED;
}

void register_governance_blocks()
{
    RegisterBlock(RungBlockType::EPOCH_GATE, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalEpochGateBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::WEIGHT_LIMIT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalWeightLimitBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::INPUT_COUNT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalInputCountBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::OUTPUT_COUNT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalOutputCountBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RELATIVE_VALUE, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRelativeValueBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::ACCUMULATOR, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalAccumulatorBlock(b);
    });
    RegisterBlock(RungBlockType::OUTPUT_CHECK, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalOutputCheckBlock(b, d.ctx);
    });
}

} // namespace rung
