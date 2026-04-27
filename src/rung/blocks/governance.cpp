// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: governance.
// Evaluators + registry function. The top-level dispatcher calls each
// registered evaluator via `rung::LookupBlockEvaluator`.
//
// REVIEWER NOTE — Governance family (0x0801..0x0807)
//   Members: EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT,
//   RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK.
//   Pattern: tx-shape introspection. Checks tx weight, input/output count,
//   relative value across outputs, Merkle membership proofs (ACCUMULATOR),
//   per-output structural constraints (OUTPUT_CHECK).
//   Load-bearing: none individually consensus-critical unless used.
//   Optional for MVP: entire family is optional. Removing it drops
//   tx-introspection expressiveness but does not affect base spend patterns.
//   Historical note: RELATIVE_VALUE had an int64 overflow fix (a4782caa8e);
//   regression-tested in rung_tests.cpp.

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

    // ctx.block_height is unsigned at the consensus layer (always >= 0
    // for any block actually being validated). Defensive guard for the
    // test-harness path where block_height could be passed as -1
    // (no-context evaluation). C++ % with a negative left operand is
    // implementation-defined in C++03 and "truncates toward zero" since
    // C++11, which would yield a negative `position` and confuse the
    // comparison below. Fail closed.
    if (ctx.block_height < 0) return EvalResult::ERROR;

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
    // Reject numerator / denominator outside uint32. The cross-division
    // below uses (a % n) * d and (c % d) * n — both expressions are
    // bounded by n*d, which must fit in int64_t. n*d < 2^63 requires
    // each of n and d to be < 2^32 (since 2^32 * 2^32 = 2^64 > int64
    // max). Without this guard, an 8-byte NUMERIC NUMERIC paired with
    // amounts near MAX_MONEY would overflow the remainder products and
    // the comparison would silently take the wrong branch.
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
    // ACCUMULATOR v2: structured-leaf set-membership proof.
    // After MergeConditionsAndWitness:
    //   block.fields[0] = HASH256(set_root)        — conditions
    //   block.fields[1] = NUMERIC(element_id)      — witness
    //   block.fields[2] = MERKLE_PROOF(siblings)   — witness (depth × 32 B)
    //
    // The leaf hash is `H_tag("LadderAccumulatorLeaf/v1", element_id_LE)` —
    // NOT free attacker bytes. Sibling hashes are 32 B opaque each but bound
    // by depth ≤ MAX_ACCUMULATOR_PROOF_DEPTH and by must-reach-root.
    //
    // Closes audit #2 finding E-001 (legacy v1 shape allowed up to 9 × 32 =
    // 288 B of attacker-chosen bytes per spend × 8 blocks/rung = ~2 KB).
    if (block.fields.size() != 3) return EvalResult::ERROR;
    if (block.fields[0].type != RungDataType::HASH256 ||
        block.fields[1].type != RungDataType::NUMERIC ||
        block.fields[2].type != RungDataType::MERKLE_PROOF) {
        return EvalResult::ERROR;
    }
    if (block.fields[0].data.size() != 32) return EvalResult::ERROR;

    auto eid_opt = ReadNumeric(block.fields[1]);
    if (!eid_opt || *eid_opt < 0 ||
        static_cast<uint64_t>(*eid_opt) > MAX_ACCUMULATOR_ELEMENT_ID) {
        return EvalResult::ERROR;
    }
    uint32_t element_id = static_cast<uint32_t>(*eid_opt);

    uint256 root;
    std::memcpy(root.data(), block.fields[0].data.data(), 32);

    std::string err;
    if (!VerifyAccumulatorProof(element_id, block.fields[2].data, root, err)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
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
