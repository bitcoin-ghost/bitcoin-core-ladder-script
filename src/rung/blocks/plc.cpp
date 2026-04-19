// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: plc.
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

EvalResult EvalHysteresisFeeBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Fee hysteresis: check the spending transaction's fee rate against band.
    // 2 NUMERICs: high_sat_vb, low_sat_vb.
    // SATISFIED if low <= fee_rate <= high.
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }
    auto high_opt = ReadNumeric(*numerics[0]);
    auto low_opt = ReadNumeric(*numerics[1]);
    if (!high_opt || !low_opt) {
        return EvalResult::ERROR;
    }
    int64_t high = *high_opt;
    int64_t low = *low_opt;
    if (high < 0 || low < 0 || low > high) {
        return EvalResult::UNSATISFIED;
    }
    // If no tx context, fail-safe to error
    if (!ctx.tx || !ctx.spent_outputs || !ctx.tx_core) {
        return EvalResult::ERROR;
    }
    // Compute fee = sum(input values) - sum(output values)
    int64_t total_in = 0;
    for (size_t i = 0; i < ctx.spent_output_count; ++i) {
        total_in += ctx.spent_outputs[i].value;
    }
    int64_t total_out = 0;
    for (size_t i = 0; i < ctx.tx->output_count; ++i) {
        total_out += ctx.tx->outputs[i].value;
    }
    int64_t fee = total_in - total_out;
    if (fee < 0) {
        return EvalResult::UNSATISFIED;
    }
    // fee_rate = fee / vsize (sat/vB)
    int64_t vsize = GetVirtualTransactionSize(*ctx.tx_core);
    if (vsize <= 0) {
        return EvalResult::ERROR;
    }
    int64_t fee_rate = fee / vsize;
    if (fee_rate >= low && fee_rate <= high) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalHysteresisValueBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Value hysteresis: check input_amount against high/low band
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }
    auto high_sats_opt = ReadNumeric(*numerics[0]);
    auto low_sats_opt = ReadNumeric(*numerics[1]);
    if (!high_sats_opt || !low_sats_opt) {
        return EvalResult::ERROR;
    }
    int64_t high_sats = *high_sats_opt;
    int64_t low_sats = *low_sats_opt;
    if (high_sats < 0 || low_sats < 0 || low_sats > high_sats) {
        return EvalResult::UNSATISFIED;
    }
    // UTXO value within band
    if (ctx.input_amount >= low_sats && ctx.input_amount <= high_sats) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalTimerContinuousBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Continuous timer: 2 NUMERICs (accumulated, target).
    // SATISFIED if accumulated >= target (timer elapsed).
    // RECURSE_MODIFIED increments accumulated each covenant spend.
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        // Single-field backward compat: treat as target, satisfied if > 0
        if (numerics.empty()) return EvalResult::ERROR;
        auto val = ReadNumeric(*numerics[0]);
        if (!val || *val <= 0) return EvalResult::UNSATISFIED;
        return EvalResult::SATISFIED;
    }
    auto accumulated_opt = ReadNumeric(*numerics[0]);
    auto target_opt = ReadNumeric(*numerics[1]);
    if (!accumulated_opt || !target_opt) return EvalResult::ERROR;
    int64_t accumulated = *accumulated_opt;
    int64_t target = *target_opt;
    if (accumulated < 0 || target < 0) return EvalResult::ERROR;
    if (accumulated >= target) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalTimerOffDelayBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Off-delay timer: NUMERIC (remaining).
    // SATISFIED if remaining > 0 (still in hold-off period).
    // UNSATISFIED when remaining == 0 (delay expired).
    // RECURSE_MODIFIED decrements remaining each covenant spend.
    const RungField* hold = FindField(block, RungDataType::NUMERIC);
    if (!hold) return EvalResult::ERROR;
    auto remaining_opt = ReadNumeric(*hold);
    if (!remaining_opt) return EvalResult::ERROR;
    int64_t remaining = *remaining_opt;
    if (remaining > 0) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalLatchSetBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Latch set — activates when state == 0 (unset).
    // Field layout: PUBKEY (setter key), NUMERIC (state: 0=unset, 1=set)
    // Pair with RECURSE_MODIFIED to enforce state 0→1 in the output.
    if (!HasRequiredPubkeys(block, 1)) return EvalResult::ERROR;
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.empty()) {
        // No state field — structural-only mode (backward compat)
        return EvalResult::SATISFIED;
    }
    auto state_opt = ReadNumeric(*numerics[0]);
    if (!state_opt) return EvalResult::ERROR;
    int64_t state = *state_opt;
    if (state == 0) return EvalResult::SATISFIED;   // unset → can set
    return EvalResult::UNSATISFIED;                  // already set → SET rung inactive
}

EvalResult EvalLatchResetBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Latch reset — activates when state >= 1 (set).
    // Field layout: PUBKEY (resetter key), NUMERIC (state), NUMERIC (delay blocks)
    // Pair with RECURSE_MODIFIED to enforce state 1→0 in the output.
    if (!HasRequiredPubkeys(block, 1)) return EvalResult::ERROR;
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR; // need state + delay
    auto state_opt = ReadNumeric(*numerics[0]);
    auto delay_opt = ReadNumeric(*numerics[1]);
    if (!state_opt || !delay_opt) return EvalResult::ERROR;
    int64_t state = *state_opt;
    int64_t delay = *delay_opt;
    if (delay < 0) return EvalResult::ERROR;
    if (state >= 1) return EvalResult::SATISFIED;    // set → can reset
    return EvalResult::UNSATISFIED;                   // already unset → RESET rung inactive
}

EvalResult EvalCounterDownBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Down counter: PUBKEY (event signer) + NUMERIC (count).
    // SATISFIED if count > 0 (can still decrement). RECURSE_MODIFIED decrements each spend.
    if (!HasRequiredPubkeys(block, 1)) return EvalResult::ERROR;
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.empty()) return EvalResult::ERROR;
    auto count_opt = ReadNumeric(*numerics[0]);
    if (!count_opt) return EvalResult::ERROR;
    int64_t count = *count_opt;
    if (count < 0) return EvalResult::ERROR;
    if (count > 0) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED; // countdown done
}

EvalResult EvalCounterPresetBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Preset counter: 2 NUMERICs (current, preset).
    // SATISFIED if current < preset (accumulating). UNSATISFIED when current >= preset (done).
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;
    auto current_opt = ReadNumeric(*numerics[0]);
    auto preset_opt = ReadNumeric(*numerics[1]);
    if (!current_opt || !preset_opt) return EvalResult::ERROR;
    int64_t current = *current_opt;
    int64_t preset = *preset_opt;
    if (current < 0 || preset < 0) return EvalResult::ERROR;
    if (current < preset) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalCounterUpBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Up counter: PUBKEY (event signer) + 2 NUMERICs (current, target).
    // SATISFIED if current < target (still counting). UNSATISFIED when done.
    if (!HasRequiredPubkeys(block, 1)) return EvalResult::ERROR;
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;
    auto current_opt = ReadNumeric(*numerics[0]);
    auto target_opt = ReadNumeric(*numerics[1]);
    if (!current_opt || !target_opt) return EvalResult::ERROR;
    int64_t current = *current_opt;
    int64_t target = *target_opt;
    if (current < 0 || target < 0) return EvalResult::ERROR;
    if (current < target) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalCompareBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Comparator: compare input_amount against thresholds using specified operator
    // First NUMERIC is the operator, second is value_b, optional third is value_c
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);

    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }

    auto op_opt = ReadNumeric(*numerics[0]);
    auto value_b_opt = ReadNumeric(*numerics[1]);
    if (!op_opt || !value_b_opt) return EvalResult::ERROR;
    uint8_t op = static_cast<uint8_t>(*op_opt);
    int64_t value_b = *value_b_opt;
    if (value_b < 0) return EvalResult::ERROR;

    CAmount amount = ctx.input_amount;

    // Operators: EQ=0x01, NEQ=0x02, GT=0x03, LT=0x04, GTE=0x05, LTE=0x06, IN_RANGE=0x07
    switch (op) {
    case 0x01: return (amount == value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x02: return (amount != value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x03: return (amount > value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x04: return (amount < value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x05: return (amount >= value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x06: return (amount <= value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x07: {
        // IN_RANGE: needs value_c as upper bound
        if (numerics.size() < 3) return EvalResult::ERROR;
        auto value_c_opt = ReadNumeric(*numerics[2]);
        if (!value_c_opt) return EvalResult::ERROR;
        int64_t value_c = *value_c_opt;
        if (value_c < 0) return EvalResult::ERROR;
        return (amount >= value_b && amount <= value_c) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    }
    default:
        return EvalResult::ERROR;
    }
}

EvalResult EvalSequencerBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Step sequencer — needs UTXO chain state, validate structure
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR; // current_step + total_steps
    auto current_opt = ReadNumeric(*numerics[0]);
    auto total_opt = ReadNumeric(*numerics[1]);
    if (!current_opt || !total_opt) return EvalResult::ERROR;
    int64_t current = *current_opt;
    int64_t total = *total_opt;
    if (current < 0 || total <= 0 || current >= total) return EvalResult::UNSATISFIED;
    return EvalResult::SATISFIED;
}

EvalResult EvalOneShotBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // One-shot: NUMERIC (state) + HASH256 (commitment).
    // SATISFIED if state == 0 (can fire). UNSATISFIED if state != 0 (already fired).
    const RungField* state_field = FindField(block, RungDataType::NUMERIC);
    if (!state_field) return EvalResult::ERROR;
    if (!HasRequiredHashes(block, 1)) return EvalResult::ERROR;
    // Hash binding: HASH256 must equal SHA256(witness PREIMAGE)
    if (!VerifyHashPreimageBinding(block)) {
        return EvalResult::UNSATISFIED;
    }
    auto state_opt = ReadNumeric(*state_field);
    if (!state_opt) return EvalResult::ERROR;
    int64_t state = *state_opt;
    if (state == 0) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalRateLimitBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Rate limiter: enforces a per-transaction spending cap.
    // NOTE: accumulation_cap and refill_blocks are condition parameters reserved
    // for L2 protocols that track UTXO chain state. L1 consensus can only enforce
    // the single-transaction limit (max_per_block). A UTXO holder can drain
    // max_per_block per transaction, potentially multiple transactions per block.
    // For full rate-limiting, combine with RECURSE_SAME (covenant re-encumberance)
    // which ensures only one spend path per output.
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 3) return EvalResult::ERROR; // max_per_block, accumulation_cap, refill_blocks

    auto max_per_block_opt = ReadNumeric(*numerics[0]);
    if (!max_per_block_opt) return EvalResult::ERROR;
    int64_t max_per_block = *max_per_block_opt;
    if (max_per_block < 0) return EvalResult::ERROR;

    // Single-tx limit: output amount must not exceed max_per_block
    if (ctx.output_amount > max_per_block) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCosignBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // COSIGN requires a HASH256 field containing SHA256 of the anchor's conditions scriptPubKey.
    // At spend time, verifies that another input in the same transaction has a spent output
    // whose scriptPubKey matches this hash.
    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    if (!hash_field || hash_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Without transaction context or spent outputs, fail-safe to error
    if (!ctx.tx || !ctx.spent_outputs) {
        return EvalResult::ERROR;
    }

    // Check each other input's spent output scriptPubKey
    for (size_t i = 0; i < ctx.tx->input_count; ++i) {
        if (i == ctx.input_index) continue; // skip self

        if (i >= ctx.spent_output_count) continue;

        const auto other_spk = ctx.spent_outputs[i].script_pub_key.as_span();

        // SHA256 of the other input's spent scriptPubKey
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(other_spk.data(), other_spk.size()).Finalize(hash);

        if (memcmp(hash, hash_field->data.data(), 32) == 0) {
            return EvalResult::SATISFIED;
        }
    }

    return EvalResult::UNSATISFIED;
}

void register_plc_blocks()
{
    RegisterBlock(RungBlockType::HYSTERESIS_FEE, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalHysteresisFeeBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::HYSTERESIS_VALUE, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalHysteresisValueBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::TIMER_CONTINUOUS, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalTimerContinuousBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::TIMER_OFF_DELAY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalTimerOffDelayBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::LATCH_SET, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalLatchSetBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::LATCH_RESET, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalLatchResetBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::COUNTER_DOWN, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCounterDownBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::COUNTER_PRESET, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCounterPresetBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::COUNTER_UP, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCounterUpBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::COMPARE, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCompareBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::SEQUENCER, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalSequencerBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::ONE_SHOT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalOneShotBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RATE_LIMIT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRateLimitBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::COSIGN, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCosignBlock(b, d.ctx);
    });
}

} // namespace rung
