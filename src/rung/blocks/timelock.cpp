// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: timelock.
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

EvalResult EvalCSVBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    auto seq_opt = ReadNumeric(*numeric_field);
    if (!seq_opt) {
        return EvalResult::ERROR;
    }
    int64_t sequence_val = *seq_opt;

    // If the disable flag is set, sequence lock is satisfied unconditionally
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return EvalResult::SATISFIED;
    }

    if (sequence_val < 0 || sequence_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
    if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCSVTimeBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    auto seq_opt = ReadNumeric(*numeric_field);
    if (!seq_opt) {
        return EvalResult::ERROR;
    }
    int64_t sequence_val = *seq_opt;

    // CSV_TIME: enforce time-based relative locktime (BIP 68 type flag)
    sequence_val |= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;

    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return EvalResult::SATISFIED;
    }

    if (sequence_val < 0 || sequence_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
    if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    auto locktime_opt = ReadNumeric(*numeric_field);
    if (!locktime_opt) {
        return EvalResult::ERROR;
    }
    int64_t locktime_val = *locktime_opt;

    if (locktime_val < 0 || locktime_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
    if (!sig_checker.CheckLockTime(static_cast<uint32_t>(locktime_val))) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVTimeBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    auto locktime_opt = ReadNumeric(*numeric_field);
    if (!locktime_opt) {
        return EvalResult::ERROR;
    }
    int64_t locktime_val = *locktime_opt;

    if (locktime_val < 0 || locktime_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
    if (!sig_checker.CheckLockTime(static_cast<uint32_t>(locktime_val))) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

void register_timelock_blocks()
{
    RegisterBlock(RungBlockType::CSV, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCSVBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::CSV_TIME, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCSVTimeBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::CLTV, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCLTVBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::CLTV_TIME, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCLTVTimeBlock(b, d.sig_checker);
    });
}

} // namespace rung
