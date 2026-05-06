// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// libFuzzer harness for the per-block evaluator dispatch.
//
// Complements `rung_verify.cpp` (full pipeline through VerifyRungTx)
// and `rung_deserialize.cpp` (wire-format only). This target hits the
// `BlockEvaluator` registry directly: pick a random block type, build
// a random RungBlock with random typed fields, dispatch through the
// registered evaluator. Stub-only sig/sequence checkers so signature
// validation always returns false; the fuzzer's job is to catch
// crashes / UB inside per-block evaluators that the wire-format
// rejection in `rung_deserialize` would otherwise mask.
//
// Fuzz invariant: no crash, no UB. Any of {SATISFIED, UNSATISFIED,
// ERROR, UNKNOWN_BLOCK_TYPE} is acceptable.
//
// Coverage:
//   - All 65 block evaluators (registered via `ladder_init` on first
//     dispatch)
//   - Field-type combinations the deserialiser would normally
//     reject — the fuzzer can build "impossible" merged blocks the
//     wire format wouldn't allow but that downstream callers might
//     synthesise via internal merges
//   - The default arm of the registry (UNKNOWN_BLOCK_TYPE) for
//     unregistered enum values — exercises forward-compat path

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <rung/api.h>
#include <rung/block_dispatch.h>
#include <rung/evaluator.h>
#include <rung/types.h>
#include <script/interpreter.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace {

// Stub checker — fail-closed for all signature predicates so the
// fuzzer doesn't need to construct valid signatures. Implements both
// the legacy `BaseSignatureChecker` virtual surface (for legacy
// wrappers' inner-script eval path) and the adapter
// `rung::api::LadderSigChecker` surface used by the registry.
class StubChecker : public BaseSignatureChecker,
                     public rung::api::LadderSigChecker {
public:
    bool CheckSchnorrSignature(std::span<const unsigned char>,
                               std::span<const unsigned char>,
                               SigVersion,
                               ScriptExecutionData&,
                               ScriptError*) const override { return false; }
    bool CheckECDSASignature(const std::vector<unsigned char>&,
                             const std::vector<unsigned char>&,
                             const CScript&,
                             SigVersion) const override { return false; }
    bool CheckLockTime(const CScriptNum&) const override { return false; }
    bool CheckSequence(const CScriptNum&) const override { return false; }

    // Adapter surface (used by per-block evaluators)
    bool CheckECDSASignature(std::span<const uint8_t>,
                             std::span<const uint8_t>,
                             std::span<const uint8_t, 32>) const override { return false; }
    bool CheckSchnorrSignature(std::span<const uint8_t>,
                               std::span<const uint8_t>,
                               std::span<const uint8_t, 32>) const override { return false; }
    bool CheckLockTime(uint32_t) const override { return false; }
    bool CheckSequence(uint32_t) const override { return false; }
};

// Pick a random known data type. The deserialiser would never
// produce some of these in some block contexts — that's the point;
// we want to feed combinations the wire format would have rejected.
rung::RungDataType random_data_type(FuzzedDataProvider& fdp)
{
    static constexpr std::array<rung::RungDataType, 11> all_types = {
        rung::RungDataType::PUBKEY,
        rung::RungDataType::PUBKEY_COMMIT,
        rung::RungDataType::HASH256,
        rung::RungDataType::HASH160,
        rung::RungDataType::PREIMAGE,
        rung::RungDataType::SIGNATURE,
        rung::RungDataType::NUMERIC,
        rung::RungDataType::SCHEME,
        rung::RungDataType::SCRIPT_BODY,
        rung::RungDataType::DATA,
        rung::RungDataType::MERKLE_PROOF,
    };
    return all_types[fdp.ConsumeIntegralInRange<size_t>(0, all_types.size() - 1)];
}

// Pick a random known block type, plus occasionally an unknown type
// to exercise the UNKNOWN_BLOCK_TYPE forward-compat path.
rung::RungBlockType random_block_type(FuzzedDataProvider& fdp)
{
    // 1-in-32 chance of an unknown type code — covers the registry's
    // nullptr-evaluator branch and ApplyInversion's UNKNOWN→ERROR
    // conversion when inverted.
    if (fdp.ConsumeIntegralInRange<uint8_t>(0, 31) == 0) {
        return static_cast<rung::RungBlockType>(
            fdp.ConsumeIntegral<uint16_t>());
    }
    // Otherwise sweep across the 65 known block types. The enum is
    // sparse (gaps between families), so iterate the descriptor table
    // by index.
    static const std::array<rung::RungBlockType, 65> known = {
        // Sig
        rung::RungBlockType::SIG, rung::RungBlockType::MULTISIG,
        rung::RungBlockType::ADAPTOR_SIG, rung::RungBlockType::MUSIG_THRESHOLD,
        rung::RungBlockType::KEY_REF_SIG,
        // Timelock
        rung::RungBlockType::CSV, rung::RungBlockType::CSV_TIME,
        rung::RungBlockType::CLTV, rung::RungBlockType::CLTV_TIME,
        // Hash
        rung::RungBlockType::TAGGED_HASH, rung::RungBlockType::HASH_GUARDED,
        // Covenant
        rung::RungBlockType::CTV, rung::RungBlockType::VAULT_LOCK,
        rung::RungBlockType::AMOUNT_LOCK,
        // Recursion
        rung::RungBlockType::RECURSE_SAME, rung::RungBlockType::RECURSE_MODIFIED,
        rung::RungBlockType::RECURSE_UNTIL, rung::RungBlockType::RECURSE_COUNT,
        rung::RungBlockType::RECURSE_SPLIT, rung::RungBlockType::RECURSE_DECAY,
        // Anchor
        rung::RungBlockType::ANCHOR, rung::RungBlockType::ANCHOR_CHANNEL,
        rung::RungBlockType::ANCHOR_POOL, rung::RungBlockType::ANCHOR_RESERVE,
        rung::RungBlockType::ANCHOR_SEAL, rung::RungBlockType::ANCHOR_ORACLE,
        rung::RungBlockType::DATA_RETURN,
        // Compound
        rung::RungBlockType::TIMELOCKED_SIG, rung::RungBlockType::HTLC,
        rung::RungBlockType::HASH_SIG, rung::RungBlockType::PTLC,
        rung::RungBlockType::CLTV_SIG, rung::RungBlockType::TIMELOCKED_MULTISIG,
        rung::RungBlockType::ANCHOR_FEE,
        // Governance
        rung::RungBlockType::EPOCH_GATE, rung::RungBlockType::WEIGHT_LIMIT,
        rung::RungBlockType::INPUT_COUNT, rung::RungBlockType::OUTPUT_COUNT,
        rung::RungBlockType::RELATIVE_VALUE, rung::RungBlockType::ACCUMULATOR,
        rung::RungBlockType::OUTPUT_CHECK,
        // PLC
        rung::RungBlockType::HYSTERESIS_FEE, rung::RungBlockType::HYSTERESIS_VALUE,
        rung::RungBlockType::TIMER_CONTINUOUS, rung::RungBlockType::TIMER_OFF_DELAY,
        rung::RungBlockType::LATCH_SET, rung::RungBlockType::LATCH_RESET,
        rung::RungBlockType::COUNTER_DOWN, rung::RungBlockType::COUNTER_PRESET,
        rung::RungBlockType::COUNTER_UP, rung::RungBlockType::COMPARE,
        rung::RungBlockType::SEQUENCER, rung::RungBlockType::ONE_SHOT,
        rung::RungBlockType::RATE_LIMIT, rung::RungBlockType::COSIGN,
        // Legacy
        rung::RungBlockType::P2PK_LEGACY, rung::RungBlockType::P2PKH_LEGACY,
        rung::RungBlockType::P2SH_LEGACY, rung::RungBlockType::P2WPKH_LEGACY,
        rung::RungBlockType::P2WSH_LEGACY, rung::RungBlockType::P2TR_LEGACY,
        rung::RungBlockType::P2TR_SCRIPT_LEGACY,
        // QABI / PQ
        rung::RungBlockType::QABI_PRIME, rung::RungBlockType::QABI_SPEND,
        rung::RungBlockType::PQ_BATCH,
    };
    return known[fdp.ConsumeIntegralInRange<size_t>(0, known.size() - 1)];
}

}  // namespace

FUZZ_TARGET(rung_evaluator)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // Initialise the registry on first call. Hosts normally call this;
    // EvalBlock would too, but going via LookupBlockEvaluator skips
    // that safety net so we trigger it explicitly.
    rung::api::ladder_init();

    // Build a random block: random type + 0..16 fields each up to 256 B.
    rung::RungBlock block;
    block.type = random_block_type(fdp);
    block.inverted = fdp.ConsumeBool();
    const size_t n_fields = fdp.ConsumeIntegralInRange<size_t>(0, 16);
    for (size_t i = 0; i < n_fields; ++i) {
        rung::RungField field;
        field.type = random_data_type(fdp);
        const size_t flen = fdp.ConsumeIntegralInRange<size_t>(0, 256);
        field.data = fdp.ConsumeBytes<uint8_t>(flen);
        block.fields.push_back(std::move(field));
    }

    // Look up the evaluator. nullptr → unknown block type → fuzzer
    // skips this iteration (the dispatcher would return
    // UNKNOWN_BLOCK_TYPE; not a crash class).
    auto eval = rung::LookupBlockEvaluator(block.type);
    if (eval == nullptr) return;

    // Build a minimal context. Most pointers are nullptr — evaluators
    // that need them (CTV's ctx.tx, COSIGN's ctx.spent_outputs, etc)
    // will return ERROR cleanly. The harness's job is "no crash"
    // regardless of which path the evaluator takes.
    StubChecker checker;
    ScriptExecutionData execdata{};
    rung::RungEvalContext ctx;
    // Set a random block_height + amounts — exercises height/amount
    // comparisons in timelock/PLC/governance evaluators without
    // needing a real LadderTxView.
    ctx.block_height = fdp.ConsumeIntegral<int32_t>();
    ctx.input_amount = fdp.ConsumeIntegral<int64_t>();
    ctx.output_amount = fdp.ConsumeIntegral<int64_t>();
    ctx.tx_weight = fdp.ConsumeIntegral<int64_t>();

    rung::BlockDispatchContext dctx{
        checker, checker,
        SigVersion::LADDER, execdata, ctx, /*depth=*/0};

    // Fuzz invariant: no crash. Any EvalResult is acceptable.
    (void)eval(block, dctx);
}
