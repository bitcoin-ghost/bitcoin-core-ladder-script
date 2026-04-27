// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: compound.
// Evaluators + registry function. The top-level dispatcher calls each
// registered evaluator via `rung::LookupBlockEvaluator`.
//
// REVIEWER NOTE — Compound family (0x0701..0x0706)
//   Members: TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG,
//   TIMELOCKED_MULTISIG.
//   These are COMPOSITIONS of base blocks that share a dedicated implicit
//   layout for compactness. Example: HTLC = SIG + PREIMAGE reveal + CSV
//   (receiver path) fused into one block.
//   Optional for MVP: the entire family can be expressed as base-block
//   compositions at larger witness cost. Retained in the reference
//   implementation as a size optimisation for common L2 patterns.

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

EvalResult EvalTimelockedSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // TIMELOCKED_SIG = SIG + CSV in one block
    // merkle_pub_key: PUBKEY in witness, bound by Merkle proof.
    // Fields: PUBKEY (witness), SIGNATURE (witness), NUMERIC (timelock blocks)
    // Optional: SCHEME field for PQ routing

    // 1. Verify signature
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);

    if (!pubkey_field || !sig_field || !numeric_field) return EvalResult::ERROR;

    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    EvalResult sig_result = VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker, ctx);
    if (sig_result != EvalResult::SATISFIED) return sig_result;

    // 2. Check CSV timelock (same logic as EvalCSVBlock)
    auto seq_opt = ReadNumeric(*numeric_field);
    if (!seq_opt) return EvalResult::ERROR;
    int64_t sequence_val = *seq_opt;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    if (sequence_val < 0 || sequence_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
    if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalHTLCBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // HTLC = hash preimage + CSV + SIG in one block
    // merkle_pub_key: PUBKEY in witness, bound by Merkle proof.
    // Fields: HASH256 (conditions), PREIMAGE (witness), NUMERIC (timelock),
    //         PUBKEY (witness), SIGNATURE (witness)

    // 1. Verify hash preimage
    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!hash_field || !preimage_field) return EvalResult::ERROR;
    if (hash_field->data.size() != 32) return EvalResult::ERROR;

    unsigned char computed_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed_hash);
    if (memcmp(computed_hash, hash_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // 2. Verify CSV timelock
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) return EvalResult::ERROR;
    auto seq_opt = ReadNumeric(*numeric_field);
    if (!seq_opt) return EvalResult::ERROR;
    int64_t sequence_val = *seq_opt;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0) {
        if (sequence_val < 0 || sequence_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
        if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) return EvalResult::UNSATISFIED;
    }

    // 3. Verify signature
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_field || !sig_field) return EvalResult::ERROR;

    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker, ctx);
}

EvalResult EvalHashSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // HASH_SIG = hash preimage + SIG in one block
    // merkle_pub_key: PUBKEY in witness, bound by Merkle proof.
    // Fields: HASH256 (conditions), PREIMAGE (witness),
    //         PUBKEY (witness), SIGNATURE (witness)

    // 1. Verify hash preimage
    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!hash_field || !preimage_field) return EvalResult::ERROR;
    if (hash_field->data.size() != 32) return EvalResult::ERROR;

    unsigned char computed_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed_hash);
    if (memcmp(computed_hash, hash_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // 2. Verify signature
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_field || !sig_field) return EvalResult::ERROR;

    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker, ctx);
}

EvalResult EvalPTLCBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // PTLC = ADAPTOR_SIG + CSV in one block
    // merkle_pub_key: PUBKEYs in witness, bound by Merkle proof.
    // Fields: PUBKEY(signing_key), SIGNATURE(adapted), NUMERIC(CSV)
    // Adaptor secret applied off-chain.

    // 1. Verify adaptor signature (same logic as EvalAdaptorSigBlock)
    auto pubkeys = ResolvePubkeyCommitments(block);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);

    if (pubkeys.empty() || !sig_field || !numeric_field) {
        return EvalResult::ERROR;
    }

    const RungField* signing_key = pubkeys[0];

    if (sig_field->data.size() < 64 || sig_field->data.size() > 65) {
        return EvalResult::ERROR;
    }
    {
        RungField pk_field = *signing_key;
        EvalResult r = VerifySigWithScheme(pk_field, *sig_field, nullptr, sig_checker, ctx);
        if (r == EvalResult::ERROR) return EvalResult::ERROR;
        if (r != EvalResult::SATISFIED) return EvalResult::UNSATISFIED;
    }

    // 2. Check CSV timelock
    auto seq_opt = ReadNumeric(*numeric_field);
    if (!seq_opt) return EvalResult::ERROR;
    int64_t sequence_val = *seq_opt;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    if (sequence_val < 0 || sequence_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
    if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // CLTV_SIG = SIG + CLTV in one block
    // merkle_pub_key: PUBKEY in witness, bound by Merkle proof.
    // Fields: PUBKEY (witness), SIGNATURE (witness), NUMERIC (CLTV height)
    // Optional: SCHEME field for PQ routing

    // 1. Verify signature
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);

    if (!pubkey_field || !sig_field || !numeric_field) return EvalResult::ERROR;

    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    EvalResult sig_result = VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker, ctx);
    if (sig_result != EvalResult::SATISFIED) return sig_result;

    // 2. Check CLTV (absolute timelock)
    auto locktime_opt = ReadNumeric(*numeric_field);
    if (!locktime_opt) return EvalResult::ERROR;
    int64_t locktime_val = *locktime_opt;
    if (locktime_val < 0 || locktime_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
    if (!sig_checker.CheckLockTime(static_cast<uint32_t>(locktime_val))) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalTimelockedMultisigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // TIMELOCKED_MULTISIG v2 layout (after MergeConditionsAndWitness):
    //   conditions: [NUMERIC(K), NUMERIC(CSV), SCHEME, HASH256(pubkey_root)]  (4 fields)
    //   witness:    K × (PUBKEY, MERKLE_PROOF, SIGNATURE)                     (3K fields)
    constexpr size_t kCondCount = 4;
    if (block.fields.size() < kCondCount) return EvalResult::ERROR;
    if (block.fields[0].type != RungDataType::NUMERIC ||
        block.fields[1].type != RungDataType::NUMERIC ||
        block.fields[2].type != RungDataType::SCHEME ||
        block.fields[3].type != RungDataType::HASH256) {
        return EvalResult::ERROR;
    }
    auto threshold_opt = ReadNumeric(block.fields[0]);
    if (!threshold_opt || *threshold_opt <= 0) return EvalResult::ERROR;
    uint32_t threshold = static_cast<uint32_t>(*threshold_opt);

    EvalResult sig_r = VerifyMultisigInnerMerkle(block, threshold, block.fields[3].data,
                                                  &block.fields[2], kCondCount,
                                                  sig_checker, ctx);
    if (sig_r != EvalResult::SATISFIED) return sig_r;

    // CSV timelock (second NUMERIC field)
    auto seq_opt = ReadNumeric(block.fields[1]);
    if (!seq_opt) return EvalResult::ERROR;
    int64_t sequence_val = *seq_opt;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    if (sequence_val < 0 || sequence_val > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
    if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

void register_compound_blocks()
{
    RegisterBlock(RungBlockType::TIMELOCKED_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalTimelockedSigBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::HTLC, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalHTLCBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::HASH_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalHashSigBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::PTLC, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalPTLCBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::CLTV_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCLTVSigBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::TIMELOCKED_MULTISIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalTimelockedMultisigBlock(b, d.sig_checker, d.ctx);
    });
}

} // namespace rung
