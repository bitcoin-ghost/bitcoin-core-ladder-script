// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: covenant.
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
#include <crypto/common.h>
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

namespace api {

uint256 ComputeCTVHash(const LadderTxView& tx, uint32_t input_index)
{
    // BIP-119 template hash:
    // SHA256(version || locktime || scriptsigs_hash || num_inputs || sequences_hash ||
    //        num_outputs || outputs_hash || input_index)

    CSHA256 scriptsigs_hasher;
    for (size_t i = 0; i < tx.input_count; ++i) {
        const auto& in = tx.inputs[i];
        scriptsigs_hasher.Write(in.script_sig.data, in.script_sig.size);
    }
    unsigned char scriptsigs_hash[32];
    scriptsigs_hasher.Finalize(scriptsigs_hash);

    CSHA256 sequences_hasher;
    for (size_t i = 0; i < tx.input_count; ++i) {
        unsigned char seq_buf[4];
        WriteLE32(seq_buf, tx.inputs[i].sequence);
        sequences_hasher.Write(seq_buf, 4);
    }
    unsigned char sequences_hash[32];
    sequences_hasher.Finalize(sequences_hash);

    CSHA256 outputs_hasher;
    for (size_t i = 0; i < tx.output_count; ++i) {
        const auto& out = tx.outputs[i];
        unsigned char amt_buf[8];
        WriteLE64(amt_buf, static_cast<uint64_t>(out.value));
        outputs_hasher.Write(amt_buf, 8);
        unsigned char len_buf[8];
        WriteLE64(len_buf, out.script_pub_key.size);
        outputs_hasher.Write(len_buf, 8);
        outputs_hasher.Write(out.script_pub_key.data, out.script_pub_key.size);
    }
    unsigned char outputs_hash[32];
    outputs_hasher.Finalize(outputs_hash);

    CSHA256 hasher;
    unsigned char version_buf[4];
    WriteLE32(version_buf, static_cast<uint32_t>(tx.version));
    hasher.Write(version_buf, 4);

    unsigned char locktime_buf[4];
    WriteLE32(locktime_buf, tx.lock_time);
    hasher.Write(locktime_buf, 4);

    hasher.Write(scriptsigs_hash, 32);

    unsigned char nins_buf[4];
    WriteLE32(nins_buf, static_cast<uint32_t>(tx.input_count));
    hasher.Write(nins_buf, 4);

    hasher.Write(sequences_hash, 32);

    unsigned char nouts_buf[4];
    WriteLE32(nouts_buf, static_cast<uint32_t>(tx.output_count));
    hasher.Write(nouts_buf, 4);

    hasher.Write(outputs_hash, 32);

    unsigned char idx_buf[4];
    WriteLE32(idx_buf, input_index);
    hasher.Write(idx_buf, 4);

    unsigned char computed[32];
    hasher.Finalize(computed);

    uint256 result;
    memcpy(result.data(), computed, 32);
    return result;
}

}  // namespace api

EvalResult EvalCTVBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // CheckTemplateVerify: verify template hash matches spending transaction
    const RungField* template_hash = FindField(block, RungDataType::HASH256);
    if (!template_hash || template_hash->data.size() != 32) {
        return EvalResult::ERROR;
    }

    if (!ctx.tx) {
        return EvalResult::UNSATISFIED;
    }

    uint256 computed = rung::api::ComputeCTVHash(*ctx.tx, ctx.input_index);

    if (memcmp(computed.data(), template_hash->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalVaultLockBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // Two-path vault:
    // - recovery_key sig → SATISFIED immediately (cold sweep)
    // - hot_key sig → check CSV hot_delay elapsed
    // merkle_pub_key: PUBKEYs in witness, bound by Merkle proof.
    // Fields: PUBKEY(recovery), PUBKEY(hot), NUMERIC(delay), SIGNATURE
    // The first PUBKEY is recovery, second is hot. Only the signing key's
    // signature is provided. We try both keys.
    auto witness_pks = FindAllFields(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    const RungField* delay_field = FindField(block, RungDataType::NUMERIC);

    if (witness_pks.size() < 2 || !sig_field || !delay_field) {
        return EvalResult::ERROR;
    }

    if (sig_field->data.size() < 64 || sig_field->data.size() > 65) {
        return EvalResult::ERROR;
    }

    auto hot_delay_opt = ReadNumeric(*delay_field);
    if (!hot_delay_opt) {
        return EvalResult::ERROR;
    }
    int64_t hot_delay = *hot_delay_opt;

    // Try recovery key (first PUBKEY) then hot key (second PUBKEY)
    for (size_t ki = 0; ki < 2; ++ki) {
        RungField pk_field = *witness_pks[ki];
        EvalResult r = VerifySigWithScheme(pk_field, *sig_field, nullptr, sig_checker, ctx);
        if (r == EvalResult::SATISFIED) {
            if (ki == 0) {
                return EvalResult::SATISFIED; // recovery key — cold sweep, no delay
            }
            // Hot key — check CSV delay. Out-of-uint32 values reject (see
            // `1a23fa32c8`: the int64 -> uint32 cast silently truncates).
            if (hot_delay < 0 || hot_delay > 0xFFFFFFFFLL) return EvalResult::UNSATISFIED;
            if (!sig_checker.CheckSequence(static_cast<uint32_t>(hot_delay))) {
                return EvalResult::UNSATISFIED; // delay not met
            }
            return EvalResult::SATISFIED;
        }
        if (r == EvalResult::ERROR) return EvalResult::ERROR;
    }

    return EvalResult::UNSATISFIED; // neither key verified
}

EvalResult EvalAmountLockBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Output amount range check: min_sats <= output_amount <= max_sats
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }

    auto min_opt = ReadNumeric(*numerics[0]);
    auto max_opt = ReadNumeric(*numerics[1]);
    if (!min_opt || !max_opt) {
        return EvalResult::ERROR;
    }
    int64_t min_sats = *min_opt;
    int64_t max_sats = *max_opt;

    CAmount output = ctx.output_amount;
    if (output >= min_sats && output <= max_sats) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

void register_covenant_blocks()
{
    RegisterBlock(RungBlockType::CTV, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCTVBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::VAULT_LOCK, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalVaultLockBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::AMOUNT_LOCK, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalAmountLockBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::DATA_RETURN, [](const RungBlock&, const BlockDispatchContext&) {
        // DATA_RETURN outputs are unspendable. If dispatch reaches here, the
        // output should never have been spent — fail the tx.
        return EvalResult::ERROR;
    });
}

} // namespace rung
