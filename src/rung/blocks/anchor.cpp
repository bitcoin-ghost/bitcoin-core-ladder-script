// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: anchor.
// Evaluators + registry function. The top-level dispatcher calls each
// registered evaluator via `rung::LookupBlockEvaluator`.
//
// REVIEWER NOTE — Anchor family (0x0501..0x0507)
//   Members: ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE,
//   ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN.
//   DATA_RETURN is the MLSC equivalent of OP_RETURN — ERROR on every spend
//   attempt, making the output consensus-unspendable (see IsUnspendable
//   extension in src/script/script.h). Max 40 bytes of DATA payload; only
//   block type where a DATA field is valid (enforced in IsDataEmbeddingType).
//   Load-bearing: DATA_RETURN — without it, no first-class data anchor.
//   Optional for MVP: everything except DATA_RETURN. The ANCHOR_* variants
//   are L2-bridge primitives (channel anchors, pool/reserve commitments,
//   seal markers, oracle attestations) — useful but not consensus-required.

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

EvalResult EvalAnchorBlock(const RungBlock& block)
{
    // Generic anchor: validate at least one typed param is present
    if (block.fields.empty()) {
        return EvalResult::ERROR;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorChannelBlock(const RungBlock& block)
{
    // Verify local_key and remote_key are valid pubkeys, commitment_number > 0
    if (!HasRequiredPubkeys(block, 2)) {
        return EvalResult::ERROR;
    }
    const RungField* commitment = FindField(block, RungDataType::NUMERIC);
    if (commitment) {
        auto val = ReadNumeric(*commitment);
        if (!val || *val <= 0) return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorFeeBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                              const RungEvalContext& ctx)
{
    // ANCHOR_FEE: compound anti-pinning block for L2 channels.
    // Combines: 2-of-2 signature check + fee rate band + weight limit + commitment number.
    // Conditions: [SCHEME, NUMERIC(min_fee), NUMERIC(max_fee), NUMERIC(max_weight), NUMERIC(commitment)]
    // Witness: [PUBKEY, PUBKEY, SIGNATURE, SIGNATURE]

    // 1. Verify 2 valid pubkeys present (merkle_pub_key)
    if (!HasRequiredPubkeys(block, 2)) {
        return EvalResult::ERROR;
    }

    // 2. Read condition parameters
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 4) return EvalResult::ERROR;

    auto min_fee_rate_opt = ReadNumeric(*numerics[0]);
    auto max_fee_rate_opt = ReadNumeric(*numerics[1]);
    auto max_weight_opt = ReadNumeric(*numerics[2]);
    auto commitment_num_opt = ReadNumeric(*numerics[3]);

    if (!min_fee_rate_opt || !max_fee_rate_opt || !max_weight_opt || !commitment_num_opt) {
        return EvalResult::ERROR;
    }
    int64_t min_fee_rate = *min_fee_rate_opt;
    int64_t max_fee_rate = *max_fee_rate_opt;
    int64_t max_weight = *max_weight_opt;
    int64_t commitment_num = *commitment_num_opt;

    if (min_fee_rate < 0 || max_fee_rate < 0 || max_weight <= 0 || commitment_num < 0) {
        return EvalResult::ERROR;
    }
    if (min_fee_rate > max_fee_rate) {
        return EvalResult::UNSATISFIED;
    }

    // 3. Verify 2-of-2 signatures cryptographically
    auto pubkeys = FindAllFields(block, RungDataType::PUBKEY);
    auto sigs = FindAllFields(block, RungDataType::SIGNATURE);
    if (pubkeys.size() < 2 || sigs.size() < 2) {
        return EvalResult::UNSATISFIED;
    }

    std::vector<bool> pubkey_used(pubkeys.size(), false);
    uint32_t valid_count = 0;
    for (const auto* sig_field : sigs) {
        for (size_t k = 0; k < pubkeys.size(); ++k) {
            if (pubkey_used[k]) continue;
            RungField pk_field = *pubkeys[k];
            RungField sig_copy = *sig_field;
            EvalResult r = VerifySigWithScheme(pk_field, sig_copy, nullptr, sig_checker, ctx);
            if (r == EvalResult::SATISFIED) {
                pubkey_used[k] = true;
                valid_count++;
                break;
            }
            if (r == EvalResult::ERROR) return EvalResult::ERROR;
        }
    }
    if (valid_count < 2) {
        return EvalResult::UNSATISFIED;
    }

    // 4. Fee rate check (consensus-enforced anti-pinning)
    if (!ctx.tx || !ctx.spent_outputs || ctx.tx_weight <= 0) {
        return EvalResult::ERROR; // fail-closed: tx context + weight required
    }
    {
        int64_t total_in = 0;
        for (size_t i = 0; i < ctx.spent_output_count; ++i) {
            total_in += ctx.spent_outputs[i].value;
        }
        int64_t total_out = 0;
        for (size_t i = 0; i < ctx.tx->output_count; ++i) {
            total_out += ctx.tx->outputs[i].value;
        }
        int64_t fee = total_in - total_out;
        if (fee < 0) return EvalResult::UNSATISFIED;

        // vsize = (weight + 3) / 4  (BIP 141 WITNESS_SCALE_FACTOR=4).
        int64_t vsize = (ctx.tx_weight + 3) / 4;
        if (vsize <= 0) return EvalResult::ERROR;

        // Truncating integer division — fee_rate is rounded toward zero.
        // Consensus rule: the *floor* of the fee rate must lie in
        // [min_fee_rate, max_fee_rate]. A tx paying 100 sat over 3 vB
        // has fee_rate=33, not 33.33, so a min_fee_rate of 34 would
        // reject it. Sub-sat/vB precision is intentionally not enforced.
        int64_t fee_rate = fee / vsize;
        if (fee_rate < min_fee_rate || fee_rate > max_fee_rate) {
            return EvalResult::UNSATISFIED;
        }
    }

    // 5. Weight limit check
    if (ctx.tx_weight > max_weight) {
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorPoolBlock(const RungBlock& block)
{
    // Verify vtxo_tree_root present and hash-bound to witness preimage
    if (!HasRequiredHashes(block, 1)) {
        return EvalResult::ERROR;
    }
    // Hash binding: HASH256 must equal SHA256(witness PREIMAGE)
    if (!VerifyHashPreimageBinding(block)) {
        return EvalResult::UNSATISFIED;
    }
    const RungField* count = FindField(block, RungDataType::NUMERIC);
    if (count) {
        auto val = ReadNumeric(*count);
        if (!val || *val <= 0) return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorReserveBlock(const RungBlock& block)
{
    // Verify threshold_n <= threshold_m, guardian set hash present and hash-bound
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2 || !HasRequiredHashes(block, 1)) {
        return EvalResult::ERROR;
    }
    // Hash binding: HASH256 must equal SHA256(witness PREIMAGE)
    if (!VerifyHashPreimageBinding(block)) {
        return EvalResult::UNSATISFIED;
    }
    auto threshold_n_opt = ReadNumeric(*numerics[0]);
    auto threshold_m_opt = ReadNumeric(*numerics[1]);
    if (!threshold_n_opt || !threshold_m_opt) {
        return EvalResult::UNSATISFIED;
    }
    int64_t threshold_n = *threshold_n_opt;
    int64_t threshold_m = *threshold_m_opt;
    if (threshold_n < 0 || threshold_m < 0 || threshold_n > threshold_m) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorSealBlock(const RungBlock& block)
{
    // Verify asset_id and state_transition hashes present and hash-bound
    if (!HasRequiredHashes(block, 2)) {
        return EvalResult::ERROR;
    }
    // Hash binding: each HASH256 must equal SHA256(witness PREIMAGE)
    if (!VerifyHashPreimageBinding(block)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorOracleBlock(const RungBlock& block)
{
    // Verify oracle_key valid pubkey, outcome_count > 0
    if (!HasRequiredPubkeys(block, 1)) {
        return EvalResult::ERROR;
    }
    const RungField* count = FindField(block, RungDataType::NUMERIC);
    if (count) {
        auto val = ReadNumeric(*count);
        if (!val || *val <= 0) return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

void register_anchor_blocks()
{
    RegisterBlock(RungBlockType::ANCHOR, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalAnchorBlock(b);
    });
    RegisterBlock(RungBlockType::ANCHOR_CHANNEL, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalAnchorChannelBlock(b);
    });
    RegisterBlock(RungBlockType::ANCHOR_FEE, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalAnchorFeeBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::ANCHOR_POOL, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalAnchorPoolBlock(b);
    });
    RegisterBlock(RungBlockType::ANCHOR_RESERVE, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalAnchorReserveBlock(b);
    });
    RegisterBlock(RungBlockType::ANCHOR_SEAL, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalAnchorSealBlock(b);
    });
    RegisterBlock(RungBlockType::ANCHOR_ORACLE, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalAnchorOracleBlock(b);
    });
}

} // namespace rung
