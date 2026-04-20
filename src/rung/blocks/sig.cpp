// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: sig.
// Evaluators + registry function. The top-level dispatcher calls each
// registered evaluator via `rung::LookupBlockEvaluator`.
//
// REVIEWER NOTE — Signature family (0x0001..0x0005)
//   Members: SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG.
//   All consensus-critical. Sig verification flows through the span-based
//   api::LadderSigChecker interface (not Core's BaseSignatureChecker),
//   so the library stays Core-free and the TAPROOT-only asserts in
//   Core's CheckSchnorrSignature do not fire.
//   Load-bearing: signature-size checks run before curve math (per BIP-340);
//   KEY_REF_SIG bounds-checks the relay index before dereferencing the cache.
//   Optional: ADAPTOR_SIG/MUSIG_THRESHOLD can be dropped for a minimum-viable
//   BIP, but SIG and MULTISIG are required.

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

EvalResult EvalSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // merkle_pub_key: PUBKEY_COMMIT no longer in conditions. The pubkey is
    // in the witness (PUBKEY field). Merkle proof verification guarantees
    // this pubkey matches what was committed at fund time.
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_field || !sig_field) {
        return EvalResult::ERROR;
    }

    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker, ctx);
}

EvalResult EvalMultisigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // Layout: NUMERIC(threshold M), N × PUBKEY (witness), M × SIGNATURE (witness).
    // Pubkeys are bound to the Merkle leaf — nothing leaks into conditions.
    const RungField* threshold_field = FindField(block, RungDataType::NUMERIC);
    if (!threshold_field || threshold_field->data.size() < 1) {
        return EvalResult::ERROR;
    }

    auto threshold_opt = ReadNumeric(*threshold_field);
    if (!threshold_opt || *threshold_opt <= 0) {
        return EvalResult::ERROR;
    }
    int64_t threshold_val = *threshold_opt;
    uint32_t threshold = static_cast<uint32_t>(threshold_val);

    auto pubkeys = FindAllFields(block, RungDataType::PUBKEY);
    auto sigs = FindAllFields(block, RungDataType::SIGNATURE);

    if (pubkeys.empty() || threshold > pubkeys.size()) {
        return EvalResult::ERROR;
    }
    if (sigs.size() < threshold) {
        return EvalResult::UNSATISFIED;
    }

    // Check for explicit SCHEME field — routes to PQ verifier if present
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            // PQ multisig: compute sighash once, verify each sig against pubkeys.
            uint8_t sighash[32];
            if (!FetchLadderSighash(ctx, SIGHASH_DEFAULT, sighash)) {
                return EvalResult::ERROR;
            }
            (void)sig_checker;  // PQ path bypasses the Core sig checker.

            std::span<const uint8_t> msg{sighash, 32};
            std::vector<bool> pubkey_used(pubkeys.size(), false);
            uint32_t valid_count = 0;

            for (const auto* sig_f : sigs) {
                std::span<const uint8_t> sig_span{sig_f->data.data(), sig_f->data.size()};
                for (size_t k = 0; k < pubkeys.size(); ++k) {
                    if (pubkey_used[k]) continue;
                    std::span<const uint8_t> pk_span{pubkeys[k]->data.data(), pubkeys[k]->data.size()};
                    if (VerifyPQSignature(scheme, sig_span, msg, pk_span)) {
                        pubkey_used[k] = true;
                        valid_count++;
                        break;
                    }
                }
            }
            return (valid_count >= threshold) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
        }
        // SCHNORR/ECDSA scheme values fall through to existing size-based routing
    }

    // Verify signatures: each signature must match a distinct pubkey.
    std::vector<bool> pubkey_used(pubkeys.size(), false);
    uint32_t valid_count = 0;

    for (const auto* sig_field : sigs) {
        for (size_t k = 0; k < pubkeys.size(); ++k) {
            if (pubkey_used[k]) continue;

            const auto* pk = pubkeys[k];
            RungField single_sig = *sig_field;
            RungField single_pk = *pk;
            EvalResult r = VerifySigWithScheme(single_pk, single_sig, nullptr, sig_checker, ctx);
            if (r == EvalResult::SATISFIED) {
                pubkey_used[k] = true;
                valid_count++;
                break;
            }
            if (r == EvalResult::ERROR) return EvalResult::ERROR;
        }
    }

    return (valid_count >= threshold) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
}

EvalResult EvalHashPreimageBlock(const RungBlock& block)
{
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) {
        return EvalResult::ERROR;
    }

    const RungField* hash256_field = FindField(block, RungDataType::HASH256);
    if (hash256_field) {
        unsigned char computed[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed);
        if (hash256_field->data.size() == 32 &&
            memcmp(computed, hash256_field->data.data(), 32) == 0) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalHash160PreimageBlock(const RungBlock& block)
{
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) {
        return EvalResult::ERROR;
    }

    const RungField* hash160_field = FindField(block, RungDataType::HASH160);
    if (hash160_field) {
        unsigned char computed[CHash160::OUTPUT_SIZE];
        CHash160().Write(preimage_field->data).Finalize(computed);
        if (hash160_field->data.size() == 20 &&
            memcmp(computed, hash160_field->data.data(), 20) == 0) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalMusigThresholdBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // MuSig2/FROST aggregate threshold signature verification.
    // merkle_pub_key: PUBKEY in witness, bound by Merkle proof.
    // Fields: PUBKEY(aggregate_key), SIGNATURE(aggregate_sig), NUMERIC(M), NUMERIC(N)
    // On-chain this looks identical to single-sig — one key, one signature.
    // The FROST/MuSig2 ceremony is entirely off-chain.
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_field || !sig_field) {
        return EvalResult::ERROR;
    }

    // Validate M and N policy fields (if present)
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() >= 2) {
        auto m_opt = ReadNumeric(*numerics[0]);
        auto n_opt = ReadNumeric(*numerics[1]);
        if (!m_opt || !n_opt) {
            return EvalResult::ERROR;
        }
        int64_t m = *m_opt;
        int64_t n = *n_opt;
        if (m <= 0 || n <= 0 || m > n) {
            return EvalResult::ERROR;
        }
    }

    // Schnorr-only: aggregate signatures are always Schnorr
    if (sig_field->data.size() < 64 || sig_field->data.size() > 65) {
        return EvalResult::ERROR;
    }

    RungField pk_field = *pubkey_field;
    return VerifySigWithScheme(pk_field, *sig_field, nullptr, sig_checker, ctx);
}

EvalResult EvalAdaptorSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker,
                        const RungEvalContext& ctx)
{
    // Adaptor signature verification:
    // merkle_pub_key: PUBKEYs in witness, bound by Merkle proof.
    // Fields: PUBKEY(signing_key), SIGNATURE(adapted)
    // The adaptor secret is applied off-chain to produce the full adapted signature.
    auto pubkeys = ResolvePubkeyCommitments(block);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (pubkeys.empty() || !sig_field) {
        return EvalResult::ERROR;
    }

    // The signing key is the resolved PUBKEY
    const RungField* signing_key = pubkeys[0];

    if (sig_field->data.size() < 64 || sig_field->data.size() > 65) {
        return EvalResult::ERROR;
    }

    // The adapted signature verifies against the signing key directly
    RungField pk_field = *signing_key;
    return VerifySigWithScheme(pk_field, *sig_field, nullptr, sig_checker, ctx);
}

EvalResult EvalKeyRefSigBlock(const RungBlock& block,
                               const api::LadderSigChecker& sig_checker,
                               const RungEvalContext& ctx)
{
    // Extract reference fields (NUMERIC: relay_index, block_index)
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    // NUMERIC fields for relay/block index must fit uint16_t range.
    // Deserialized NUMERICs are always 4-byte LE — check VALUE, not size.
    auto ri_opt = ReadNumeric(*numerics[0]);
    auto bi_opt = ReadNumeric(*numerics[1]);
    if (!ri_opt || !bi_opt || *ri_opt > 0xFFFF || *bi_opt > 0xFFFF) return EvalResult::ERROR;

    uint16_t relay_idx = static_cast<uint16_t>(*ri_opt);
    uint16_t block_idx = static_cast<uint16_t>(*bi_opt);

    // Validate relay context is available
    if (!ctx.relays || !ctx.rung_relay_refs) return EvalResult::ERROR;

    // Validate relay_index is in this rung's relay_refs (security: can only reference declared relays)
    bool relay_declared = false;
    for (uint16_t ref : *ctx.rung_relay_refs) {
        if (ref == relay_idx) { relay_declared = true; break; }
    }
    if (!relay_declared) return EvalResult::ERROR;

    // Resolve target relay and block
    if (relay_idx >= ctx.relays->size()) return EvalResult::ERROR;
    const Relay& target_relay = (*ctx.relays)[relay_idx];
    if (block_idx >= target_relay.blocks.size()) return EvalResult::ERROR;
    const RungBlock& target_block = target_relay.blocks[block_idx];

    // merkle_pub_key: resolve PUBKEY from target relay block (bound by Merkle proof)
    const RungField* pubkey_field = FindField(target_block, RungDataType::PUBKEY);
    if (!pubkey_field) return EvalResult::ERROR;

    // SCHEME from target block (optional — defaults to Schnorr)
    const RungField* target_scheme = FindField(target_block, RungDataType::SCHEME);

    // Extract witness SIGNATURE from this block
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    if (!sig_field) return EvalResult::ERROR;

    RungField pk_field = *pubkey_field;
    RungField sig_copy = *sig_field;
    return VerifySigWithScheme(pk_field, sig_copy, target_scheme, sig_checker, ctx);
}

void register_sig_blocks()
{
    RegisterBlock(RungBlockType::SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalSigBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::MULTISIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalMultisigBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::ADAPTOR_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalAdaptorSigBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::MUSIG_THRESHOLD, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalMusigThresholdBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::KEY_REF_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalKeyRefSigBlock(b, d.sig_checker, d.ctx);
    });
    // EvalHashPreimageBlock / EvalHash160PreimageBlock have no dedicated
    // RungBlockType — they are helpers invoked from inside other block
    // evaluators (e.g. HTLC preimage check), not dispatched directly.
}

} // namespace rung
