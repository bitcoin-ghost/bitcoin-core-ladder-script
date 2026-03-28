// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/evaluator.h>
#include <rung/conditions.h>
#include <rung/pq_verify.h>
#include <rung/serialize.h>
#include <rung/sighash.h>

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
#include <map>

namespace rung {

/** Lazily initialized secp256k1 context for EC operations that require ecmult_gen
 *  (e.g., pubkey_create, pubkey_tweak_add). Thread-safe via function-local static. */
static const secp256k1_context* GetVerifyContext()
{
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
}

bool LadderSignatureChecker::CheckSchnorrSignature(std::span<const unsigned char> sig,
                                                    std::span<const unsigned char> pubkey_in,
                                                    SigVersion sigversion,
                                                    ScriptExecutionData& /*execdata*/,
                                                    ScriptError* serror) const
{
    if (sigversion != SigVersion::LADDER) {
        // Fall through to the wrapped checker for non-ladder sigversions
        ScriptExecutionData fallback_execdata;
        return m_checker.CheckSchnorrSignature(sig, pubkey_in, sigversion, fallback_execdata, serror);
    }

    // Schnorr signatures are 64 bytes (default hashtype) or 65 bytes (explicit hashtype)
    if (sig.size() != 64 && sig.size() != 65) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_SIZE;
        return false;
    }

    if (pubkey_in.size() != 32) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG;
        return false;
    }

    XOnlyPubKey pubkey{pubkey_in};

    uint8_t hashtype = SIGHASH_DEFAULT;
    // For 65-byte sig, last byte is hashtype (copy sig to strip it)
    std::vector<unsigned char> sig_data(sig.begin(), sig.end());
    if (sig_data.size() == 65) {
        hashtype = sig_data.back();
        sig_data.pop_back();
        if (hashtype == SIGHASH_DEFAULT) {
            if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
            return false;
        }
    }

    uint256 sighash;
    if (!SignatureHashLadder(m_txdata, m_tx, m_nIn, hashtype, m_conditions, sighash)) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
        return false;
    }

    // Batch mode: defer verification
    if (m_batch && m_batch->active) {
        m_batch->Add(sighash, pubkey, std::span<const unsigned char>{sig_data.data(), sig_data.size()});
        return true; // Deferred — will be verified in batch
    }

    std::span<const unsigned char> sig_span{sig_data.data(), sig_data.size()};
    if (!pubkey.VerifySchnorr(sighash, sig_span)) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG;
        return false;
    }
    return true;
}

bool BatchVerifier::Verify() const
{
    // Separate inline and aggregated entries
    bool has_aggregated = false;
    for (const auto& entry : entries) {
        if (entry.aggregated) { has_aggregated = true; break; }
    }

    // Verify inline (non-aggregated) entries individually
    for (const auto& entry : entries) {
        if (entry.aggregated) continue;
        std::span<const unsigned char> sig_span{entry.sig.data(), entry.sig.size()};
        if (!entry.pubkey.VerifySchnorr(entry.sighash, sig_span)) {
            return false;
        }
    }

    // Half-aggregation verification for aggregated entries
    // Equation: s_agg * G == sum(z_i * (R_i + e_i * P_i))
    // where z_i are deterministic weights and e_i are BIP-340 challenges
    if (has_aggregated) {
        if (aggregated_s.size() != 32) return false;

        // Collect aggregated entries
        std::vector<const Entry*> agg_entries;
        for (const auto& entry : entries) {
            if (entry.aggregated) agg_entries.push_back(&entry);
        }
        if (agg_entries.empty()) return true;

        // Compute deterministic weights: z_0 = 1, z_i = H(all_R || all_pk || i) for i > 0
        // Build the aggregation context: concatenation of all R values and pubkeys
        HashWriter agg_ctx{TaggedHash("LadderHalfAggCtx")};
        for (const auto* e : agg_entries) {
            agg_ctx.write(std::as_bytes(std::span<const unsigned char>{e->sig.data(), e->sig.size()}));   // R_i (32 bytes)
            agg_ctx.write(std::as_bytes(std::span<const unsigned char>{e->pubkey.data(), 32})); // pk_i
        }
        uint256 ctx_hash = agg_ctx.GetSHA256();

        // For each aggregated entry, reconstruct (R_i, s_i) where s_i = s_agg's contribution
        // and verify individually with weight applied.
        // Simple approach: verify s_agg * G == sum(z_i * R_i + z_i * e_i * P_i)
        // using secp256k1 multi-point operations.
        //
        // Since secp256k1 doesn't expose a direct multi-scalar-mult API, we use
        // the available pubkey combine/tweak_mul operations.
        //
        // TODO: Replace with dedicated secp256k1_schnorr_halfagg_verify when available.
        // For now, use a conservative approach: compute each z_i * s_i from the aggregated
        // s and verify the sum equation holds.

        // Conservative verification: decompose and verify individually.
        // This is correct but doesn't save verification time (saves only witness bytes).
        // A proper multi-scalar-mult implementation would be faster.

        // For N=1 aggregated entry: z_0 = 1, s_agg = s_0. Just verify normally.
        if (agg_entries.size() == 1) {
            std::vector<unsigned char> full_sig(64);
            std::memcpy(full_sig.data(), agg_entries[0]->sig.data(), 32);
            std::memcpy(full_sig.data() + 32, aggregated_s.data(), 32);
            if (!agg_entries[0]->pubkey.VerifySchnorr(
                    agg_entries[0]->sighash,
                    std::span<const unsigned char>{full_sig.data(), 64})) {
                return false;
            }
        } else {
            // Multi-entry half-aggregation verification using EC math.
            // Verify: s_agg * G == sum(z_i * R_i + z_i * e_i * P_i)
            // Uses secp256k1 pubkey_create, tweak_mul, and combine operations.

            // Step 1: Compute LHS = s_agg * G
            const secp256k1_context* vctx = GetVerifyContext();
            secp256k1_pubkey lhs;
            if (!secp256k1_ec_pubkey_create(vctx, &lhs, aggregated_s.data())) {
                LogPrintf("BatchVerifier: failed to compute s_agg * G\n");
                return false;
            }

            // Step 2: Compute RHS = sum(z_i * R_i + z_i * e_i * P_i)
            std::vector<secp256k1_pubkey> terms;
            terms.reserve(agg_entries.size() * 2);

            for (size_t i = 0; i < agg_entries.size(); ++i) {
                const auto* e = agg_entries[i];
                if (e->sig.size() != 32) return false;

                // Weight z_i: z_0 = 1, z_i = H(ctx || i) for i > 0
                unsigned char z_i[32];
                if (i == 0) {
                    std::memset(z_i, 0, 31);
                    z_i[31] = 1; // big-endian 1
                } else {
                    uint256 z_hash = (HashWriter{TaggedHash("LadderHalfAggWeight")} << ctx_hash << static_cast<uint32_t>(i)).GetSHA256();
                    std::memcpy(z_i, z_hash.data(), 32);
                }

                // Parse R_i as full pubkey (0x02 || x-coordinate for even Y, BIP-340 convention)
                unsigned char R_compressed[33];
                R_compressed[0] = 0x02;
                std::memcpy(R_compressed + 1, e->sig.data(), 32);
                secp256k1_pubkey R_full;
                if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &R_full, R_compressed, 33)) {
                    LogPrintf("BatchVerifier: failed to parse R_%zu\n", i);
                    return false;
                }

                // Parse P_i as full pubkey (0x02 || x-coordinate)
                unsigned char P_compressed[33];
                P_compressed[0] = 0x02;
                std::memcpy(P_compressed + 1, e->pubkey.data(), 32);
                secp256k1_pubkey P_full;
                if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &P_full, P_compressed, 33)) {
                    LogPrintf("BatchVerifier: failed to parse P_%zu\n", i);
                    return false;
                }

                // Compute BIP-340 challenge: e_i = H("BIP0340/challenge", R_x || P_x || m_i)
                unsigned char e_i[32];
                {
                    CSHA256 hasher;
                    // Pre-compute tagged hash prefix for "BIP0340/challenge"
                    unsigned char tag_hash[32];
                    CSHA256().Write(reinterpret_cast<const unsigned char*>("BIP0340/challenge"), 17).Finalize(tag_hash);
                    hasher.Write(tag_hash, 32);
                    hasher.Write(tag_hash, 32);
                    hasher.Write(e->sig.data(), 32);      // R_x
                    hasher.Write(e->pubkey.data(), 32);    // P_x
                    hasher.Write(e->sighash.data(), 32);   // m
                    hasher.Finalize(e_i);
                }

                // Compute z_i * e_i (scalar multiplication mod n)
                unsigned char z_e_i[32];
                std::memcpy(z_e_i, e_i, 32);
                if (!secp256k1_ec_seckey_tweak_mul(secp256k1_context_static, z_e_i, z_i)) {
                    LogPrintf("BatchVerifier: scalar mul failed for entry %zu\n", i);
                    return false;
                }

                // Compute z_i * R_i (point scalar multiplication)
                secp256k1_pubkey R_scaled = R_full;
                if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_context_static, &R_scaled, z_i)) {
                    LogPrintf("BatchVerifier: R scaling failed for entry %zu\n", i);
                    return false;
                }
                terms.push_back(R_scaled);

                // Compute z_i * e_i * P_i (point scalar multiplication)
                secp256k1_pubkey P_scaled = P_full;
                if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_context_static, &P_scaled, z_e_i)) {
                    LogPrintf("BatchVerifier: P scaling failed for entry %zu\n", i);
                    return false;
                }
                terms.push_back(P_scaled);
            }

            // Step 3: Sum all terms to get RHS
            std::vector<const secp256k1_pubkey*> term_ptrs;
            term_ptrs.reserve(terms.size());
            for (const auto& t : terms) term_ptrs.push_back(&t);

            secp256k1_pubkey rhs;
            if (!secp256k1_ec_pubkey_combine(secp256k1_context_static, &rhs, term_ptrs.data(), term_ptrs.size())) {
                LogPrintf("BatchVerifier: point combination failed\n");
                return false;
            }

            // Step 4: Compare LHS (s_agg * G) == RHS (sum of terms)
            unsigned char lhs_ser[33], rhs_ser[33];
            size_t lhs_len = 33, rhs_len = 33;
            secp256k1_ec_pubkey_serialize(secp256k1_context_static, lhs_ser, &lhs_len, &lhs, SECP256K1_EC_COMPRESSED);
            secp256k1_ec_pubkey_serialize(secp256k1_context_static, rhs_ser, &rhs_len, &rhs, SECP256K1_EC_COMPRESSED);
            if (lhs_len != rhs_len || std::memcmp(lhs_ser, rhs_ser, lhs_len) != 0) {
                LogPrintf("BatchVerifier: half-aggregation verification failed (LHS != RHS)\n");
                return false;
            }
        }
    }

    return true;
}

int BatchVerifier::FindFailure() const
{
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].aggregated) continue; // Aggregated entries fail as a group
        std::span<const unsigned char> sig_span{entries[i].sig.data(), entries[i].sig.size()};
        if (!entries[i].pubkey.VerifySchnorr(entries[i].sighash, sig_span)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool LadderSignatureChecker::ComputeSighash(uint8_t hash_type, uint256& hash_out) const
{
    return SignatureHashLadder(m_txdata, m_tx, m_nIn, hash_type, m_conditions, hash_out);
}

/** Helper: find the first field of a given type in a block. Returns nullptr if not found. */
static const RungField* FindField(const RungBlock& block, RungDataType type)
{
    for (const auto& field : block.fields) {
        if (field.type == type) return &field;
    }
    return nullptr;
}

/** Helper: collect all fields of a given type from a block. */
static std::vector<const RungField*> FindAllFields(const RungBlock& block, RungDataType type)
{
    std::vector<const RungField*> result;
    for (const auto& field : block.fields) {
        if (field.type == type) result.push_back(&field);
    }
    return result;
}

/** Helper: read a little-endian numeric value from a NUMERIC field (1-8 bytes). */
static int64_t ReadNumeric(const RungField& field)
{
    if (field.data.empty() || field.data.size() > 8) return -1;
    uint64_t val = 0;
    for (size_t i = 0; i < field.data.size(); ++i) {
        val |= static_cast<uint64_t>(field.data[i]) << (8 * i);
    }
    return static_cast<int64_t>(val);
}

/** Helper: check if a block has at least `count` PUBKEY fields.
 *  merkle_pub_key: pubkeys are in the witness, bound by Merkle proof. */
static bool HasRequiredPubkeys(const RungBlock& block, size_t count)
{
    auto pks = FindAllFields(block, RungDataType::PUBKEY);
    return pks.size() >= count;
}

/** Return PUBKEY fields from the block.
 *  merkle_pub_key: PUBKEY_COMMIT removed from conditions. Pubkeys are in the
 *  witness (PUBKEY fields), bound to the Merkle leaf at fund time. */
static std::vector<const RungField*> ResolvePubkeyCommitments(const RungBlock& block)
{
    return FindAllFields(block, RungDataType::PUBKEY);
}

EvalResult ApplyInversion(EvalResult raw, bool inverted)
{
    if (!inverted) return raw;
    switch (raw) {
    case EvalResult::SATISFIED:        return EvalResult::UNSATISFIED;
    case EvalResult::UNSATISFIED:      return EvalResult::SATISFIED;
    case EvalResult::ERROR:            return EvalResult::ERROR; // errors never flip
    case EvalResult::UNKNOWN_BLOCK_TYPE: return EvalResult::ERROR; // unknown types must not satisfy
    }
    return raw;
}

// ============================================================================
// PQ signature verification helper
// ============================================================================

/** Verify a post-quantum signature using the SCHEME field routing.
 *  Computes the ladder sighash via dynamic_cast to LadderSignatureChecker. */
static EvalResult EvalPQSig(RungScheme scheme,
                             const RungField& sig_field,
                             const RungField& pubkey_field,
                             const BaseSignatureChecker& checker)
{
    auto* ladder_checker = dynamic_cast<const LadderSignatureChecker*>(&checker);
    if (!ladder_checker) return EvalResult::ERROR;
    if (!HasPQSupport()) return EvalResult::ERROR;

    uint256 sighash;
    if (!ladder_checker->ComputeSighash(SIGHASH_DEFAULT, sighash)) {
        return EvalResult::ERROR;
    }

    std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
    std::span<const uint8_t> msg{sighash.begin(), 32};
    std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};

    if (VerifyPQSignature(scheme, sig, msg, pubkey)) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Signature evaluators
// ============================================================================

EvalResult EvalSigBlock(const RungBlock& block,
                        const BaseSignatureChecker& checker,
                        SigVersion sigversion,
                        ScriptExecutionData& execdata)
{
    // merkle_pub_key: PUBKEY_COMMIT no longer in conditions. The pubkey is
    // in the witness (PUBKEY field). Merkle proof verification guarantees
    // this pubkey matches what was committed at fund time.
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_field || !sig_field) {
        return EvalResult::ERROR;
    }

    // Check for explicit SCHEME field — routes to PQ verifier if present
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            return EvalPQSig(scheme, *sig_field, *pubkey_field, checker);
        }
        // Explicit SCHNORR/ECDSA routing when SCHEME is specified
        if (scheme == RungScheme::SCHNORR) {
            std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
            std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};
            std::vector<unsigned char> xonly;
            if (pubkey_field->data.size() == 33) {
                xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
                pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
            }
            if (checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
                return EvalResult::SATISFIED;
            }
            return EvalResult::UNSATISFIED;
        }
        if (scheme == RungScheme::ECDSA) {
            std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
            std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
            CScript empty_script;
            if (checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
                return EvalResult::SATISFIED;
            }
            return EvalResult::UNSATISFIED;
        }
        // Unknown classical scheme — fall through to size-based routing
    }

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

    // Schnorr sigs are 64 bytes (no sighash type byte) or 65 bytes (with sighash type).
    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        // For Schnorr, use x-only pubkey (32 bytes). If we have compressed key (33 bytes),
        // strip the prefix.
        std::vector<unsigned char> xonly;
        if (pubkey_field->data.size() == 33) {
            xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }

        if (checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    // ECDSA signatures (DER encoded, 71-72 bytes typically)
    if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
        CScript empty_script;
        if (checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalMultisigBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker,
                             SigVersion sigversion,
                             ScriptExecutionData& execdata)
{
    // merkle_pub_key: PUBKEY_COMMIT removed. Layout: NUMERIC (threshold M),
    //   N x PUBKEY (witness), M x SIGNATURE (witness).
    //   Pubkeys bound to leaf via Merkle proof.
    const RungField* threshold_field = FindField(block, RungDataType::NUMERIC);
    if (!threshold_field || threshold_field->data.size() < 1) {
        return EvalResult::ERROR;
    }

    int64_t threshold_val = ReadNumeric(*threshold_field);
    if (threshold_val <= 0) {
        return EvalResult::ERROR;
    }
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
            // PQ multisig: compute sighash once, verify each sig against pubkeys
            auto* ladder_checker = dynamic_cast<const LadderSignatureChecker*>(&checker);
            if (!ladder_checker) return EvalResult::ERROR;

            uint256 sighash;
            if (!ladder_checker->ComputeSighash(SIGHASH_DEFAULT, sighash)) {
                return EvalResult::ERROR;
            }

            std::span<const uint8_t> msg{sighash.begin(), 32};
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
            std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

            bool verified = false;
            if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
                // Schnorr
                std::vector<unsigned char> xonly;
                std::span<const unsigned char> pk_span{pk->data.data(), pk->data.size()};
                if (pk->data.size() == 33) {
                    xonly.assign(pk->data.begin() + 1, pk->data.end());
                    pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
                }
                verified = checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr);
            } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
                // ECDSA
                std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
                std::vector<unsigned char> pk_vec(pk->data.begin(), pk->data.end());
                CScript empty_script;
                verified = checker.CheckECDSASignature(sig_vec, pk_vec, empty_script, sigversion);
            }

            if (verified) {
                pubkey_used[k] = true;
                valid_count++;
                break;
            }
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

EvalResult EvalCSVBlock(const RungBlock& block,
                        const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nSequence(sequence_val);

    // If the disable flag is set, sequence lock is satisfied unconditionally
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return EvalResult::SATISFIED;
    }

    if (!checker.CheckSequence(nSequence)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCSVTimeBlock(const RungBlock& block,
                            const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) {
        return EvalResult::ERROR;
    }

    // CSV_TIME: enforce time-based relative locktime (BIP 68 type flag)
    sequence_val |= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;

    CScriptNum nSequence(sequence_val);

    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return EvalResult::SATISFIED;
    }

    if (!checker.CheckSequence(nSequence)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVBlock(const RungBlock& block,
                         const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t locktime_val = ReadNumeric(*numeric_field);
    if (locktime_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nLockTime(locktime_val);

    if (!checker.CheckLockTime(nLockTime)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVTimeBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t locktime_val = ReadNumeric(*numeric_field);
    if (locktime_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nLockTime(locktime_val);

    if (!checker.CheckLockTime(nLockTime)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalMusigThresholdBlock(const RungBlock& block,
                                    const BaseSignatureChecker& checker,
                                    SigVersion sigversion,
                                    ScriptExecutionData& execdata)
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
        int64_t m = ReadNumeric(*numerics[0]);
        int64_t n = ReadNumeric(*numerics[1]);
        if (m <= 0 || n <= 0 || m > n) {
            return EvalResult::ERROR;
        }
    }

    // Schnorr-only: aggregate signatures are always Schnorr
    if (sig_field->data.size() < 64 || sig_field->data.size() > 65) {
        return EvalResult::ERROR;
    }

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pk_span{pubkey_field->data.data(), pubkey_field->data.size()};

    // Convert compressed pubkey (33 bytes) to x-only (32 bytes)
    std::vector<unsigned char> xonly;
    if (pubkey_field->data.size() == 33) {
        xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
        pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
    }

    if (checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr)) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalAdaptorSigBlock(const RungBlock& block,
                                const BaseSignatureChecker& checker,
                                SigVersion sigversion,
                                ScriptExecutionData& execdata)
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

    // The adapted signature verifies against the signing key directly
    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        std::vector<unsigned char> xonly;
        std::span<const unsigned char> pk_span{signing_key->data.data(), signing_key->data.size()};
        if (signing_key->data.size() == 33) {
            xonly.assign(signing_key->data.begin() + 1, signing_key->data.end());
            pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }

        if (checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalTaggedHashBlock(const RungBlock& block)
{
    // BIP-340 tagged hash verification:
    // Requires two HASH256 fields: tag_hash and expected_hash
    // Plus a PREIMAGE field from witness
    auto hashes = FindAllFields(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);

    if (hashes.size() < 2 || !preimage_field) {
        return EvalResult::ERROR;
    }

    // First HASH256 is the tag hash, second is the expected result
    const RungField* tag_hash = hashes[0];
    const RungField* expected_hash = hashes[1];

    if (tag_hash->data.size() != 32 || expected_hash->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute TaggedHash(tag, preimage) = SHA256(SHA256(tag) || SHA256(tag) || preimage)
    // The tag_hash field IS SHA256(tag) already, so we compute:
    // SHA256(tag_hash || tag_hash || preimage)
    unsigned char computed[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(tag_hash->data.data(), 32)
        .Write(tag_hash->data.data(), 32)
        .Write(preimage_field->data.data(), preimage_field->data.size())
        .Finalize(computed);

    if (memcmp(computed, expected_hash->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalHashGuardedBlock(const RungBlock& block)
{
    // Raw SHA256 preimage verification (non-invertible).
    // Conditions: HASH256 (committed hash). Witness: PREIMAGE (raw preimage).
    // SATISFIED when SHA256(preimage) == committed_hash.
    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);

    if (!hash_field || !preimage_field) {
        return EvalResult::ERROR;
    }

    if (hash_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute SHA256(preimage) and compare to committed hash
    unsigned char computed[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(preimage_field->data.data(), preimage_field->data.size())
        .Finalize(computed);

    if (memcmp(computed, hash_field->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Covenant evaluators
// ============================================================================

uint256 ComputeCTVHash(const CTransaction& tx, uint32_t input_index)
{
    // BIP-119 template hash:
    // SHA256(version || locktime || scriptsigs_hash || num_inputs || sequences_hash ||
    //        num_outputs || outputs_hash || input_index)

    // scriptsigs hash (SHA256 of all scriptSigs concatenated)
    CSHA256 scriptsigs_hasher;
    for (const auto& vin : tx.vin) {
        scriptsigs_hasher.Write(reinterpret_cast<const unsigned char*>(vin.scriptSig.data()), vin.scriptSig.size());
    }
    unsigned char scriptsigs_hash[32];
    scriptsigs_hasher.Finalize(scriptsigs_hash);

    // sequences hash
    CSHA256 sequences_hasher;
    for (const auto& vin : tx.vin) {
        unsigned char seq_buf[4];
        seq_buf[0] = vin.nSequence & 0xFF;
        seq_buf[1] = (vin.nSequence >> 8) & 0xFF;
        seq_buf[2] = (vin.nSequence >> 16) & 0xFF;
        seq_buf[3] = (vin.nSequence >> 24) & 0xFF;
        sequences_hasher.Write(seq_buf, 4);
    }
    unsigned char sequences_hash[32];
    sequences_hasher.Finalize(sequences_hash);

    // outputs hash
    CSHA256 outputs_hasher;
    for (const auto& vout : tx.vout) {
        unsigned char amt_buf[8];
        uint64_t amt = static_cast<uint64_t>(vout.nValue);
        for (int i = 0; i < 8; ++i) amt_buf[i] = (amt >> (8 * i)) & 0xFF;
        outputs_hasher.Write(amt_buf, 8);
        uint64_t spk_len = vout.scriptPubKey.size();
        unsigned char len_buf[8];
        for (int i = 0; i < 8; ++i) len_buf[i] = (spk_len >> (8 * i)) & 0xFF;
        outputs_hasher.Write(len_buf, 8);
        outputs_hasher.Write(vout.scriptPubKey.data(), vout.scriptPubKey.size());
    }
    unsigned char outputs_hash[32];
    outputs_hasher.Finalize(outputs_hash);

    // Compute final template hash
    CSHA256 hasher;
    unsigned char version_buf[4];
    uint32_t version = static_cast<uint32_t>(tx.version);
    for (int i = 0; i < 4; ++i) version_buf[i] = (version >> (8 * i)) & 0xFF;
    hasher.Write(version_buf, 4);

    unsigned char locktime_buf[4];
    for (int i = 0; i < 4; ++i) locktime_buf[i] = (tx.nLockTime >> (8 * i)) & 0xFF;
    hasher.Write(locktime_buf, 4);

    hasher.Write(scriptsigs_hash, 32);

    unsigned char nins_buf[4];
    uint32_t nins = static_cast<uint32_t>(tx.vin.size());
    for (int i = 0; i < 4; ++i) nins_buf[i] = (nins >> (8 * i)) & 0xFF;
    hasher.Write(nins_buf, 4);

    hasher.Write(sequences_hash, 32);

    unsigned char nouts_buf[4];
    uint32_t nouts = static_cast<uint32_t>(tx.vout.size());
    for (int i = 0; i < 4; ++i) nouts_buf[i] = (nouts >> (8 * i)) & 0xFF;
    hasher.Write(nouts_buf, 4);

    hasher.Write(outputs_hash, 32);

    unsigned char idx_buf[4];
    for (int i = 0; i < 4; ++i) idx_buf[i] = (input_index >> (8 * i)) & 0xFF;
    hasher.Write(idx_buf, 4);

    unsigned char computed[32];
    hasher.Finalize(computed);

    uint256 result;
    memcpy(result.data(), computed, 32);
    return result;
}

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

    uint256 computed = ComputeCTVHash(*ctx.tx, ctx.input_index);

    if (memcmp(computed.data(), template_hash->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalVaultLockBlock(const RungBlock& block,
                               const BaseSignatureChecker& checker,
                               SigVersion sigversion,
                               ScriptExecutionData& execdata)
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

    int64_t hot_delay = ReadNumeric(*delay_field);
    if (hot_delay < 0) {
        return EvalResult::ERROR;
    }

    // Try recovery key (first PUBKEY) then hot key (second PUBKEY)
    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

    for (size_t ki = 0; ki < 2; ++ki) {
        const RungField* pk = witness_pks[ki];
        std::vector<unsigned char> xonly;
        std::span<const unsigned char> pk_span{pk->data.data(), pk->data.size()};
        if (pk->data.size() == 33) {
            xonly.assign(pk->data.begin() + 1, pk->data.end());
            pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }

        if (checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr)) {
            if (ki == 0) {
                return EvalResult::SATISFIED; // recovery key — cold sweep, no delay
            }
            // Hot key — check CSV delay
            CScriptNum nSequence(hot_delay);
            if (!checker.CheckSequence(nSequence)) {
                return EvalResult::UNSATISFIED; // delay not met
            }
            return EvalResult::SATISFIED;
        }
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

    int64_t min_sats = ReadNumeric(*numerics[0]);
    int64_t max_sats = ReadNumeric(*numerics[1]);
    if (min_sats < 0 || max_sats < 0) {
        return EvalResult::ERROR;
    }

    CAmount output = ctx.output_amount;
    if (output >= min_sats && output <= max_sats) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Anchor evaluators
// ============================================================================

static bool HasRequiredHashes(const RungBlock& block, size_t count)
{
    return FindAllFields(block, RungDataType::HASH256).size() >= count;
}

/** Verify that each HASH256 field in a block has a matching PREIMAGE field
 *  where SHA256(preimage) == hash. This binds hash content to revealed data,
 *  preventing arbitrary data embedding via unverified hash fields.
 *  Hashes and preimages are matched positionally (1st hash ↔ 1st preimage, etc.). */
static bool VerifyHashPreimageBinding(const RungBlock& block)
{
    auto hashes = FindAllFields(block, RungDataType::HASH256);
    auto preimages = FindAllFields(block, RungDataType::PREIMAGE);

    if (hashes.empty()) return true; // no hashes to verify
    if (preimages.size() < hashes.size()) return false; // not enough preimages

    for (size_t i = 0; i < hashes.size(); ++i) {
        if (hashes[i]->data.size() != 32) return false;
        unsigned char computed[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(preimages[i]->data.data(), preimages[i]->data.size()).Finalize(computed);
        if (memcmp(computed, hashes[i]->data.data(), 32) != 0) {
            return false; // preimage doesn't match hash
        }
    }
    return true;
}

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
        int64_t val = ReadNumeric(*commitment);
        if (val <= 0) return EvalResult::UNSATISFIED;
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
        int64_t val = ReadNumeric(*count);
        if (val <= 0) return EvalResult::UNSATISFIED;
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
    int64_t threshold_n = ReadNumeric(*numerics[0]);
    int64_t threshold_m = ReadNumeric(*numerics[1]);
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
        int64_t val = ReadNumeric(*count);
        if (val <= 0) return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

// ============================================================================
// Leaf-centric covenant helpers
// ============================================================================

/** Check if an output's MLSC root matches the verified input root (identity check).
 *  Used by RECURSE_SAME and RECURSE_UNTIL (before deadline). */
static bool OutputRootMatchesInput(const CTxOut& output, const MLSCVerifiedLeaves& verified_leaves)
{
    uint256 output_root;
    if (!GetMLSCRoot(output.scriptPubKey, output_root)) {
        return false;
    }
    return output_root == verified_leaves.root;
}

/** Compute expected MLSC root after replacing one leaf in the verified array.
 *  Used by RECURSE_COUNT/SPLIT/MODIFIED/DECAY for same-rung mutations. */
static uint256 ComputeExpectedRoot(const MLSCVerifiedLeaves& verified_leaves,
                                    size_t leaf_index, const uint256& new_leaf)
{
    std::vector<uint256> leaves_copy = verified_leaves.leaves;
    if (leaf_index >= leaves_copy.size()) return uint256{}; // should not happen
    leaves_copy[leaf_index] = new_leaf;
    return BuildMerkleTree(std::move(leaves_copy));
}

/** Helper: a single mutation target (rung, block, param, delta). */
struct MutationSpec {
    int64_t rung_idx;
    int64_t block_idx;
    int64_t param_idx;
    int64_t delta;
};

/** Helper: write a little-endian int64 into a 4-byte NUMERIC field. */
static void WriteNumericField(RungField& f, int64_t val)
{
    f.data.clear();
    for (int i = 0; i < 4; ++i) {
        f.data.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xFF));
    }
}

/** Leaf-centric mutation verification: apply mutations to a copy of the revealed rung,
 *  recompute the rung leaf, rebuild the tree, and compare against the output root.
 *  Cross-rung mutations use revealed_mutation_targets from the MLSC proof. */
static EvalResult VerifyMutatedLeaves(const RungEvalContext& ctx,
                                       const std::vector<MutationSpec>& mutations)
{
    if (!ctx.input_conditions || !ctx.spending_output) {
        return EvalResult::ERROR;
    }

    // Fallback path: when verified_leaves is not available (unit tests),
    // apply mutations to a full copy of conditions and compare roots.
    if (!ctx.verified_leaves) {
        RungConditions expected = *ctx.input_conditions;
        std::vector<std::vector<std::vector<uint8_t>>> pubkeys;
        if (ctx.rung_pubkeys) pubkeys = *ctx.rung_pubkeys;

        for (const auto& m : mutations) {
            if (m.rung_idx < 0 || static_cast<size_t>(m.rung_idx) >= expected.rungs.size()) {
                return EvalResult::UNSATISFIED;
            }
            auto& rung = expected.rungs[m.rung_idx];
            if (m.block_idx < 0 || static_cast<size_t>(m.block_idx) >= rung.blocks.size()) {
                return EvalResult::UNSATISFIED;
            }
            auto& blk = rung.blocks[m.block_idx];
            size_t cond_idx = 0;
            bool applied = false;
            for (auto& f : blk.fields) {
                if (!IsConditionDataType(f.type)) continue;
                if (static_cast<int64_t>(cond_idx) == m.param_idx) {
                    if (f.type != RungDataType::NUMERIC) return EvalResult::UNSATISFIED;
                    WriteNumericField(f, ReadNumeric(f) + m.delta);
                    applied = true;
                    break;
                }
                ++cond_idx;
            }
            if (!applied) return EvalResult::UNSATISFIED;
        }
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->scriptPubKey, output_root)) {
            return EvalResult::UNSATISFIED;
        }
        if (output_root != ComputeConditionsRoot(expected, pubkeys)) {
            return EvalResult::UNSATISFIED;
        }
        return EvalResult::SATISFIED;
    }

    const auto& vl = *ctx.verified_leaves;
    std::vector<uint256> leaves_copy = vl.leaves;

    // Group mutations by target rung
    for (const auto& m : mutations) {
        if (m.rung_idx < 0 || static_cast<size_t>(m.rung_idx) >= vl.total_rungs) {
            return EvalResult::UNSATISFIED;
        }

        // Determine which rung to mutate
        Rung mutated_rung;
        std::vector<std::vector<uint8_t>> rung_pks;

        if (static_cast<uint16_t>(m.rung_idx) == vl.rung_index) {
            // Same-rung mutation: use the revealed rung from input conditions
            // (input_conditions has exactly 1 rung for MLSC — the revealed one)
            if (ctx.input_conditions->rungs.empty()) return EvalResult::UNSATISFIED;
            mutated_rung = ctx.input_conditions->rungs[0];
            // Pubkeys for the revealed rung
            if (ctx.rung_pubkeys && !ctx.rung_pubkeys->empty()) {
                rung_pks = (*ctx.rung_pubkeys)[0];
            }
        } else {
            // Cross-rung mutation: find in revealed_mutation_targets
            if (!ctx.mlsc_proof) return EvalResult::UNSATISFIED;
            bool found = false;
            for (const auto& [mt_idx, mt_rung] : ctx.mlsc_proof->revealed_mutation_targets) {
                if (mt_idx == static_cast<uint16_t>(m.rung_idx)) {
                    mutated_rung = mt_rung;
                    found = true;
                    break;
                }
            }
            if (!found) return EvalResult::UNSATISFIED;
            // Cross-rung mutation targets don't carry witness pubkeys
        }

        // Apply the mutation
        if (m.block_idx < 0 || static_cast<size_t>(m.block_idx) >= mutated_rung.blocks.size()) {
            return EvalResult::UNSATISFIED;
        }
        auto& blk = mutated_rung.blocks[m.block_idx];

        // Find the param_idx-th condition field (NUMERIC)
        size_t cond_idx = 0;
        bool applied = false;
        for (auto& f : blk.fields) {
            if (!IsConditionDataType(f.type)) continue;
            if (static_cast<int64_t>(cond_idx) == m.param_idx) {
                if (f.type != RungDataType::NUMERIC) {
                    return EvalResult::UNSATISFIED;
                }
                int64_t val = ReadNumeric(f);
                WriteNumericField(f, val + m.delta);
                applied = true;
                break;
            }
            ++cond_idx;
        }
        if (!applied) return EvalResult::UNSATISFIED;

        // Recompute the leaf for this rung
        leaves_copy[m.rung_idx] = ComputeRungLeaf(mutated_rung, rung_pks);
    }

    // Build tree from mutated leaves and compare with output root
    uint256 expected_root = BuildMerkleTree(std::move(leaves_copy));
    uint256 output_root;
    if (!GetMLSCRoot(ctx.spending_output->scriptPubKey, output_root)) {
        return EvalResult::UNSATISFIED;
    }
    if (output_root != expected_root) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

// ============================================================================
// Recursion evaluators
// ============================================================================

EvalResult EvalRecurseSameBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Verify output carries identical rung conditions as input
    const RungField* max_depth = FindField(block, RungDataType::NUMERIC);
    if (!max_depth) {
        return EvalResult::ERROR;
    }
    int64_t depth = ReadNumeric(*max_depth);
    if (depth <= 0) {
        return EvalResult::UNSATISFIED;
    }

    // Leaf-centric: output root must equal input root (identity)
    if (ctx.verified_leaves && ctx.spending_output) {
        if (!OutputRootMatchesInput(*ctx.spending_output, *ctx.verified_leaves)) {
            return EvalResult::UNSATISFIED;
        }
    } else if (ctx.input_conditions && ctx.spending_output) {
        // Fallback: compare MLSC roots directly
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->scriptPubKey, output_root)) {
            return EvalResult::UNSATISFIED;
        }
        std::vector<std::vector<std::vector<uint8_t>>> pks;
        if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
        if (output_root != ComputeConditionsRoot(*ctx.input_conditions, pks)) {
            return EvalResult::UNSATISFIED;
        }
    }
    return EvalResult::SATISFIED;
}

/** Parse mutation specs from NUMERIC fields. Returns max_depth via out-param.
 *  Supports legacy (4 NUMERICs: rung 0, single mutation) and new format (6+ NUMERICs). */
static bool ParseMutationSpecs(const std::vector<const RungField*>& numerics,
                                int64_t& max_depth,
                                std::vector<MutationSpec>& mutations)
{
    if (numerics.size() < 4) return false;

    max_depth = ReadNumeric(*numerics[0]);

    if (numerics.size() == 4 || numerics.size() == 5) {
        // Legacy format: single mutation at rung 0
        mutations.push_back({0, ReadNumeric(*numerics[1]),
                             ReadNumeric(*numerics[2]), ReadNumeric(*numerics[3])});
        return true;
    }

    // New format: numerics[1] = num_mutations, then 4 fields per mutation
    int64_t num_mutations = ReadNumeric(*numerics[1]);
    if (num_mutations < 1 || num_mutations > 64 ||
        static_cast<size_t>(2 + 4 * num_mutations) > numerics.size()) {
        return false;
    }
    for (int64_t i = 0; i < num_mutations; ++i) {
        size_t base = 2 + 4 * i;
        mutations.push_back({ReadNumeric(*numerics[base]),
                             ReadNumeric(*numerics[base + 1]),
                             ReadNumeric(*numerics[base + 2]),
                             ReadNumeric(*numerics[base + 3])});
    }
    return true;
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
    int64_t until_height = ReadNumeric(*until_height_field);
    if (until_height < 0) {
        return EvalResult::ERROR;
    }
    // Use tx nLockTime as height proxy (like CLTV — consensus ensures tx can't
    // be included before nLockTime). If nLockTime >= until_height, covenant terminates.
    int64_t effective_height = ctx.block_height;
    if (ctx.tx && ctx.tx->nLockTime < LOCKTIME_THRESHOLD) {
        effective_height = std::max(effective_height, static_cast<int64_t>(ctx.tx->nLockTime));
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
        if (!GetMLSCRoot(ctx.spending_output->scriptPubKey, output_root)) {
            return EvalResult::UNSATISFIED;
        }
        std::vector<std::vector<std::vector<uint8_t>>> pks;
        if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
        if (output_root != ComputeConditionsRoot(*ctx.input_conditions, pks)) {
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
    int64_t count = ReadNumeric(*max_count);
    if (count < 0) {
        return EvalResult::ERROR;
    }
    if (count == 0) {
        return EvalResult::SATISFIED; // countdown reached zero — covenant terminates
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
                        WriteNumericField(f, ReadNumeric(f) - 1);
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
            uint256 new_leaf = ComputeRungLeaf(mutated, rung_pks);
            uint256 expected_root = ComputeExpectedRoot(*ctx.verified_leaves,
                                                         ctx.verified_leaves->rung_index, new_leaf);
            uint256 output_root;
            if (!GetMLSCRoot(ctx.spending_output->scriptPubKey, output_root)) {
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
            if (!GetMLSCRoot(ctx.spending_output->scriptPubKey, output_root)) {
                return EvalResult::UNSATISFIED;
            }
            if (output_root != ComputeConditionsRoot(expected, pks)) {
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
    int64_t max_splits = ReadNumeric(*numerics[0]);
    int64_t min_split_sats = ReadNumeric(*numerics[1]);
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
                        WriteNumericField(f, ReadNumeric(f) - 1);
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
            uint256 new_leaf = ComputeRungLeaf(mutated, rung_pks);
            expected_root = ComputeExpectedRoot(*ctx.verified_leaves,
                                                ctx.verified_leaves->rung_index, new_leaf);
        } else {
            // Fallback: build full conditions with decremented rung
            RungConditions expected = *ctx.input_conditions;
            expected.rungs[0] = mutated;
            std::vector<std::vector<std::vector<uint8_t>>> pks;
            if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
            expected_root = ComputeConditionsRoot(expected, pks);
        }

        CAmount total_output = 0;
        for (const auto& vout : ctx.tx->vout) {
            // DATA_RETURN outputs (nValue == 0) are exempt from covenant checks
            if (vout.nValue == 0) continue;
            if (vout.nValue < min_split_sats) {
                return EvalResult::UNSATISFIED;
            }
            total_output += vout.nValue;
            // Every spendable output must be MLSC with the expected root
            uint256 out_root;
            if (!GetMLSCRoot(vout.scriptPubKey, out_root)) {
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

// ============================================================================
// PLC evaluators
// ============================================================================

EvalResult EvalHysteresisFeeBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Fee hysteresis: check the spending transaction's fee rate against band.
    // 2 NUMERICs: high_sat_vb, low_sat_vb.
    // SATISFIED if low <= fee_rate <= high.
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }
    int64_t high = ReadNumeric(*numerics[0]);
    int64_t low = ReadNumeric(*numerics[1]);
    if (high < 0 || low < 0 || low > high) {
        return EvalResult::UNSATISFIED;
    }
    // If no tx context, fail-safe to error
    if (!ctx.tx || !ctx.spent_outputs) {
        return EvalResult::ERROR;
    }
    // Compute fee = sum(input values) - sum(output values)
    int64_t total_in = 0;
    for (const auto& spent : *ctx.spent_outputs) {
        total_in += spent.nValue;
    }
    int64_t total_out = 0;
    for (const auto& out : ctx.tx->vout) {
        total_out += out.nValue;
    }
    int64_t fee = total_in - total_out;
    if (fee < 0) {
        return EvalResult::UNSATISFIED;
    }
    // fee_rate = fee / vsize (sat/vB)
    int64_t vsize = GetVirtualTransactionSize(*ctx.tx);
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
    int64_t high_sats = ReadNumeric(*numerics[0]);
    int64_t low_sats = ReadNumeric(*numerics[1]);
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
        int64_t val = ReadNumeric(*numerics[0]);
        if (val <= 0) return EvalResult::UNSATISFIED;
        return EvalResult::SATISFIED;
    }
    int64_t accumulated = ReadNumeric(*numerics[0]);
    int64_t target = ReadNumeric(*numerics[1]);
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
    int64_t remaining = ReadNumeric(*hold);
    if (remaining < 0) return EvalResult::ERROR;
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
    int64_t state = ReadNumeric(*numerics[0]);
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
    int64_t state = ReadNumeric(*numerics[0]);
    int64_t delay = ReadNumeric(*numerics[1]);
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
    int64_t count = ReadNumeric(*numerics[0]);
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
    int64_t current = ReadNumeric(*numerics[0]);
    int64_t preset = ReadNumeric(*numerics[1]);
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
    int64_t current = ReadNumeric(*numerics[0]);
    int64_t target = ReadNumeric(*numerics[1]);
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

    uint8_t op = static_cast<uint8_t>(ReadNumeric(*numerics[0]));
    int64_t value_b = ReadNumeric(*numerics[1]);
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
        int64_t value_c = ReadNumeric(*numerics[2]);
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
    int64_t current = ReadNumeric(*numerics[0]);
    int64_t total = ReadNumeric(*numerics[1]);
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
    int64_t state = ReadNumeric(*state_field);
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

    int64_t max_per_block = ReadNumeric(*numerics[0]);
    if (max_per_block < 0) return EvalResult::ERROR;

    // Single-tx limit: output amount must not exceed max_per_block
    if (ctx.output_amount > max_per_block) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

// ============================================================================
// COSIGN — co-spend contact
// ============================================================================

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
    for (size_t i = 0; i < ctx.tx->vin.size(); ++i) {
        if (i == ctx.input_index) continue; // skip self

        if (i >= ctx.spent_outputs->size()) continue;

        const CScript& other_spk = (*ctx.spent_outputs)[i].scriptPubKey;

        // SHA256 of the other input's spent scriptPubKey
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(other_spk.data(), other_spk.size()).Finalize(hash);

        if (memcmp(hash, hash_field->data.data(), 32) == 0) {
            return EvalResult::SATISFIED;
        }
    }

    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Compound evaluators (multi-block patterns in single block)
// ============================================================================

EvalResult EvalTimelockedSigBlock(const RungBlock& block,
                                   const BaseSignatureChecker& checker,
                                   SigVersion sigversion,
                                   ScriptExecutionData& execdata)
{
    // TIMELOCKED_SIG = SIG + CSV in one block
    // merkle_pub_key: PUBKEY in witness, bound by Merkle proof.
    // Fields: PUBKEY (witness), SIGNATURE (witness), NUMERIC (timelock blocks)
    // Optional: SCHEME field for PQ routing

    // 1. Verify signature (same logic as EvalSigBlock)
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);

    if (!pubkey_field || !sig_field || !numeric_field) return EvalResult::ERROR;

    // Check for PQ scheme
    bool sig_verified = false;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            EvalResult sig_result = EvalPQSig(scheme, *sig_field, *pubkey_field, checker);
            if (sig_result != EvalResult::SATISFIED) return sig_result;
            sig_verified = true;
        }
    }

    if (!sig_verified) {
        std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
        std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

        if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
            std::vector<unsigned char> xonly;
            if (pubkey_field->data.size() == 33) {
                xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
                pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
            }
            if (!checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
                return EvalResult::UNSATISFIED;
            }
        } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
            std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
            std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
            CScript empty_script;
            if (!checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
                return EvalResult::UNSATISFIED;
            }
        } else {
            return EvalResult::ERROR;
        }
    }

    // 2. Check CSV timelock (same logic as EvalCSVBlock)
    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) return EvalResult::ERROR;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    CScriptNum nSequence(sequence_val);
    if (!checker.CheckSequence(nSequence)) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalHTLCBlock(const RungBlock& block,
                          const BaseSignatureChecker& checker,
                          SigVersion sigversion,
                          ScriptExecutionData& execdata)
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
    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) return EvalResult::ERROR;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0) {
        CScriptNum nSequence(sequence_val);
        if (!checker.CheckSequence(nSequence)) return EvalResult::UNSATISFIED;
    }

    // 3. Verify signature
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_field || !sig_field) return EvalResult::ERROR;

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        std::vector<unsigned char> xonly;
        if (pubkey_field->data.size() == 33) {
            xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }
        if (!checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::UNSATISFIED;
        }
    } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
        CScript empty_script;
        if (!checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::UNSATISFIED;
        }
    } else {
        return EvalResult::ERROR;
    }

    return EvalResult::SATISFIED;
}

EvalResult EvalHashSigBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker,
                             SigVersion sigversion,
                             ScriptExecutionData& execdata)
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

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        std::vector<unsigned char> xonly;
        if (pubkey_field->data.size() == 33) {
            xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }
        if (!checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::UNSATISFIED;
        }
    } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
        CScript empty_script;
        if (!checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::UNSATISFIED;
        }
    } else {
        return EvalResult::ERROR;
    }

    return EvalResult::SATISFIED;
}

EvalResult EvalPTLCBlock(const RungBlock& block,
                          const BaseSignatureChecker& checker,
                          SigVersion sigversion,
                          ScriptExecutionData& execdata)
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

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        std::vector<unsigned char> xonly;
        std::span<const unsigned char> pk_span{signing_key->data.data(), signing_key->data.size()};
        if (signing_key->data.size() == 33) {
            xonly.assign(signing_key->data.begin() + 1, signing_key->data.end());
            pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }

        if (!checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr)) {
            return EvalResult::UNSATISFIED;
        }
    } else {
        return EvalResult::ERROR;
    }

    // 2. Check CSV timelock
    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) return EvalResult::ERROR;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    CScriptNum nSequence(sequence_val);
    if (!checker.CheckSequence(nSequence)) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVSigBlock(const RungBlock& block,
                              const BaseSignatureChecker& checker,
                              SigVersion sigversion,
                              ScriptExecutionData& execdata)
{
    // CLTV_SIG = SIG + CLTV in one block
    // merkle_pub_key: PUBKEY in witness, bound by Merkle proof.
    // Fields: PUBKEY (witness), SIGNATURE (witness), NUMERIC (CLTV height)
    // Optional: SCHEME field for PQ routing

    // 1. Verify signature (same logic as EvalSigBlock / EvalTimelockedSigBlock)
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);

    if (!pubkey_field || !sig_field || !numeric_field) return EvalResult::ERROR;

    // Check for PQ scheme
    bool sig_verified = false;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            EvalResult sig_result = EvalPQSig(scheme, *sig_field, *pubkey_field, checker);
            if (sig_result != EvalResult::SATISFIED) return sig_result;
            sig_verified = true;
        }
    }

    if (!sig_verified) {
        std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
        std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

        if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
            std::vector<unsigned char> xonly;
            if (pubkey_field->data.size() == 33) {
                xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
                pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
            }
            if (!checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
                return EvalResult::UNSATISFIED;
            }
        } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
            std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
            std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
            CScript empty_script;
            if (!checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
                return EvalResult::UNSATISFIED;
            }
        } else {
            return EvalResult::ERROR;
        }
    }

    // 2. Check CLTV (absolute timelock)
    int64_t locktime_val = ReadNumeric(*numeric_field);
    if (locktime_val < 0) return EvalResult::ERROR;
    CScriptNum nLockTime(locktime_val);
    if (!checker.CheckLockTime(nLockTime)) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalTimelockedMultisigBlock(const RungBlock& block,
                                        const BaseSignatureChecker& checker,
                                        SigVersion sigversion,
                                        ScriptExecutionData& execdata)
{
    // TIMELOCKED_MULTISIG = MULTISIG + CSV in one block
    // merkle_pub_key: PUBKEYs in witness, bound by Merkle proof.
    // Fields: NUMERIC[0] (threshold M), N x PUBKEY (witness),
    //         M x SIGNATURE (witness), NUMERIC[1] (CSV timelock)

    // 1. Verify multisig (same logic as EvalMultisigBlock)
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    int64_t threshold_val = ReadNumeric(*numerics[0]);
    if (threshold_val <= 0) return EvalResult::ERROR;
    uint32_t threshold = static_cast<uint32_t>(threshold_val);

    auto pubkeys = ResolvePubkeyCommitments(block);
    auto sigs = FindAllFields(block, RungDataType::SIGNATURE);

    if (pubkeys.empty() || threshold > pubkeys.size()) return EvalResult::ERROR;
    if (sigs.size() < threshold) return EvalResult::UNSATISFIED;

    // Check for PQ scheme
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            auto* ladder_checker = dynamic_cast<const LadderSignatureChecker*>(&checker);
            if (!ladder_checker) return EvalResult::ERROR;

            uint256 sighash;
            if (!ladder_checker->ComputeSighash(SIGHASH_DEFAULT, sighash)) {
                return EvalResult::ERROR;
            }

            std::span<const uint8_t> msg{sighash.begin(), 32};
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
            if (valid_count < threshold) return EvalResult::UNSATISFIED;
            goto csv_check;
        }
    }

    {
        std::vector<bool> pubkey_used(pubkeys.size(), false);
        uint32_t valid_count = 0;

        for (const auto* sig_field : sigs) {
            for (size_t k = 0; k < pubkeys.size(); ++k) {
                if (pubkey_used[k]) continue;

                const auto* pk = pubkeys[k];
                std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

                bool verified = false;
                if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
                    std::vector<unsigned char> xonly;
                    std::span<const unsigned char> pk_span{pk->data.data(), pk->data.size()};
                    if (pk->data.size() == 33) {
                        xonly.assign(pk->data.begin() + 1, pk->data.end());
                        pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
                    }
                    verified = checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr);
                } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
                    std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
                    std::vector<unsigned char> pk_vec(pk->data.begin(), pk->data.end());
                    CScript empty_script;
                    verified = checker.CheckECDSASignature(sig_vec, pk_vec, empty_script, sigversion);
                }

                if (verified) {
                    pubkey_used[k] = true;
                    valid_count++;
                    break;
                }
            }
        }

        if (valid_count < threshold) return EvalResult::UNSATISFIED;
    }

csv_check:
    // 2. Check CSV timelock (second NUMERIC field)
    int64_t sequence_val = ReadNumeric(*numerics[1]);
    if (sequence_val < 0) return EvalResult::ERROR;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    CScriptNum nSequence(sequence_val);
    if (!checker.CheckSequence(nSequence)) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

// ============================================================================
// Governance evaluators (transaction-level constraints)
// ============================================================================

EvalResult EvalEpochGateBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // EPOCH_GATE: spending allowed only within periodic windows.
    // Fields: NUMERIC[0] = epoch_size (blocks per epoch),
    //         NUMERIC[1] = window_size (blocks within epoch where spending is allowed)
    // Gate opens at block_height % epoch_size < window_size
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    int64_t epoch_size = ReadNumeric(*numerics[0]);
    int64_t window_size = ReadNumeric(*numerics[1]);
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

    int64_t max_weight = ReadNumeric(*numeric_field);
    if (max_weight <= 0) return EvalResult::ERROR;

    if (!ctx.tx) return EvalResult::ERROR; // fail-safe: no tx context

    int64_t tx_weight = GetTransactionWeight(*ctx.tx);
    if (tx_weight <= max_weight) {
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

    int64_t min_inputs = ReadNumeric(*numerics[0]);
    int64_t max_inputs = ReadNumeric(*numerics[1]);
    if (min_inputs < 0 || max_inputs < 0 || min_inputs > max_inputs) {
        return EvalResult::ERROR;
    }

    if (!ctx.tx) return EvalResult::ERROR;

    int64_t count = static_cast<int64_t>(ctx.tx->vin.size());
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

    int64_t min_outputs = ReadNumeric(*numerics[0]);
    int64_t max_outputs = ReadNumeric(*numerics[1]);
    if (min_outputs < 0 || max_outputs < 0 || min_outputs > max_outputs) {
        return EvalResult::ERROR;
    }

    if (!ctx.tx) return EvalResult::ERROR;

    int64_t count = static_cast<int64_t>(ctx.tx->vout.size());
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

    int64_t numerator = ReadNumeric(*numerics[0]);
    int64_t denominator = ReadNumeric(*numerics[1]);
    if (numerator < 0 || denominator <= 0) return EvalResult::ERROR;

    // Use 64-bit multiplication to avoid overflow: compare output*denom >= input*num
    // Both amounts are in satoshis (max ~2.1e15), and num/denom are small (max 2^32),
    // so the products fit in int64_t (max ~9.2e18).
    int64_t lhs = ctx.output_amount * denominator;
    int64_t rhs = ctx.input_amount * numerator;

    // Overflow check: if either multiplication would overflow, use __int128
    bool lhs_overflow = (ctx.output_amount > 0 && lhs / denominator != ctx.output_amount);
    bool rhs_overflow = (ctx.input_amount > 0 && numerator != 0 && rhs / numerator != ctx.input_amount);
    if (lhs_overflow || rhs_overflow) {
        // Overflow — use extended precision
        __int128 lhs128 = static_cast<__int128>(ctx.output_amount) * denominator;
        __int128 rhs128 = static_cast<__int128>(ctx.input_amount) * numerator;
        if (lhs128 >= rhs128) return EvalResult::SATISFIED;
        return EvalResult::UNSATISFIED;
    }

    if (lhs >= rhs) return EvalResult::SATISFIED;
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

// ============================================================================
// OUTPUT_CHECK evaluator
// ============================================================================

EvalResult EvalOutputCheckBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // OUTPUT_CHECK: per-output value and script constraint
    // Conditions fields: NUMERIC(output_index) + NUMERIC(min_sats) + NUMERIC(max_sats) + HASH256(script_hash)
    // script_hash = all zeros means "skip script check"
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 3) return EvalResult::ERROR;

    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    if (!hash_field || hash_field->data.size() != 32) return EvalResult::ERROR;

    int64_t output_index = ReadNumeric(*numerics[0]);
    int64_t min_sats = ReadNumeric(*numerics[1]);
    int64_t max_sats = ReadNumeric(*numerics[2]);

    if (output_index < 0 || min_sats < 0 || max_sats < 0) return EvalResult::ERROR;
    if (min_sats > max_sats) return EvalResult::ERROR;

    if (!ctx.tx) return EvalResult::ERROR;

    // Bounds check
    if (static_cast<size_t>(output_index) >= ctx.tx->vout.size()) {
        return EvalResult::UNSATISFIED;
    }

    const auto& vout = ctx.tx->vout[static_cast<size_t>(output_index)];

    // Value check
    if (vout.nValue < min_sats || vout.nValue > max_sats) {
        return EvalResult::UNSATISFIED;
    }

    // Script check (skip if hash is all zeros)
    static const std::vector<uint8_t> zero_hash(32, 0x00);
    if (hash_field->data != zero_hash) {
        unsigned char computed[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(vout.scriptPubKey.data(), vout.scriptPubKey.size()).Finalize(computed);
        if (memcmp(computed, hash_field->data.data(), 32) != 0) {
            return EvalResult::UNSATISFIED;
        }
    }

    return EvalResult::SATISFIED;
}

// ============================================================================
// KEY_REF_SIG evaluator
// ============================================================================

/** Evaluate a KEY_REF_SIG block: verify a signature using PUBKEY + SCHEME
 *  resolved from a relay block.
 *
 *  Conditions fields: NUMERIC(relay_index) + NUMERIC(block_index)
 *  Witness fields:    SIGNATURE
 *
 *  The referenced relay must be in the rung's relay_refs. The target block
 *  must contain PUBKEY (bound by Merkle proof, and optionally SCHEME).
 *  The signature is checked against the relay's PUBKEY. */
EvalResult EvalKeyRefSigBlock(const RungBlock& block,
                               const BaseSignatureChecker& checker,
                               SigVersion sigversion,
                               ScriptExecutionData& execdata,
                               const RungEvalContext& ctx)
{
    // Extract reference fields (NUMERIC: relay_index, block_index)
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    uint16_t relay_idx = 0;
    uint16_t block_idx = 0;
    for (size_t i = 0; i < numerics[0]->data.size(); ++i) {
        relay_idx |= static_cast<uint16_t>(numerics[0]->data[i]) << (8 * i);
    }
    for (size_t i = 0; i < numerics[1]->data.size(); ++i) {
        block_idx |= static_cast<uint16_t>(numerics[1]->data[i]) << (8 * i);
    }

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

    // Extract SCHEME from target block (optional — defaults to Schnorr)
    RungScheme scheme = RungScheme::SCHNORR;
    const RungField* target_scheme = FindField(target_block, RungDataType::SCHEME);
    if (target_scheme && !target_scheme->data.empty()) {
        scheme = static_cast<RungScheme>(target_scheme->data[0]);
    }

    // Extract witness SIGNATURE from this block
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    if (!sig_field) return EvalResult::ERROR;

    // Verify signature using the resolved scheme
    if (IsPQScheme(scheme)) {
        return EvalPQSig(scheme, *sig_field, *pubkey_field, checker);
    }

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

    // Schnorr
    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        std::vector<unsigned char> xonly;
        if (pubkey_field->data.size() == 33) {
            xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }
        if (checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    // ECDSA
    if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
        CScript empty_script;
        if (checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

// ============================================================================
// Shared signature verification helper
// ============================================================================

/** Verify a signature using SCHEME routing + sig dispatch.
 *  Shared by SIG-like evaluators (P2PKH, P2WPKH, etc.).
 *  Assumes pubkey_field and sig_field are non-null. */
static EvalResult VerifySigFromFields(const RungField& pubkey_field,
                                       const RungField& sig_field,
                                       const RungField* scheme_field,
                                       const BaseSignatureChecker& checker,
                                       SigVersion sigversion,
                                       ScriptExecutionData& execdata)
{
    // Check for explicit SCHEME field — routes to PQ verifier if present
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            return EvalPQSig(scheme, sig_field, pubkey_field, checker);
        }
    }

    std::span<const unsigned char> sig_span{sig_field.data.data(), sig_field.data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field.data.data(), pubkey_field.data.size()};

    if (sig_field.data.size() >= 64 && sig_field.data.size() <= 65) {
        std::vector<unsigned char> xonly;
        if (pubkey_field.data.size() == 33) {
            xonly.assign(pubkey_field.data.begin() + 1, pubkey_field.data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }
        if (checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    if (sig_field.data.size() >= 8 && sig_field.data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field.data.begin(), sig_field.data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field.data.begin(), pubkey_field.data.end());
        CScript empty_script;
        if (checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

// ============================================================================
// Legacy evaluators (wrapped Bitcoin transaction types)
// ============================================================================

/** Maximum recursion depth for P2SH/P2WSH/P2TR_SCRIPT inner condition evaluation. */
static constexpr int MAX_LEGACY_INNER_DEPTH = 2;

/** Evaluate inner conditions from a PREIMAGE field (used by P2SH, P2WSH, P2TR_SCRIPT).
 *  Deserializes the PREIMAGE as LadderWitness conditions, then evaluates using remaining
 *  witness fields from the outer block. */
static EvalResult EvalInnerConditions(const std::vector<uint8_t>& preimage_data,
                                       const RungBlock& outer_block,
                                       const BaseSignatureChecker& checker,
                                       SigVersion sigversion,
                                       ScriptExecutionData& execdata,
                                       const RungEvalContext& ctx,
                                       int depth)
{
    if (depth > MAX_LEGACY_INNER_DEPTH) {
        return EvalResult::ERROR;
    }

    // Deserialize inner conditions from PREIMAGE bytes
    LadderWitness inner;
    std::string error;
    if (!DeserializeLadderWitness(preimage_data, inner, error, SerializationContext::CONDITIONS)) {
        return EvalResult::ERROR;
    }

    if (inner.rungs.empty()) {
        return EvalResult::ERROR;
    }

    // Collect witness fields from outer block (everything except HASH160/HASH256/PREIMAGE)
    // These become the witness fields for the inner conditions' blocks
    std::vector<const RungField*> witness_fields;
    for (const auto& field : outer_block.fields) {
        if (field.type == RungDataType::PUBKEY || field.type == RungDataType::SIGNATURE ||
            field.type == RungDataType::NUMERIC || field.type == RungDataType::SCHEME) {
            witness_fields.push_back(&field);
        }
    }

    // Evaluate inner rungs: OR logic (first satisfied rung wins)
    for (const auto& rung : inner.rungs) {
        bool all_satisfied = true;
        for (const auto& block : rung.blocks) {
            // Build a combined block with inner conditions + outer witness fields
            RungBlock combined;
            combined.type = block.type;
            combined.inverted = block.inverted;
            // Add inner condition fields
            for (const auto& f : block.fields) {
                combined.fields.push_back(f);
            }
            // Add outer witness fields
            for (const auto* wf : witness_fields) {
                combined.fields.push_back(*wf);
            }

            // Check for recursive legacy blocks
            if (block.type == RungBlockType::P2SH_LEGACY ||
                block.type == RungBlockType::P2WSH_LEGACY ||
                block.type == RungBlockType::P2TR_SCRIPT_LEGACY) {
                // These would need deeper recursion — check depth
                if (depth + 1 > MAX_LEGACY_INNER_DEPTH) {
                    all_satisfied = false;
                    break;
                }
            }

            EvalResult result = EvalBlock(combined, checker, sigversion, execdata, ctx, depth);
            if (result != EvalResult::SATISFIED) {
                all_satisfied = false;
                break;
            }
        }
        if (all_satisfied) return EvalResult::SATISFIED;
    }

    return EvalResult::UNSATISFIED;
}

EvalResult EvalP2PKLegacyBlock(const RungBlock& block,
                                const BaseSignatureChecker& checker,
                                SigVersion sigversion,
                                ScriptExecutionData& execdata)
{
    // P2PK_LEGACY: identical to SIG block — delegates directly
    return EvalSigBlock(block, checker, sigversion, execdata);
}

EvalResult EvalP2PKHLegacyBlock(const RungBlock& block,
                                 const BaseSignatureChecker& checker,
                                 SigVersion sigversion,
                                 ScriptExecutionData& execdata)
{
    // P2PKH_LEGACY: HASH160(pubkey) == committed hash, then verify sig
    const RungField* hash160_field = FindField(block, RungDataType::HASH160);
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!hash160_field || !pubkey_field || !sig_field) {
        return EvalResult::ERROR;
    }
    if (hash160_field->data.size() != 20) {
        return EvalResult::ERROR;
    }

    // Compute HASH160(pubkey) and compare
    unsigned char computed[CHash160::OUTPUT_SIZE];
    CHash160().Write(pubkey_field->data).Finalize(computed);
    if (memcmp(computed, hash160_field->data.data(), 20) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // Verify signature
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigFromFields(*pubkey_field, *sig_field, scheme_field, checker, sigversion, execdata);
}

EvalResult EvalP2WPKHLegacyBlock(const RungBlock& block,
                                  const BaseSignatureChecker& checker,
                                  SigVersion sigversion,
                                  ScriptExecutionData& execdata)
{
    // P2WPKH_LEGACY: identical evaluation to P2PKH
    return EvalP2PKHLegacyBlock(block, checker, sigversion, execdata);
}

EvalResult EvalP2TRLegacyBlock(const RungBlock& block,
                                const BaseSignatureChecker& checker,
                                SigVersion sigversion,
                                ScriptExecutionData& execdata)
{
    // P2TR_LEGACY key-path: identical to SIG block — delegates directly
    return EvalSigBlock(block, checker, sigversion, execdata);
}

EvalResult EvalP2SHLegacyBlock(const RungBlock& block,
                                const BaseSignatureChecker& checker,
                                SigVersion sigversion,
                                ScriptExecutionData& execdata,
                                const RungEvalContext& ctx,
                                int depth)
{
    // P2SH_LEGACY: HASH160(inner_conditions) == committed hash, then eval inner
    const RungField* hash160_field = FindField(block, RungDataType::HASH160);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) preimage_field = FindField(block, RungDataType::SCRIPT_BODY);

    if (!hash160_field || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (hash160_field->data.size() != 20) {
        return EvalResult::ERROR;
    }

    // Compute HASH160(preimage) and compare
    unsigned char computed[CHash160::OUTPUT_SIZE];
    CHash160().Write(preimage_field->data).Finalize(computed);
    if (memcmp(computed, hash160_field->data.data(), 20) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // Deserialize and evaluate inner conditions
    return EvalInnerConditions(preimage_field->data, block, checker, sigversion, execdata, ctx, depth + 1);
}

EvalResult EvalP2WSHLegacyBlock(const RungBlock& block,
                                 const BaseSignatureChecker& checker,
                                 SigVersion sigversion,
                                 ScriptExecutionData& execdata,
                                 const RungEvalContext& ctx,
                                 int depth)
{
    // P2WSH_LEGACY: SHA256(inner_conditions) == committed hash, then eval inner
    const RungField* hash256_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) preimage_field = FindField(block, RungDataType::SCRIPT_BODY);

    if (!hash256_field || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (hash256_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute SHA256(preimage) and compare
    unsigned char computed[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed);
    if (memcmp(computed, hash256_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // Deserialize and evaluate inner conditions
    return EvalInnerConditions(preimage_field->data, block, checker, sigversion, execdata, ctx, depth + 1);
}

EvalResult EvalP2TRScriptLegacyBlock(const RungBlock& block,
                                      const BaseSignatureChecker& checker,
                                      SigVersion sigversion,
                                      ScriptExecutionData& execdata,
                                      const RungEvalContext& ctx,
                                      int depth)
{
    // P2TR_SCRIPT_LEGACY: script-path spend
    // merkle_pub_key: internal key bound by Merkle proof (no longer in conditions).
    // Fields: HASH256 (Merkle root of script tree), PREIMAGE (revealed leaf)
    // Verification: hash the revealed leaf, check it matches the Merkle root,
    //               then deserialize and evaluate inner conditions.
    const RungField* hash256_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) preimage_field = FindField(block, RungDataType::SCRIPT_BODY);

    if (!hash256_field || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (hash256_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Verify revealed leaf hashes into Merkle root.
    // For a single-leaf tree, SHA256(leaf) == root.
    unsigned char leaf_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(leaf_hash);
    if (memcmp(leaf_hash, hash256_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // Deserialize and evaluate inner conditions
    return EvalInnerConditions(preimage_field->data, block, checker, sigversion, execdata, ctx, depth + 1);
}

// ============================================================================
// Block dispatch
// ============================================================================

EvalResult EvalBlock(const RungBlock& block,
                     const BaseSignatureChecker& checker,
                     SigVersion sigversion,
                     ScriptExecutionData& execdata,
                     const RungEvalContext& ctx,
                     int depth)
{
    // Defense in depth: reject inverted key-consuming blocks
    if (block.inverted && !IsInvertibleBlockType(block.type)) {
        return EvalResult::ERROR;
    }

    EvalResult raw;
    switch (block.type) {
    // Signature
    case RungBlockType::SIG:
        raw = EvalSigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::MULTISIG:
        raw = EvalMultisigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::ADAPTOR_SIG:
        raw = EvalAdaptorSigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::MUSIG_THRESHOLD:
        raw = EvalMusigThresholdBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::KEY_REF_SIG:
        raw = EvalKeyRefSigBlock(block, checker, sigversion, execdata, ctx);
        break;
    // Timelock
    case RungBlockType::CSV:
        raw = EvalCSVBlock(block, checker);
        break;
    case RungBlockType::CSV_TIME:
        raw = EvalCSVTimeBlock(block, checker);
        break;
    case RungBlockType::CLTV:
        raw = EvalCLTVBlock(block, checker);
        break;
    case RungBlockType::CLTV_TIME:
        raw = EvalCLTVTimeBlock(block, checker);
        break;
    // Hash
    case RungBlockType::TAGGED_HASH:
        raw = EvalTaggedHashBlock(block);
        break;
    case RungBlockType::HASH_GUARDED:
        raw = EvalHashGuardedBlock(block);
        break;
    // Covenant
    case RungBlockType::CTV:
        raw = EvalCTVBlock(block, ctx);
        break;
    case RungBlockType::VAULT_LOCK:
        raw = EvalVaultLockBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::AMOUNT_LOCK:
        raw = EvalAmountLockBlock(block, ctx);
        break;
    // Anchor
    case RungBlockType::ANCHOR:
        raw = EvalAnchorBlock(block);
        break;
    case RungBlockType::ANCHOR_CHANNEL:
        raw = EvalAnchorChannelBlock(block);
        break;
    case RungBlockType::ANCHOR_POOL:
        raw = EvalAnchorPoolBlock(block);
        break;
    case RungBlockType::ANCHOR_RESERVE:
        raw = EvalAnchorReserveBlock(block);
        break;
    case RungBlockType::ANCHOR_SEAL:
        raw = EvalAnchorSealBlock(block);
        break;
    case RungBlockType::ANCHOR_ORACLE:
        raw = EvalAnchorOracleBlock(block);
        break;
    // Recursion
    case RungBlockType::RECURSE_SAME:
        raw = EvalRecurseSameBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_MODIFIED:
        raw = EvalRecurseModifiedBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_UNTIL:
        raw = EvalRecurseUntilBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_COUNT:
        raw = EvalRecurseCountBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_SPLIT:
        raw = EvalRecurseSplitBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_DECAY:
        raw = EvalRecurseDecayBlock(block, ctx);
        break;
    // PLC
    case RungBlockType::HYSTERESIS_FEE:
        raw = EvalHysteresisFeeBlock(block, ctx);
        break;
    case RungBlockType::HYSTERESIS_VALUE:
        raw = EvalHysteresisValueBlock(block, ctx);
        break;
    case RungBlockType::TIMER_CONTINUOUS:
        raw = EvalTimerContinuousBlock(block, ctx);
        break;
    case RungBlockType::TIMER_OFF_DELAY:
        raw = EvalTimerOffDelayBlock(block, ctx);
        break;
    case RungBlockType::LATCH_SET:
        raw = EvalLatchSetBlock(block, ctx);
        break;
    case RungBlockType::LATCH_RESET:
        raw = EvalLatchResetBlock(block, ctx);
        break;
    case RungBlockType::COUNTER_DOWN:
        raw = EvalCounterDownBlock(block, ctx);
        break;
    case RungBlockType::COUNTER_PRESET:
        raw = EvalCounterPresetBlock(block, ctx);
        break;
    case RungBlockType::COUNTER_UP:
        raw = EvalCounterUpBlock(block, ctx);
        break;
    case RungBlockType::COMPARE:
        raw = EvalCompareBlock(block, ctx);
        break;
    case RungBlockType::SEQUENCER:
        raw = EvalSequencerBlock(block, ctx);
        break;
    case RungBlockType::ONE_SHOT:
        raw = EvalOneShotBlock(block, ctx);
        break;
    case RungBlockType::RATE_LIMIT:
        raw = EvalRateLimitBlock(block, ctx);
        break;
    case RungBlockType::COSIGN:
        raw = EvalCosignBlock(block, ctx);
        break;
    // Compound
    case RungBlockType::TIMELOCKED_SIG:
        raw = EvalTimelockedSigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::HTLC:
        raw = EvalHTLCBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::HASH_SIG:
        raw = EvalHashSigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::PTLC:
        raw = EvalPTLCBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::CLTV_SIG:
        raw = EvalCLTVSigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::TIMELOCKED_MULTISIG:
        raw = EvalTimelockedMultisigBlock(block, checker, sigversion, execdata);
        break;
    // Governance
    case RungBlockType::EPOCH_GATE:
        raw = EvalEpochGateBlock(block, ctx);
        break;
    case RungBlockType::WEIGHT_LIMIT:
        raw = EvalWeightLimitBlock(block, ctx);
        break;
    case RungBlockType::INPUT_COUNT:
        raw = EvalInputCountBlock(block, ctx);
        break;
    case RungBlockType::OUTPUT_COUNT:
        raw = EvalOutputCountBlock(block, ctx);
        break;
    case RungBlockType::RELATIVE_VALUE:
        raw = EvalRelativeValueBlock(block, ctx);
        break;
    case RungBlockType::ACCUMULATOR:
        raw = EvalAccumulatorBlock(block);
        break;
    case RungBlockType::OUTPUT_CHECK:
        raw = EvalOutputCheckBlock(block, ctx);
        break;
    // Legacy
    case RungBlockType::P2PK_LEGACY:
        raw = EvalP2PKLegacyBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::P2PKH_LEGACY:
        raw = EvalP2PKHLegacyBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::P2SH_LEGACY:
        raw = EvalP2SHLegacyBlock(block, checker, sigversion, execdata, ctx, depth);
        break;
    case RungBlockType::P2WPKH_LEGACY:
        raw = EvalP2WPKHLegacyBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::P2WSH_LEGACY:
        raw = EvalP2WSHLegacyBlock(block, checker, sigversion, execdata, ctx, depth);
        break;
    case RungBlockType::P2TR_LEGACY:
        raw = EvalP2TRLegacyBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::P2TR_SCRIPT_LEGACY:
        raw = EvalP2TRScriptLegacyBlock(block, checker, sigversion, execdata, ctx, depth);
        break;
    // Utility family
    case RungBlockType::DATA_RETURN:
        // DATA_RETURN is unspendable — if we reach evaluation, the output should
        // never have been spent. Return ERROR to make the transaction invalid.
        raw = EvalResult::ERROR;
        break;
    default:
        raw = EvalResult::UNKNOWN_BLOCK_TYPE;
        break;
    }
    return ApplyInversion(raw, block.inverted);
}

bool EvalRelays(const std::vector<Relay>& relays,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx,
                std::vector<EvalResult>& relay_results_out)
{
    relay_results_out.resize(relays.size(), EvalResult::UNSATISFIED);

    for (size_t i = 0; i < relays.size(); ++i) {
        const auto& relay = relays[i];

        // Check relay_refs: all required relays must be SATISFIED
        bool requires_met = true;
        for (uint16_t req : relay.relay_refs) {
            if (req >= i || relay_results_out[req] != EvalResult::SATISFIED) {
                requires_met = false;
                break;
            }
        }

        if (!requires_met) {
            relay_results_out[i] = EvalResult::UNSATISFIED;
            continue;
        }

        // Evaluate relay blocks (AND logic, same as a rung)
        if (relay.blocks.empty()) {
            relay_results_out[i] = EvalResult::ERROR;
            return false;
        }

        // Set relay context so KEY_REF_SIG blocks in relays can resolve references
        RungEvalContext relay_ctx = ctx;
        relay_ctx.relays = &relays;
        relay_ctx.rung_relay_refs = relay.relay_refs.empty() ? nullptr : &relay.relay_refs;

        EvalResult relay_result = EvalResult::SATISFIED;
        for (const auto& block : relay.blocks) {
            EvalResult result = EvalBlock(block, checker, sigversion, execdata, relay_ctx);
            if (result != EvalResult::SATISFIED) {
                relay_result = result;
                break;
            }
        }

        if (relay_result == EvalResult::ERROR) {
            return false;
        }
        relay_results_out[i] = relay_result;
    }
    return true;
}

EvalResult EvalRung(const Rung& rung,
                    const BaseSignatureChecker& checker,
                    SigVersion sigversion,
                    ScriptExecutionData& execdata,
                    const RungEvalContext& ctx,
                    const std::vector<EvalResult>* relay_results)
{
    if (rung.blocks.empty()) {
        return EvalResult::ERROR;
    }

    // Check relay_refs: all required relays must be SATISFIED
    if (relay_results && !rung.relay_refs.empty()) {
        for (uint16_t req : rung.relay_refs) {
            if (req >= relay_results->size() || (*relay_results)[req] != EvalResult::SATISFIED) {
                return EvalResult::UNSATISFIED;
            }
        }
    }

    for (const auto& block : rung.blocks) {
        EvalResult result = EvalBlock(block, checker, sigversion, execdata, ctx);
        if (result != EvalResult::SATISFIED) {
            return result;
        }
    }
    return EvalResult::SATISFIED;
}

bool EvalLadder(const LadderWitness& ladder,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx,
                size_t* satisfied_rung_out)
{
    if (ladder.IsEmpty()) {
        return false;
    }

    // Evaluate relays first, cache results
    std::vector<EvalResult> relay_results;
    if (!ladder.relays.empty()) {
        if (!EvalRelays(ladder.relays, checker, sigversion, execdata, ctx, relay_results)) {
            return false;
        }
    }

    // First satisfied rung wins (OR logic across rungs)
    const std::vector<EvalResult>* relay_ptr = relay_results.empty() ? nullptr : &relay_results;
    RungEvalContext rung_ctx = ctx;
    if (!ladder.relays.empty()) {
        rung_ctx.relays = &ladder.relays;
    }
    for (size_t r = 0; r < ladder.rungs.size(); ++r) {
        const auto& rung = ladder.rungs[r];
        rung_ctx.rung_relay_refs = rung.relay_refs.empty() ? nullptr : &rung.relay_refs;
        EvalResult result = EvalRung(rung, checker, sigversion, execdata, rung_ctx, relay_ptr);
        if (result == EvalResult::SATISFIED) {
            if (satisfied_rung_out) *satisfied_rung_out = r;
            return true;
        }
    }
    return false;
}

/** Merge conditions (from spent output) with witness (from input).
 *  For each rung/block, the conditions provide the "locks" (pubkeys, hashes, timelocks)
 *  and the witness provides the "keys" (signatures, preimages). The merged result
 *  has all fields from both, which EvalLadder can then evaluate.
 *
 *  The witness must have the same rung/block structure as the conditions.
 *  The inverted flag is taken from conditions (witness doesn't override). */
static bool MergeConditionsAndWitness(const RungConditions& conditions,
                                       const LadderWitness& witness,
                                       LadderWitness& merged,
                                       std::string& error)
{
    if (conditions.rungs.size() != witness.rungs.size()) {
        error = "rung count mismatch: conditions=" + std::to_string(conditions.rungs.size()) +
                " witness=" + std::to_string(witness.rungs.size());
        return false;
    }

    merged.rungs.resize(conditions.rungs.size());
    merged.coil = conditions.coil;
    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
        const auto& cond_rung = conditions.rungs[r];
        const auto& wit_rung = witness.rungs[r];

        // Compact rungs (COMPACT_SIG) removed — merkle_pub_key eliminates this path.
        if (cond_rung.blocks.size() != wit_rung.blocks.size()) {
            error = "block count mismatch in rung " + std::to_string(r);
            return false;
        }

        merged.rungs[r].blocks.resize(cond_rung.blocks.size());
        merged.rungs[r].rung_id = cond_rung.rung_id;
        merged.rungs[r].relay_refs = cond_rung.relay_refs; // relay_refs come from conditions

        for (size_t b = 0; b < cond_rung.blocks.size(); ++b) {
            const auto& cond_block = cond_rung.blocks[b];
            const auto& wit_block = wit_rung.blocks[b];

            if (cond_block.type != wit_block.type) {
                error = "block type mismatch in rung " + std::to_string(r) +
                        " block " + std::to_string(b);
                return false;
            }

            // Merge: all condition fields first, then all witness fields
            auto& merged_block = merged.rungs[r].blocks[b];
            merged_block.type = cond_block.type;
            merged_block.inverted = cond_block.inverted; // inverted comes from conditions
            merged_block.fields.insert(merged_block.fields.end(),
                                       cond_block.fields.begin(), cond_block.fields.end());
            merged_block.fields.insert(merged_block.fields.end(),
                                       wit_block.fields.begin(), wit_block.fields.end());
        }
    }

    // Merge relays: conditions provide locks, witness provides keys
    if (conditions.relays.size() != witness.relays.size()) {
        error = "relay count mismatch: conditions=" + std::to_string(conditions.relays.size()) +
                " witness=" + std::to_string(witness.relays.size());
        return false;
    }
    merged.relays.resize(conditions.relays.size());
    for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
        const auto& cond_relay = conditions.relays[rl];
        const auto& wit_relay = witness.relays[rl];

        if (cond_relay.blocks.size() != wit_relay.blocks.size()) {
            error = "block count mismatch in relay " + std::to_string(rl);
            return false;
        }

        merged.relays[rl].blocks.resize(cond_relay.blocks.size());
        merged.relays[rl].relay_refs = cond_relay.relay_refs; // relay_refs come from conditions

        for (size_t b = 0; b < cond_relay.blocks.size(); ++b) {
            const auto& cond_block = cond_relay.blocks[b];
            const auto& wit_block = wit_relay.blocks[b];

            if (cond_block.type != wit_block.type) {
                error = "block type mismatch in relay " + std::to_string(rl) +
                        " block " + std::to_string(b);
                return false;
            }

            auto& merged_block = merged.relays[rl].blocks[b];
            merged_block.type = cond_block.type;
            merged_block.inverted = cond_block.inverted;
            merged_block.fields.insert(merged_block.fields.end(),
                                       cond_block.fields.begin(), cond_block.fields.end());
            merged_block.fields.insert(merged_block.fields.end(),
                                       wit_block.fields.begin(), wit_block.fields.end());
        }
    }

    return true;
}

/** Resolve a witness reference: copy rungs/relays from the referenced input's
 *  witness and apply field-level diffs. Coil is already populated (always fresh).
 *  @param[in,out] witness     The witness with witness_ref set (rungs/relays empty).
 *                              On success, rungs/relays are populated and witness_ref cleared.
 *  @param[in]     tx          The spending transaction.
 *  @param[in]     nIn         Current input index.
 *  @param[out]    error       Error message on failure.
 *  @return true on success. */
static bool ResolveWitnessReference(LadderWitness& witness,
                                    const CTransaction& tx,
                                    unsigned int nIn,
                                    std::string& error)
{
    if (!witness.IsWitnessRef()) {
        error = "witness does not have a witness reference";
        return false;
    }

    const auto& ref = *witness.witness_ref;

    // Forward-only: source must be a lower-indexed input (prevents cycles)
    if (ref.input_index >= nIn) {
        error = "witness reference must be forward-only: input_index " +
                std::to_string(ref.input_index) + " >= current " + std::to_string(nIn);
        return false;
    }

    // Deserialize the source input's witness
    const auto& source_wit = tx.vin[ref.input_index].scriptWitness;
    if (source_wit.stack.empty()) {
        error = "witness reference source input " + std::to_string(ref.input_index) +
                " has empty witness";
        return false;
    }

    LadderWitness source_ladder;
    std::string deser_error;
    if (!DeserializeLadderWitness(source_wit.stack[0], source_ladder, deser_error)) {
        error = "witness reference source deserialization failed: " + deser_error;
        return false;
    }

    // No chaining: source must not itself be a witness reference
    if (source_ladder.IsWitnessRef()) {
        error = "witness reference points to another witness reference (no chaining)";
        return false;
    }

    // Copy rungs and relays from source
    witness.rungs = source_ladder.rungs;
    witness.relays = source_ladder.relays;
    // Coil is already populated fresh from deserialization — do NOT copy

    // Apply diffs
    for (size_t d = 0; d < ref.diffs.size(); ++d) {
        const auto& diff = ref.diffs[d];

        if (diff.rung_index >= witness.rungs.size()) {
            error = "witness diff rung_index out of range: " +
                    std::to_string(diff.rung_index) + " at diff " + std::to_string(d);
            return false;
        }
        auto& rung = witness.rungs[diff.rung_index];

        if (diff.block_index >= rung.blocks.size()) {
            error = "witness diff block_index out of range: " +
                    std::to_string(diff.block_index) + " at diff " + std::to_string(d);
            return false;
        }
        auto& block = rung.blocks[diff.block_index];

        if (diff.field_index >= block.fields.size()) {
            error = "witness diff field_index out of range: " +
                    std::to_string(diff.field_index) + " at diff " + std::to_string(d);
            return false;
        }

        // Type must match source field type
        if (block.fields[diff.field_index].type != diff.new_field.type) {
            error = "witness diff type mismatch at rung " +
                    std::to_string(diff.rung_index) + " block " +
                    std::to_string(diff.block_index) + " field " +
                    std::to_string(diff.field_index) + ": expected " +
                    DataTypeName(block.fields[diff.field_index].type) +
                    ", got " + DataTypeName(diff.new_field.type);
            return false;
        }

        block.fields[diff.field_index] = diff.new_field;
    }

    // Clear witness reference — witness is now fully resolved
    witness.witness_ref.reset();
    return true;
}


bool ValidateRungOutputs(const CTransaction& tx, unsigned int flags, std::string& error)
{
    size_t data_return_count = 0;

    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& spk = tx.vout[i].scriptPubKey;

        // MLSC output: 0xDF + 32 bytes (+ optional DATA_RETURN payload)
        if (IsMLSCScript(spk)) {
            // MLSC with DATA_RETURN payload (> 33 bytes)
            if (HasMLSCData(spk)) {
                data_return_count++;
                // Must be zero-value (unspendable)
                if (tx.vout[i].nValue != 0) {
                    error = "output " + std::to_string(i) + ": DATA_RETURN output must have zero value";
                    return false;
                }
            } else {
                // Consensus dust threshold: non-DATA_RETURN outputs must carry
                // minimum value to prevent UTXO set bloat and cheap spam.
                if (tx.vout[i].nValue < MIN_RUNG_OUTPUT_VALUE) {
                    error = "output " + std::to_string(i) + ": value " +
                            std::to_string(tx.vout[i].nValue) + " below minimum " +
                            std::to_string(MIN_RUNG_OUTPUT_VALUE);
                    return false;
                }
            }
            continue;
        }

        // Reject everything else: inline (0xC1) removed, OP_RETURN, P2TR, P2WPKH, arbitrary data
        error = "output " + std::to_string(i) + ": non-Ladder Script output rejected in v4 transaction";
        return false;
    }

    // Only one DATA_RETURN output allowed per transaction
    if (data_return_count > 1) {
        error = "too many DATA_RETURN outputs: " + std::to_string(data_return_count) + " (max 1)";
        return false;
    }

    return true;
}

/** Extract pubkeys from witness blocks positionally (merkle_pub_key).
 *  Walks blocks left-to-right, collecting PUBKEY fields based on
 *  PubkeyCountForBlock() for each block type. */
static std::vector<std::vector<uint8_t>> ExtractBlockPubkeys(const std::vector<RungBlock>& blocks)
{
    std::vector<std::vector<uint8_t>> pubkeys;
    for (const auto& block : blocks) {
        size_t count = PubkeyCountForBlock(block.type, block);
        if (count == 0) continue;
        auto pks = FindAllFields(block, RungDataType::PUBKEY);
        for (size_t i = 0; i < count && i < pks.size(); ++i) {
            pubkeys.push_back(pks[i]->data);
        }
    }
    return pubkeys;
}

/** Count PREIMAGE/SCRIPT_BODY fields across ALL inputs in a transaction.
 *  Deserializes each MLSC input's ladder witness to count preimage-bearing fields.
 *  Non-MLSC inputs (e.g. standard P2WPKH bootstrap) are skipped.
 *  Returns total count; callers reject if > MAX_PREIMAGE_FIELDS_PER_TX. */
/** Count PREIMAGE/SCRIPT_BODY fields in a single deserialized witness. */
static size_t CountWitnessPreimageFields(const LadderWitness& lw)
{
    size_t total = 0;
    for (const auto& rung : lw.rungs) {
        for (const auto& block : rung.blocks) {
            for (const auto& field : block.fields) {
                if (field.type == RungDataType::PREIMAGE ||
                    field.type == RungDataType::SCRIPT_BODY) {
                    total++;
                }
            }
        }
    }
    for (const auto& relay : lw.relays) {
        for (const auto& block : relay.blocks) {
            for (const auto& field : block.fields) {
                if (field.type == RungDataType::PREIMAGE ||
                    field.type == RungDataType::SCRIPT_BODY) {
                    total++;
                }
            }
        }
    }
    return total;
}

/** Count PREIMAGE/SCRIPT_BODY fields across ALL inputs in a transaction.
 *  Deserializes each input's witness once. O(N) in total inputs. */
static size_t CountTxPreimageFields(const CTransaction& tx)
{
    size_t total = 0;
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& witness = tx.vin[i].scriptWitness;
        if (witness.stack.size() != 2) continue;

        LadderWitness lw;
        std::string err;
        if (!DeserializeLadderWitness(witness.stack[0], lw, err)) continue;

        total += CountWitnessPreimageFields(lw);
    }
    return total;
}

bool VerifyRungTx(const CTransaction& tx,
                  unsigned int nIn,
                  const CTxOut& spent_output,
                  unsigned int flags,
                  const BaseSignatureChecker& checker,
                  const PrecomputedTransactionData& txdata,
                  ScriptError* serror,
                  int32_t block_height,
                  SharedTreeCache* shared_cache)
{
    if (nIn >= tx.vin.size()) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    // No creation proof validation — conditions_root is an opaque commitment.
    // Validation happens at spend time via Merkle proof against the revealed rung.

    // Dust threshold: every spendable output must carry minimum value (unconditional)
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (tx.vout[i].nValue > 0 && tx.vout[i].nValue < MIN_RUNG_OUTPUT_VALUE) {
            LogPrintf("TX_MLSC output %zu: value %lld below minimum %lld\n",
                      i, (long long)tx.vout[i].nValue, (long long)MIN_RUNG_OUTPUT_VALUE);
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }
    }

    // Consensus: PREIMAGE/SCRIPT_BODY field count across ALL inputs.
    // Only computed on first input (result is tx-wide, same for all inputs).
    if (nIn == 0 && CountTxPreimageFields(tx) > MAX_PREIMAGE_FIELDS_PER_TX) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    const auto& witness = tx.vin[nIn].scriptWitness;

    // Witness stack size determines spending path:
    //   1 element  = key-path spend (signature only)
    //   2 elements = script-path (LadderWitness + MLSCProof, legacy — no tweak check)
    //   3 elements = script-path with tweak (LadderWitness + MLSCProof + internal_pubkey)
    if (witness.stack.empty() || witness.stack.size() > 3) {
        if (serror) *serror = SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
        return false;
    }

    // Only MLSC (0xDF) outputs accepted. Inline (0xC1) removed.
    if (!IsMLSCScript(spent_output.scriptPubKey)) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    // ================================================================
    // KEY-PATH SPEND: witness = [signature]
    // Verify Schnorr signature directly against the output's conditions_root
    // treated as an x-only public key. No conditions revealed, no Merkle proof.
    // ================================================================
    if (witness.stack.size() == 1) {
        uint256 conditions_root;
        if (!GetMLSCRoot(spent_output.scriptPubKey, conditions_root)) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        const auto& sig = witness.stack[0];
        if (sig.size() != 64 && sig.size() != 65) {
            if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_SIZE;
            return false;
        }

        // Parse the conditions_root as an x-only public key
        XOnlyPubKey output_key;
        std::memcpy(output_key.begin(), conditions_root.data(), 32);
        if (!output_key.IsFullyValid()) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        // Extract sighash type from trailing byte (BIP341 convention)
        uint8_t hashtype = SIGHASH_DEFAULT;
        std::vector<unsigned char> sig_data(sig.begin(), sig.end());
        if (sig_data.size() == 65) {
            hashtype = sig_data.back();
            sig_data.pop_back();
            if (hashtype == SIGHASH_DEFAULT) {
                if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
                return false;
            }
        }

        // Compute key-path sighash (no conditions commitment)
        uint256 sighash;
        if (!SignatureHashLadderKeyPath(txdata, tx, nIn, hashtype, sighash)) {
            if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
            return false;
        }

        // Verify Schnorr signature against the output key
        if (!output_key.VerifySchnorr(sighash, std::span<const unsigned char>{sig_data.data(), sig_data.size()})) {
            if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG;
            return false;
        }

        return true;
    }

    // ================================================================
    // SCRIPT-PATH SPEND: witness = [LadderWitness, MLSCProof] or
    //                               [LadderWitness, MLSCProof, internal_pubkey]
    // ================================================================
    const auto& witness_bytes = witness.stack[0];

    LadderWitness witness_ladder;
    std::string deser_error;
    if (!DeserializeLadderWitness(witness_bytes, witness_ladder, deser_error)) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    // Resolve witness references if needed (diff witness mode)
    if (witness_ladder.IsWitnessRef()) {
        std::string ref_error;
        if (!ResolveWitnessReference(witness_ladder, tx, nIn, ref_error)) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }
    }

    RungConditions conditions;
    bool has_conditions = false;
    std::vector<std::vector<std::vector<uint8_t>>> eval_rung_pubkeys;
    MLSCVerifiedLeaves verified_leaves_data;
    MLSCProof mlsc_proof;

    {
        // ================================================================
        // MLSC path: conditions come from witness, not scriptPubKey
        // ================================================================
        uint256 conditions_root;
        if (!GetMLSCRoot(spent_output.scriptPubKey, conditions_root)) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        // stack[0] = LadderWitness (already deserialized above)
        // stack[1] = MLSCProof (revealed conditions + Merkle proof hashes)
        // (exact stack size already enforced at entry)

        // Deserialize MLSC proof from stack[1]
        std::string proof_error;
        if (!DeserializeMLSCProof(witness.stack[1], mlsc_proof, proof_error)) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        // SHARED proof mode: validate against a previously verified input from the same source tx
        if (mlsc_proof.proof_mode == MLSCProofMode::SHARED) {
            if (!shared_cache) {
                LogPrintf("MLSC shared proof: no cache available\n");
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
            uint16_t src_idx = mlsc_proof.shared_source_input;
            if (src_idx >= nIn) {
                LogPrintf("MLSC shared proof: source_input %u >= current input %u (must reference earlier input)\n",
                          src_idx, nIn);
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
            // Verify same source tx
            if (tx.vin[src_idx].prevout.hash != tx.vin[nIn].prevout.hash) {
                LogPrintf("MLSC shared proof: source input %u has different prevout hash\n", src_idx);
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
            // Look up the verified root from the source input
            auto it = shared_cache->find(tx.vin[src_idx].prevout.hash);
            if (it == shared_cache->end()) {
                LogPrintf("MLSC shared proof: source input %u not in cache\n", src_idx);
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
            if (it->second.root != conditions_root) {
                LogPrintf("MLSC shared proof: cached root mismatch\n");
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
            // Root matches. Now verify the revealed leaf is actually in the cached tree.
            // Without this check, an attacker could fabricate conditions that were never
            // committed in the original Merkle tree.
            // (my_leaf is computed below after pubkey extraction — defer check to after line 3786)
        }

        // Single rung rule: standard spends reveal exactly 1 rung
        if (witness_ladder.rungs.size() != 1) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        // Extract pubkeys from witness for merkle_pub_key leaf computation
        std::vector<std::vector<uint8_t>> rung_pks;
        if (!witness_ladder.rungs.empty()) {
            rung_pks = ExtractBlockPubkeys(witness_ladder.rungs[0].blocks);
        }
        std::vector<std::vector<std::vector<uint8_t>>> relay_pks;
        for (const auto& [relay_idx, relay] : mlsc_proof.revealed_relays) {
            // Find the corresponding witness relay to extract pubkeys
            if (relay_idx < witness_ladder.relays.size()) {
                relay_pks.push_back(ExtractBlockPubkeys(witness_ladder.relays[relay_idx].blocks));
            } else {
                relay_pks.push_back({});
            }
        }

        // Extract pubkeys for mutation targets (cross-rung mutations)
        std::vector<std::vector<std::vector<uint8_t>>> mutation_target_pks;
        for (size_t i = 0; i < mlsc_proof.revealed_mutation_targets.size(); ++i) {
            // Mutation target pubkeys come from the witness — find matching relay/rung
            // For now, mutation targets don't carry witness pubkeys (conditions-only blocks)
            mutation_target_pks.push_back({});
        }

        // Verify Merkle proof: TX_MLSC leaf = TaggedHash(template || value_commitment)
        std::string verify_error;

        // Build CreationProofRung from the revealed rung + witness data
        CreationProofRung cp_rung;
        for (const auto& block : mlsc_proof.revealed_rung.blocks) {
            cp_rung.blocks.push_back({
                static_cast<uint16_t>(block.type),
                static_cast<uint8_t>(block.inverted ? 1 : 0)
            });
        }
        cp_rung.coil = witness_ladder.coil;
        cp_rung.value_commitment = ComputeValueCommitment(
            mlsc_proof.revealed_rung, rung_pks);

        // Compute leaf (needed for rung evaluation even in SHARED mode)
        uint256 my_leaf = ComputeTxMLSCLeaf(cp_rung);

        // SHARED proofs: root was validated via cache. Now verify leaf membership —
        // the revealed rung's leaf must exist in the cached tree's leaf set.
        if (mlsc_proof.proof_mode == MLSCProofMode::SHARED) {
            auto cache_it = shared_cache->find(tx.vin[nIn].prevout.hash);
            if (cache_it == shared_cache->end()) {
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
            const auto& cached_leaves = cache_it->second.leaves;
            bool leaf_found = false;
            for (const auto& cached_leaf : cached_leaves) {
                if (cached_leaf == my_leaf) {
                    leaf_found = true;
                    break;
                }
            }
            if (!leaf_found) {
                LogPrintf("MLSC shared proof: leaf not found in cached tree\n");
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
        } else if (witness.stack.size() == 3) {
            // Compute raw Merkle root from proof, then verify tweak
            uint256 computed_merkle_root;
            if (mlsc_proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
                computed_merkle_root = ComputeMerkleRootFromPath(my_leaf, mlsc_proof.proof_hashes);
            } else {
                size_t total_leaves = mlsc_proof.total_rungs;
                std::vector<uint256> leaves(total_leaves);
                leaves[mlsc_proof.rung_index] = my_leaf;
                size_t ph_idx = 0;
                for (size_t i = 0; i < total_leaves; ++i) {
                    if (i == mlsc_proof.rung_index) continue;
                    if (ph_idx >= mlsc_proof.proof_hashes.size()) {
                        LogPrintf("MLSC proof failed: not enough proof hashes\n");
                        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                        return false;
                    }
                    leaves[i] = mlsc_proof.proof_hashes[ph_idx++];
                }
                computed_merkle_root = BuildMerkleTree(std::move(leaves));
            }

            // Verify tweak: conditions_root == internal_pubkey + H(internal_pubkey || merkle_root) * G
            if (witness.stack[2].size() != 32) {
                LogPrintf("MLSC tweak: internal pubkey must be 32 bytes\n");
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
            XOnlyPubKey internal_key;
            std::memcpy(internal_key.begin(), witness.stack[2].data(), 32);
            if (!internal_key.IsFullyValid()) {
                LogPrintf("MLSC tweak: invalid internal pubkey\n");
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
            XOnlyPubKey output_key;
            std::memcpy(output_key.begin(), conditions_root.data(), 32);
            if (!output_key.CheckLadderTweak(internal_key, computed_merkle_root, false) &&
                !output_key.CheckLadderTweak(internal_key, computed_merkle_root, true)) {
                LogPrintf("MLSC tweak verification failed\n");
                if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                return false;
            }
        } else {
            // 2-element witness (legacy): verify Merkle proof directly against conditions_root
            if (mlsc_proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
                std::string path_error;
                if (!VerifyMerklePath(my_leaf, mlsc_proof.proof_hashes,
                                      mlsc_proof.total_rungs, conditions_root, path_error)) {
                    LogPrintf("MLSC Merkle path verification failed: %s\n", path_error.c_str());
                    if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                    return false;
                }
            } else {
                size_t total_leaves = mlsc_proof.total_rungs;
                std::vector<uint256> leaves(total_leaves);
                leaves[mlsc_proof.rung_index] = my_leaf;
                size_t ph_idx = 0;
                for (size_t i = 0; i < total_leaves; ++i) {
                    if (i == mlsc_proof.rung_index) continue;
                    if (ph_idx >= mlsc_proof.proof_hashes.size()) {
                        LogPrintf("MLSC proof failed: not enough proof hashes\n");
                        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                        return false;
                    }
                    leaves[i] = mlsc_proof.proof_hashes[ph_idx++];
                }
                uint256 computed_root = BuildMerkleTree(std::move(leaves));
                if (computed_root != conditions_root) {
                    LogPrintf("MLSC root mismatch: computed %s != expected %s\n",
                              computed_root.GetHex(), conditions_root.GetHex());
                    if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                    return false;
                }
            }
        }

        // Verify coil.output_index matches the output being spent
        uint32_t spent_vout = tx.vin[nIn].prevout.n;
        if (witness_ladder.coil.output_index != spent_vout) {
            LogPrintf("coil.output_index %u != spent vout %u\n",
                      witness_ladder.coil.output_index, spent_vout);
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        // Populate verified_leaves_data for recursive covenant blocks.
        // For FULL_LEAVES mode, we can reconstruct the full leaf array.
        // For MERKLE_PATH mode, store the leaf + path for covenant root recomputation.
        verified_leaves_data.root = conditions_root;
        verified_leaves_data.rung_index = mlsc_proof.rung_index;
        verified_leaves_data.total_rungs = mlsc_proof.total_rungs;
        verified_leaves_data.total_relays = mlsc_proof.total_relays;
        // Store the verified leaf at rung_index + all proof hashes as the leaf set.
        // Covenant blocks use this to swap a leaf and recompute the root.
        if (mlsc_proof.proof_mode == MLSCProofMode::MERKLE_PATH) {
            // For Merkle path mode: store just the verified leaf.
            // Covenant recomputation uses ComputeMerkleRootFromPath(new_leaf, proof_hashes).
            verified_leaves_data.leaves.resize(1);
            verified_leaves_data.leaves[0] = my_leaf;
        } else if (mlsc_proof.proof_mode != MLSCProofMode::SHARED) {
            // FULL_LEAVES mode: reconstruct the full leaf array
            verified_leaves_data.leaves.resize(mlsc_proof.total_rungs);
            verified_leaves_data.leaves[mlsc_proof.rung_index] = my_leaf;
            size_t ph = 0;
            for (size_t i = 0; i < mlsc_proof.total_rungs; ++i) {
                if (i != mlsc_proof.rung_index && ph < mlsc_proof.proof_hashes.size()) {
                    verified_leaves_data.leaves[i] = mlsc_proof.proof_hashes[ph++];
                }
            }
        }

        // Populate shared tree cache for same-source proof sharing.
        // Store root + all leaf hashes so SHARED proofs can verify leaf membership.
        if (shared_cache && mlsc_proof.proof_mode != MLSCProofMode::SHARED) {
            SharedTreeEntry entry;
            entry.root = conditions_root;
            entry.leaves = verified_leaves_data.leaves;
            (*shared_cache)[tx.vin[nIn].prevout.hash] = std::move(entry);
        }

        // Build RungConditions from MLSC proof (1 rung + relays + coil)
        conditions.rungs.push_back(mlsc_proof.revealed_rung);
        conditions.coil = witness_ladder.coil;
        conditions.conditions_root = conditions_root; // For sighash computation

        // Build relay vector: allocate for total_relays, fill in revealed ones
        conditions.relays.resize(mlsc_proof.total_relays);
        for (const auto& [relay_idx, relay] : mlsc_proof.revealed_relays) {
            if (relay_idx < conditions.relays.size()) {
                conditions.relays[relay_idx] = relay;
            }
        }

        has_conditions = true;

        // Save per-rung pubkeys for covenant root comparison
        eval_rung_pubkeys.push_back(rung_pks);

    } // end MLSC block

    // Build evaluation context for covenant, anchor, recursion, and PLC blocks
    RungEvalContext eval_ctx;
    eval_ctx.tx = &tx;
    eval_ctx.input_index = nIn;
    eval_ctx.input_amount = spent_output.nValue;
    eval_ctx.block_height = block_height;
    // Use the output matching coil.output_index for covenant amount checks
    {
        uint32_t coil_out_idx = witness_ladder.coil.output_index;
        if (coil_out_idx < tx.vout.size()) {
            eval_ctx.output_amount = tx.vout[coil_out_idx].nValue;
            eval_ctx.spending_output = &tx.vout[coil_out_idx];
        } else if (!tx.vout.empty()) {
            eval_ctx.output_amount = tx.vout[0].nValue;
            eval_ctx.spending_output = &tx.vout[0];
        }
    }
    if (has_conditions) {
        eval_ctx.input_conditions = &conditions;
    }
    if (!eval_rung_pubkeys.empty()) {
        eval_ctx.rung_pubkeys = &eval_rung_pubkeys;
    }
    if (has_conditions) {
        eval_ctx.verified_leaves = &verified_leaves_data;
        eval_ctx.mlsc_proof = &mlsc_proof;
    }
    if (txdata.m_spent_outputs_ready) {
        eval_ctx.spent_outputs = &txdata.m_spent_outputs;
    }

    LadderWitness eval_ladder;
    ScriptExecutionData execdata;

    if (has_conditions) {
        // Merge conditions with witness
        std::string merge_error;
        if (!MergeConditionsAndWitness(conditions, witness_ladder, eval_ladder, merge_error)) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        LadderSignatureChecker ladder_checker(checker, conditions, txdata, tx, nIn);
        if (!EvalLadder(eval_ladder, ladder_checker, SigVersion::LADDER, execdata, eval_ctx)) {
            if (serror) *serror = SCRIPT_ERR_EVAL_FALSE;
            return false;
        }
    } else {
        // Bootstrap spend: v4 tx spending a v1/v2 UTXO
        RungConditions empty_conditions;
        LadderSignatureChecker ladder_checker(checker, empty_conditions, txdata, tx, nIn);
        if (!EvalLadder(witness_ladder, ladder_checker, SigVersion::LADDER, execdata, eval_ctx)) {
            if (serror) *serror = SCRIPT_ERR_EVAL_FALSE;
            return false;
        }
    }

    return true;
}

} // namespace rung
