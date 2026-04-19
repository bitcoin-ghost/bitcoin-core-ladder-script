// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/evaluator.h>
#include <rung/block_dispatch.h>
#include <rung/conditions.h>
#include <rung/pq_verify.h>
#include <rung/qabi.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung_shims.h>  // transitional: CTransaction/PrecomputedTransactionData wrappers

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
#include <map>
#include <optional>

namespace rung {
using namespace api;  // Bring libladder public API (span-based) into file scope

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
static std::optional<int64_t> ReadNumeric(const RungField& field)
{
    if (field.data.empty() || field.data.size() > 8) return std::nullopt;
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

/** Return PUBKEY fields from the block. Pubkeys travel in the witness
 *  and are bound to the Merkle leaf at fund time (merkle_pub_key). */
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

/** Helper: pull the Ladder sighash from the adapter. Returns false if the
 *  adapter lacks precomputed data (library fuzzers, minimal test stubs). */
static bool FetchLadderSighash(const api::LadderSigChecker& sig_checker,
                               uint8_t hash_type,
                               uint8_t out[32])
{
    return sig_checker.ComputeSighash(hash_type, out);
}

/** Helper: extract the hash_type byte that a Schnorr signature commits to.
 *  64-byte sigs use SIGHASH_DEFAULT; 65-byte sigs carry hash_type in the last
 *  byte (which must not be SIGHASH_DEFAULT per BIP340). Returns false on an
 *  invalid 65-byte sig. */
static bool ExtractSchnorrHashType(std::span<const uint8_t> sig, uint8_t& hash_type)
{
    if (sig.size() == 64) { hash_type = SIGHASH_DEFAULT; return true; }
    if (sig.size() == 65) {
        hash_type = sig.back();
        if (hash_type == SIGHASH_DEFAULT) return false;
        return true;
    }
    return false;
}

/** Verify a post-quantum signature using the SCHEME field routing.
 *  PQ schemes always sign the default Ladder sighash (SIGHASH_DEFAULT). */
static EvalResult EvalPQSig(RungScheme scheme,
                             const RungField& sig_field,
                             const RungField& pubkey_field,
                             const api::LadderSigChecker& sig_checker)
{
    if (!HasPQSupport()) return EvalResult::ERROR;

    uint8_t sighash[32];
    if (!FetchLadderSighash(sig_checker, SIGHASH_DEFAULT, sighash)) {
        return EvalResult::ERROR;
    }

    std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
    std::span<const uint8_t> msg{sighash, 32};
    std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};

    if (VerifyPQSignature(scheme, sig, msg, pubkey)) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Single-sig verification helper
// ============================================================================

/** Helper: verify a single signature against a single pubkey, routing by scheme.
 *  Returns SATISFIED on valid sig, UNSATISFIED on invalid sig, ERROR on malformed data.
 *  If scheme_field is non-null and contains a PQ scheme, routes to PQ verifier.
 *  Otherwise routes by signature size (64-65 = Schnorr, 8-72 = ECDSA). */
static EvalResult VerifySigWithScheme(const RungField& pubkey_field,
                                       const RungField& sig_field,
                                       const RungField* scheme_field,
                                       const api::LadderSigChecker& sig_checker)
{
    auto try_schnorr = [&](std::span<const uint8_t> sig,
                           std::span<const uint8_t> pubkey) -> EvalResult {
        if (pubkey.size() != 32) return EvalResult::UNSATISFIED;
        uint8_t hash_type;
        if (!ExtractSchnorrHashType(sig, hash_type)) return EvalResult::UNSATISFIED;
        uint8_t sighash[32];
        if (!FetchLadderSighash(sig_checker, hash_type, sighash)) return EvalResult::ERROR;
        std::span<const uint8_t, 32> sighash_span{sighash, 32};
        if (sig_checker.CheckSchnorrSignature(sig, pubkey, sighash_span)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    };

    auto try_ecdsa = [&](std::span<const uint8_t> sig,
                         std::span<const uint8_t> pubkey) -> EvalResult {
        // Classical ECDSA sigs in v4 are DER + trailing 1-byte hash_type.
        if (sig.empty()) return EvalResult::UNSATISFIED;
        uint8_t hash_type = sig.back();
        uint8_t sighash[32];
        if (!FetchLadderSighash(sig_checker, hash_type, sighash)) return EvalResult::ERROR;
        std::span<const uint8_t, 32> sighash_span{sighash, 32};
        if (sig_checker.CheckECDSASignature(sig, pubkey, sighash_span)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    };

    // Check for explicit SCHEME field — routes to PQ verifier if present
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            return EvalPQSig(scheme, sig_field, pubkey_field, sig_checker);
        }
        if (scheme == RungScheme::SCHNORR) {
            std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
            std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};
            std::vector<uint8_t> xonly;
            if (pubkey_field.data.size() == 33) {
                xonly.assign(pubkey_field.data.begin() + 1, pubkey_field.data.end());
                pubkey = std::span<const uint8_t>{xonly.data(), xonly.size()};
            }
            return try_schnorr(sig, pubkey);
        }
        if (scheme == RungScheme::ECDSA) {
            std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
            std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};
            return try_ecdsa(sig, pubkey);
        }
        // Unknown classical scheme — fall through to size-based routing
    }

    // Size-based fallback: Schnorr (64-65 bytes) or ECDSA (8-72 bytes)
    std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
    std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};

    if (sig_field.data.size() >= 64 && sig_field.data.size() <= 65) {
        std::vector<uint8_t> xonly;
        if (pubkey_field.data.size() == 33) {
            xonly.assign(pubkey_field.data.begin() + 1, pubkey_field.data.end());
            pubkey = std::span<const uint8_t>{xonly.data(), xonly.size()};
        }
        return try_schnorr(sig, pubkey);
    }

    if (sig_field.data.size() >= 8 && sig_field.data.size() <= 72) {
        return try_ecdsa(sig, pubkey);
    }

    return EvalResult::ERROR;
}

// ============================================================================
// Signature evaluators
// ============================================================================

EvalResult EvalSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker);
}

EvalResult EvalMultisigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
            // PQ multisig: compute sighash once, verify each sig against pubkeys
            uint8_t sighash[32];
            if (!sig_checker.ComputeSighash(SIGHASH_DEFAULT, sighash)) {
                return EvalResult::ERROR;
            }

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
            EvalResult r = VerifySigWithScheme(single_pk, single_sig, nullptr, sig_checker);
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

    if (!sig_checker.CheckLockTime(static_cast<uint32_t>(locktime_val))) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalMusigThresholdBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
    return VerifySigWithScheme(pk_field, *sig_field, nullptr, sig_checker);
}

EvalResult EvalAdaptorSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
    return VerifySigWithScheme(pk_field, *sig_field, nullptr, sig_checker);
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
        uint32_t seq = tx.inputs[i].sequence;
        unsigned char seq_buf[4];
        seq_buf[0] = seq & 0xFF;
        seq_buf[1] = (seq >> 8) & 0xFF;
        seq_buf[2] = (seq >> 16) & 0xFF;
        seq_buf[3] = (seq >> 24) & 0xFF;
        sequences_hasher.Write(seq_buf, 4);
    }
    unsigned char sequences_hash[32];
    sequences_hasher.Finalize(sequences_hash);

    CSHA256 outputs_hasher;
    for (size_t i = 0; i < tx.output_count; ++i) {
        const auto& out = tx.outputs[i];
        unsigned char amt_buf[8];
        uint64_t amt = static_cast<uint64_t>(out.value);
        for (int j = 0; j < 8; ++j) amt_buf[j] = (amt >> (8 * j)) & 0xFF;
        outputs_hasher.Write(amt_buf, 8);
        uint64_t spk_len = out.script_pub_key.size;
        unsigned char len_buf[8];
        for (int j = 0; j < 8; ++j) len_buf[j] = (spk_len >> (8 * j)) & 0xFF;
        outputs_hasher.Write(len_buf, 8);
        outputs_hasher.Write(out.script_pub_key.data, out.script_pub_key.size);
    }
    unsigned char outputs_hash[32];
    outputs_hasher.Finalize(outputs_hash);

    CSHA256 hasher;
    unsigned char version_buf[4];
    uint32_t version = static_cast<uint32_t>(tx.version);
    for (int i = 0; i < 4; ++i) version_buf[i] = (version >> (8 * i)) & 0xFF;
    hasher.Write(version_buf, 4);

    unsigned char locktime_buf[4];
    for (int i = 0; i < 4; ++i) locktime_buf[i] = (tx.lock_time >> (8 * i)) & 0xFF;
    hasher.Write(locktime_buf, 4);

    hasher.Write(scriptsigs_hash, 32);

    unsigned char nins_buf[4];
    uint32_t nins = static_cast<uint32_t>(tx.input_count);
    for (int i = 0; i < 4; ++i) nins_buf[i] = (nins >> (8 * i)) & 0xFF;
    hasher.Write(nins_buf, 4);

    hasher.Write(sequences_hash, 32);

    unsigned char nouts_buf[4];
    uint32_t nouts = static_cast<uint32_t>(tx.output_count);
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
                        const api::LadderSigChecker& sig_checker)
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
        EvalResult r = VerifySigWithScheme(pk_field, *sig_field, nullptr, sig_checker);
        if (r == EvalResult::SATISFIED) {
            if (ki == 0) {
                return EvalResult::SATISFIED; // recovery key — cold sweep, no delay
            }
            // Hot key — check CSV delay
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
            EvalResult r = VerifySigWithScheme(pk_field, sig_copy, nullptr, sig_checker);
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
    if (!ctx.tx || !ctx.spent_outputs || !ctx.tx_core) {
        return EvalResult::ERROR; // fail-closed: tx context required for fee/weight checks
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

        int64_t vsize = GetVirtualTransactionSize(*ctx.tx_core);
        if (vsize <= 0) return EvalResult::ERROR;

        int64_t fee_rate = fee / vsize;
        if (fee_rate < min_fee_rate || fee_rate > max_fee_rate) {
            return EvalResult::UNSATISFIED;
        }
    }

    // 5. Weight limit check
    {
        int64_t tx_weight = GetTransactionWeight(*ctx.tx_core);
        if (tx_weight > max_weight) {
            return EvalResult::UNSATISFIED;
        }
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

// ============================================================================
// Leaf-centric covenant helpers
// ============================================================================

/** Check if an output's MLSC root matches the verified input root (identity check).
 *  Used by RECURSE_SAME and RECURSE_UNTIL (before deadline). */
static bool OutputRootMatchesInput(const api::LadderOutputView& output, const MLSCVerifiedLeaves& verified_leaves)
{
    uint256 output_root;
    if (!GetMLSCRoot(output.script_pub_key.as_span(), output_root)) {
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

/** Build a CreationProofRung from a Rung + pubkeys, suitable for ComputeTxMLSCLeaf. */
static CreationProofRung BuildCPRung(const Rung& rung,
                                      const std::vector<std::vector<uint8_t>>& pks,
                                      const RungCoil& coil)
{
    CreationProofRung cp;
    for (const auto& block : rung.blocks) {
        cp.blocks.push_back({
            static_cast<uint16_t>(block.type),
            static_cast<uint8_t>(block.inverted ? 1 : 0)
        });
    }
    cp.coil = coil;
    cp.value_commitment = ComputeValueCommitment(rung, pks);
    return cp;
}

/** Compute TX_MLSC root from a RungConditions + per-rung pubkeys (fallback path). */
static uint256 ComputeConditionsRootMLSC(const RungConditions& conditions,
                                          const std::vector<std::vector<std::vector<uint8_t>>>& rung_pubkeys)
{
    std::vector<CreationProofRung> cp_rungs;
    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
        const auto& pks = (r < rung_pubkeys.size()) ? rung_pubkeys[r] : std::vector<std::vector<uint8_t>>{};
        cp_rungs.push_back(BuildCPRung(conditions.rungs[r], pks, conditions.coil));
    }
    return ComputeTxMLSCRoot(cp_rungs);
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
                    auto cur = ReadNumeric(f);
                    if (!cur) return EvalResult::ERROR;
                    WriteNumericField(f, *cur + m.delta);
                    applied = true;
                    break;
                }
                ++cond_idx;
            }
            if (!applied) return EvalResult::UNSATISFIED;
        }
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
            return EvalResult::UNSATISFIED;
        }
        if (output_root != ComputeConditionsRootMLSC(expected, pubkeys)) {
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
            for (const auto& target : ctx.mlsc_proof->revealed_mutation_targets) {
                if (target.idx == static_cast<uint16_t>(m.rung_idx)) {
                    mutated_rung = target.rung;
                    rung_pks = target.pubkeys;
                    found = true;
                    break;
                }
            }
            if (!found) return EvalResult::UNSATISFIED;
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
                auto cur = ReadNumeric(f);
                if (!cur) return EvalResult::ERROR;
                WriteNumericField(f, *cur + m.delta);
                applied = true;
                break;
            }
            ++cond_idx;
        }
        if (!applied) return EvalResult::UNSATISFIED;

        // Recompute the leaf for this rung using TX_MLSC leaf computation
        RungCoil coil = ctx.input_conditions->coil;
        auto cp = BuildCPRung(mutated_rung, rung_pks, coil);
        leaves_copy[m.rung_idx] = ComputeTxMLSCLeaf(cp);
    }

    // Build tree from mutated leaves and compare with output root
    uint256 expected_root = BuildMerkleTree(std::move(leaves_copy));
    uint256 output_root;
    if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
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
    auto depth_opt = ReadNumeric(*max_depth);
    if (!depth_opt || *depth_opt <= 0) {
        return EvalResult::UNSATISFIED;
    }

    // Leaf-centric: output root must equal input root (identity)
    if (ctx.verified_leaves) {
        if (!ctx.spending_output) return EvalResult::ERROR;
        if (!OutputRootMatchesInput(*ctx.spending_output, *ctx.verified_leaves)) {
            return EvalResult::UNSATISFIED;
        }
    } else if (ctx.input_conditions) {
        if (!ctx.spending_output) return EvalResult::ERROR;
        // Fallback: compare MLSC roots directly
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
            return EvalResult::UNSATISFIED;
        }
        std::vector<std::vector<std::vector<uint8_t>>> pks;
        if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
        if (output_root != ComputeConditionsRootMLSC(*ctx.input_conditions, pks)) {
            return EvalResult::UNSATISFIED;
        }
    }
    // No covenant context available — structural check passed (depth > 0)
    return EvalResult::SATISFIED;
}

/** Parse mutation specs from NUMERIC fields. Returns max_depth via out-param.
 *  Supports legacy (4 NUMERICs: rung 0, single mutation) and new format (6+ NUMERICs). */
static bool ParseMutationSpecs(const std::vector<const RungField*>& numerics,
                                int64_t& max_depth,
                                std::vector<MutationSpec>& mutations)
{
    if (numerics.size() < 4) return false;

    auto depth_opt = ReadNumeric(*numerics[0]);
    if (!depth_opt) return false;
    max_depth = *depth_opt;

    if (numerics.size() == 4 || numerics.size() == 5) {
        // Legacy format: single mutation at rung 0
        auto v1 = ReadNumeric(*numerics[1]);
        auto v2 = ReadNumeric(*numerics[2]);
        auto v3 = ReadNumeric(*numerics[3]);
        if (!v1 || !v2 || !v3) return false;
        mutations.push_back({0, *v1, *v2, *v3});
        return true;
    }

    // New format: numerics[1] = num_mutations, then 4 fields per mutation
    auto num_mutations_opt = ReadNumeric(*numerics[1]);
    if (!num_mutations_opt) return false;
    int64_t num_mutations = *num_mutations_opt;
    if (num_mutations < 1 || num_mutations > 64 ||
        static_cast<size_t>(2 + 4 * num_mutations) > numerics.size()) {
        return false;
    }
    for (int64_t i = 0; i < num_mutations; ++i) {
        size_t base = 2 + 4 * i;
        auto v0 = ReadNumeric(*numerics[base]);
        auto v1 = ReadNumeric(*numerics[base + 1]);
        auto v2 = ReadNumeric(*numerics[base + 2]);
        auto v3 = ReadNumeric(*numerics[base + 3]);
        if (!v0 || !v1 || !v2 || !v3) return false;
        mutations.push_back({*v0, *v1, *v2, *v3});
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
    auto until_height_opt = ReadNumeric(*until_height_field);
    if (!until_height_opt) {
        return EvalResult::ERROR;
    }
    int64_t until_height = *until_height_opt;
    // Use tx nLockTime as height proxy (like CLTV — consensus ensures tx can't
    // be included before nLockTime). If nLockTime >= until_height, covenant terminates.
    int64_t effective_height = ctx.block_height;
    if (ctx.tx && ctx.tx->lock_time < LOCKTIME_THRESHOLD) {
        effective_height = std::max(effective_height, static_cast<int64_t>(ctx.tx->lock_time));
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
        if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
            return EvalResult::UNSATISFIED;
        }
        std::vector<std::vector<std::vector<uint8_t>>> pks;
        if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
        if (output_root != ComputeConditionsRootMLSC(*ctx.input_conditions, pks)) {
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
    auto count_opt = ReadNumeric(*max_count);
    if (!count_opt) {
        return EvalResult::ERROR;
    }
    int64_t count = *count_opt;
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
                        auto cur = ReadNumeric(f);
                        if (!cur) return EvalResult::ERROR;
                        WriteNumericField(f, *cur - 1);
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
            auto cp = BuildCPRung(mutated, rung_pks, ctx.input_conditions->coil);
            uint256 new_leaf = ComputeTxMLSCLeaf(cp);
            uint256 expected_root = ComputeExpectedRoot(*ctx.verified_leaves,
                                                         ctx.verified_leaves->rung_index, new_leaf);
            uint256 output_root;
            if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
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
            if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
                return EvalResult::UNSATISFIED;
            }
            if (output_root != ComputeConditionsRootMLSC(expected, pks)) {
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
    auto max_splits_opt = ReadNumeric(*numerics[0]);
    auto min_split_sats_opt = ReadNumeric(*numerics[1]);
    if (!max_splits_opt || !min_split_sats_opt) {
        return EvalResult::ERROR;
    }
    int64_t max_splits = *max_splits_opt;
    int64_t min_split_sats = *min_split_sats_opt;
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
                        auto cur = ReadNumeric(f);
                        if (!cur) return EvalResult::ERROR;
                        WriteNumericField(f, *cur - 1);
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
            auto cp = BuildCPRung(mutated, rung_pks, ctx.input_conditions->coil);
            uint256 new_leaf = ComputeTxMLSCLeaf(cp);
            expected_root = ComputeExpectedRoot(*ctx.verified_leaves,
                                                ctx.verified_leaves->rung_index, new_leaf);
        } else {
            // Fallback: build full conditions with decremented rung
            RungConditions expected = *ctx.input_conditions;
            expected.rungs[0] = mutated;
            std::vector<std::vector<std::vector<uint8_t>>> pks;
            if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
            expected_root = ComputeConditionsRootMLSC(expected, pks);
        }

        int64_t total_output = 0;
        for (size_t voi = 0; voi < ctx.tx->output_count; ++voi) {
            const auto& vout = ctx.tx->outputs[voi];
            // DATA_RETURN outputs (value == 0) are exempt from covenant checks
            if (vout.value == 0) continue;
            if (vout.value < min_split_sats) {
                return EvalResult::UNSATISFIED;
            }
            total_output += vout.value;
            // Every spendable output must be MLSC with the expected root
            uint256 out_root;
            if (!GetMLSCRoot(vout.script_pub_key.as_span(), out_root)) {
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

// ============================================================================
// Compound evaluators (multi-block patterns in single block)
// ============================================================================

EvalResult EvalTimelockedSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
    EvalResult sig_result = VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker);
    if (sig_result != EvalResult::SATISFIED) return sig_result;

    // 2. Check CSV timelock (same logic as EvalCSVBlock)
    auto seq_opt = ReadNumeric(*numeric_field);
    if (!seq_opt) return EvalResult::ERROR;
    int64_t sequence_val = *seq_opt;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalHTLCBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
        if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) return EvalResult::UNSATISFIED;
    }

    // 3. Verify signature
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_field || !sig_field) return EvalResult::ERROR;

    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker);
}

EvalResult EvalHashSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker);
}

EvalResult EvalPTLCBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
        EvalResult r = VerifySigWithScheme(pk_field, *sig_field, nullptr, sig_checker);
        if (r == EvalResult::ERROR) return EvalResult::ERROR;
        if (r != EvalResult::SATISFIED) return EvalResult::UNSATISFIED;
    }

    // 2. Check CSV timelock
    auto seq_opt = ReadNumeric(*numeric_field);
    if (!seq_opt) return EvalResult::ERROR;
    int64_t sequence_val = *seq_opt;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVSigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
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
    EvalResult sig_result = VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker);
    if (sig_result != EvalResult::SATISFIED) return sig_result;

    // 2. Check CLTV (absolute timelock)
    auto locktime_opt = ReadNumeric(*numeric_field);
    if (!locktime_opt) return EvalResult::ERROR;
    int64_t locktime_val = *locktime_opt;
    if (!sig_checker.CheckLockTime(static_cast<uint32_t>(locktime_val))) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalTimelockedMultisigBlock(const RungBlock& block,
                        const api::LadderSigChecker& sig_checker)
{
    // TIMELOCKED_MULTISIG = MULTISIG + CSV in one block
    // merkle_pub_key: PUBKEYs in witness, bound by Merkle proof.
    // Fields: NUMERIC[0] (threshold M), N x PUBKEY (witness),
    //         M x SIGNATURE (witness), NUMERIC[1] (CSV timelock)

    // 1. Verify multisig (same logic as EvalMultisigBlock)
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    auto threshold_opt = ReadNumeric(*numerics[0]);
    if (!threshold_opt || *threshold_opt <= 0) return EvalResult::ERROR;
    int64_t threshold_val = *threshold_opt;
    uint32_t threshold = static_cast<uint32_t>(threshold_val);

    auto pubkeys = ResolvePubkeyCommitments(block);
    auto sigs = FindAllFields(block, RungDataType::SIGNATURE);

    if (pubkeys.empty() || threshold > pubkeys.size()) return EvalResult::ERROR;
    if (sigs.size() < threshold) return EvalResult::UNSATISFIED;

    // Multisig verification (VerifySigWithScheme handles SCHNORR / ECDSA /
    // PQ routing via the optional SCHEME field).
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    {
        std::vector<bool> pubkey_used(pubkeys.size(), false);
        uint32_t valid_count = 0;

        for (const auto* sig_f : sigs) {
            for (size_t k = 0; k < pubkeys.size(); ++k) {
                if (pubkey_used[k]) continue;
                RungField pk_field = *pubkeys[k];
                RungField sig_copy = *sig_f;
                EvalResult r = VerifySigWithScheme(pk_field, sig_copy, scheme_field, sig_checker);
                if (r == EvalResult::SATISFIED) {
                    pubkey_used[k] = true;
                    valid_count++;
                    break;
                }
                if (r == EvalResult::ERROR) return EvalResult::ERROR;
            }
        }

        if (valid_count < threshold) return EvalResult::UNSATISFIED;
    }

    // 2. Check CSV timelock (second NUMERIC field)
    auto seq_opt = ReadNumeric(*numerics[1]);
    if (!seq_opt) return EvalResult::ERROR;
    int64_t sequence_val = *seq_opt;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    if (!sig_checker.CheckSequence(static_cast<uint32_t>(sequence_val))) return EvalResult::UNSATISFIED;

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

    if (!ctx.tx_core) return EvalResult::ERROR; // fail-safe: no tx context

    int64_t tx_weight = GetTransactionWeight(*ctx.tx_core);
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
    return VerifySigWithScheme(pk_field, sig_copy, target_scheme, sig_checker);
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
    // Legacy wrappers use Core's BaseSignatureChecker, which verifies against
    // Core's legacy / SegWit / Taproot sighash — not the Ladder sighash that
    // PQ signatures commit to. Reject PQ schemes here: PQ sigs belong in
    // Ladder-native blocks (SIG, MULTISIG, etc.) and go through the
    // LadderSigChecker adapter.
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) return EvalResult::ERROR;
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
                                       const api::LadderSigChecker& sig_checker,
                                       const BaseSignatureChecker& legacy_checker,
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

            EvalResult result = EvalBlock(combined, sig_checker, legacy_checker, sigversion, execdata, ctx, depth);
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
    // P2PK_LEGACY: pubkey + sig, verified against Core's legacy ECDSA /
    // SegWit / Taproot sighash (not Ladder sighash — this is a legacy
    // wrapper, see Phase 1E.3 design note).
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    if (!pubkey_field || !sig_field) return EvalResult::ERROR;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigFromFields(*pubkey_field, *sig_field, scheme_field, checker, sigversion, execdata);
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
    // P2TR_LEGACY key-path: pubkey + sig against Core's Taproot sighash.
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    if (!pubkey_field || !sig_field) return EvalResult::ERROR;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigFromFields(*pubkey_field, *sig_field, scheme_field, checker, sigversion, execdata);
}

EvalResult EvalP2SHLegacyBlock(const RungBlock& block,
                                const api::LadderSigChecker& sig_checker,
                                const BaseSignatureChecker& legacy_checker,
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
    return EvalInnerConditions(preimage_field->data, block, sig_checker, legacy_checker, sigversion, execdata, ctx, depth + 1);
}

EvalResult EvalP2WSHLegacyBlock(const RungBlock& block,
                                 const api::LadderSigChecker& sig_checker,
                                 const BaseSignatureChecker& legacy_checker,
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
    return EvalInnerConditions(preimage_field->data, block, sig_checker, legacy_checker, sigversion, execdata, ctx, depth + 1);
}

EvalResult EvalP2TRScriptLegacyBlock(const RungBlock& block,
                                      const api::LadderSigChecker& sig_checker,
                                      const BaseSignatureChecker& legacy_checker,
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
    return EvalInnerConditions(preimage_field->data, block, sig_checker, legacy_checker, sigversion, execdata, ctx, depth + 1);
}

// ============================================================================
// QABI family — BIP-YYYY consensus evaluators
// ============================================================================
//
// Everything from here to the matching `#endif // ENABLE_QABIO` is gated
// on the ENABLE_QABIO compile flag. When the flag is off, the evaluator
// dispatch above returns UNSATISFIED for QABI_PRIME and QABI_SPEND block
// types (the base Ladder Script forward-compatibility rule) and these
// function definitions are not compiled.
#ifdef ENABLE_QABIO

/** QABI_PRIME — priming state transition.
 *
 *  Witness-only fields (in order):
 *    [0] HASH256  new_committed_root    (from witness)
 *    [1] NUMERIC  prime_depth           (from witness)
 *    [2] NUMERIC  new_committed_expiry  (from witness)
 *    [3] PREIMAGE prime_preimage        (from witness)
 *
 *  The "current state" (auth_tip, committed_root, committed_depth,
 *  committed_expiry, owner_pubkey_hash) is read from the input's QABI_SPEND
 *  block (searched across all rungs in ctx.input_conditions). QABI_PRIME
 *  does not duplicate state in its own committed fields.
 *
 *  Consensus checks:
 *    1. All 4 witness fields present, correctly typed, correct sizes
 *    2. Exactly one QABI_SPEND block is discoverable in input_conditions
 *    3. prime_depth > committed_depth                (monotonic progression)
 *    4. SHA256^prime_depth(prime_preimage) == auth_tip (preimage valid)
 *    5. Covenant: rebuild input_conditions with the QABI_SPEND block's
 *       committed_root/committed_depth/committed_expiry mutated to the new
 *       values, recompute the MLSC root, and verify it matches the output's
 *       committed conditions_root. Everything else (auth_tip, owner_pubkey,
 *       other rungs, coil data) must be preserved bit-exact.
 */
static EvalResult EvalQABIPrimeBlock(const RungBlock& block,
                                      const api::LadderSigChecker& /*sig_checker*/,
                                      const RungEvalContext& ctx)
{
    // -- Witness field extraction ---------------------------------------

    if (block.fields.size() != 4) return EvalResult::ERROR;

    const RungField* new_root_field   = FindField(block, RungDataType::HASH256);
    auto nums = FindAllFields(block, RungDataType::NUMERIC);
    const RungField* preimage_field   = FindField(block, RungDataType::PREIMAGE);

    if (!new_root_field || nums.size() != 2 || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (new_root_field->data.size() != 32) return EvalResult::ERROR;
    if (preimage_field->data.size() != 32) return EvalResult::ERROR;

    auto prime_depth_opt          = ReadNumeric(*nums[0]);
    auto new_committed_expiry_opt = ReadNumeric(*nums[1]);
    if (!prime_depth_opt || !new_committed_expiry_opt) return EvalResult::ERROR;
    if (*prime_depth_opt <= 0 || *new_committed_expiry_opt < 0) return EvalResult::ERROR;
    const int64_t prime_depth          = *prime_depth_opt;
    const int64_t new_committed_expiry = *new_committed_expiry_opt;

    if (prime_depth >= static_cast<int64_t>(rung::QABI_AUTH_CHAIN_DEFAULT_LENGTH * 10)) {
        return EvalResult::ERROR;
    }

    // -- Locate the QABI_SPEND block ------------------------------------
    //
    // QABI_PRIME's covenant check 5 needs the FULL input conditions tree
    // to recompute the mutated MLSC root. But for MLSC spends the
    // consensus-time ctx.input_conditions only carries the revealed
    // rung (1 entry — kept 1:1 with witness_ladder.rungs so the merge
    // pass works). The QABI_SPEND rung that carries committed state
    // must be revealed via the MLSC proof's `revealed_mutation_targets`
    // at sign time (signrungtx does this automatically when spending a
    // rung that contains QABI_PRIME).
    //
    // Build a "full tree" here by taking the revealed rung (placed at
    // its real index) and overlaying every mutation target at its own
    // real index. That tree is used for:
    //   (a) the QABI_SPEND lookup (block-type search across all rungs)
    //   (b) check 5's covenant root recomputation
    //
    // Non-revealed rungs are left as default-empty Rungs; they only
    // contribute if the spender reveals them as mutation targets.

    if (ctx.input_conditions == nullptr || ctx.spending_output == nullptr) {
        return EvalResult::ERROR;
    }
    if (ctx.mlsc_proof == nullptr) {
        // Unit-test fallback: no MLSC proof plumbed. Fall back to the
        // single-rung input_conditions layout used by unit tests that
        // build the full tree directly in ctx.
        RungConditions unit_test_full = *ctx.input_conditions;
        // Fall through using unit_test_full below.
        const RungBlock* qabi_spend = nullptr;
        size_t qabi_spend_rung_idx_ut = 0;
        size_t qabi_spend_block_idx_ut = 0;
        for (size_t r = 0; r < unit_test_full.rungs.size(); ++r) {
            const auto& rung = unit_test_full.rungs[r];
            for (size_t b = 0; b < rung.blocks.size(); ++b) {
                if (rung.blocks[b].type == RungBlockType::QABI_SPEND) {
                    if (qabi_spend != nullptr) return EvalResult::ERROR;
                    qabi_spend = &rung.blocks[b];
                    qabi_spend_rung_idx_ut = r;
                    qabi_spend_block_idx_ut = b;
                }
            }
        }
        if (qabi_spend == nullptr) return EvalResult::UNSATISFIED;
        // Run the rest of the checks against unit_test_full. The checks
        // below are copy-pasted from the mainline path to keep this
        // fallback self-contained.
        if (qabi_spend->fields.size() != 5) return EvalResult::ERROR;
        auto spend_hashes_ut = FindAllFields(*qabi_spend, RungDataType::HASH256);
        auto spend_nums_ut   = FindAllFields(*qabi_spend, RungDataType::NUMERIC);
        if (spend_hashes_ut.size() != 2 || spend_nums_ut.size() != 2) return EvalResult::ERROR;
        if (spend_hashes_ut[0]->data.size() != 32) return EvalResult::ERROR;
        const RungField* auth_tip_field_ut = spend_hashes_ut[0];
        auto committed_depth_opt_ut = ReadNumeric(*spend_nums_ut[0]);
        if (!committed_depth_opt_ut || *committed_depth_opt_ut < 0) return EvalResult::ERROR;
        const int64_t committed_depth_ut = *committed_depth_opt_ut;
        if (prime_depth <= committed_depth_ut) return EvalResult::UNSATISFIED;
        unsigned char current_ut[CSHA256::OUTPUT_SIZE];
        std::memcpy(current_ut, preimage_field->data.data(), 32);
        for (int64_t i = 0; i < prime_depth; ++i) {
            unsigned char next[CSHA256::OUTPUT_SIZE];
            CSHA256().Write(current_ut, 32).Finalize(next);
            std::memcpy(current_ut, next, 32);
        }
        if (std::memcmp(current_ut, auth_tip_field_ut->data.data(), 32) != 0) {
            return EvalResult::UNSATISFIED;
        }
        RungConditions expected = unit_test_full;
        Rung& mutated_rung = expected.rungs[qabi_spend_rung_idx_ut];
        RungBlock& mutated_block = mutated_rung.blocks[qabi_spend_block_idx_ut];
        std::vector<RungField*> m_hashes, m_nums;
        for (auto& f : mutated_block.fields) {
            if (f.type == RungDataType::HASH256) m_hashes.push_back(&f);
            else if (f.type == RungDataType::NUMERIC) m_nums.push_back(&f);
        }
        if (m_hashes.size() != 2 || m_nums.size() != 2) return EvalResult::ERROR;
        m_hashes[1]->data.assign(new_root_field->data.begin(), new_root_field->data.end());
        WriteNumericField(*m_nums[0], prime_depth);
        WriteNumericField(*m_nums[1], new_committed_expiry);
        std::vector<std::vector<std::vector<uint8_t>>> pks;
        if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
        uint256 expected_root = ComputeConditionsRootMLSC(expected, pks);
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
            return EvalResult::UNSATISFIED;
        }
        if (output_root != expected_root) return EvalResult::UNSATISFIED;
        return EvalResult::SATISFIED;
    }

    // Mainline path: reconstruct the full tree from the MLSC proof.
    RungConditions full_tree;
    full_tree.coil = ctx.input_conditions->coil;
    full_tree.rungs.resize(ctx.mlsc_proof->total_rungs);
    // Place the revealed rung at its real index.
    if (ctx.mlsc_proof->rung_index < full_tree.rungs.size() &&
        !ctx.input_conditions->rungs.empty()) {
        full_tree.rungs[ctx.mlsc_proof->rung_index] = ctx.input_conditions->rungs[0];
    }
    // Overlay mutation-target rungs + their pubkeys at their real
    // indices. The pubkey list travels inside each MLSCMutationTarget
    // (required for rungs with SIG/key-consuming blocks so the
    // consensus-time leaf hash matches bit-exact).
    std::vector<std::vector<std::vector<uint8_t>>> full_pks;
    full_pks.resize(ctx.mlsc_proof->total_rungs);
    for (const auto& target : ctx.mlsc_proof->revealed_mutation_targets) {
        if (target.idx < full_tree.rungs.size()) {
            full_tree.rungs[target.idx] = target.rung;
            full_pks[target.idx] = target.pubkeys;
        }
    }
    // Revealed rung sits at its real index.
    if (ctx.rung_pubkeys && !ctx.rung_pubkeys->empty() &&
        ctx.mlsc_proof->rung_index < full_pks.size()) {
        full_pks[ctx.mlsc_proof->rung_index] = (*ctx.rung_pubkeys)[0];
    }

    const RungBlock* qabi_spend = nullptr;
    size_t qabi_spend_rung_idx = 0;
    size_t qabi_spend_block_idx = 0;
    for (size_t r = 0; r < full_tree.rungs.size(); ++r) {
        const auto& rung = full_tree.rungs[r];
        for (size_t b = 0; b < rung.blocks.size(); ++b) {
            if (rung.blocks[b].type == RungBlockType::QABI_SPEND) {
                if (qabi_spend != nullptr) {
                    // Multiple QABI_SPEND blocks — ambiguous, reject.
                    return EvalResult::ERROR;
                }
                qabi_spend = &rung.blocks[b];
                qabi_spend_rung_idx = r;
                qabi_spend_block_idx = b;
            }
        }
    }
    if (qabi_spend == nullptr) {
        return EvalResult::UNSATISFIED;
    }

    // -- Read current state from QABI_SPEND -----------------------------
    //
    // input_conditions carries CONDITIONS-context blocks. QABI_SPEND in
    // conditions context has 5 fields (auth_tip, committed_root,
    // committed_depth, committed_expiry, owner_id) — the witness-only
    // PREIMAGE spend_preimage is not in the committed tree.
    if (qabi_spend->fields.size() != 5) return EvalResult::ERROR;
    auto spend_hashes = FindAllFields(*qabi_spend, RungDataType::HASH256);
    auto spend_nums   = FindAllFields(*qabi_spend, RungDataType::NUMERIC);
    if (spend_hashes.size() != 2 || spend_nums.size() != 2) return EvalResult::ERROR;
    if (spend_hashes[0]->data.size() != 32) return EvalResult::ERROR;

    const RungField* auth_tip_field        = spend_hashes[0];
    auto committed_depth_opt = ReadNumeric(*spend_nums[0]);
    if (!committed_depth_opt || *committed_depth_opt < 0) return EvalResult::ERROR;
    const int64_t committed_depth = *committed_depth_opt;

    // -- Check 3: monotonic depth progression ----------------------------

    if (prime_depth <= committed_depth) return EvalResult::UNSATISFIED;

    // -- Check 4: preimage valid against auth_tip ------------------------

    unsigned char current[CSHA256::OUTPUT_SIZE];
    std::memcpy(current, preimage_field->data.data(), 32);
    for (int64_t i = 0; i < prime_depth; ++i) {
        unsigned char next[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(current, 32).Finalize(next);
        std::memcpy(current, next, 32);
    }
    if (std::memcmp(current, auth_tip_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // -- Check 5: covenant — rebuild with mutated QABI_SPEND state -------

    RungConditions expected = full_tree;
    Rung& mutated_rung = expected.rungs[qabi_spend_rung_idx];
    RungBlock& mutated_block = mutated_rung.blocks[qabi_spend_block_idx];

    // Re-locate the fields in the mutated copy (same order preserved).
    auto m_hashes = std::vector<RungField*>{};
    auto m_nums   = std::vector<RungField*>{};
    for (auto& f : mutated_block.fields) {
        if (f.type == RungDataType::HASH256) m_hashes.push_back(&f);
        else if (f.type == RungDataType::NUMERIC) m_nums.push_back(&f);
    }
    if (m_hashes.size() != 2 || m_nums.size() != 2) return EvalResult::ERROR;

    // Mutate committed_root (HASH256 index 1 — second hash, first is auth_tip)
    m_hashes[1]->data.assign(new_root_field->data.begin(), new_root_field->data.end());

    // Mutate committed_depth (NUMERIC index 0)
    WriteNumericField(*m_nums[0], prime_depth);

    // Mutate committed_expiry (NUMERIC index 1)
    WriteNumericField(*m_nums[1], new_committed_expiry);

    // Compute expected MLSC root from the mutated full tree.
    uint256 expected_root = ComputeConditionsRootMLSC(expected, full_pks);

    // Extract the output's committed conditions_root.
    uint256 output_root;
    if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
        return EvalResult::UNSATISFIED;
    }

    if (output_root != expected_root) {
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::SATISFIED;
}

/** QABI_SPEND — fat evaluator doing nine consensus checks per primed input.
 *
 *  Block field layout (strict order):
 *    [0] HASH256       auth_tip           (committed; H^N(auth_seed))
 *    [1] HASH256       committed_root     (committed; current primed batch root)
 *    [2] NUMERIC       committed_depth    (committed; depth of last consumed preimage)
 *    [3] NUMERIC       committed_expiry   (committed; max block height for spend)
 *    [4] PUBKEY_COMMIT owner_pubkey_hash  (committed; = participant_id =
 *                                          SHA256(Rung 0 FALCON pubkey))
 *    [5] PREIMAGE      spend_preimage     (witness; preimage at committed_depth+1)
 *
 *  The nine checks in order:
 *    1. committed_root != 0                           (UTXO is primed)
 *    2. ctx.block_height <= committed_expiry          (batch not expired)
 *    3. SHA256^(committed_depth+1)(spend_preimage) == auth_tip
 *                                                     (spend preimage valid, deeper than priming)
 *    4. SHA256(tx.qabi_block) == committed_root       (root match)
 *    5. ParseQABIBlock(tx.qabi_block) succeeds        (block is well-formed)
 *    6. parsed_block.prime_expiry_height == committed_expiry  (expiry binding)
 *    7. owner_pubkey_hash appears in parsed_block.entries[*].participant_id
 *                                                     (identity in block)
 *    8. tx.conditions_root == parsed_block.outputs_conditions_root
 *       tx.vout.size() == parsed_block.output_values.size()
 *       tx.vout[i].nValue == parsed_block.output_values[i] for all i
 *                                                     (output-set binding —
 *                                                      closes coordinator-skim hole.
 *                                                      Per-output SPK is structurally
 *                                                      0xDF + tx.conditions_root for any
 *                                                      v4 MLSC tx, so binding
 *                                                      tx.conditions_root pins every
 *                                                      destination SPK without storing
 *                                                      them on the wire.)
 *    9. FalconVerify(coordinator_pubkey,
 *                    ComputeSighashQABO(tx),
 *                    tx.aggregated_sig) == VALID      (QABO sig valid)
 */
static EvalResult EvalQABISpendBlock(const RungBlock& block,
                                      const api::LadderSigChecker& /*sig_checker*/,
                                      const RungEvalContext& ctx)
{
    // Context safety
    if (ctx.tx == nullptr) return EvalResult::ERROR;

    // -- Field extraction & validation ----------------------------------

    if (block.fields.size() != 6) return EvalResult::ERROR;

    auto hashes = FindAllFields(block, RungDataType::HASH256);
    auto nums   = FindAllFields(block, RungDataType::NUMERIC);
    const RungField* commit_field   = FindField(block, RungDataType::PUBKEY_COMMIT);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);

    if (hashes.size() != 2 || nums.size() != 2 || !commit_field || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (hashes[0]->data.size() != 32) return EvalResult::ERROR;
    if (hashes[1]->data.size() != 32) return EvalResult::ERROR;
    if (commit_field->data.size() != 32) return EvalResult::ERROR;
    if (preimage_field->data.size() != 32) return EvalResult::ERROR;

    const RungField* auth_tip_field       = hashes[0];
    const RungField* committed_root_field = hashes[1];

    auto committed_depth_opt  = ReadNumeric(*nums[0]);
    auto committed_expiry_opt = ReadNumeric(*nums[1]);
    if (!committed_depth_opt || !committed_expiry_opt) return EvalResult::ERROR;
    if (*committed_depth_opt < 0 || *committed_expiry_opt < 0) return EvalResult::ERROR;
    const int64_t committed_depth  = *committed_depth_opt;
    const int64_t committed_expiry = *committed_expiry_opt;

    // Sanity ceiling on depth to bound the hash-chain walk cost.
    if (committed_depth >= static_cast<int64_t>(rung::QABI_AUTH_CHAIN_DEFAULT_LENGTH * 10)) {
        return EvalResult::ERROR;
    }

    // -- Check 1: UTXO is primed ----------------------------------------

    const bool all_zero = std::all_of(committed_root_field->data.begin(),
                                       committed_root_field->data.end(),
                                       [](uint8_t b) { return b == 0; });
    if (all_zero) return EvalResult::UNSATISFIED;

    // -- Check 2: expiry window -----------------------------------------

    if (static_cast<int64_t>(ctx.block_height) > committed_expiry) {
        return EvalResult::UNSATISFIED;
    }

    // -- Check 3: spend preimage at depth committed_depth+1 -------------

    unsigned char current[CSHA256::OUTPUT_SIZE];
    std::memcpy(current, preimage_field->data.data(), 32);
    const int64_t total_iterations = committed_depth + 1;
    for (int64_t i = 0; i < total_iterations; ++i) {
        unsigned char next[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(current, 32).Finalize(next);
        std::memcpy(current, next, 32);
    }
    if (std::memcmp(current, auth_tip_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // -- Checks 4 + 5 + 8 + 9 are cacheable (tx-level, not per-input) ---
    //
    // Four of the nine checks depend only on tx-level state:
    //   (4) SHA256(tx.qabi_block) == committed_root
    //   (5) ParseQABIBlock(tx.qabi_block)
    //   (8) tx.vout bit-exact equal to parsed.outputs
    //   (9) FalconVerify(coordinator_pubkey, sighash, aggregated_sig)
    //
    // Per-input checks 1, 2, 3, 6, 7 must still run for every input
    // (primed state, expiry, preimage, expiry binding, identity match).
    //
    // Cache key is sighash — constant within a single tx.

    if (ctx.tx->qabi_block_size == 0) return EvalResult::UNSATISFIED;

    uint256 sighash = rung::api::ComputeSighashQABO(*ctx.tx);

    const rung::QABIBlock* parsed_ptr = nullptr;
    const uint8_t* qabi_root_hash_ptr = nullptr;
    uint256 fresh_root_hash;
    std::shared_ptr<const rung::QABIBlock> fresh_parsed;
    bool sig_ok = false;
    bool vout_matches_outputs = false;
    bool need_tx_level_checks = true;
    // Pointer to the hash-indexed participant_id set for check 7. On
    // cache hit, borrows the set stored in the cache entry. On cache
    // miss, points to a fresh set built during the block parse below.
    const std::unordered_set<uint256, QABIUint256Hasher>* entries_set_ptr = nullptr;
    std::unordered_set<uint256, QABIUint256Hasher> fresh_entries_set;

    if (ctx.qabo_sig_cache != nullptr) {
        auto it = ctx.qabo_sig_cache->find(sighash);
        if (it != ctx.qabo_sig_cache->end()) {
            // Cache HIT: read the pre-computed tx-level results.
            // If any tx-level check failed (bad parse, wrong sig,
            // vout mismatch), the cached entry reflects that and we
            // short-circuit without re-running any expensive work.
            if (!it->second.sig_ok || !it->second.parsed ||
                !it->second.vout_matches_outputs) {
                return EvalResult::UNSATISFIED;
            }
            parsed_ptr = it->second.parsed.get();
            qabi_root_hash_ptr = it->second.computed_root.begin();
            sig_ok = it->second.sig_ok;
            vout_matches_outputs = it->second.vout_matches_outputs;
            entries_set_ptr = &it->second.entries_set;
            need_tx_level_checks = false;
        }
    }

    auto cache_failure = [&](const uint256& root,
                              std::shared_ptr<const rung::QABIBlock> p,
                              bool sig, bool vout_ok) {
        if (ctx.qabo_sig_cache != nullptr) {
            QABOVerifiedEntry neg;
            neg.sig_ok = sig;
            neg.computed_root = root;
            neg.parsed = std::move(p);
            neg.vout_matches_outputs = vout_ok;
            ctx.qabo_sig_cache->emplace(sighash, std::move(neg));
        }
    };

    if (need_tx_level_checks) {
        // Cache MISS — run the four tx-level checks and populate the
        // cache. All failure paths still populate the cache (with a
        // negative result) so subsequent inputs short-circuit.

        // Check 4: SHA256 of qabi_block.
        CSHA256()
            .Write(ctx.tx->qabi_block, ctx.tx->qabi_block_size)
            .Finalize(fresh_root_hash.begin());
        qabi_root_hash_ptr = fresh_root_hash.begin();

        // Check 5: parse the block.
        std::string parse_err;
        std::vector<uint8_t> qabi_bytes(ctx.tx->qabi_block, ctx.tx->qabi_block + ctx.tx->qabi_block_size);
        auto parsed_opt = rung::ParseQABIBlock(qabi_bytes, parse_err);
        if (!parsed_opt) {
            cache_failure(fresh_root_hash, nullptr, false, false);
            return EvalResult::UNSATISFIED;
        }
        fresh_parsed = std::make_shared<const rung::QABIBlock>(std::move(*parsed_opt));
        parsed_ptr = fresh_parsed.get();

        // Build the hash-indexed participant_id set. Single O(N) pass
        // over parsed.entries now; subsequent inputs get O(1) lookups
        // instead of O(N) linear scans, collapsing check 7's total
        // work from O(N²) to O(N) per QABIO tx.
        fresh_entries_set.reserve(parsed_ptr->entries.size());
        for (const auto& e : parsed_ptr->entries) {
            fresh_entries_set.insert(e.participant_id);
        }
        entries_set_ptr = &fresh_entries_set;

        // Check 8: bind tx.conditions_root to the participants' agreed root,
        // and verify the per-output values match. The per-output scriptPubKey
        // is structurally 0xDF + tx.conditions_root for any v4 MLSC tx, so
        // binding tx.conditions_root pins every destination SPK without
        // storing them on the wire.
        vout_matches_outputs = true;
        if (!ctx.tx->conditions_root ||
            std::memcmp(ctx.tx->conditions_root,
                        parsed_ptr->outputs_conditions_root.data(), 32) != 0) {
            vout_matches_outputs = false;
        } else if (ctx.tx->output_count != parsed_ptr->output_values.size()) {
            vout_matches_outputs = false;
        } else {
            for (size_t i = 0; i < parsed_ptr->output_values.size(); ++i) {
                if (ctx.tx->outputs[i].value != parsed_ptr->output_values[i]) {
                    vout_matches_outputs = false;
                    break;
                }
            }
        }
        if (!vout_matches_outputs) {
            cache_failure(fresh_root_hash, fresh_parsed, false, false);
            return EvalResult::UNSATISFIED;
        }

        // Check 9: FALCON verify.
        if (ctx.tx->aggregated_sig_size != rung::QABI_AGGREGATED_SIG_MAX) {
            cache_failure(fresh_root_hash, fresh_parsed, false, true);
            return EvalResult::UNSATISFIED;
        }
        if (parsed_ptr->coordinator_pubkey.size() != rung::QABI_COORDINATOR_PUBKEY_SIZE) {
            cache_failure(fresh_root_hash, fresh_parsed, false, true);
            return EvalResult::UNSATISFIED;
        }
        sig_ok = rung::VerifyPQSignature(
            rung::RungScheme::FALCON512,
            std::span<const uint8_t>(ctx.tx->aggregated_sig, ctx.tx->aggregated_sig_size),
            std::span<const uint8_t>(sighash.begin(), 32),
            std::span<const uint8_t>(parsed_ptr->coordinator_pubkey.data(),
                                      parsed_ptr->coordinator_pubkey.size()));

        // Populate the cache. Even on sig_ok == false we cache it so
        // subsequent inputs short-circuit. Move the hash-indexed set
        // into the cached entry so subsequent inputs borrow it.
        if (ctx.qabo_sig_cache != nullptr) {
            QABOVerifiedEntry entry;
            entry.sig_ok = sig_ok;
            entry.computed_root = fresh_root_hash;
            entry.parsed = fresh_parsed;
            entry.vout_matches_outputs = vout_matches_outputs;
            entry.entries_set = std::move(fresh_entries_set);
            auto [it_inserted, was_inserted] =
                ctx.qabo_sig_cache->emplace(sighash, std::move(entry));
            // After the move, re-point entries_set_ptr at the cached
            // copy since fresh_entries_set is now empty.
            if (was_inserted) {
                entries_set_ptr = &it_inserted->second.entries_set;
            }
        }

        if (!sig_ok) return EvalResult::UNSATISFIED;
    }

    // ---- Per-input checks (always run, never cached) ------------------

    // Check 4: verify the cached/computed qabi_block hash matches this
    // input's committed_root (which is per-input committed state).
    if (std::memcmp(qabi_root_hash_ptr, committed_root_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    const rung::QABIBlock& parsed = *parsed_ptr;

    // Check 6: expiry binding — this input's committed_expiry must match
    // block.prime_expiry_height.
    if (static_cast<int64_t>(parsed.prime_expiry_height) != committed_expiry) {
        return EvalResult::UNSATISFIED;
    }

    // Check 7: this input's owner_id must appear in block.entries.
    // Uses the hash-indexed set built once per tx (during cache-miss
    // parse) — O(1) lookup instead of O(N) linear scan. Total identity-
    // check work across all inputs drops from O(N²) to O(N).
    uint256 my_id;
    std::memcpy(my_id.begin(), commit_field->data.data(), 32);
    if (entries_set_ptr != nullptr) {
        if (entries_set_ptr->count(my_id) == 0) return EvalResult::UNSATISFIED;
    } else {
        // Fallback: no set available (shouldn't happen in practice —
        // set is built during cache-miss regardless of whether the
        // cache pointer is non-null). Scan linearly just in case.
        bool identity_found = false;
        for (const auto& e : parsed.entries) {
            if (e.participant_id == my_id) {
                identity_found = true;
                break;
            }
        }
        if (!identity_found) return EvalResult::UNSATISFIED;
    }

    // Final sig check (respects cached or fresh result).
    if (!sig_ok) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

#endif // ENABLE_QABIO

// ============================================================================
// Block dispatch
// ============================================================================

EvalResult EvalBlock(const RungBlock& block,
                     const api::LadderSigChecker& sig_checker,
                     const BaseSignatureChecker& legacy_checker,
                     SigVersion sigversion,
                     ScriptExecutionData& execdata,
                     const RungEvalContext& ctx,
                     int depth)
{
    ladder_init();  // no-op after the first call

    // Defense in depth: reject inverted key-consuming blocks.
    if (block.inverted && !IsInvertibleBlockType(block.type)) {
        return EvalResult::ERROR;
    }

    BlockEvaluator fn = LookupBlockEvaluator(block.type);
    if (!fn) {
        // Not registered. Pre-soft-fork nodes must treat unknown block types as
        // UNSATISFIED (forward-compat — newer BIPs can add block types, and old
        // nodes see those spends as anyone-can-spend at the Ladder layer).
        // ApplyInversion flips UNKNOWN to ERROR, which is the correct behaviour
        // for an inverted unknown block: "unknown must not satisfy".
        return ApplyInversion(EvalResult::UNKNOWN_BLOCK_TYPE, block.inverted);
    }

    const BlockDispatchContext dctx{sig_checker, legacy_checker, sigversion,
                                     execdata, ctx, depth};
    return ApplyInversion(fn(block, dctx), block.inverted);
}

bool EvalRelays(const std::vector<Relay>& relays,
                const api::LadderSigChecker& sig_checker,
                const BaseSignatureChecker& legacy_checker,
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
            EvalResult result = EvalBlock(block, sig_checker, legacy_checker, sigversion, execdata, relay_ctx);
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
                    const api::LadderSigChecker& sig_checker,
                    const BaseSignatureChecker& legacy_checker,
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
        EvalResult result = EvalBlock(block, sig_checker, legacy_checker, sigversion, execdata, ctx);
        if (result != EvalResult::SATISFIED) {
            return result;
        }
    }
    return EvalResult::SATISFIED;
}

bool EvalLadder(const LadderWitness& ladder,
                const api::LadderSigChecker& sig_checker,
                const BaseSignatureChecker& legacy_checker,
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
        if (!EvalRelays(ladder.relays, sig_checker, legacy_checker, sigversion, execdata, ctx, relay_results)) {
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
        EvalResult result = EvalRung(rung, sig_checker, legacy_checker, sigversion, execdata, rung_ctx, relay_ptr);
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


namespace api {

bool ValidateRungOutputs(const LadderTxView& tx, uint32_t /*flags*/, std::string& error)
{
    size_t data_return_count = 0;

    for (size_t i = 0; i < tx.output_count; ++i) {
        const auto spk = tx.outputs[i].script_pub_key.as_span();
        const int64_t value = tx.outputs[i].value;

        // MLSC output: 0xDF + 32 bytes (+ optional DATA_RETURN payload)
        if (IsMLSCScript(spk)) {
            // MLSC with DATA_RETURN payload (> 33 bytes)
            if (HasMLSCData(spk)) {
                data_return_count++;
                // Must be zero-value (unspendable)
                if (value != 0) {
                    error = "output " + std::to_string(i) + ": DATA_RETURN output must have zero value";
                    return false;
                }
            } else {
                // Consensus dust threshold: non-DATA_RETURN outputs must carry
                // minimum value to prevent UTXO set bloat and cheap spam.
                if (value < MIN_RUNG_OUTPUT_VALUE) {
                    error = "output " + std::to_string(i) + ": value " +
                            std::to_string(value) + " below minimum " +
                            std::to_string(MIN_RUNG_OUTPUT_VALUE);
                    return false;
                }
            }
            continue;
        }

        // Only MLSC (0xDF) outputs are accepted in v4. Everything else
        // (OP_RETURN, P2TR, P2WPKH, 0xC1, arbitrary data) is rejected.
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

} // namespace api

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
            // QABI_SPEND preimages are exempt from the per-tx spam limit:
            // their count is already bounded by the qabi_block entry count
            // (max STANDARD_RELAY_MAX_N), and the preimage is consensus-
            // validated against the auth chain — not arbitrary data.
            if (block.type == RungBlockType::QABI_SPEND) continue;
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
static size_t CountTxPreimageFields(const LadderTxView& tx)
{
    size_t total = 0;
    for (size_t i = 0; i < tx.input_count; ++i) {
        const auto& witness = tx.inputs[i].witness;
        if (witness.count < 2 || witness.count > 3) continue;

        const auto& stack0 = witness.elements[0];
        std::vector<uint8_t> bytes(stack0.data, stack0.data + stack0.size);

        LadderWitness lw;
        std::string err;
        if (!DeserializeLadderWitness(bytes, lw, err)) continue;

        total += CountWitnessPreimageFields(lw);
    }
    return total;
}

namespace api {

bool CheckRungTxLevel(const LadderTxView& tx, uint32_t flags, std::string& error)
{
    // Consensus: validate all outputs are valid Ladder Script format.
    // Ensures only MLSC (0xDF) outputs, max 1 DATA_RETURN, dust threshold.
    if (!ValidateRungOutputs(tx, flags, error)) {
        return false;
    }

    // Consensus: PREIMAGE/SCRIPT_BODY field count across ALL inputs.
    if (CountTxPreimageFields(tx) > MAX_PREIMAGE_FIELDS_PER_TX) {
        error = "TX_MLSC: per-tx preimage field count exceeds limit";
        return false;
    }

    return true;
}

} // namespace api

bool VerifyRungTx(const CTransaction& tx,
                  unsigned int nIn,
                  const CTxOut& spent_output,
                  unsigned int flags,
                  const BaseSignatureChecker& checker,
                  const PrecomputedTransactionData& txdata,
                  ScriptError* serror,
                  int32_t block_height,
                  SharedTreeCache* shared_cache,
                  QABOSigCache* qabo_sig_cache)
{
    if (nIn >= tx.vin.size()) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    // Per-transaction checks: only run on first input (same result for all inputs).
    // Note: for wallet-funded v4 txs (where input 0 is a standard P2WPKH/P2TR
    // spend), VerifyRungTx is never called — the tx-level checks in
    // CheckRungTxLevel must be invoked separately from the tx-level validator
    // (src/validation.cpp CheckInputScripts) so the rules apply regardless
    // of input types. The call here is a safety net for pure-MLSC txs and
    // is redundant (but harmless) when CheckRungTxLevel has already run.
    // Build adapter views once at function scope. RungEvalContext carries
    // these to every EvalBlock and QABI_SPEND, keeping the library code
    // on the api side of the boundary.
    LadderTxViewBuilder tx_view_builder(tx);
    LadderPrecomputedBuilder precomputed_builder(txdata);

    if (nIn == 0) {
        std::string tx_error;
        if (!api::CheckRungTxLevel(tx_view_builder.view, flags, tx_error)) {
            LogPrintf("TX_MLSC tx-level check failed: %s\n", tx_error);
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }
    } // end nIn == 0

    const auto& witness = tx.vin[nIn].scriptWitness;

    // Witness stack size determines spending path:
    //   1 element  = key-path spend (signature only)
    //   2 elements = script-path, no tweak check (LadderWitness + MLSCProof)
    //   3 elements = script-path with tweak (LadderWitness + MLSCProof + internal_pubkey)
    if (witness.stack.empty() || witness.stack.size() > 3) {
        if (serror) *serror = SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
        return false;
    }

    // ================================================================
    // Dispatch invariant — defense in depth.
    //
    // VerifyRungTx must only ever be called for inputs spending an MLSC
    // scriptPubKey (0xDF prefix). The actual dispatch lives in
    // src/validation.cpp (CScriptCheck::operator()), gated by:
    //   tx.version == RUNG_TX_VERSION && IsMLSCScript(spent_pk)
    //
    // That gate makes ladder-vs-taproot witness "mixing" structurally
    // impossible: P2TR (OP_1 + 32B) and MLSC (0xDF + 32B) have disjoint
    // scriptPubKey prefixes, so a single input is dispatched to exactly
    // one parser based on the spent output, never both. The witness
    // stack is interpreted by the parser the dispatch chose; ladder
    // bytes never reach the taproot interpreter and vice versa.
    //
    // This check is the safety net: if a future refactor changes the
    // dispatch in validation.cpp, ladder code still refuses to evaluate
    // a non-MLSC scriptPubKey instead of silently mis-interpreting the
    // witness as ladder. Do not weaken or remove without auditing
    // every call site of VerifyRungTx.
    // ================================================================
    if (!IsMLSCScript(spent_output.scriptPubKey)) {
        LogPrintf("VerifyRungTx called on non-MLSC scriptPubKey — dispatch invariant violated\n");
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
            LogPrintf("MLSC proof deserialization failed: %s\n", proof_error);
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

        // Mutation target pubkeys now travel inline inside each
        // MLSCMutationTarget — no parallel vector needed here.

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
                if (total_leaves > MAX_RUNGS + MAX_RELAYS + 1) {
                    LogPrintf("MLSC proof: total_leaves %zu exceeds maximum\n", total_leaves);
                    if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                    return false;
                }
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
            // 2-element witness: verify the Merkle proof directly against conditions_root
            // (no tweak — the output was created without an internal_pubkey).
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
                if (total_leaves > MAX_RUNGS + MAX_RELAYS + 1) {
                    LogPrintf("MLSC proof: total_leaves %zu exceeds maximum\n", total_leaves);
                    if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
                    return false;
                }
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

        // Build RungConditions from MLSC proof. conditions.rungs is
        // kept at exactly 1 rung (the revealed one) so it stays 1:1
        // with witness_ladder.rungs for MergeConditionsAndWitness.
        // Cross-rung covenant checks (QABI_PRIME) read the full tree
        // indirectly via ctx.mlsc_proof->revealed_mutation_targets.
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
    eval_ctx.tx = &tx_view_builder.view;
    eval_ctx.tx_core = &tx;
    eval_ctx.input_index = nIn;
    eval_ctx.input_amount = spent_output.nValue;
    eval_ctx.block_height = block_height;
    // Use the output matching coil.output_index for covenant amount checks
    {
        uint32_t coil_out_idx = witness_ladder.coil.output_index;
        if (coil_out_idx < tx_view_builder.output_views.size()) {
            eval_ctx.output_amount = tx_view_builder.output_views[coil_out_idx].value;
            eval_ctx.spending_output = &tx_view_builder.output_views[coil_out_idx];
        } else if (!tx_view_builder.output_views.empty()) {
            eval_ctx.output_amount = tx_view_builder.output_views[0].value;
            eval_ctx.spending_output = &tx_view_builder.output_views[0];
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
    if (precomputed_builder.view.spent_output_count > 0) {
        eval_ctx.spent_outputs = precomputed_builder.view.spent_outputs;
        eval_ctx.spent_output_count = precomputed_builder.view.spent_output_count;
    }
    // Plumb the QABO sig cache through so QABI_SPEND can short-circuit
    // duplicate FALCON verifications across primed inputs of the same tx.
    eval_ctx.qabo_sig_cache = qabo_sig_cache;

    LadderWitness eval_ladder;
    ScriptExecutionData execdata;

    if (has_conditions) {
        // Merge conditions with witness
        std::string merge_error;
        if (!MergeConditionsAndWitness(conditions, witness_ladder, eval_ladder, merge_error)) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        CoreLadderSigChecker sig_checker(checker, txdata, tx, nIn, conditions);
        if (!EvalLadder(eval_ladder, sig_checker, checker, SigVersion::LADDER, execdata, eval_ctx)) {
            if (serror) *serror = SCRIPT_ERR_EVAL_FALSE;
            return false;
        }
    } else {
        // Bootstrap spend: v4 tx spending a v1/v2 UTXO
        RungConditions empty_conditions;
        CoreLadderSigChecker sig_checker(checker, txdata, tx, nIn, empty_conditions);
        if (!EvalLadder(witness_ladder, sig_checker, checker, SigVersion::LADDER, execdata, eval_ctx)) {
            if (serror) *serror = SCRIPT_ERR_EVAL_FALSE;
            return false;
        }
    }

    return true;
}

// ============================================================================
// Block-type dispatch registry
// ============================================================================
//
// Each Ladder block family exports a `register_<family>_blocks()` function
// below. `ladder_init()` calls them all at first use. The goal is selective
// compilation: a host that wants to ship a reduced block set (BIP sub-
// proposal opt-out, fuzz harness, kernel library, etc.) defines the
// corresponding `LADDER_NO_<FAMILY>` macro and that family is stripped from
// the build. Block types whose evaluators never register behave as
// UNKNOWN_BLOCK_TYPE at dispatch time — the same forward-compat semantics
// used for genuinely unknown block types.

namespace {
// RungBlockType is a uint16_t enum (rung/types.h), using values up to at
// least 0x0A02 (QABI_SPEND). A 65536-slot direct-lookup array costs ~512 KB
// of BSS and amortises to a single load per dispatch — cheaper than a hash
// map for a hot consensus path.
std::array<BlockEvaluator, 0x10000> g_block_registry{};
} // namespace

void RegisterBlock(RungBlockType type, BlockEvaluator fn)
{
    g_block_registry[static_cast<uint16_t>(type)] = fn;
}

BlockEvaluator LookupBlockEvaluator(RungBlockType type)
{
    return g_block_registry[static_cast<uint16_t>(type)];
}

// ---- Family: signature ----
#ifndef LADDER_NO_SIG
void register_sig_blocks()
{
    RegisterBlock(RungBlockType::SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalSigBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::MULTISIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalMultisigBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::ADAPTOR_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalAdaptorSigBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::MUSIG_THRESHOLD, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalMusigThresholdBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::KEY_REF_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalKeyRefSigBlock(b, d.sig_checker, d.ctx);
    });
    // EvalHashPreimageBlock / EvalHash160PreimageBlock have no dedicated
    // RungBlockType — they are helpers invoked from inside other block
    // evaluators (e.g. HTLC preimage check), not dispatched directly.
}
#else
void register_sig_blocks() {}
#endif

// ---- Family: timelock ----
#ifndef LADDER_NO_TIMELOCK
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
#else
void register_timelock_blocks() {}
#endif

// ---- Family: hash ----
#ifndef LADDER_NO_HASH
void register_hash_blocks()
{
    RegisterBlock(RungBlockType::TAGGED_HASH, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalTaggedHashBlock(b);
    });
    RegisterBlock(RungBlockType::HASH_GUARDED, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalHashGuardedBlock(b);
    });
}
#else
void register_hash_blocks() {}
#endif

// ---- Family: covenant ----
#ifndef LADDER_NO_COVENANT
void register_covenant_blocks()
{
    RegisterBlock(RungBlockType::CTV, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCTVBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::VAULT_LOCK, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalVaultLockBlock(b, d.sig_checker);
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
#else
void register_covenant_blocks() {}
#endif

// ---- Family: anchor ----
#ifndef LADDER_NO_ANCHOR
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
#else
void register_anchor_blocks() {}
#endif

// ---- Family: recursion ----
#ifndef LADDER_NO_RECURSION
void register_recursion_blocks()
{
    RegisterBlock(RungBlockType::RECURSE_SAME, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseSameBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_MODIFIED, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseModifiedBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_UNTIL, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseUntilBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_COUNT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseCountBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_SPLIT, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseSplitBlock(b, d.ctx);
    });
    RegisterBlock(RungBlockType::RECURSE_DECAY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalRecurseDecayBlock(b, d.ctx);
    });
}
#else
void register_recursion_blocks() {}
#endif

// ---- Family: PLC (hysteresis / timer / latch / counter / compare / sequencer / one-shot / rate-limit / cosign) ----
#ifndef LADDER_NO_PLC
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
#else
void register_plc_blocks() {}
#endif

// ---- Family: compound (combinations of sig + timelock + hash in one block) ----
#ifndef LADDER_NO_COMPOUND
void register_compound_blocks()
{
    RegisterBlock(RungBlockType::TIMELOCKED_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalTimelockedSigBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::HTLC, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalHTLCBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::HASH_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalHashSigBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::PTLC, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalPTLCBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::CLTV_SIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalCLTVSigBlock(b, d.sig_checker);
    });
    RegisterBlock(RungBlockType::TIMELOCKED_MULTISIG, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalTimelockedMultisigBlock(b, d.sig_checker);
    });
}
#else
void register_compound_blocks() {}
#endif

// ---- Family: governance (tx-level constraints) ----
#ifndef LADDER_NO_GOVERNANCE
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
#else
void register_governance_blocks() {}
#endif

// ---- Family: legacy P2* wrappers ----
#ifndef LADDER_NO_LEGACY
void register_legacy_blocks()
{
    RegisterBlock(RungBlockType::P2PK_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2PKLegacyBlock(b, d.legacy_checker, d.sigversion, d.execdata);
    });
    RegisterBlock(RungBlockType::P2PKH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2PKHLegacyBlock(b, d.legacy_checker, d.sigversion, d.execdata);
    });
    RegisterBlock(RungBlockType::P2SH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2SHLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
    RegisterBlock(RungBlockType::P2WPKH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2WPKHLegacyBlock(b, d.legacy_checker, d.sigversion, d.execdata);
    });
    RegisterBlock(RungBlockType::P2WSH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2WSHLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
    RegisterBlock(RungBlockType::P2TR_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2TRLegacyBlock(b, d.legacy_checker, d.sigversion, d.execdata);
    });
    RegisterBlock(RungBlockType::P2TR_SCRIPT_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2TRScriptLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
}
#else
void register_legacy_blocks() {}
#endif

// ---- Family: QABIO (BIP-YYYY) ----
#ifdef ENABLE_QABIO
void register_qabi_blocks()
{
    RegisterBlock(RungBlockType::QABI_PRIME, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalQABIPrimeBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::QABI_SPEND, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalQABISpendBlock(b, d.sig_checker, d.ctx);
    });
}
#else
// Stub: QABIO types still parse on the wire but evaluate to UNSATISFIED on
// nodes that didn't compile in the extension (soft-fork forward compat).
static void register_qabi_stub()
{
    RegisterBlock(RungBlockType::QABI_PRIME, [](const RungBlock&, const BlockDispatchContext&) {
        return EvalResult::UNSATISFIED;
    });
    RegisterBlock(RungBlockType::QABI_SPEND, [](const RungBlock&, const BlockDispatchContext&) {
        return EvalResult::UNSATISFIED;
    });
}
#endif

namespace api {
void ladder_init()
{
    static const bool initialised = []() {
        register_sig_blocks();
        register_timelock_blocks();
        register_hash_blocks();
        register_covenant_blocks();
        register_anchor_blocks();
        register_recursion_blocks();
        register_plc_blocks();
        register_compound_blocks();
        register_governance_blocks();
        register_legacy_blocks();
#ifdef ENABLE_QABIO
        register_qabi_blocks();
#else
        register_qabi_stub();
#endif
        return true;
    }();
    (void)initialised;
}

void ladder_shutdown()
{
    // No-op for now. The registry is constructed lazily inside ladder_init
    // and persists for the process lifetime. Test fixtures that want a
    // clean registry per run should live with this — re-registration
    // overwrites previous entries.
}
}  // namespace api

} // namespace rung
