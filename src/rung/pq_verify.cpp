// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/pq_verify.h>

#include <logging.h>

#ifndef HAVE_LIBOQS
#error \
    "Ladder Script consensus requires liboqs. Building without it would " \
    "produce a binary that silently disagrees with liboqs-enabled nodes " \
    "on every PQ signature, splitting the network. Set HAVE_LIBOQS via " \
    "find_package(liboqs REQUIRED) (see src/rung/CMakeLists.txt) and " \
    "rebuild."
#endif

#include <oqs/oqs.h>

namespace rung {

bool HasPQSupport()
{
    // Compile-time guaranteed by the #error above. The runtime function
    // is kept as a stable ABI surface for code that wants to advertise
    // PQ support to RPC / tooling, but in this build it always returns
    // true — a binary without liboqs cannot exist.
    return true;
}

static const char* SchemeToAlgName(RungScheme scheme)
{
    switch (scheme) {
    case RungScheme::FALCON512:   return OQS_SIG_alg_falcon_512;
    case RungScheme::FALCON1024:  return OQS_SIG_alg_falcon_1024;
    case RungScheme::DILITHIUM3:  return OQS_SIG_alg_dilithium_3;
    case RungScheme::SPHINCS_SHA: return OQS_SIG_alg_sphincs_sha2_256f_simple;
    default: return nullptr;
    }
}

bool VerifyPQSignature(RungScheme scheme,
                       std::span<const uint8_t> sig,
                       std::span<const uint8_t> msg,
                       std::span<const uint8_t> pubkey)
{
    const char* alg_name = SchemeToAlgName(scheme);
    if (!alg_name) return false;

    OQS_SIG* oqs_sig = OQS_SIG_new(alg_name);
    if (!oqs_sig) {
        LogPrintf("PQ: Failed to initialize algorithm %s\n", alg_name);
        return false;
    }

    // Validate key and signature sizes match the scheme before calling OQS.
    if (pubkey.size() != oqs_sig->length_public_key) {
        LogPrintf("PQ: pubkey size mismatch for %s: got %zu, expected %zu\n",
                  alg_name, pubkey.size(), oqs_sig->length_public_key);
        OQS_SIG_free(oqs_sig);
        return false;
    }

    // FALCON signatures are variable-length up to length_signature.
    // Dilithium and SPHINCS+ are fixed-length — accept only the exact size.
    // This prevents under-sized payloads from reaching OQS_SIG_verify, where
    // different liboqs versions might handle them inconsistently and produce
    // a consensus split.
    const bool is_variable_length =
        (scheme == RungScheme::FALCON512 || scheme == RungScheme::FALCON1024);
    const bool sig_size_ok = is_variable_length
        ? (sig.size() > 0 && sig.size() <= oqs_sig->length_signature)
        : (sig.size() == oqs_sig->length_signature);
    if (!sig_size_ok) {
        LogPrintf("PQ: signature size invalid for %s: got %zu, expected %s%zu\n",
                  alg_name, sig.size(),
                  is_variable_length ? "<=" : "==",
                  oqs_sig->length_signature);
        OQS_SIG_free(oqs_sig);
        return false;
    }

    OQS_STATUS result = OQS_SIG_verify(oqs_sig, msg.data(), msg.size(),
                                         sig.data(), sig.size(), pubkey.data());
    OQS_SIG_free(oqs_sig);
    return (result == OQS_SUCCESS);
}

bool SignPQ(RungScheme scheme,
            std::span<const uint8_t> privkey,
            std::span<const uint8_t> msg,
            std::vector<uint8_t>& sig_out)
{
    const char* alg_name = SchemeToAlgName(scheme);
    if (!alg_name) return false;

    OQS_SIG* oqs_sig = OQS_SIG_new(alg_name);
    if (!oqs_sig) {
        LogPrintf("PQ: Failed to initialize algorithm %s for signing\n", alg_name);
        return false;
    }

    // Validate the privkey is the right size for the scheme — OQS_SIG_sign
    // reads exactly `length_secret_key` bytes from `privkey.data()` and a
    // short buffer would read OOB. RPC callers can submit arbitrary blobs;
    // do not trust the length.
    if (privkey.size() != oqs_sig->length_secret_key) {
        LogPrintf("PQ: privkey size mismatch for %s: got %zu, expected %zu\n",
                  alg_name, privkey.size(), oqs_sig->length_secret_key);
        OQS_SIG_free(oqs_sig);
        return false;
    }

    sig_out.resize(oqs_sig->length_signature);
    size_t sig_len = 0;

    OQS_STATUS result = OQS_SIG_sign(oqs_sig, sig_out.data(), &sig_len,
                                      msg.data(), msg.size(), privkey.data());
    OQS_SIG_free(oqs_sig);

    if (result != OQS_SUCCESS) return false;
    sig_out.resize(sig_len);
    return true;
}

bool GeneratePQKeypair(RungScheme scheme,
                       std::vector<uint8_t>& pubkey_out,
                       std::vector<uint8_t>& privkey_out)
{
    const char* alg_name = SchemeToAlgName(scheme);
    if (!alg_name) return false;

    OQS_SIG* oqs_sig = OQS_SIG_new(alg_name);
    if (!oqs_sig) {
        LogPrintf("PQ: Failed to initialize algorithm %s for keygen\n", alg_name);
        return false;
    }

    pubkey_out.resize(oqs_sig->length_public_key);
    privkey_out.resize(oqs_sig->length_secret_key);

    OQS_STATUS result = OQS_SIG_keypair(oqs_sig, pubkey_out.data(), privkey_out.data());
    OQS_SIG_free(oqs_sig);

    return (result == OQS_SUCCESS);
}

} // namespace rung
