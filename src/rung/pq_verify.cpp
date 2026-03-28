// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/pq_verify.h>

#include <logging.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace rung {

bool HasPQSupport()
{
#ifdef HAVE_LIBOQS
    return true;
#else
    return false;
#endif
}

#ifdef HAVE_LIBOQS
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
#endif

bool VerifyPQSignature(RungScheme scheme,
                       std::span<const uint8_t> sig,
                       std::span<const uint8_t> msg,
                       std::span<const uint8_t> pubkey)
{
#ifdef HAVE_LIBOQS
    const char* alg_name = SchemeToAlgName(scheme);
    if (!alg_name) return false;

    OQS_SIG* oqs_sig = OQS_SIG_new(alg_name);
    if (!oqs_sig) {
        LogPrintf("PQ: Failed to initialize algorithm %s\n", alg_name);
        return false;
    }

    // Validate key and signature sizes match the scheme before calling OQS
    if (pubkey.size() != oqs_sig->length_public_key) {
        LogPrintf("PQ: pubkey size mismatch for %s: got %zu, expected %zu\n",
                  alg_name, pubkey.size(), oqs_sig->length_public_key);
        OQS_SIG_free(oqs_sig);
        return false;
    }
    if (sig.size() > oqs_sig->length_signature) {
        LogPrintf("PQ: signature too large for %s: got %zu, max %zu\n",
                  alg_name, sig.size(), oqs_sig->length_signature);
        OQS_SIG_free(oqs_sig);
        return false;
    }

    OQS_STATUS result = OQS_SIG_verify(oqs_sig, msg.data(), msg.size(),
                                         sig.data(), sig.size(), pubkey.data());
    OQS_SIG_free(oqs_sig);
    return (result == OQS_SUCCESS);
#else
    (void)scheme;
    (void)sig;
    (void)msg;
    (void)pubkey;
    LogPrintf("PQ: Post-quantum signature verification unavailable (liboqs not compiled in)\n");
    return false;
#endif
}

bool SignPQ(RungScheme scheme,
            std::span<const uint8_t> privkey,
            std::span<const uint8_t> msg,
            std::vector<uint8_t>& sig_out)
{
#ifdef HAVE_LIBOQS
    const char* alg_name = SchemeToAlgName(scheme);
    if (!alg_name) return false;

    OQS_SIG* oqs_sig = OQS_SIG_new(alg_name);
    if (!oqs_sig) {
        LogPrintf("PQ: Failed to initialize algorithm %s for signing\n", alg_name);
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
#else
    (void)scheme;
    (void)privkey;
    (void)msg;
    (void)sig_out;
    LogPrintf("PQ: Post-quantum signing unavailable (liboqs not compiled in)\n");
    return false;
#endif
}

bool GeneratePQKeypair(RungScheme scheme,
                       std::vector<uint8_t>& pubkey_out,
                       std::vector<uint8_t>& privkey_out)
{
#ifdef HAVE_LIBOQS
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
#else
    (void)scheme;
    (void)pubkey_out;
    (void)privkey_out;
    LogPrintf("PQ: Post-quantum keygen unavailable (liboqs not compiled in)\n");
    return false;
#endif
}

} // namespace rung
