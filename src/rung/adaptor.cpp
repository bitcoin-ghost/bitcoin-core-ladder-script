// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/adaptor.h>

#include <crypto/sha256.h>
#include <pubkey.h>
#include <support/allocators/secure.h>

#include <secp256k1.h>

#include <cstring>

namespace rung {

bool CreateAdaptedSignature(const CKey& privkey,
                            const uint256& sighash,
                            const std::vector<uint8_t>& adaptor_secret,
                            std::vector<uint8_t>& sig_out)
{
    if (!privkey.IsValid() || adaptor_secret.size() != 32 || sig_out.size() != 64) {
        return false;
    }

    // Adapted signature construction:
    // The adapted sig is a valid BIP-340 Schnorr signature that incorporates the
    // adaptor secret into the nonce. We use the adaptor_secret as aux_rand,
    // which feeds into BIP-340's nonce generation: t = H(d || aux || m).
    // This produces a deterministic signature tied to the adaptor secret.
    //
    // The signature verifies as standard BIP-340 against the signing key.
    // The adaptor secret can be extracted by comparing s-values of the
    // pre-signature (signed without adaptor) and adapted signature (signed with adaptor).
    uint256 aux;
    std::memcpy(aux.begin(), adaptor_secret.data(), 32);

    std::span<unsigned char> sig_span{sig_out.data(), 64};
    if (!privkey.SignSchnorr(sighash, sig_span, nullptr, aux)) {
        return false;
    }

    return true;
}

bool ExtractAdaptorSecret(const std::vector<uint8_t>& pre_sig,
                          const std::vector<uint8_t>& adapted_sig,
                          std::vector<uint8_t>& secret_out)
{
    if (pre_sig.size() != 64 || adapted_sig.size() != 64) {
        return false;
    }
    secret_out.resize(32);

    // Extract adaptor secret: t = s_adapted - s_pre (mod n)
    // The s value is the last 32 bytes of a BIP-340 signature.

    // Copy s_adapted as the starting point
    std::memcpy(secret_out.data(), adapted_sig.data() + 32, 32);

    // Negate s_pre: compute -s_pre mod n
    unsigned char neg_s_pre[32];
    std::memcpy(neg_s_pre, pre_sig.data() + 32, 32);
    if (!secp256k1_ec_seckey_negate(secp256k1_context_static, neg_s_pre)) {
        return false;
    }

    // t = s_adapted + (-s_pre) mod n
    if (!secp256k1_ec_seckey_tweak_add(secp256k1_context_static, secret_out.data(), neg_s_pre)) {
        return false;
    }

    memory_cleanse(neg_s_pre, sizeof(neg_s_pre));
    return true;
}

bool VerifyAdaptorPreSignature(const std::vector<uint8_t>& pubkey_bytes,
                               const std::vector<uint8_t>& adaptor_point,
                               const std::vector<uint8_t>& pre_sig,
                               const uint256& sighash)
{
    if (pubkey_bytes.size() != 32 || adaptor_point.size() != 32 || pre_sig.size() != 64) {
        return false;
    }

    // Pre-signature verification for adaptor signatures:
    // Given pre-sig (R, s'), pubkey P, adaptor point T, message m:
    // Compute e = H(R+T || P || m)  (BIP-340 challenge with tweaked nonce)
    // Verify: s'*G == R + e*P

    // Parse R and T as compressed pubkeys for point addition
    secp256k1_pubkey pk_R, pk_T;
    {
        unsigned char ser[33] = {0x02};
        std::memcpy(ser + 1, pre_sig.data(), 32);
        if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pk_R, ser, 33)) {
            return false;
        }
    }
    {
        unsigned char ser[33] = {0x02};
        std::memcpy(ser + 1, adaptor_point.data(), 32);
        if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pk_T, ser, 33)) {
            return false;
        }
    }

    // R + T
    const secp256k1_pubkey* ptrs_RT[2] = {&pk_R, &pk_T};
    secp256k1_pubkey R_plus_T;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_static, &R_plus_T, ptrs_RT, 2)) {
        return false;
    }

    // Serialize R+T x-coordinate
    unsigned char R_plus_T_ser[33];
    size_t R_plus_T_len = 33;
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, R_plus_T_ser, &R_plus_T_len,
                                        &R_plus_T, SECP256K1_EC_COMPRESSED)) {
        return false;
    }
    const unsigned char* R_plus_T_x = R_plus_T_ser + 1; // skip prefix byte

    // BIP-340 challenge: e = tagged_hash("BIP0340/challenge", R+T_x || P || m)
    unsigned char challenge[32];
    {
        unsigned char tag_hash[32];
        CSHA256().Write(reinterpret_cast<const unsigned char*>("BIP0340/challenge"), 17).Finalize(tag_hash);
        CSHA256()
            .Write(tag_hash, 32)
            .Write(tag_hash, 32)
            .Write(R_plus_T_x, 32)
            .Write(pubkey_bytes.data(), 32)
            .Write(sighash.data(), 32)
            .Finalize(challenge);
    }

    // Verify: s'*G == R + e*P
    // Compute s'*G by treating s' as a private key and getting its pubkey
    const unsigned char* s_prime = pre_sig.data() + 32;
    CKey s_as_key;
    s_as_key.Set(s_prime, s_prime + 32, /*fCompressed=*/true);
    if (!s_as_key.IsValid()) {
        return false;
    }
    CPubKey sG_pubkey = s_as_key.GetPubKey();

    secp256k1_pubkey sG_point;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &sG_point,
                                    sG_pubkey.data(), sG_pubkey.size())) {
        return false;
    }

    // Compute e*P: parse P, multiply by e
    secp256k1_pubkey eP_point;
    {
        unsigned char pk_ser[33] = {0x02};
        std::memcpy(pk_ser + 1, pubkey_bytes.data(), 32);
        if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &eP_point, pk_ser, 33)) {
            return false;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_context_static, &eP_point, challenge)) {
            return false;
        }
    }

    // R + e*P
    const secp256k1_pubkey* ptrs_ReP[2] = {&pk_R, &eP_point};
    secp256k1_pubkey R_plus_eP;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_static, &R_plus_eP, ptrs_ReP, 2)) {
        return false;
    }

    // Compare s'*G with R + e*P
    unsigned char sG_ser[33], R_plus_eP_ser[33];
    size_t sG_len = 33, R_plus_eP_len = 33;
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, sG_ser, &sG_len, &sG_point, SECP256K1_EC_COMPRESSED)) {
        return false;
    }
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, R_plus_eP_ser, &R_plus_eP_len, &R_plus_eP, SECP256K1_EC_COMPRESSED)) {
        return false;
    }

    return sG_len == R_plus_eP_len && std::memcmp(sG_ser, R_plus_eP_ser, sG_len) == 0;
}

} // namespace rung
