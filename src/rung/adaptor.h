// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_ADAPTOR_H
#define BITCOIN_RUNG_ADAPTOR_H

#include <key.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace rung {

/** Create an adapted Schnorr signature (BIP-340 compatible).
 *  The adapted signature is: (R+T, k_tweaked + e*x) where k_tweaked = k + t,
 *  T = t*G, and e = BIP340_challenge(R+T, P, sighash).
 *  The result is a valid BIP-340 signature against pubkey P.
 *
 *  @param[in]  privkey         The signing private key
 *  @param[in]  sighash         The 32-byte message hash to sign
 *  @param[in]  adaptor_secret  The 32-byte adaptor secret scalar t
 *  @param[out] sig_out         64-byte adapted signature (must be pre-sized)
 *  @return true on success */
bool CreateAdaptedSignature(const CKey& privkey,
                            const uint256& sighash,
                            const std::vector<uint8_t>& adaptor_secret,
                            std::vector<uint8_t>& sig_out);

/** Extract the adaptor secret from a pre-signature and adapted signature.
 *  Computes t = s_adapted - s_pre (scalar subtraction mod n).
 *
 *  @param[in]  pre_sig      64-byte pre-signature (R, s')
 *  @param[in]  adapted_sig  64-byte adapted signature (R+T, s'+t)
 *  @param[out] secret_out   32-byte adaptor secret
 *  @return true on success */
bool ExtractAdaptorSecret(const std::vector<uint8_t>& pre_sig,
                          const std::vector<uint8_t>& adapted_sig,
                          std::vector<uint8_t>& secret_out);

/** Verify an adaptor pre-signature.
 *  Checks that s'*G == R + e*P where e = H(R+T||P||m).
 *
 *  @param[in] pubkey_bytes    32-byte x-only public key
 *  @param[in] adaptor_point   32-byte x-only adaptor point T
 *  @param[in] pre_sig         64-byte pre-signature (R, s')
 *  @param[in] sighash         32-byte message hash
 *  @return true if the pre-signature is valid */
bool VerifyAdaptorPreSignature(const std::vector<uint8_t>& pubkey_bytes,
                               const std::vector<uint8_t>& adaptor_point,
                               const std::vector<uint8_t>& pre_sig,
                               const uint256& sighash);

} // namespace rung

#endif // BITCOIN_RUNG_ADAPTOR_H
