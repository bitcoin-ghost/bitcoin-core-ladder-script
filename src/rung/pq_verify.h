// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_PQ_VERIFY_H
#define BITCOIN_RUNG_PQ_VERIFY_H

#include <rung/types.h>

#include <cstdint>
#include <span>

namespace rung {

/** Returns true if the build has liboqs support for post-quantum signatures. */
bool HasPQSupport();

/** Verify a post-quantum signature.
 *  @param scheme   The PQ signature scheme (FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA)
 *  @param sig      The signature bytes
 *  @param msg      The message that was signed
 *  @param pubkey   The public key bytes
 *  @return true if the signature is valid, false otherwise (including if PQ not compiled in) */
bool VerifyPQSignature(RungScheme scheme,
                       std::span<const uint8_t> sig,
                       std::span<const uint8_t> msg,
                       std::span<const uint8_t> pubkey);

/** Sign a message with a post-quantum private key.
 *  @param scheme    The PQ signature scheme
 *  @param privkey   The private key bytes
 *  @param msg       The message to sign
 *  @param sig_out   Output: the generated signature bytes
 *  @return true on success */
bool SignPQ(RungScheme scheme,
            std::span<const uint8_t> privkey,
            std::span<const uint8_t> msg,
            std::vector<uint8_t>& sig_out);

/** Generate a post-quantum keypair.
 *  @param scheme      The PQ signature scheme
 *  @param pubkey_out  Output: the public key bytes
 *  @param privkey_out Output: the private key bytes
 *  @return true on success */
bool GeneratePQKeypair(RungScheme scheme,
                       std::vector<uint8_t>& pubkey_out,
                       std::vector<uint8_t>& privkey_out);

} // namespace rung

#endif // BITCOIN_RUNG_PQ_VERIFY_H
