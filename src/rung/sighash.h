// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_SIGHASH_H
#define BITCOIN_RUNG_SIGHASH_H

#include <rung/conditions.h>
#include <script/interpreter.h>

#include <cstdint>

class CTransaction;
class CMutableTransaction;
class uint256;

namespace rung {

/** ANYPREVOUT sighash flag: skip prevout commitment (BIP-118 analogue).
 *  Enables LN-Symmetry/eltoo. Still commits to amounts, sequences, and conditions. */
static constexpr uint8_t LADDER_SIGHASH_ANYPREVOUT = 0x40;

/** ANYPREVOUTANYSCRIPT sighash flag: skip prevout + conditions commitment.
 *  Enables rebindable signatures across different scripts. */
static constexpr uint8_t LADDER_SIGHASH_ANYPREVOUTANYSCRIPT = 0xC0;

/** Tagged hash writer for LadderSighash, pre-fed with the tag. */
extern const HashWriter HASHER_LADDERSIGHASH;

/** Tagged hash writer for LadderKeyPathSighash, pre-fed with the tag. */
extern const HashWriter HASHER_LADDERKEYPATH;

/** Compute the signature hash for a v4 RUNG_TX input.
 *
 *  Similar to BIP341 sighash but without annex/tapscript/codeseparator extensions.
 *  Uses tagged hash: TaggedHash("LadderSighash").
 *
 *  Commits to:
 *    - epoch (0)
 *    - hash_type
 *    - tx version, locktime
 *    - prevouts hash, amounts hash, sequences hash (unless ANYONECANPAY)
 *    - outputs hash (unless NONE)
 *    - spend_type (always 0 for ladder — no annex, no extensions)
 *    - input-specific data (prevout or index)
 *    - conditions hash (SHA256 of serialized rung conditions from spent output)
 *    - output for SIGHASH_SINGLE
 *
 *  @param[in]  cache       Precomputed transaction data (must have m_ladder_ready set)
 *  @param[in]  tx          The transaction being signed
 *  @param[in]  nIn         Input index being signed
 *  @param[in]  hash_type   Sighash type (SIGHASH_DEFAULT=0, ALL=1, NONE=2, SINGLE=3, ANYONECANPAY=0x80)
 *  @param[in]  conditions  Rung conditions from the spent output
 *  @param[out] hash_out    The computed sighash
 *  @return true on success, false if hash_type is invalid or data is missing
 */
template <class T>
bool SignatureHashLadder(const PrecomputedTransactionData& cache,
                         const T& tx,
                         unsigned int nIn,
                         uint8_t hash_type,
                         const RungConditions& conditions,
                         uint256& hash_out);

/** Compute the key-path signature hash for a v4 RUNG_TX input.
 *  Same as SignatureHashLadder but:
 *  - Uses TaggedHash("LadderKeyPathSighash")
 *  - Does NOT commit to conditions (conditions not revealed in key-path)
 *  - spend_type = 0x00 (key-path marker) */
template <class T>
bool SignatureHashLadderKeyPath(const PrecomputedTransactionData& cache,
                                const T& tx,
                                unsigned int nIn,
                                uint8_t hash_type,
                                uint256& hash_out);

} // namespace rung

#endif // BITCOIN_RUNG_SIGHASH_H
