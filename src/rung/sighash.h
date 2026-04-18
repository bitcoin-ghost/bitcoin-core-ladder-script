// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_SIGHASH_H
#define BITCOIN_RUNG_SIGHASH_H

#include <rung/api.h>
#include <rung/conditions.h>

#include <cstdint>

class uint256;

namespace rung {

/** ANYPREVOUT sighash flag: skip prevout commitment (BIP-118 analogue).
 *  Enables LN-Symmetry/eltoo. Still commits to amounts, sequences, and conditions. */
static constexpr uint8_t LADDER_SIGHASH_ANYPREVOUT = 0x40;

/** ANYPREVOUTANYSCRIPT sighash flag: skip prevout + conditions commitment.
 *  Enables rebindable signatures across different scripts. */
static constexpr uint8_t LADDER_SIGHASH_ANYPREVOUTANYSCRIPT = 0xC0;

namespace api {

/** Compute the signature hash for a v4 RUNG_TX input.
 *
 *  Similar to BIP341 sighash but without annex/tapscript/codeseparator extensions.
 *  Uses tagged hash: TaggedHash("LadderSighash/v1").
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
 */
bool SignatureHashLadder(const LadderPrecomputedTxData& cache,
                         const LadderTxView& tx,
                         unsigned int nIn,
                         uint8_t hash_type,
                         const ::rung::RungConditions& conditions,
                         uint256& hash_out);

/** Compute the key-path signature hash for a v4 RUNG_TX input.
 *  Same as SignatureHashLadder but:
 *  - Uses TaggedHash("LadderKeyPathSighash/v1")
 *  - Does NOT commit to conditions (conditions not revealed in key-path)
 *  - spend_type = 0x00 (key-path marker) */
bool SignatureHashLadderKeyPath(const LadderPrecomputedTxData& cache,
                                const LadderTxView& tx,
                                unsigned int nIn,
                                uint8_t hash_type,
                                uint256& hash_out);

}  // namespace api

} // namespace rung

#endif // BITCOIN_RUNG_SIGHASH_H
