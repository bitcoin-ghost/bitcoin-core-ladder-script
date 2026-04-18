// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_POLICY_H
#define BITCOIN_RUNG_POLICY_H

#include <rung/api.h>

#include <cstdint>
#include <string>

namespace rung {

// Block-type family predicates — plain primitives, no Core types.
// Not part of rung::api because they're introspection (used by RPC /
// tooling) rather than consensus-critical.

/** Check whether a block type is a base block (signature, timelock, hash, compound). */
bool IsBaseBlockType(uint16_t block_type);

/** Check whether a block type is a covenant, anchor, or governance block. */
bool IsCovenantBlockType(uint16_t block_type);

/** Check whether a block type is a recursion or PLC block. */
bool IsStatefulBlockType(uint16_t block_type);

namespace api {

/** Check whether a v4 RUNG_TX transaction conforms to mempool policy.
 *  Delegates structural validation (MAX_RUNGS=16, MAX_BLOCKS_PER_RUNG=8,
 *  known block types, field size ranges, etc.) to the consensus
 *  deserializer; the extra checks here are: per-output MLSC format, and
 *  the qabi_block soft cap. */
bool IsStandardRungTx(const LadderTxView& tx, std::string& reason);

}  // namespace api

/** QABI Replace-By-Depth (RBD) mempool policy.
 *
 *  When two priming transactions spending the same UTXO are in the mempool,
 *  the one with the deeper QABI_PRIME prime_depth wins. The depth asymmetry
 *  is cryptographic: deeper preimages can only be produced by the UTXO owner
 *  (one-way hash), so RBD gives the legitimate owner a last word over any
 *  sniper who scrapes a shallower preimage from the mempool.
 *
 *  These helpers are pure policy functions — integrating them into the
 *  mempool's actual replacement workflow (txmempool / acceptance) is a
 *  separate wiring step.
 */

// QABIO (BIP-YYYY) Replace-By-Depth mempool policy helpers. These
// signatures are always visible so validation.cpp callers don't need
// conditional compilation — when ENABLE_QABIO is off, IsQABIPrimingTx
// always returns false and the RBD path is never taken.

namespace api {

/** Extract the prime_depth from the first QABI_PRIME block found in the
 *  witness of the given input. Returns false if the witness cannot be parsed,
 *  the input has no QABI_PRIME block, or the prime_depth field is malformed.
 *
 *  prime_depth is the second NUMERIC field in the QABI_PRIME block's witness
 *  (order: new_committed_root HASH256, prime_depth NUMERIC, new_committed_expiry
 *  NUMERIC, prime_preimage PREIMAGE).
 *
 *  When ENABLE_QABIO is off this helper always returns false. */
bool ExtractQABIPrimeDepth(const LadderTxView& tx,
                            uint32_t input_index,
                            int64_t& depth_out);

/** True iff the given tx contains at least one input whose witness has a
 *  QABI_PRIME block (i.e. this is a priming tx).
 *
 *  When ENABLE_QABIO is off this helper always returns false, which
 *  cleanly disables the Replace-By-Depth mempool path without any
 *  call-site conditional compilation. */
bool IsQABIPrimingTx(const LadderTxView& tx);

/** RBD policy check: return true iff new_tx is a valid Replace-By-Depth
 *  replacement for old_tx.
 *
 *  Requirements:
 *    - Both txs are priming txs (contain QABI_PRIME)
 *    - They spend at least one common UTXO via QABI_PRIME
 *    - For every shared primed input, new_tx's prime_depth > old_tx's prime_depth
 *    - Both witnesses parse cleanly
 *
 *  On failure, `reason` is populated with a machine-readable error tag.
 *  When ENABLE_QABIO is off this helper always returns false. */
bool IsValidRBDReplacement(const LadderTxView& new_tx,
                            const LadderTxView& old_tx,
                            std::string& reason);

}  // namespace api

} // namespace rung

#endif // BITCOIN_RUNG_POLICY_H
