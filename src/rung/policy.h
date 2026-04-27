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

// IsStandardRungTx is declared in <rung/api.h> (the canonical public surface).
// Including api.h above makes it visible to all consumers of policy.h —
// re-declaring it here triggered -Wredundant-decls.

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

/** Minimum prime_depth gap for an RBD replacement. The legitimate UTXO
 *  owner can produce arbitrarily deep preimages and could otherwise
 *  flood the mempool with `depth+1, depth+2, depth+3, …` replacements
 *  at zero fee cost. Requiring a 5-step gap forces the owner to either
 *  pay the regular RBF rule or commit a meaningful depth jump. */
inline constexpr int64_t MIN_RBD_DEPTH_GAP = 5;

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

// IsQABIPrimingTx and IsValidRBDReplacement are declared in <rung/api.h>.
// Re-declaring them here triggered -Wredundant-decls — see api.h for the
// canonical signatures and the rationale doc-comments.

}  // namespace api

} // namespace rung

#endif // BITCOIN_RUNG_POLICY_H
