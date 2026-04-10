// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_POLICY_H
#define BITCOIN_RUNG_POLICY_H

#include <primitives/transaction.h>
#include <script/script.h>

#include <string>

namespace rung {

/** Check whether a block type is a base block (signature, timelock, hash, compound). */
bool IsBaseBlockType(uint16_t block_type);

/** Check whether a block type is a covenant, anchor, or governance block. */
bool IsCovenantBlockType(uint16_t block_type);

/** Check whether a block type is a recursion or PLC block. */
bool IsStatefulBlockType(uint16_t block_type);

/** Check whether a v4 RUNG_TX transaction conforms to mempool policy.
 *  Thin deserialize-only check — delegates to the consensus deserializer which
 *  enforces all structural limits (MAX_RUNGS=16, MAX_BLOCKS_PER_RUNG=8,
 *  known block types, deprecated block rejection, field size ranges, etc.).
 *  Returns false with reason populated on policy violation. */
bool IsStandardRungTx(const CTransaction& tx, std::string& reason);

// IsStandardRungOutput removed — output validation is consensus (ValidateRungOutputs).

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

/** Extract the prime_depth from the first QABI_PRIME block found in the
 *  witness of the given input. Returns false if the witness cannot be parsed,
 *  the input has no QABI_PRIME block, or the prime_depth field is malformed.
 *
 *  prime_depth is the second NUMERIC field in the QABI_PRIME block's witness
 *  (order: new_committed_root HASH256, prime_depth NUMERIC, new_committed_expiry
 *  NUMERIC, prime_preimage PREIMAGE). */
bool ExtractQABIPrimeDepth(const CTransaction& tx,
                            uint32_t input_index,
                            int64_t& depth_out);

/** True iff the given tx contains at least one input whose witness has a
 *  QABI_PRIME block (i.e. this is a priming tx). */
bool IsQABIPrimingTx(const CTransaction& tx);

/** RBD policy check: return true iff new_tx is a valid Replace-By-Depth
 *  replacement for old_tx.
 *
 *  Requirements:
 *    - Both txs are priming txs (contain QABI_PRIME)
 *    - They spend at least one common UTXO via QABI_PRIME
 *    - For every shared primed input, new_tx's prime_depth > old_tx's prime_depth
 *    - Both witnesses parse cleanly
 *
 *  On failure, `reason` is populated with a machine-readable error tag. */
bool IsValidRBDReplacement(const CTransaction& new_tx,
                            const CTransaction& old_tx,
                            std::string& reason);

} // namespace rung

#endif // BITCOIN_RUNG_POLICY_H
