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

} // namespace rung

#endif // BITCOIN_RUNG_POLICY_H
