// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

#ifndef BITCOIN_RUNG_BLOCK_DISPATCH_H
#define BITCOIN_RUNG_BLOCK_DISPATCH_H

// ============================================================================
// Block-type dispatch registry
// ============================================================================
//
// Each RungBlockType maps to an evaluator function. Block families live in
// their own translation units under `src/rung/blocks/` and register their
// evaluators at startup via `ladder_init()`.
//
// A block type that is compiled out (ENABLE_QABIO=OFF, future BIP
// sub-proposal flags, fuzz harnesses with a reduced block set, etc.) never
// registers. EvalBlock returns UNKNOWN_BLOCK_TYPE for any type without a
// registered evaluator — same semantics as the old `default:` arm in the
// switch statement, and the same forward-compatibility rule.

#include <rung/evaluator.h>
#include <rung/types.h>

#include <script/interpreter.h>

class BaseSignatureChecker;

namespace rung {

/** All state a block evaluator might need, bundled so the registry function
 *  pointer has a uniform signature. Individual evaluators read only the
 *  fields they care about. */
struct BlockDispatchContext {
    const api::LadderSigChecker& sig_checker;
    const BaseSignatureChecker& legacy_checker;
    SigVersion sigversion;
    ScriptExecutionData& execdata;
    const RungEvalContext& ctx;
    int depth;
};

/** Uniform evaluator signature: one function pointer per block type. */
using BlockEvaluator = EvalResult (*)(const RungBlock& block,
                                       const BlockDispatchContext& dctx);

/** Register an evaluator for a block type. Later calls overwrite earlier
 *  registrations (useful for tests that want to stub a block type). */
void RegisterBlock(RungBlockType type, BlockEvaluator fn);

/** Look up the registered evaluator for a block type, or `nullptr` if the
 *  type is not registered. */
BlockEvaluator LookupBlockEvaluator(RungBlockType type);

// The public one-shot initialiser is `rung::api::ladder_init()` declared in
// `rung/api.h`. `EvalBlock` calls it on first dispatch; hosts that want to
// pre-register may call it explicitly.

// ----------------------------------------------------------------------------
// Per-family registration functions. Each block-family TU provides its
// definition, and `rung::api::ladder_init()` calls them in a deterministic
// order.
// ----------------------------------------------------------------------------
void register_sig_blocks();
void register_timelock_blocks();
void register_hash_blocks();
void register_covenant_blocks();
void register_anchor_blocks();
void register_recursion_blocks();
void register_plc_blocks();
void register_compound_blocks();
void register_governance_blocks();
void register_legacy_blocks();
#ifdef ENABLE_QABIO
void register_qabi_blocks();
#endif

} // namespace rung

#endif // BITCOIN_RUNG_BLOCK_DISPATCH_H
