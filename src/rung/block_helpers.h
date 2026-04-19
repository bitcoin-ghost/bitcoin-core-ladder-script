// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

#ifndef BITCOIN_RUNG_BLOCK_HELPERS_H
#define BITCOIN_RUNG_BLOCK_HELPERS_H

// ============================================================================
// Shared helpers used by per-family block evaluators under src/rung/blocks/.
// Declarations only — implementations live in `block_helpers.cpp`.
// ============================================================================

#include <rung/conditions.h>
#include <rung/evaluator.h>
#include <rung/types.h>

#include <script/interpreter.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace rung {

// ----------------------------------------------------------------------------
// Field lookup
// ----------------------------------------------------------------------------

const RungField* FindField(const RungBlock& block, RungDataType type);
std::vector<const RungField*> FindAllFields(const RungBlock& block, RungDataType type);
std::optional<int64_t> ReadNumeric(const RungField& field);
bool HasRequiredPubkeys(const RungBlock& block, size_t count);
bool HasRequiredHashes(const RungBlock& block, size_t count);
std::vector<const RungField*> ResolvePubkeyCommitments(const RungBlock& block);

/** HASH256/HASH160/PREIMAGE binding check — the PREIMAGE field must hash to
 *  the committed HASH256 (or HASH160 for legacy 160-bit anchors). */
bool VerifyHashPreimageBinding(const RungBlock& block);

// ----------------------------------------------------------------------------
// Signature helpers — Ladder-native path
// ----------------------------------------------------------------------------

bool FetchLadderSighash(const RungEvalContext& ctx,
                        uint8_t hash_type,
                        uint8_t out[32]);
bool ExtractSchnorrHashType(std::span<const uint8_t> sig, uint8_t& hash_type);

EvalResult EvalPQSig(RungScheme scheme,
                     const RungField& sig_field,
                     const RungField& pubkey_field,
                     const api::LadderSigChecker& sig_checker,
                     const RungEvalContext& ctx);

EvalResult VerifySigWithScheme(const RungField& pubkey_field,
                               const RungField& sig_field,
                               const RungField* scheme_field,
                               const api::LadderSigChecker& sig_checker,
                               const RungEvalContext& ctx);

// Note: VerifySigFromFields + EvalInnerConditions + MAX_LEGACY_INNER_DEPTH
// are file-local to `src/rung/blocks/legacy.cpp`. They only bridge legacy
// wrappers to Core's sighash machinery — no other block family uses them.

// ----------------------------------------------------------------------------
// MLSC recursion helpers
// ----------------------------------------------------------------------------

/** A single mutation target (rung, block, param, delta) — used by RECURSE_*
 *  blocks and the QABI prime check. */
struct MutationSpec {
    int64_t rung_idx;
    int64_t block_idx;
    int64_t param_idx;
    int64_t delta;
};

bool OutputRootMatchesInput(const api::LadderOutputView& output,
                            const MLSCVerifiedLeaves& verified_leaves);

uint256 ComputeConditionsRootMLSC(const RungConditions& conditions,
                                   const std::vector<std::vector<std::vector<uint8_t>>>& rung_pubkeys);

uint256 ComputeExpectedRoot(const MLSCVerifiedLeaves& verified_leaves,
                             size_t rung_index,
                             const uint256& new_leaf);

void WriteNumericField(RungField& f, int64_t val);

CreationProofRung BuildCPRung(const Rung& rung,
                               const std::vector<std::vector<uint8_t>>& pks,
                               const RungCoil& coil);

EvalResult VerifyMutatedLeaves(const RungEvalContext& ctx,
                                const std::vector<MutationSpec>& mutations);

bool ParseMutationSpecs(const std::vector<const RungField*>& numerics,
                        int64_t& max_depth,
                        std::vector<MutationSpec>& mutations);

} // namespace rung

#endif // BITCOIN_RUNG_BLOCK_HELPERS_H
