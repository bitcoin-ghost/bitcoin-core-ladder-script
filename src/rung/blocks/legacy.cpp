// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: legacy.
// Evaluators + registry function. The top-level dispatcher calls each
// registered evaluator via `rung::LookupBlockEvaluator`.
//
// REVIEWER NOTE — Legacy P2* wrappers (0x0901..0x0907)
//   Members: P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY,
//   P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY.
//   Pattern: wrap the semantic of Core's legacy script types inside an
//   MLSC rung so legacy-script users can migrate without re-signing
//   infrastructure.
//   Load-bearing invariants:
//     - Schnorr signature verification here flows through the Ladder
//       api::LadderSigChecker, NOT Core's BaseSignatureChecker. Going
//       through Core's checker triggers three TAPROOT-only assertions in
//       CheckSchnorrSignature (sigversion, annex_init, m_bip341_taproot_ready)
//       and crashes the process. Regression fix: commit 83f3a99a25. If you
//       re-introduce a Core-checker-based path here, add the Taproot-state
//       prerequisites first.
//     - VerifySigWithScheme (in adaptor.cpp) replaces the earlier
//       VerifySigFromFields; the new helper uses LadderSigChecker directly.
//   Optional for MVP: entire family is optional. Removing drops the ability
//   to bridge legacy-script UTXOs into MLSC rungs. Base spend patterns are
//   unaffected.

#include <rung/block_dispatch.h>
#include <rung/block_helpers.h>
#include <rung/evaluator.h>

#include <rung/conditions.h>
#include <rung/pq_verify.h>
#include <rung/qabi.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung_shims.h>

#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>

namespace rung {
using namespace api;

/** Maximum recursion depth for P2SH/P2WSH/P2TR_SCRIPT inner condition evaluation. */
static constexpr int MAX_LEGACY_INNER_DEPTH = 2;

static EvalResult EvalInnerConditions(const std::vector<uint8_t>& preimage_data,
                                       const RungBlock& outer_block,
                                       const api::LadderSigChecker& sig_checker,
                                       const BaseSignatureChecker& legacy_checker,
                                       SigVersion sigversion,
                                       ScriptExecutionData& execdata,
                                       const RungEvalContext& ctx,
                                       int depth)
{
    if (depth > MAX_LEGACY_INNER_DEPTH) {
        return EvalResult::ERROR;
    }

    // Deserialize inner conditions from PREIMAGE bytes
    LadderWitness inner;
    std::string error;
    if (!DeserializeLadderWitness(preimage_data, inner, error, SerializationContext::CONDITIONS)) {
        return EvalResult::ERROR;
    }

    if (inner.rungs.empty()) {
        return EvalResult::ERROR;
    }

    // Collect witness fields from outer block (everything except HASH160/HASH256/PREIMAGE)
    // These become the witness fields for the inner conditions' blocks
    std::vector<const RungField*> witness_fields;
    for (const auto& field : outer_block.fields) {
        if (field.type == RungDataType::PUBKEY || field.type == RungDataType::SIGNATURE ||
            field.type == RungDataType::NUMERIC || field.type == RungDataType::SCHEME) {
            witness_fields.push_back(&field);
        }
    }

    // Evaluate inner rungs: OR logic (first satisfied rung wins)
    for (const auto& rung : inner.rungs) {
        bool all_satisfied = true;
        for (const auto& block : rung.blocks) {
            // Build a combined block with inner conditions + outer witness fields
            RungBlock combined;
            combined.type = block.type;
            combined.inverted = block.inverted;
            // Add inner condition fields
            for (const auto& f : block.fields) {
                combined.fields.push_back(f);
            }
            // Add outer witness fields
            for (const auto* wf : witness_fields) {
                combined.fields.push_back(*wf);
            }

            // Check for recursive legacy blocks
            if (block.type == RungBlockType::P2SH_LEGACY ||
                block.type == RungBlockType::P2WSH_LEGACY ||
                block.type == RungBlockType::P2TR_SCRIPT_LEGACY) {
                // These would need deeper recursion — check depth
                if (depth + 1 > MAX_LEGACY_INNER_DEPTH) {
                    all_satisfied = false;
                    break;
                }
            }

            EvalResult result = EvalBlock(combined, sig_checker, legacy_checker, sigversion, execdata, ctx, depth);
            if (result != EvalResult::SATISFIED) {
                all_satisfied = false;
                break;
            }
        }
        if (all_satisfied) return EvalResult::SATISFIED;
    }

    return EvalResult::UNSATISFIED;
}

// Legacy P2* wrapper sig verification runs through the Ladder sig_checker
// adapter (same path as EvalSigBlock). Core's BaseSignatureChecker asserts
// hard on non-Taproot tx state when handed a Schnorr sig (interpreter.cpp
// CheckSchnorrSignature + SignatureHashSchnorr require m_bip341_taproot_ready
// which a RUNG_TX does not set), so we cannot hand Schnorr sigs to Core's
// checker from inside Ladder evaluation. The signing side already commits
// to the Ladder sighash (see SignSingleKey in rung/rpc.cpp), so the legacy
// wrappers are effectively "SIG-block semantics + HASH160 commitment check"
// at this point.

EvalResult EvalP2PKLegacyBlock(const RungBlock& block,
                                const api::LadderSigChecker& sig_checker,
                                const RungEvalContext& ctx)
{
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    if (!pubkey_field || !sig_field) return EvalResult::ERROR;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker, ctx);
}

EvalResult EvalP2PKHLegacyBlock(const RungBlock& block,
                                 const api::LadderSigChecker& sig_checker,
                                 const RungEvalContext& ctx)
{
    // P2PKH_LEGACY: HASH160(pubkey) == committed hash, then verify sig
    const RungField* hash160_field = FindField(block, RungDataType::HASH160);
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!hash160_field || !pubkey_field || !sig_field) {
        return EvalResult::ERROR;
    }
    if (hash160_field->data.size() != 20) {
        return EvalResult::ERROR;
    }

    unsigned char computed[CHash160::OUTPUT_SIZE];
    CHash160().Write(pubkey_field->data).Finalize(computed);
    if (memcmp(computed, hash160_field->data.data(), 20) != 0) {
        return EvalResult::UNSATISFIED;
    }

    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker, ctx);
}

EvalResult EvalP2WPKHLegacyBlock(const RungBlock& block,
                                  const api::LadderSigChecker& sig_checker,
                                  const RungEvalContext& ctx)
{
    // P2WPKH_LEGACY: identical evaluation to P2PKH
    return EvalP2PKHLegacyBlock(block, sig_checker, ctx);
}

EvalResult EvalP2TRLegacyBlock(const RungBlock& block,
                                const api::LadderSigChecker& sig_checker,
                                const RungEvalContext& ctx)
{
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    if (!pubkey_field || !sig_field) return EvalResult::ERROR;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigWithScheme(*pubkey_field, *sig_field, scheme_field, sig_checker, ctx);
}

EvalResult EvalP2SHLegacyBlock(const RungBlock& block,
                                const api::LadderSigChecker& sig_checker,
                                const BaseSignatureChecker& legacy_checker,
                                SigVersion sigversion,
                                ScriptExecutionData& execdata,
                                const RungEvalContext& ctx,
                                int depth)
{
    // P2SH_LEGACY: HASH160(inner_conditions) == committed hash, then eval inner
    const RungField* hash160_field = FindField(block, RungDataType::HASH160);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) preimage_field = FindField(block, RungDataType::SCRIPT_BODY);

    if (!hash160_field || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (hash160_field->data.size() != 20) {
        return EvalResult::ERROR;
    }

    // Compute HASH160(preimage) and compare
    unsigned char computed[CHash160::OUTPUT_SIZE];
    CHash160().Write(preimage_field->data).Finalize(computed);
    if (memcmp(computed, hash160_field->data.data(), 20) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // Deserialize and evaluate inner conditions
    return EvalInnerConditions(preimage_field->data, block, sig_checker, legacy_checker, sigversion, execdata, ctx, depth + 1);
}

EvalResult EvalP2WSHLegacyBlock(const RungBlock& block,
                                 const api::LadderSigChecker& sig_checker,
                                 const BaseSignatureChecker& legacy_checker,
                                 SigVersion sigversion,
                                 ScriptExecutionData& execdata,
                                 const RungEvalContext& ctx,
                                 int depth)
{
    // P2WSH_LEGACY: SHA256(inner_conditions) == committed hash, then eval inner
    const RungField* hash256_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) preimage_field = FindField(block, RungDataType::SCRIPT_BODY);

    if (!hash256_field || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (hash256_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute SHA256(preimage) and compare
    unsigned char computed[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed);
    if (memcmp(computed, hash256_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // Deserialize and evaluate inner conditions
    return EvalInnerConditions(preimage_field->data, block, sig_checker, legacy_checker, sigversion, execdata, ctx, depth + 1);
}

EvalResult EvalP2TRScriptLegacyBlock(const RungBlock& block,
                                      const api::LadderSigChecker& sig_checker,
                                      const BaseSignatureChecker& legacy_checker,
                                      SigVersion sigversion,
                                      ScriptExecutionData& execdata,
                                      const RungEvalContext& ctx,
                                      int depth)
{
    // P2TR_SCRIPT_LEGACY: script-path spend
    // merkle_pub_key: internal key bound by Merkle proof (no longer in conditions).
    // Fields: HASH256 (Merkle root of script tree), PREIMAGE (revealed leaf)
    // Verification: hash the revealed leaf, check it matches the Merkle root,
    //               then deserialize and evaluate inner conditions.
    const RungField* hash256_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) preimage_field = FindField(block, RungDataType::SCRIPT_BODY);

    if (!hash256_field || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (hash256_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Verify revealed leaf hashes into Merkle root.
    // For a single-leaf tree, SHA256(leaf) == root.
    unsigned char leaf_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(leaf_hash);
    if (memcmp(leaf_hash, hash256_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // Deserialize and evaluate inner conditions
    return EvalInnerConditions(preimage_field->data, block, sig_checker, legacy_checker, sigversion, execdata, ctx, depth + 1);
}

void register_legacy_blocks()
{
    RegisterBlock(RungBlockType::P2PK_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2PKLegacyBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::P2PKH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2PKHLegacyBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::P2SH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2SHLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
    RegisterBlock(RungBlockType::P2WPKH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2WPKHLegacyBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::P2WSH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2WSHLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
    RegisterBlock(RungBlockType::P2TR_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2TRLegacyBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::P2TR_SCRIPT_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2TRScriptLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
}

} // namespace rung
