// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: legacy.
// Evaluators + registry function. The top-level dispatcher calls each
// registered evaluator via `rung::LookupBlockEvaluator`.

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

static EvalResult VerifySigFromFields(const RungField& pubkey_field,
                                       const RungField& sig_field,
                                       const RungField* scheme_field,
                                       const BaseSignatureChecker& checker,
                                       SigVersion sigversion,
                                       ScriptExecutionData& execdata)
{
    // Legacy wrappers use Core's BaseSignatureChecker, which verifies against
    // Core's legacy / SegWit / Taproot sighash — not the Ladder sighash that
    // PQ signatures commit to. Reject PQ schemes here: PQ sigs belong in
    // Ladder-native blocks (SIG, MULTISIG, etc.) and go through the
    // LadderSigChecker adapter.
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) return EvalResult::ERROR;
    }

    std::span<const unsigned char> sig_span{sig_field.data.data(), sig_field.data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field.data.data(), pubkey_field.data.size()};

    if (sig_field.data.size() >= 64 && sig_field.data.size() <= 65) {
        std::vector<unsigned char> xonly;
        if (pubkey_field.data.size() == 33) {
            xonly.assign(pubkey_field.data.begin() + 1, pubkey_field.data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }
        if (checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    if (sig_field.data.size() >= 8 && sig_field.data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field.data.begin(), sig_field.data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field.data.begin(), pubkey_field.data.end());
        CScript empty_script;
        if (checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

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

EvalResult EvalP2PKLegacyBlock(const RungBlock& block,
                                const BaseSignatureChecker& checker,
                                SigVersion sigversion,
                                ScriptExecutionData& execdata)
{
    // P2PK_LEGACY: pubkey + sig, verified against Core's legacy ECDSA /
    // SegWit / Taproot sighash (not Ladder sighash — this is a legacy
    // wrapper, see Phase 1E.3 design note).
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    if (!pubkey_field || !sig_field) return EvalResult::ERROR;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigFromFields(*pubkey_field, *sig_field, scheme_field, checker, sigversion, execdata);
}

EvalResult EvalP2PKHLegacyBlock(const RungBlock& block,
                                 const BaseSignatureChecker& checker,
                                 SigVersion sigversion,
                                 ScriptExecutionData& execdata)
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

    // Compute HASH160(pubkey) and compare
    unsigned char computed[CHash160::OUTPUT_SIZE];
    CHash160().Write(pubkey_field->data).Finalize(computed);
    if (memcmp(computed, hash160_field->data.data(), 20) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // Verify signature
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigFromFields(*pubkey_field, *sig_field, scheme_field, checker, sigversion, execdata);
}

EvalResult EvalP2WPKHLegacyBlock(const RungBlock& block,
                                  const BaseSignatureChecker& checker,
                                  SigVersion sigversion,
                                  ScriptExecutionData& execdata)
{
    // P2WPKH_LEGACY: identical evaluation to P2PKH
    return EvalP2PKHLegacyBlock(block, checker, sigversion, execdata);
}

EvalResult EvalP2TRLegacyBlock(const RungBlock& block,
                                const BaseSignatureChecker& checker,
                                SigVersion sigversion,
                                ScriptExecutionData& execdata)
{
    // P2TR_LEGACY key-path: pubkey + sig against Core's Taproot sighash.
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    if (!pubkey_field || !sig_field) return EvalResult::ERROR;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    return VerifySigFromFields(*pubkey_field, *sig_field, scheme_field, checker, sigversion, execdata);
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
        return EvalP2PKLegacyBlock(b, d.legacy_checker, d.sigversion, d.execdata);
    });
    RegisterBlock(RungBlockType::P2PKH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2PKHLegacyBlock(b, d.legacy_checker, d.sigversion, d.execdata);
    });
    RegisterBlock(RungBlockType::P2SH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2SHLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
    RegisterBlock(RungBlockType::P2WPKH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2WPKHLegacyBlock(b, d.legacy_checker, d.sigversion, d.execdata);
    });
    RegisterBlock(RungBlockType::P2WSH_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2WSHLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
    RegisterBlock(RungBlockType::P2TR_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2TRLegacyBlock(b, d.legacy_checker, d.sigversion, d.execdata);
    });
    RegisterBlock(RungBlockType::P2TR_SCRIPT_LEGACY, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalP2TRScriptLegacyBlock(b, d.sig_checker, d.legacy_checker, d.sigversion, d.execdata, d.ctx, d.depth);
    });
}

} // namespace rung
