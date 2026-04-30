// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Implementations of the helpers declared in `rung/block_helpers.h`. Shared
// across every block-family TU under `src/rung/blocks/` and by the top-level
// dispatcher / VerifyRungTx in `rung/evaluator.cpp`.

#include <rung/block_helpers.h>

#include <rung/conditions.h>
#include <rung/pq_verify.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung/evaluator.h>
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

/** Helper: find the first field of a given type in a block. Returns nullptr if not found. */
const RungField* FindField(const RungBlock& block, RungDataType type)
{
    for (const auto& field : block.fields) {
        if (field.type == type) return &field;
    }
    return nullptr;
}

/** Helper: collect all fields of a given type from a block. */
std::vector<const RungField*> FindAllFields(const RungBlock& block, RungDataType type)
{
    std::vector<const RungField*> result;
    for (const auto& field : block.fields) {
        if (field.type == type) result.push_back(&field);
    }
    return result;
}

/** Helper: read a little-endian numeric value from a NUMERIC field (1-8 bytes). */
std::optional<int64_t> ReadNumeric(const RungField& field)
{
    if (field.data.empty() || field.data.size() > 8) return std::nullopt;
    uint64_t val = 0;
    for (size_t i = 0; i < field.data.size(); ++i) {
        val |= static_cast<uint64_t>(field.data[i]) << (8 * i);
    }
    return static_cast<int64_t>(val);
}

bool HasRequiredPubkeys(const RungBlock& block, size_t count)
{
    auto pks = FindAllFields(block, RungDataType::PUBKEY);
    return pks.size() >= count;
}

std::vector<const RungField*> ResolvePubkeyCommitments(const RungBlock& block)
{
    return FindAllFields(block, RungDataType::PUBKEY);
}

EvalResult ApplyInversion(EvalResult raw, bool inverted)
{
    if (!inverted) return raw;
    switch (raw) {
    case EvalResult::SATISFIED:        return EvalResult::UNSATISFIED;
    case EvalResult::UNSATISFIED:      return EvalResult::SATISFIED;
    case EvalResult::ERROR:            return EvalResult::ERROR; // errors never flip
    case EvalResult::UNKNOWN_BLOCK_TYPE: return EvalResult::ERROR; // unknown types must not satisfy
    }
    return raw;
}

bool FetchLadderSighash(const RungEvalContext& ctx,
                        uint8_t hash_type,
                        uint8_t out[32])
{
    // Production path: precomputed + tx + conditions all present.
    if (ctx.precomputed && ctx.tx && ctx.input_conditions && ctx.precomputed->ladder_ready) {
        uint256 hash;
        if (rung::api::SignatureHashLadder(*ctx.precomputed, *ctx.tx,
                                            ctx.input_index, hash_type,
                                            *ctx.input_conditions, hash)) {
            std::memcpy(out, hash.data(), 32);
            return true;
        }
    }
    // Test stub path: no backing tx. Zero sighash; mock checkers ignore the
    // hash bytes, real consensus never takes this branch (VerifyRungTx always
    // populates precomputed + input_conditions before dispatch).
    std::memset(out, 0, 32);
    return true;
}

bool ExtractSchnorrHashType(std::span<const uint8_t> sig, uint8_t& hash_type)
{
    if (sig.size() == 64) { hash_type = SIGHASH_DEFAULT; return true; }
    if (sig.size() == 65) {
        hash_type = sig.back();
        if (hash_type == SIGHASH_DEFAULT) return false;
        return true;
    }
    return false;
}

EvalResult EvalPQSig(RungScheme scheme,
                             const RungField& sig_field,
                             const RungField& pubkey_field,
                             const api::LadderSigChecker& sig_checker,
                             const RungEvalContext& ctx)
{
    (void)sig_checker;  // PQ schemes bypass the Core sig checker entirely;
                        // library verifies via oqs directly.
    if (!HasPQSupport()) return EvalResult::ERROR;

    uint8_t sighash[32];
    if (!FetchLadderSighash(ctx, SIGHASH_DEFAULT, sighash)) {
        return EvalResult::ERROR;
    }

    std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
    std::span<const uint8_t> msg{sighash, 32};
    std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};

    if (VerifyPQSignature(scheme, sig, msg, pubkey)) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult VerifySigWithScheme(const RungField& pubkey_field,
                                       const RungField& sig_field,
                                       const RungField* scheme_field,
                                       const api::LadderSigChecker& sig_checker,
                                       const RungEvalContext& ctx)
{
    auto try_schnorr = [&](std::span<const uint8_t> sig,
                           std::span<const uint8_t> pubkey) -> EvalResult {
        if (pubkey.size() != 32) return EvalResult::UNSATISFIED;
        uint8_t hash_type;
        if (!ExtractSchnorrHashType(sig, hash_type)) return EvalResult::UNSATISFIED;
        uint8_t sighash[32];
        if (!FetchLadderSighash(ctx, hash_type, sighash)) return EvalResult::ERROR;
        std::span<const uint8_t, 32> sighash_span{sighash, 32};
        if (sig_checker.CheckSchnorrSignature(sig, pubkey, sighash_span)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    };

    auto try_ecdsa = [&](std::span<const uint8_t> sig,
                         std::span<const uint8_t> pubkey) -> EvalResult {
        // Classical ECDSA sigs in v4 are DER + trailing 1-byte hash_type.
        if (sig.empty()) return EvalResult::UNSATISFIED;
        uint8_t hash_type = sig.back();
        uint8_t sighash[32];
        if (!FetchLadderSighash(ctx, hash_type, sighash)) return EvalResult::ERROR;
        std::span<const uint8_t, 32> sighash_span{sighash, 32};
        if (sig_checker.CheckECDSASignature(sig, pubkey, sighash_span)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    };

    // Check for explicit SCHEME field — routes to PQ verifier if present
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            return EvalPQSig(scheme, sig_field, pubkey_field, sig_checker, ctx);
        }
        if (scheme == RungScheme::SCHNORR) {
            std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
            std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};
            std::vector<uint8_t> xonly;
            if (pubkey_field.data.size() == 33) {
                xonly.assign(pubkey_field.data.begin() + 1, pubkey_field.data.end());
                pubkey = std::span<const uint8_t>{xonly.data(), xonly.size()};
            }
            return try_schnorr(sig, pubkey);
        }
        if (scheme == RungScheme::ECDSA) {
            std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
            std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};
            return try_ecdsa(sig, pubkey);
        }
        // Unknown classical scheme — fall through to size-based routing
    }

    // Size-based fallback: Schnorr (64-65 bytes) or ECDSA (8-72 bytes)
    std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
    std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};

    if (sig_field.data.size() >= 64 && sig_field.data.size() <= 65) {
        std::vector<uint8_t> xonly;
        if (pubkey_field.data.size() == 33) {
            xonly.assign(pubkey_field.data.begin() + 1, pubkey_field.data.end());
            pubkey = std::span<const uint8_t>{xonly.data(), xonly.size()};
        }
        return try_schnorr(sig, pubkey);
    }

    if (sig_field.data.size() >= 8 && sig_field.data.size() <= 72) {
        return try_ecdsa(sig, pubkey);
    }

    return EvalResult::ERROR;
}

EvalResult VerifyMultisigInnerMerkle(const RungBlock& block,
                                      uint32_t threshold,
                                      const std::vector<uint8_t>& pubkey_root_bytes,
                                      const RungField* scheme_field,
                                      size_t conditions_field_count,
                                      const api::LadderSigChecker& sig_checker,
                                      const RungEvalContext& ctx)
{
    if (threshold == 0 || threshold > MAX_PUBKEYS_PER_MULTISIG) {
        return EvalResult::ERROR;
    }
    if (pubkey_root_bytes.size() != 32) {
        return EvalResult::ERROR;
    }
    uint256 pubkey_root;
    std::memcpy(pubkey_root.data(), pubkey_root_bytes.data(), 32);

    // Witness must be exactly K triplets: (PUBKEY, MERKLE_PROOF, SIGNATURE).
    // Deserialiser already enforced the triplet pattern and the global cap;
    // here we cross-check against the K read from conditions.
    if (block.fields.size() < conditions_field_count) return EvalResult::ERROR;
    const size_t witness_field_count = block.fields.size() - conditions_field_count;
    if (witness_field_count != static_cast<size_t>(threshold) * 3) {
        return EvalResult::UNSATISFIED;
    }

    // v0.8 (E-018b): triplets MUST be in strict ascending lexicographic order
    // by PUBKEY bytes. The verify check enforces both ordering and
    // distinctness — a duplicate pubkey is an order violation (lex compare
    // returns 0). Closes ~log2(K!) bits/spend of permutation channel
    // (~25 bits/3 B for K=11). Signers (signrungtx, MULTISIG/TIMELOCKED_MULTISIG)
    // produce sorted triplets; relayed witnesses fail this check at consensus.
    std::vector<uint8_t> prev_pk;
    uint32_t valid_count = 0;
    // v0.14 (audit #10 A2): all K Merkle proofs in a single multisig spend
    // descend from the same pubkey_root, so they MUST share the same depth.
    // Sorted-pair Merkle with distinct leaf/interior tagged-hash domains
    // already makes shorter-than-expected proofs rely on a 256-bit preimage
    // (not exploitable today), but enforcing uniform depth removes the
    // failure mode entirely. `expected_depth` latches on the first proof.
    size_t expected_depth = 0;

    for (uint32_t i = 0; i < threshold; ++i) {
        const RungField& pk = block.fields[conditions_field_count + 3 * i + 0];
        const RungField& proof_f = block.fields[conditions_field_count + 3 * i + 1];
        const RungField& sig = block.fields[conditions_field_count + 3 * i + 2];

        if (pk.type != RungDataType::PUBKEY ||
            proof_f.type != RungDataType::MERKLE_PROOF ||
            sig.type != RungDataType::SIGNATURE) {
            return EvalResult::ERROR;
        }

        if (i > 0) {
            const size_t cmp_len = std::min(prev_pk.size(), pk.data.size());
            const int c = std::memcmp(prev_pk.data(), pk.data.data(), cmp_len);
            // Reject ≤ — strict ascending. Equal pubkeys violate the same rule
            // and replace the prior duplicate-pubkey check.
            if (c > 0 || (c == 0 && prev_pk.size() >= pk.data.size())) {
                return EvalResult::UNSATISFIED;
            }
        }

        // MERKLE_PROOF carries depth × 32 bytes of sibling hashes.
        if (proof_f.data.size() % 32 != 0) {
            return EvalResult::ERROR;
        }
        const size_t depth = proof_f.data.size() / 32;
        if (depth > MAX_MULTISIG_TREE_DEPTH) {
            return EvalResult::ERROR;
        }
        // v0.14 (audit #10 A2): enforce uniform depth across all K proofs.
        if (i == 0) {
            expected_depth = depth;
        } else if (depth != expected_depth) {
            return EvalResult::UNSATISFIED;
        }
        std::vector<uint256> proof(depth);
        for (size_t d = 0; d < depth; ++d) {
            std::memcpy(proof[d].data(), proof_f.data.data() + d * 32, 32);
        }

        std::string proof_err;
        if (!VerifyPubkeyMerkleProof(pk.data, proof, pubkey_root, proof_err)) {
            return EvalResult::UNSATISFIED;
        }

        EvalResult r = VerifySigWithScheme(pk, sig, scheme_field, sig_checker, ctx);
        if (r == EvalResult::ERROR) return EvalResult::ERROR;
        if (r != EvalResult::SATISFIED) return EvalResult::UNSATISFIED;

        prev_pk = pk.data;
        ++valid_count;
    }

    return (valid_count >= threshold) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
}

bool HasRequiredHashes(const RungBlock& block, size_t count)
{
    return FindAllFields(block, RungDataType::HASH256).size() >= count;
}

bool VerifyHashPreimageBinding(const RungBlock& block)
{
    auto hashes = FindAllFields(block, RungDataType::HASH256);
    auto preimages = FindAllFields(block, RungDataType::PREIMAGE);

    if (hashes.empty()) return true; // no hashes to verify
    if (preimages.size() < hashes.size()) return false; // not enough preimages

    for (size_t i = 0; i < hashes.size(); ++i) {
        if (hashes[i]->data.size() != 32) return false;
        unsigned char computed[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(preimages[i]->data.data(), preimages[i]->data.size()).Finalize(computed);
        if (memcmp(computed, hashes[i]->data.data(), 32) != 0) {
            return false; // preimage doesn't match hash
        }
    }
    return true;
}

bool OutputRootMatchesInput(const api::LadderOutputView& output, const MLSCVerifiedLeaves& verified_leaves)
{
    uint256 output_root;
    if (!GetMLSCRoot(output.script_pub_key.as_span(), output_root)) {
        return false;
    }
    return output_root == verified_leaves.root;
}

uint256 ComputeExpectedRoot(const MLSCVerifiedLeaves& verified_leaves,
                                    size_t leaf_index, const uint256& new_leaf)
{
    std::vector<uint256> leaves_copy = verified_leaves.leaves;
    if (leaf_index >= leaves_copy.size()) return uint256{}; // should not happen
    leaves_copy[leaf_index] = new_leaf;
    return BuildMerkleTree(std::move(leaves_copy));
}

/** Helper: write a little-endian int64 into a 4-byte NUMERIC field. */
void WriteNumericField(RungField& f, int64_t val)
{
    f.data.clear();
    for (int i = 0; i < 4; ++i) {
        f.data.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xFF));
    }
}

/** Build a CreationProofRung from a Rung + pubkeys, suitable for ComputeTxMLSCLeaf.
 *  v0.10 (F-1): propagate `rung.relay_refs` into the structural template so
 *  every leaf produced by this helper binds the rung's relay dependencies.
 *  Without this the v0.9 R-1 fix is bypassed at every recursive-covenant
 *  transition (RECURSE_DECAY / RECURSE_SPLIT / RECURSE_MODIFIED) — the
 *  spend-input verifier hashes `relay_refs`, but the output-side
 *  recomputation here strips them and accepts an output rung that committed
 *  to no relay dependencies. */
CreationProofRung BuildCPRung(const Rung& rung,
                                      const std::vector<std::vector<uint8_t>>& pks,
                                      const RungCoil& coil)
{
    CreationProofRung cp;
    for (const auto& block : rung.blocks) {
        cp.blocks.push_back({
            static_cast<uint16_t>(block.type),
            static_cast<uint8_t>(block.inverted ? 1 : 0)
        });
    }
    cp.relay_refs = rung.relay_refs;
    cp.coil = coil;
    cp.value_commitment = ComputeValueCommitment(rung, pks);
    return cp;
}

/** Compute TX_MLSC root from a RungConditions + per-rung pubkeys (fallback path).
 *  v0.7: includes relay leaves so the recomputed root matches what createrungtx
 *  produced — required for RECURSE_ family / QABI covenant checks against
 *  relay-bearing inputs to verify correctly. */
uint256 ComputeConditionsRootMLSC(const RungConditions& conditions,
                                          const std::vector<std::vector<std::vector<uint8_t>>>& rung_pubkeys,
                                          const std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys)
{
    std::vector<CreationProofRung> cp_rungs;
    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
        const auto& pks = (r < rung_pubkeys.size()) ? rung_pubkeys[r] : std::vector<std::vector<uint8_t>>{};
        cp_rungs.push_back(BuildCPRung(conditions.rungs[r], pks, conditions.coil));
    }
    std::vector<CreationProofRelay> cp_relays;
    for (size_t i = 0; i < conditions.relays.size(); ++i) {
        const auto& pks = (i < relay_pubkeys.size()) ? relay_pubkeys[i]
                                                     : std::vector<std::vector<uint8_t>>{};
        CreationProofRelay cp;
        for (const auto& blk : conditions.relays[i].blocks) {
            cp.blocks.push_back({static_cast<uint16_t>(blk.type),
                                  static_cast<uint8_t>(blk.inverted ? 1 : 0)});
        }
        cp.relay_refs = conditions.relays[i].relay_refs;
        Rung tmp; tmp.blocks = conditions.relays[i].blocks;
        cp.value_commitment = ComputeValueCommitment(tmp, pks);
        cp_relays.push_back(std::move(cp));
    }
    return ComputeTxMLSCRoot(cp_rungs, cp_relays);
}

EvalResult VerifyMutatedLeaves(const RungEvalContext& ctx,
                                       const std::vector<MutationSpec>& mutations)
{
    if (!ctx.input_conditions || !ctx.spending_output) {
        return EvalResult::ERROR;
    }

    // Fallback path: when verified_leaves is not available (unit tests),
    // apply mutations to a full copy of conditions and compare roots.
    if (!ctx.verified_leaves) {
        RungConditions expected = *ctx.input_conditions;
        std::vector<std::vector<std::vector<uint8_t>>> pubkeys;
        if (ctx.rung_pubkeys) pubkeys = *ctx.rung_pubkeys;

        for (const auto& m : mutations) {
            if (m.rung_idx < 0 || static_cast<size_t>(m.rung_idx) >= expected.rungs.size()) {
                return EvalResult::UNSATISFIED;
            }
            auto& rung = expected.rungs[m.rung_idx];
            if (m.block_idx < 0 || static_cast<size_t>(m.block_idx) >= rung.blocks.size()) {
                return EvalResult::UNSATISFIED;
            }
            auto& blk = rung.blocks[m.block_idx];
            size_t cond_idx = 0;
            bool applied = false;
            for (auto& f : blk.fields) {
                if (!IsConditionDataType(f.type)) continue;
                if (static_cast<int64_t>(cond_idx) == m.param_idx) {
                    if (f.type != RungDataType::NUMERIC) return EvalResult::UNSATISFIED;
                    auto cur = ReadNumeric(f);
                    if (!cur) return EvalResult::ERROR;
                    WriteNumericField(f, *cur + m.delta);
                    applied = true;
                    break;
                }
                ++cond_idx;
            }
            if (!applied) return EvalResult::UNSATISFIED;
        }
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
            return EvalResult::UNSATISFIED;
        }
        if (output_root != ComputeConditionsRootMLSC(expected, pubkeys)) {
            return EvalResult::UNSATISFIED;
        }
        return EvalResult::SATISFIED;
    }

    const auto& vl = *ctx.verified_leaves;
    std::vector<uint256> leaves_copy = vl.leaves;

    // Group mutations by target rung
    for (const auto& m : mutations) {
        if (m.rung_idx < 0 || static_cast<size_t>(m.rung_idx) >= vl.total_rungs) {
            return EvalResult::UNSATISFIED;
        }

        // Determine which rung to mutate
        Rung mutated_rung;
        std::vector<std::vector<uint8_t>> rung_pks;

        if (static_cast<uint16_t>(m.rung_idx) == vl.rung_index) {
            // Same-rung mutation: use the revealed rung from input conditions
            // (input_conditions has exactly 1 rung for MLSC — the revealed one)
            if (ctx.input_conditions->rungs.empty()) return EvalResult::UNSATISFIED;
            mutated_rung = ctx.input_conditions->rungs[0];
            // Pubkeys for the revealed rung
            if (ctx.rung_pubkeys && !ctx.rung_pubkeys->empty()) {
                rung_pks = (*ctx.rung_pubkeys)[0];
            }
        } else {
            // Cross-rung mutation: find in revealed_mutation_targets.
            // v0.12 (audit 8b F1): the spender supplies target.rung at spend
            // time; we MUST verify that ComputeTxMLSCLeaf(target.rung) matches
            // the leaf the conditions_root committed to. Without this check
            // a spender can substitute a fake rung at any non-revealed index
            // and erase its constraints across the covenant transition — the
            // post-mutation tree would commit to fake_rung_post_mutation and
            // the spender chooses output_root to match.
            if (!ctx.mlsc_proof) return EvalResult::UNSATISFIED;
            bool found = false;
            for (const auto& target : ctx.mlsc_proof->revealed_mutation_targets) {
                if (target.idx == static_cast<uint16_t>(m.rung_idx)) {
                    // Verify target.rung's pre-mutation leaf matches the
                    // committed leaf at this index in verified_leaves.
                    RungCoil tgt_coil = ctx.input_conditions->coil;
                    auto tgt_cp = BuildCPRung(target.rung, target.pubkeys, tgt_coil);
                    if (ComputeTxMLSCLeaf(tgt_cp) != vl.leaves[m.rung_idx]) {
                        return EvalResult::UNSATISFIED;
                    }
                    mutated_rung = target.rung;
                    rung_pks = target.pubkeys;
                    found = true;
                    break;
                }
            }
            if (!found) return EvalResult::UNSATISFIED;
        }

        // Apply the mutation
        if (m.block_idx < 0 || static_cast<size_t>(m.block_idx) >= mutated_rung.blocks.size()) {
            return EvalResult::UNSATISFIED;
        }
        auto& blk = mutated_rung.blocks[m.block_idx];

        // Find the param_idx-th condition field (NUMERIC)
        size_t cond_idx = 0;
        bool applied = false;
        for (auto& f : blk.fields) {
            if (!IsConditionDataType(f.type)) continue;
            if (static_cast<int64_t>(cond_idx) == m.param_idx) {
                if (f.type != RungDataType::NUMERIC) {
                    return EvalResult::UNSATISFIED;
                }
                auto cur = ReadNumeric(f);
                if (!cur) return EvalResult::ERROR;
                WriteNumericField(f, *cur + m.delta);
                applied = true;
                break;
            }
            ++cond_idx;
        }
        if (!applied) return EvalResult::UNSATISFIED;

        // Recompute the leaf for this rung using TX_MLSC leaf computation
        RungCoil coil = ctx.input_conditions->coil;
        auto cp = BuildCPRung(mutated_rung, rung_pks, coil);
        leaves_copy[m.rung_idx] = ComputeTxMLSCLeaf(cp);
    }

    // Build tree from mutated leaves and compare with output root
    uint256 expected_root = BuildMerkleTree(std::move(leaves_copy));
    uint256 output_root;
    if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
        return EvalResult::UNSATISFIED;
    }
    if (output_root != expected_root) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

bool ParseMutationSpecs(const std::vector<const RungField*>& numerics,
                                int64_t& max_depth,
                                std::vector<MutationSpec>& mutations)
{
    if (numerics.size() < 4) return false;

    auto depth_opt = ReadNumeric(*numerics[0]);
    if (!depth_opt) return false;
    max_depth = *depth_opt;

    if (numerics.size() == 4 || numerics.size() == 5) {
        // Legacy format: single mutation at rung 0
        auto v1 = ReadNumeric(*numerics[1]);
        auto v2 = ReadNumeric(*numerics[2]);
        auto v3 = ReadNumeric(*numerics[3]);
        if (!v1 || !v2 || !v3) return false;
        mutations.push_back({0, *v1, *v2, *v3});
        return true;
    }

    // New format: numerics[1] = num_mutations, then 4 fields per mutation
    auto num_mutations_opt = ReadNumeric(*numerics[1]);
    if (!num_mutations_opt) return false;
    int64_t num_mutations = *num_mutations_opt;
    if (num_mutations < 1 || num_mutations > 64 ||
        static_cast<size_t>(2 + 4 * num_mutations) > numerics.size()) {
        return false;
    }
    for (int64_t i = 0; i < num_mutations; ++i) {
        size_t base = 2 + 4 * i;
        auto v0 = ReadNumeric(*numerics[base]);
        auto v1 = ReadNumeric(*numerics[base + 1]);
        auto v2 = ReadNumeric(*numerics[base + 2]);
        auto v3 = ReadNumeric(*numerics[base + 3]);
        if (!v0 || !v1 || !v2 || !v3) return false;
        mutations.push_back({*v0, *v1, *v2, *v3});
    }
    return true;
}

} // namespace rung
