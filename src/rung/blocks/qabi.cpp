// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: qabi.
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

/** QABI_PRIME — priming state transition.
 *
 *  Witness-only fields (in order):
 *    [0] HASH256  new_committed_root    (from witness)
 *    [1] NUMERIC  prime_depth           (from witness)
 *    [2] NUMERIC  new_committed_expiry  (from witness)
 *    [3] PREIMAGE prime_preimage        (from witness)
 *
 *  The "current state" (auth_tip, committed_root, committed_depth,
 *  committed_expiry, owner_pubkey_hash) is read from the input's QABI_SPEND
 *  block (searched across all rungs in ctx.input_conditions). QABI_PRIME
 *  does not duplicate state in its own committed fields.
 *
 *  Consensus checks:
 *    1. All 4 witness fields present, correctly typed, correct sizes
 *    2. Exactly one QABI_SPEND block is discoverable in input_conditions
 *    3. prime_depth > committed_depth                (monotonic progression)
 *    4. SHA256^prime_depth(prime_preimage) == auth_tip (preimage valid)
 *    5. Covenant: rebuild input_conditions with the QABI_SPEND block's
 *       committed_root/committed_depth/committed_expiry mutated to the new
 *       values, recompute the MLSC root, and verify it matches the output's
 *       committed conditions_root. Everything else (auth_tip, owner_pubkey,
 *       other rungs, coil data) must be preserved bit-exact.
 */
static EvalResult EvalQABIPrimeBlock(const RungBlock& block,
                                      const api::LadderSigChecker& /*sig_checker*/,
                                      const RungEvalContext& ctx)
{
    // -- Witness field extraction ---------------------------------------

    if (block.fields.size() != 4) return EvalResult::ERROR;

    const RungField* new_root_field   = FindField(block, RungDataType::HASH256);
    auto nums = FindAllFields(block, RungDataType::NUMERIC);
    const RungField* preimage_field   = FindField(block, RungDataType::PREIMAGE);

    if (!new_root_field || nums.size() != 2 || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (new_root_field->data.size() != 32) return EvalResult::ERROR;
    if (preimage_field->data.size() != 32) return EvalResult::ERROR;

    auto prime_depth_opt          = ReadNumeric(*nums[0]);
    auto new_committed_expiry_opt = ReadNumeric(*nums[1]);
    if (!prime_depth_opt || !new_committed_expiry_opt) return EvalResult::ERROR;
    if (*prime_depth_opt <= 0 || *new_committed_expiry_opt < 0) return EvalResult::ERROR;
    const int64_t prime_depth          = *prime_depth_opt;
    const int64_t new_committed_expiry = *new_committed_expiry_opt;

    if (prime_depth >= static_cast<int64_t>(rung::QABI_AUTH_CHAIN_DEFAULT_LENGTH * 10)) {
        return EvalResult::ERROR;
    }
    // Block heights fit in 32 bits. `WriteNumericField` stores the low 32
    // bits of its input, so an 8-byte NUMERIC with a value > 0xFFFFFFFF
    // would silently lose its high bits when covenant-written into the
    // output rung. Reject such malformed primes up front.
    if (new_committed_expiry > 0xFFFFFFFFLL) return EvalResult::ERROR;

    // -- Locate the QABI_SPEND block ------------------------------------
    //
    // QABI_PRIME's covenant check 5 needs the FULL input conditions tree
    // to recompute the mutated MLSC root. But for MLSC spends the
    // consensus-time ctx.input_conditions only carries the revealed
    // rung (1 entry — kept 1:1 with witness_ladder.rungs so the merge
    // pass works). The QABI_SPEND rung that carries committed state
    // must be revealed via the MLSC proof's `revealed_mutation_targets`
    // at sign time (signrungtx does this automatically when spending a
    // rung that contains QABI_PRIME).
    //
    // Build a "full tree" here by taking the revealed rung (placed at
    // its real index) and overlaying every mutation target at its own
    // real index. That tree is used for:
    //   (a) the QABI_SPEND lookup (block-type search across all rungs)
    //   (b) check 5's covenant root recomputation
    //
    // Non-revealed rungs are left as default-empty Rungs; they only
    // contribute if the spender reveals them as mutation targets.

    if (ctx.input_conditions == nullptr || ctx.spending_output == nullptr) {
        return EvalResult::ERROR;
    }
    if (ctx.mlsc_proof == nullptr) {
        // Unit-test fallback: no MLSC proof plumbed. Fall back to the
        // single-rung input_conditions layout used by unit tests that
        // build the full tree directly in ctx.
        RungConditions unit_test_full = *ctx.input_conditions;
        // Fall through using unit_test_full below.
        const RungBlock* qabi_spend = nullptr;
        size_t qabi_spend_rung_idx_ut = 0;
        size_t qabi_spend_block_idx_ut = 0;
        for (size_t r = 0; r < unit_test_full.rungs.size(); ++r) {
            const auto& rung = unit_test_full.rungs[r];
            for (size_t b = 0; b < rung.blocks.size(); ++b) {
                if (rung.blocks[b].type == RungBlockType::QABI_SPEND) {
                    if (qabi_spend != nullptr) return EvalResult::ERROR;
                    qabi_spend = &rung.blocks[b];
                    qabi_spend_rung_idx_ut = r;
                    qabi_spend_block_idx_ut = b;
                }
            }
        }
        if (qabi_spend == nullptr) return EvalResult::UNSATISFIED;
        // Run the rest of the checks against unit_test_full. The checks
        // below are copy-pasted from the mainline path to keep this
        // fallback self-contained.
        if (qabi_spend->fields.size() != 5) return EvalResult::ERROR;
        auto spend_hashes_ut = FindAllFields(*qabi_spend, RungDataType::HASH256);
        auto spend_nums_ut   = FindAllFields(*qabi_spend, RungDataType::NUMERIC);
        if (spend_hashes_ut.size() != 2 || spend_nums_ut.size() != 2) return EvalResult::ERROR;
        if (spend_hashes_ut[0]->data.size() != 32) return EvalResult::ERROR;
        const RungField* auth_tip_field_ut = spend_hashes_ut[0];
        auto committed_depth_opt_ut = ReadNumeric(*spend_nums_ut[0]);
        if (!committed_depth_opt_ut || *committed_depth_opt_ut < 0) return EvalResult::ERROR;
        const int64_t committed_depth_ut = *committed_depth_opt_ut;
        if (prime_depth <= committed_depth_ut) return EvalResult::UNSATISFIED;
        unsigned char current_ut[CSHA256::OUTPUT_SIZE];
        std::memcpy(current_ut, preimage_field->data.data(), 32);
        for (int64_t i = 0; i < prime_depth; ++i) {
            unsigned char next[CSHA256::OUTPUT_SIZE];
            CSHA256().Write(current_ut, 32).Finalize(next);
            std::memcpy(current_ut, next, 32);
        }
        if (std::memcmp(current_ut, auth_tip_field_ut->data.data(), 32) != 0) {
            return EvalResult::UNSATISFIED;
        }
        RungConditions expected = unit_test_full;
        Rung& mutated_rung = expected.rungs[qabi_spend_rung_idx_ut];
        RungBlock& mutated_block = mutated_rung.blocks[qabi_spend_block_idx_ut];
        std::vector<RungField*> m_hashes, m_nums;
        for (auto& f : mutated_block.fields) {
            if (f.type == RungDataType::HASH256) m_hashes.push_back(&f);
            else if (f.type == RungDataType::NUMERIC) m_nums.push_back(&f);
        }
        if (m_hashes.size() != 2 || m_nums.size() != 2) return EvalResult::ERROR;
        m_hashes[1]->data.assign(new_root_field->data.begin(), new_root_field->data.end());
        WriteNumericField(*m_nums[0], prime_depth);
        WriteNumericField(*m_nums[1], new_committed_expiry);
        std::vector<std::vector<std::vector<uint8_t>>> pks;
        if (ctx.rung_pubkeys) pks = *ctx.rung_pubkeys;
        uint256 expected_root = ComputeConditionsRootMLSC(expected, pks);
        uint256 output_root;
        if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
            return EvalResult::UNSATISFIED;
        }
        if (output_root != expected_root) return EvalResult::UNSATISFIED;
        return EvalResult::SATISFIED;
    }

    // Mainline path: reconstruct the full tree from the MLSC proof.
    RungConditions full_tree;
    full_tree.coil = ctx.input_conditions->coil;
    full_tree.rungs.resize(ctx.mlsc_proof->total_rungs);
    // Place the revealed rung at its real index.
    if (ctx.mlsc_proof->rung_index < full_tree.rungs.size() &&
        !ctx.input_conditions->rungs.empty()) {
        full_tree.rungs[ctx.mlsc_proof->rung_index] = ctx.input_conditions->rungs[0];
    }
    // Overlay mutation-target rungs + their pubkeys at their real
    // indices. The pubkey list travels inside each MLSCMutationTarget
    // (required for rungs with SIG/key-consuming blocks so the
    // consensus-time leaf hash matches bit-exact).
    std::vector<std::vector<std::vector<uint8_t>>> full_pks;
    full_pks.resize(ctx.mlsc_proof->total_rungs);
    for (const auto& target : ctx.mlsc_proof->revealed_mutation_targets) {
        if (target.idx < full_tree.rungs.size()) {
            full_tree.rungs[target.idx] = target.rung;
            full_pks[target.idx] = target.pubkeys;
        }
    }
    // Revealed rung sits at its real index.
    if (ctx.rung_pubkeys && !ctx.rung_pubkeys->empty() &&
        ctx.mlsc_proof->rung_index < full_pks.size()) {
        full_pks[ctx.mlsc_proof->rung_index] = (*ctx.rung_pubkeys)[0];
    }

    const RungBlock* qabi_spend = nullptr;
    size_t qabi_spend_rung_idx = 0;
    size_t qabi_spend_block_idx = 0;
    for (size_t r = 0; r < full_tree.rungs.size(); ++r) {
        const auto& rung = full_tree.rungs[r];
        for (size_t b = 0; b < rung.blocks.size(); ++b) {
            if (rung.blocks[b].type == RungBlockType::QABI_SPEND) {
                if (qabi_spend != nullptr) {
                    // Multiple QABI_SPEND blocks — ambiguous, reject.
                    return EvalResult::ERROR;
                }
                qabi_spend = &rung.blocks[b];
                qabi_spend_rung_idx = r;
                qabi_spend_block_idx = b;
            }
        }
    }
    if (qabi_spend == nullptr) {
        return EvalResult::UNSATISFIED;
    }

    // -- Read current state from QABI_SPEND -----------------------------
    //
    // input_conditions carries CONDITIONS-context blocks. QABI_SPEND in
    // conditions context has 5 fields (auth_tip, committed_root,
    // committed_depth, committed_expiry, owner_id) — the witness-only
    // PREIMAGE spend_preimage is not in the committed tree.
    if (qabi_spend->fields.size() != 5) return EvalResult::ERROR;
    auto spend_hashes = FindAllFields(*qabi_spend, RungDataType::HASH256);
    auto spend_nums   = FindAllFields(*qabi_spend, RungDataType::NUMERIC);
    if (spend_hashes.size() != 2 || spend_nums.size() != 2) return EvalResult::ERROR;
    if (spend_hashes[0]->data.size() != 32) return EvalResult::ERROR;

    const RungField* auth_tip_field        = spend_hashes[0];
    auto committed_depth_opt = ReadNumeric(*spend_nums[0]);
    if (!committed_depth_opt || *committed_depth_opt < 0) return EvalResult::ERROR;
    const int64_t committed_depth = *committed_depth_opt;

    // -- Check 3: monotonic depth progression ----------------------------

    if (prime_depth <= committed_depth) return EvalResult::UNSATISFIED;

    // -- Check 4: preimage valid against auth_tip ------------------------

    unsigned char current[CSHA256::OUTPUT_SIZE];
    std::memcpy(current, preimage_field->data.data(), 32);
    for (int64_t i = 0; i < prime_depth; ++i) {
        unsigned char next[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(current, 32).Finalize(next);
        std::memcpy(current, next, 32);
    }
    if (std::memcmp(current, auth_tip_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // -- Check 5: covenant — rebuild with mutated QABI_SPEND state -------

    RungConditions expected = full_tree;
    Rung& mutated_rung = expected.rungs[qabi_spend_rung_idx];
    RungBlock& mutated_block = mutated_rung.blocks[qabi_spend_block_idx];

    // Re-locate the fields in the mutated copy (same order preserved).
    auto m_hashes = std::vector<RungField*>{};
    auto m_nums   = std::vector<RungField*>{};
    for (auto& f : mutated_block.fields) {
        if (f.type == RungDataType::HASH256) m_hashes.push_back(&f);
        else if (f.type == RungDataType::NUMERIC) m_nums.push_back(&f);
    }
    if (m_hashes.size() != 2 || m_nums.size() != 2) return EvalResult::ERROR;

    // Mutate committed_root (HASH256 index 1 — second hash, first is auth_tip)
    m_hashes[1]->data.assign(new_root_field->data.begin(), new_root_field->data.end());

    // Mutate committed_depth (NUMERIC index 0)
    WriteNumericField(*m_nums[0], prime_depth);

    // Mutate committed_expiry (NUMERIC index 1)
    WriteNumericField(*m_nums[1], new_committed_expiry);

    // Compute expected MLSC root from the mutated full tree.
    uint256 expected_root = ComputeConditionsRootMLSC(expected, full_pks);

    // Extract the output's committed conditions_root.
    uint256 output_root;
    if (!GetMLSCRoot(ctx.spending_output->script_pub_key.as_span(), output_root)) {
        return EvalResult::UNSATISFIED;
    }

    if (output_root != expected_root) {
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::SATISFIED;
}

/** QABI_SPEND — fat evaluator doing nine consensus checks per primed input.
 *
 *  Block field layout (strict order):
 *    [0] HASH256       auth_tip           (committed; H^N(auth_seed))
 *    [1] HASH256       committed_root     (committed; current primed batch root)
 *    [2] NUMERIC       committed_depth    (committed; depth of last consumed preimage)
 *    [3] NUMERIC       committed_expiry   (committed; max block height for spend)
 *    [4] PUBKEY_COMMIT owner_pubkey_hash  (committed; = participant_id =
 *                                          SHA256(Rung 0 FALCON pubkey))
 *    [5] PREIMAGE      spend_preimage     (witness; preimage at committed_depth+1)
 *
 *  The nine checks in order:
 *    1. committed_root != 0                           (UTXO is primed)
 *    2. ctx.block_height <= committed_expiry          (batch not expired)
 *    3. SHA256^(committed_depth+1)(spend_preimage) == auth_tip
 *                                                     (spend preimage valid, deeper than priming)
 *    4. SHA256(tx.qabi_block) == committed_root       (root match)
 *    5. ParseQABIBlock(tx.qabi_block) succeeds        (block is well-formed)
 *    6. parsed_block.prime_expiry_height == committed_expiry  (expiry binding)
 *    7. owner_pubkey_hash appears in parsed_block.entries[*].participant_id
 *                                                     (identity in block)
 *    8. tx.conditions_root == parsed_block.outputs_conditions_root
 *       tx.vout.size() == parsed_block.output_values.size()
 *       tx.vout[i].nValue == parsed_block.output_values[i] for all i
 *                                                     (output-set binding —
 *                                                      closes coordinator-skim hole.
 *                                                      Per-output SPK is structurally
 *                                                      0xDF + tx.conditions_root for any
 *                                                      v4 MLSC tx, so binding
 *                                                      tx.conditions_root pins every
 *                                                      destination SPK without storing
 *                                                      them on the wire.)
 *    9. FalconVerify(coordinator_pubkey,
 *                    ComputeSighashQABO(tx),
 *                    tx.aggregated_sig) == VALID      (QABO sig valid)
 */
static EvalResult EvalQABISpendBlock(const RungBlock& block,
                                      const api::LadderSigChecker& /*sig_checker*/,
                                      const RungEvalContext& ctx)
{
    // Context safety
    if (ctx.tx == nullptr) return EvalResult::ERROR;

    // -- Field extraction & validation ----------------------------------

    if (block.fields.size() != 6) return EvalResult::ERROR;

    auto hashes = FindAllFields(block, RungDataType::HASH256);
    auto nums   = FindAllFields(block, RungDataType::NUMERIC);
    const RungField* commit_field   = FindField(block, RungDataType::PUBKEY_COMMIT);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);

    if (hashes.size() != 2 || nums.size() != 2 || !commit_field || !preimage_field) {
        return EvalResult::ERROR;
    }
    if (hashes[0]->data.size() != 32) return EvalResult::ERROR;
    if (hashes[1]->data.size() != 32) return EvalResult::ERROR;
    if (commit_field->data.size() != 32) return EvalResult::ERROR;
    if (preimage_field->data.size() != 32) return EvalResult::ERROR;

    const RungField* auth_tip_field       = hashes[0];
    const RungField* committed_root_field = hashes[1];

    auto committed_depth_opt  = ReadNumeric(*nums[0]);
    auto committed_expiry_opt = ReadNumeric(*nums[1]);
    if (!committed_depth_opt || !committed_expiry_opt) return EvalResult::ERROR;
    if (*committed_depth_opt < 0 || *committed_expiry_opt < 0) return EvalResult::ERROR;
    const int64_t committed_depth  = *committed_depth_opt;
    const int64_t committed_expiry = *committed_expiry_opt;

    // Sanity ceiling on depth to bound the hash-chain walk cost.
    if (committed_depth >= static_cast<int64_t>(rung::QABI_AUTH_CHAIN_DEFAULT_LENGTH * 10)) {
        return EvalResult::ERROR;
    }

    // -- Check 1: UTXO is primed ----------------------------------------

    const bool all_zero = std::all_of(committed_root_field->data.begin(),
                                       committed_root_field->data.end(),
                                       [](uint8_t b) { return b == 0; });
    if (all_zero) return EvalResult::UNSATISFIED;

    // -- Check 2: expiry window -----------------------------------------

    if (static_cast<int64_t>(ctx.block_height) > committed_expiry) {
        return EvalResult::UNSATISFIED;
    }

    // -- Check 3: spend preimage at depth committed_depth+1 -------------

    unsigned char current[CSHA256::OUTPUT_SIZE];
    std::memcpy(current, preimage_field->data.data(), 32);
    const int64_t total_iterations = committed_depth + 1;
    for (int64_t i = 0; i < total_iterations; ++i) {
        unsigned char next[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(current, 32).Finalize(next);
        std::memcpy(current, next, 32);
    }
    if (std::memcmp(current, auth_tip_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // -- Checks 4 + 5 + 8 + 9 are cacheable (tx-level, not per-input) ---
    //
    // Four of the nine checks depend only on tx-level state:
    //   (4) SHA256(tx.qabi_block) == committed_root
    //   (5) ParseQABIBlock(tx.qabi_block)
    //   (8) tx.vout bit-exact equal to parsed.outputs
    //   (9) FalconVerify(coordinator_pubkey, sighash, aggregated_sig)
    //
    // Per-input checks 1, 2, 3, 6, 7 must still run for every input
    // (primed state, expiry, preimage, expiry binding, identity match).
    //
    // Cache key is sighash — constant within a single tx.

    if (ctx.tx->qabi_block_size == 0) return EvalResult::UNSATISFIED;

    uint256 sighash = rung::api::ComputeSighashQABO(*ctx.tx);

    const rung::QABIBlock* parsed_ptr = nullptr;
    const uint8_t* qabi_root_hash_ptr = nullptr;
    uint256 fresh_root_hash;
    std::shared_ptr<const rung::QABIBlock> fresh_parsed;
    bool sig_ok = false;
    bool vout_matches_outputs = false;
    bool need_tx_level_checks = true;
    // Pointer to the hash-indexed participant_id set for check 7. On
    // cache hit, borrows the set stored in the cache entry. On cache
    // miss, points to a fresh set built during the block parse below.
    const std::unordered_set<uint256, QABIUint256Hasher>* entries_set_ptr = nullptr;
    std::unordered_set<uint256, QABIUint256Hasher> fresh_entries_set;

    if (ctx.qabo_sig_cache != nullptr) {
        auto it = ctx.qabo_sig_cache->find(sighash);
        if (it != ctx.qabo_sig_cache->end()) {
            // Cache HIT: read the pre-computed tx-level results.
            // If any tx-level check failed (bad parse, wrong sig,
            // vout mismatch), the cached entry reflects that and we
            // short-circuit without re-running any expensive work.
            if (!it->second.sig_ok || !it->second.parsed ||
                !it->second.vout_matches_outputs) {
                return EvalResult::UNSATISFIED;
            }
            parsed_ptr = it->second.parsed.get();
            qabi_root_hash_ptr = it->second.computed_root.begin();
            sig_ok = it->second.sig_ok;
            vout_matches_outputs = it->second.vout_matches_outputs;
            entries_set_ptr = &it->second.entries_set;
            need_tx_level_checks = false;
        }
    }

    auto cache_failure = [&](const uint256& root,
                              std::shared_ptr<const rung::QABIBlock> p,
                              bool sig, bool vout_ok) {
        if (ctx.qabo_sig_cache != nullptr) {
            QABOVerifiedEntry neg;
            neg.sig_ok = sig;
            neg.computed_root = root;
            neg.parsed = std::move(p);
            neg.vout_matches_outputs = vout_ok;
            ctx.qabo_sig_cache->emplace(sighash, std::move(neg));
        }
    };

    if (need_tx_level_checks) {
        // Cache MISS — run the four tx-level checks and populate the
        // cache. All failure paths still populate the cache (with a
        // negative result) so subsequent inputs short-circuit.

        // Check 4: SHA256 of qabi_block.
        CSHA256()
            .Write(ctx.tx->qabi_block, ctx.tx->qabi_block_size)
            .Finalize(fresh_root_hash.begin());
        qabi_root_hash_ptr = fresh_root_hash.begin();

        // Check 5: parse the block.
        std::string parse_err;
        std::vector<uint8_t> qabi_bytes(ctx.tx->qabi_block, ctx.tx->qabi_block + ctx.tx->qabi_block_size);
        auto parsed_opt = rung::ParseQABIBlock(qabi_bytes, parse_err);
        if (!parsed_opt) {
            cache_failure(fresh_root_hash, nullptr, false, false);
            return EvalResult::UNSATISFIED;
        }
        fresh_parsed = std::make_shared<const rung::QABIBlock>(std::move(*parsed_opt));
        parsed_ptr = fresh_parsed.get();

        // Build the hash-indexed participant_id set. Single O(N) pass
        // over parsed.entries now; subsequent inputs get O(1) lookups
        // instead of O(N) linear scans, collapsing check 7's total
        // work from O(N²) to O(N) per QABIO tx.
        fresh_entries_set.reserve(parsed_ptr->entries.size());
        for (const auto& e : parsed_ptr->entries) {
            fresh_entries_set.insert(e.participant_id);
        }
        entries_set_ptr = &fresh_entries_set;

        // Check 8: bind tx.conditions_root to the participants' agreed root,
        // and verify the per-output values match. The per-output scriptPubKey
        // is structurally 0xDF + tx.conditions_root for any v4 MLSC tx, so
        // binding tx.conditions_root pins every destination SPK without
        // storing them on the wire.
        vout_matches_outputs = true;
        if (!ctx.tx->conditions_root ||
            std::memcmp(ctx.tx->conditions_root,
                        parsed_ptr->outputs_conditions_root.data(), 32) != 0) {
            vout_matches_outputs = false;
        } else if (ctx.tx->output_count != parsed_ptr->output_values.size()) {
            vout_matches_outputs = false;
        } else {
            for (size_t i = 0; i < parsed_ptr->output_values.size(); ++i) {
                if (ctx.tx->outputs[i].value != parsed_ptr->output_values[i]) {
                    vout_matches_outputs = false;
                    break;
                }
            }
        }
        if (!vout_matches_outputs) {
            cache_failure(fresh_root_hash, fresh_parsed, false, false);
            return EvalResult::UNSATISFIED;
        }

        // Check 9: FALCON verify.
        if (ctx.tx->aggregated_sig_size != rung::QABI_AGGREGATED_SIG_MAX) {
            cache_failure(fresh_root_hash, fresh_parsed, false, true);
            return EvalResult::UNSATISFIED;
        }
        if (parsed_ptr->coordinator_pubkey.size() != rung::QABI_COORDINATOR_PUBKEY_SIZE) {
            cache_failure(fresh_root_hash, fresh_parsed, false, true);
            return EvalResult::UNSATISFIED;
        }
        sig_ok = rung::VerifyPQSignature(
            rung::RungScheme::FALCON512,
            std::span<const uint8_t>(ctx.tx->aggregated_sig, ctx.tx->aggregated_sig_size),
            std::span<const uint8_t>(sighash.begin(), 32),
            std::span<const uint8_t>(parsed_ptr->coordinator_pubkey.data(),
                                      parsed_ptr->coordinator_pubkey.size()));

        // Populate the cache. Even on sig_ok == false we cache it so
        // subsequent inputs short-circuit. Move the hash-indexed set
        // into the cached entry so subsequent inputs borrow it.
        if (ctx.qabo_sig_cache != nullptr) {
            QABOVerifiedEntry entry;
            entry.sig_ok = sig_ok;
            entry.computed_root = fresh_root_hash;
            entry.parsed = fresh_parsed;
            entry.vout_matches_outputs = vout_matches_outputs;
            entry.entries_set = std::move(fresh_entries_set);
            auto [it_inserted, was_inserted] =
                ctx.qabo_sig_cache->emplace(sighash, std::move(entry));
            // After the move, re-point entries_set_ptr at the cached
            // copy since fresh_entries_set is now empty.
            if (was_inserted) {
                entries_set_ptr = &it_inserted->second.entries_set;
            }
        }

        if (!sig_ok) return EvalResult::UNSATISFIED;
    }

    // ---- Per-input checks (always run, never cached) ------------------

    // Check 4: verify the cached/computed qabi_block hash matches this
    // input's committed_root (which is per-input committed state).
    if (std::memcmp(qabi_root_hash_ptr, committed_root_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    const rung::QABIBlock& parsed = *parsed_ptr;

    // Check 6: expiry binding — this input's committed_expiry must match
    // block.prime_expiry_height.
    if (static_cast<int64_t>(parsed.prime_expiry_height) != committed_expiry) {
        return EvalResult::UNSATISFIED;
    }

    // Check 7: this input's owner_id must appear in block.entries.
    // Uses the hash-indexed set built once per tx (during cache-miss
    // parse) — O(1) lookup instead of O(N) linear scan. Total identity-
    // check work across all inputs drops from O(N²) to O(N).
    uint256 my_id;
    std::memcpy(my_id.begin(), commit_field->data.data(), 32);
    if (entries_set_ptr != nullptr) {
        if (entries_set_ptr->count(my_id) == 0) return EvalResult::UNSATISFIED;
    } else {
        // Fallback: no set available (shouldn't happen in practice —
        // set is built during cache-miss regardless of whether the
        // cache pointer is non-null). Scan linearly just in case.
        bool identity_found = false;
        for (const auto& e : parsed.entries) {
            if (e.participant_id == my_id) {
                identity_found = true;
                break;
            }
        }
        if (!identity_found) return EvalResult::UNSATISFIED;
    }

    // Final sig check (respects cached or fresh result).
    if (!sig_ok) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

void register_qabi_blocks()
{
    RegisterBlock(RungBlockType::QABI_PRIME, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalQABIPrimeBlock(b, d.sig_checker, d.ctx);
    });
    RegisterBlock(RungBlockType::QABI_SPEND, [](const RungBlock& b, const BlockDispatchContext& d) {
        return EvalQABISpendBlock(b, d.sig_checker, d.ctx);
    });
}

// Stub: QABIO types still parse on the wire but evaluate to UNSATISFIED on
// nodes that didn't compile in the extension (soft-fork forward compat).
static void register_qabi_stub()
{
    RegisterBlock(RungBlockType::QABI_PRIME, [](const RungBlock&, const BlockDispatchContext&) {
        return EvalResult::UNSATISFIED;
    });
    RegisterBlock(RungBlockType::QABI_SPEND, [](const RungBlock&, const BlockDispatchContext&) {
        return EvalResult::UNSATISFIED;
    });
}

} // namespace rung
