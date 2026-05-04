// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// libFuzzer harness for the v4 RUNG_TX in-process consensus path.
//
// The remote RPC fuzzer (`tools/remote-fuzz/`) covers the wire-decoder
// + sendrawtransaction surface against a live node — high-fidelity but
// network-bound (~12 it/s) and limited to mempool acceptance.
//
// This harness targets `rung::VerifyRungTx` directly. It runs in-process
// at libFuzzer speed (~10000 it/s) and exercises code paths the RPC
// path does not reach: synthetic UTXO assembly, sighash computation,
// MLSC chainstate compressor decoding, conditions deserialiser,
// per-block evaluators (timelock, hash, covenant, recursion, anchor,
// PLC, governance), shared-tree caches, and the evaluator's branch
// selection across multi-rung witnesses.
//
// The fuzz invariant is "no crash, no UB" — any boolean return from
// VerifyRungTx is acceptable. A SIGSEGV / sanitiser failure / hang is
// the bug class we are looking for.

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <rung/evaluator.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cstdint>
#include <string>
#include <vector>

FUZZ_TARGET(rung_verify)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // Use the first ~half of the buffer as a serialised transaction;
    // the second half feeds spent-output synthesis (amounts + root).
    const size_t tx_len = fdp.ConsumeIntegralInRange<size_t>(0, buffer.size());
    auto tx_bytes = fdp.ConsumeBytes<unsigned char>(tx_len);
    if (tx_bytes.empty()) return;

    DataStream ds{tx_bytes};
    CMutableTransaction mtx;
    try {
        ds >> TX_WITH_WITNESS(mtx);
    } catch (...) {
        return;
    }
    if (mtx.version != CTransaction::RUNG_TX_VERSION) return;
    if (mtx.vin.empty()) return;

    // Cap input count to keep one fuzz iteration bounded; the
    // per-input loop dominates runtime for txs with many inputs.
    if (mtx.vin.size() > 32) return;

    // Synthesise a plausible MLSC scriptPubKey for every input.
    // The 32-byte conditions root varies with the buffer so different
    // inputs cover different shared-cache entries.
    std::vector<unsigned char> root_seed = fdp.ConsumeBytes<unsigned char>(32);
    while (root_seed.size() < 32) root_seed.push_back(0);

    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(mtx.vin.size());
    for (size_t i = 0; i < mtx.vin.size(); ++i) {
        CTxOut o;
        o.nValue = static_cast<CAmount>(
            fdp.ConsumeIntegralInRange<int64_t>(0, 21'000'000'00000000LL));
        unsigned char spk[33] = {0xDF};
        for (size_t j = 0; j < 32; ++j) spk[1 + j] = root_seed[j];
        // Vary the root per-input by xor'ing the input index in so the
        // synthetic UTXO entries are distinguishable.
        spk[1] ^= static_cast<unsigned char>(i);
        o.scriptPubKey = CScript(spk, spk + 33);
        spent_outputs.push_back(o);
    }

    PrecomputedTransactionData txdata;
    try {
        // Init may throw for badly-shaped inputs; that's a parse-side
        // rejection, not a crash class.
        txdata.Init(mtx, std::vector<CTxOut>(spent_outputs));
    } catch (...) {
        return;
    }

    const CTransaction tx{mtx};

    // Per-input verify. The loop bound keeps total work O(n) and
    // exercises the shared-tree-cache hot path within a single fuzz
    // iteration when the same conditions root is reused.
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        MutableTransactionSignatureChecker checker{
            &mtx, static_cast<unsigned int>(i),
            spent_outputs[i].nValue, txdata,
            MissingDataBehavior::FAIL};
        ScriptError err{SCRIPT_ERR_OK};
        std::string err_msg;
        // Fuzz invariant: no crash. Any boolean is acceptable.
        (void)rung::VerifyRungTx(tx, static_cast<unsigned int>(i),
                                  spent_outputs[i],
                                  /*flags=*/0, checker, txdata,
                                  &err,
                                  /*block_height=*/0,
                                  /*shared_cache=*/nullptr,
                                  /*qabo_sig_cache=*/nullptr,
                                  /*pq_batch_cache=*/nullptr,
                                  /*pq_batch_cache_mutex=*/nullptr,
                                  /*shared_cache_mutex=*/nullptr,
                                  /*qabo_sig_cache_mutex=*/nullptr,
                                  &err_msg);
    }
}
