// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

#ifndef BITCOIN_RUNG_SHIMS_H
#define BITCOIN_RUNG_SHIMS_H

// ============================================================================
// Bitcoin Core → libladder shim layer
// ============================================================================
//
// libladder (under src/rung/) is written to accept byte spans, LadderScript,
// LadderTxView, and other adapter types from src/rung/api.h. The library
// knows nothing about Core's CScript, CTransaction, CTxOut, CAmount, or
// BaseSignatureChecker.
//
// This header provides thin inline overloads that accept the Core types
// and forward to the library's adapter-typed entry points. It is the ONLY
// file that spans the boundary — any Bitcoin Core code that calls into
// rung includes this header, never reaches into src/rung/ with Core types.
//
// Every function here is inline and header-only so there is no object file
// to link against (nothing goes into bitcoin_rung — bitcoin_rung's link
// deps stay limited to crypto / util / secp256k1 / oqs).

#include <primitives/transaction.h>
#include <rung/api.h>
#include <rung/conditions.h>
#include <rung/policy.h>
#include <rung/sighash.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace rung {

// --- Conversions -----------------------------------------------------------

/** View a CScript as a read-only byte span for the library. */
inline std::span<const uint8_t> ToLadderScript(const CScript& s)
{
    return std::span<const uint8_t>{s.data(), s.size()};
}

/** Copy a library-returned byte vector back into a CScript. */
inline CScript ToCScript(const std::vector<uint8_t>& bytes)
{
    return CScript(bytes.begin(), bytes.end());
}

// --- Conditions / MLSC script predicates ----------------------------------
//
// Overloads that accept CScript and forward to the span-based library API.

inline bool IsMLSCScript(const CScript& s)          { return rung::api::IsMLSCScript(ToLadderScript(s)); }
inline bool IsLadderScript(const CScript& s)        { return rung::api::IsLadderScript(ToLadderScript(s)); }
inline bool IsCompactMLSC(const CScript& s)         { return rung::api::IsCompactMLSC(ToLadderScript(s)); }
inline bool GetMLSCRoot(const CScript& s, uint256& out)
                                                    { return rung::api::GetMLSCRoot(ToLadderScript(s), out); }
inline std::vector<uint8_t> GetMLSCData(const CScript& s)
                                                    { return rung::api::GetMLSCData(ToLadderScript(s)); }
inline bool HasMLSCData(const CScript& s)           { return rung::api::HasMLSCData(ToLadderScript(s)); }

// Builders: library returns byte vectors, shim wraps back into CScript.
inline CScript CreateMLSCScript(const uint256& root)
{
    return ToCScript(rung::api::CreateMLSCScript(root));
}
inline CScript CreateMLSCScript(const uint256& root, const std::vector<uint8_t>& data)
{
    return ToCScript(rung::api::CreateMLSCScript(root, data));
}

// Deserialise / serialise inline conditions (0xC1 — always rejected).
inline bool IsRungConditionsScript(const CScript& s)
{
    return rung::api::IsRungConditionsScript(ToLadderScript(s));
}
inline bool DeserializeRungConditions(const CScript& s, rung::RungConditions& out, std::string& error)
{
    return rung::api::DeserializeRungConditions(ToLadderScript(s), out, error);
}
inline CScript SerializeRungConditions(const rung::RungConditions& c)
{
    return ToCScript(rung::api::SerializeRungConditions(c));
}

// --- LadderTxView construction --------------------------------------------
//
// Build a rung::api::LadderTxView from a CTransaction. The resulting view
// borrows pointers into the CTransaction and its members, so the view's
// lifetime must not exceed the CTransaction it was built from. We also
// need to keep the per-input witness-element arrays alive somewhere; the
// helper struct below owns those in std::vectors so the view's pointers
// remain valid for as long as the helper is alive.
struct LadderTxViewBuilder {
    // Owned buffers. Kept flat so LadderTxView can point straight at them.
    std::vector<rung::api::LadderInputView> input_views;
    std::vector<rung::api::LadderOutputView> output_views;
    std::vector<std::vector<rung::api::LadderWitnessElement>> witness_stacks;
    rung::api::LadderTxView view;

    template <class T>
    explicit LadderTxViewBuilder(const T& tx)
    {
        input_views.reserve(tx.vin.size());
        output_views.reserve(tx.vout.size());
        witness_stacks.reserve(tx.vin.size());

        for (const auto& in : tx.vin) {
            std::vector<rung::api::LadderWitnessElement> elems;
            elems.reserve(in.scriptWitness.stack.size());
            for (const auto& e : in.scriptWitness.stack) {
                elems.push_back({e.data(), e.size()});
            }
            witness_stacks.push_back(std::move(elems));

            rung::api::LadderInputView iv;
            std::memcpy(iv.prevout.txid, in.prevout.hash.data(), 32);
            iv.prevout.n = in.prevout.n;
            iv.script_sig = {in.scriptSig.data(), in.scriptSig.size()};
            iv.witness.elements = witness_stacks.back().data();
            iv.witness.count = witness_stacks.back().size();
            iv.sequence = in.nSequence;
            input_views.push_back(iv);
        }

        for (const auto& out : tx.vout) {
            rung::api::LadderOutputView ov;
            ov.value = out.nValue;
            ov.script_pub_key = {out.scriptPubKey.data(), out.scriptPubKey.size()};
            output_views.push_back(ov);
        }

        // CTransaction.version is int32_t; CMutableTransaction.version is int32_t as well.
        view.version = static_cast<int32_t>(tx.version);
        view.lock_time = tx.nLockTime;
        view.inputs = input_views.data();
        view.input_count = input_views.size();
        view.outputs = output_views.data();
        view.output_count = output_views.size();
        view.txid = nullptr;   // library computes on demand
        view.wtxid = nullptr;
#ifdef ENABLE_QABIO
        view.qabi_block = tx.qabi_block.data();
        view.qabi_block_size = tx.qabi_block.size();
#else
        view.qabi_block = nullptr;
        view.qabi_block_size = 0;
#endif
    }
};

// --- Policy shims (CTransaction -> LadderTxView) --------------------------

inline bool IsStandardRungTx(const CTransaction& tx, std::string& reason)
{
    LadderTxViewBuilder b(tx);
    return rung::api::IsStandardRungTx(b.view, reason);
}

inline bool ExtractQABIPrimeDepth(const CTransaction& tx, uint32_t input_index, int64_t& depth_out)
{
    LadderTxViewBuilder b(tx);
    return rung::api::ExtractQABIPrimeDepth(b.view, input_index, depth_out);
}

inline bool IsQABIPrimingTx(const CTransaction& tx)
{
    LadderTxViewBuilder b(tx);
    return rung::api::IsQABIPrimingTx(b.view);
}

inline bool IsValidRBDReplacement(const CTransaction& new_tx, const CTransaction& old_tx, std::string& reason)
{
    LadderTxViewBuilder bn(new_tx), bo(old_tx);
    return rung::api::IsValidRBDReplacement(bn.view, bo.view, reason);
}

// --- LadderPrecomputedTxData construction ---------------------------------
//
// Build a rung::api::LadderPrecomputedTxData from Core's PrecomputedTransactionData
// + spent CTxOut array. Borrows pointers; lifetime must not exceed the cache +
// spent-outputs vector that back it.
struct LadderPrecomputedBuilder {
    std::vector<rung::api::LadderOutputView> spent_output_views;
    rung::api::LadderPrecomputedTxData view;

    explicit LadderPrecomputedBuilder(const PrecomputedTransactionData& cache)
    {
        if (cache.m_ladder_ready) {
            view.hash_prevouts_sha256       = cache.m_prevouts_single_hash.begin();
            view.hash_sequences_sha256      = cache.m_sequences_single_hash.begin();
            view.hash_outputs_sha256        = cache.m_outputs_single_hash.begin();
            view.hash_spent_amounts_sha256  = cache.m_spent_amounts_single_hash.begin();
            view.ladder_ready               = true;
        }
        if (cache.m_spent_outputs_ready) {
            spent_output_views.reserve(cache.m_spent_outputs.size());
            for (const auto& out : cache.m_spent_outputs) {
                rung::api::LadderOutputView ov;
                ov.value = out.nValue;
                ov.script_pub_key = {out.scriptPubKey.data(), out.scriptPubKey.size()};
                spent_output_views.push_back(ov);
            }
            view.spent_outputs = spent_output_views.data();
            view.spent_output_count = spent_output_views.size();
        }
    }
};

// --- Sighash shims (CTransaction / CMutableTransaction + PrecomputedTransactionData) -----

template <class T>
inline bool SignatureHashLadder(const PrecomputedTransactionData& cache,
                                const T& tx,
                                unsigned int nIn,
                                uint8_t hash_type,
                                const rung::RungConditions& conditions,
                                uint256& hash_out)
{
    LadderTxViewBuilder tvb(tx);
    LadderPrecomputedBuilder pcb(cache);
    return rung::api::SignatureHashLadder(pcb.view, tvb.view, nIn, hash_type,
                                          conditions, hash_out);
}

template <class T>
inline bool SignatureHashLadderKeyPath(const PrecomputedTransactionData& cache,
                                       const T& tx,
                                       unsigned int nIn,
                                       uint8_t hash_type,
                                       uint256& hash_out)
{
    LadderTxViewBuilder tvb(tx);
    LadderPrecomputedBuilder pcb(cache);
    return rung::api::SignatureHashLadderKeyPath(pcb.view, tvb.view, nIn, hash_type,
                                                 hash_out);
}

}  // namespace rung

#endif  // BITCOIN_RUNG_SHIMS_H
