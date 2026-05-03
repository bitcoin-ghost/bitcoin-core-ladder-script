// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <coins.h>
#include <compressor.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <serialize.h>

/** Formatter for undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is compatible with older versions which expect to see
 *  the transaction version there.
 */
struct TxInUndoFormatter
{
    template<typename Stream>
    void Ser(Stream &s, const Coin& txout) {
        ::Serialize(s, VARINT(txout.nHeight * uint32_t{2} + txout.fCoinBase ));
        if (txout.nHeight > 0) {
            // Required to maintain compatibility with older undo format.
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, Using<TxOutCompression>(txout.out));
    }

    template<typename Stream>
    void Unser(Stream &s, Coin& txout) {
        uint32_t nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout.nHeight = nCode >> 1;
        txout.fCoinBase = nCode & 1;
        if (txout.nHeight > 0) {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            unsigned int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, Using<TxOutCompression>(txout.out));
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    // Audit 2026-05-03 F2 v2: per-input MLSC synthetic-entry recovery data.
    // For each input index whose spend triggered MLSC synthetic root entry
    // deletion (refcount went to 0), this carries the creating tx's
    // conditions_root so DisconnectBlock can recreate the entry
    // deterministically without a block-storage read on the disconnect hot
    // path. Empty for blocks whose v4 spends didn't trigger any deletion
    // (the common case). Format: vector<pair<input_index, conditions_root>>.
    //
    // The presence of this field is a rev*.dat on-disk format change. Old
    // undo files (pre-v0.14) lack it and will fail to deserialize under
    // the new code. Operators upgrading must -reindex; this is acceptable
    // because v4 RUNG_TX has not activated on mainnet at the time of this
    // change. See validation.cpp UpdateCoins / DisconnectBlock for the
    // populate / consume sites.
    std::vector<std::pair<uint32_t, uint256>> mlsc_recovery;

    SERIALIZE_METHODS(CTxUndo, obj) {
        READWRITE(Using<VectorFormatter<TxInUndoFormatter>>(obj.vprevout));
        READWRITE(obj.mlsc_recovery);
    }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    SERIALIZE_METHODS(CBlockUndo, obj) { READWRITE(obj.vtxundo); }
};

#endif // BITCOIN_UNDO_H
