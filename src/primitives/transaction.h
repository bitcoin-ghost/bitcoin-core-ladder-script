// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include <attributes.h>
#include <consensus/amount.h>
#include <primitives/transaction_identifier.h> // IWYU pragma: export
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <memory>
#include <numeric>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    Txid hash;
    uint32_t n;

    static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

    COutPoint(): n(NULL_INDEX) { }
    COutPoint(const Txid& hashIn, uint32_t nIn): hash(hashIn), n(nIn) { }

    SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.hash, obj.n); }

    void SetNull() { hash.SetNull(); n = NULL_INDEX; }
    bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return std::tie(a.hash, a.n) < std::tie(b.hash, b.n);
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness; //!< Only serialized through CTransaction

    /**
     * Setting nSequence to this value for every input in a transaction
     * disables nLockTime/IsFinalTx().
     * It fails OP_CHECKLOCKTIMEVERIFY/CheckLockTime() for any input that has
     * it set (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;
    /**
     * This is the maximum sequence number that enables both nLockTime and
     * OP_CHECKLOCKTIMEVERIFY (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static const uint32_t MAX_SEQUENCE_NONFINAL{SEQUENCE_FINAL - 1};

    // Below flags apply in the context of BIP 68. BIP 68 requires the tx
    // version to be set to 2, or higher.
    /**
     * If this flag is set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time.
     * It skips SequenceLocks() for any input that has it set (BIP 68).
     * It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
     * it set (BIP 112).
     */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31);

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /**
     * In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(Txid hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    SERIALIZE_METHODS(CTxIn, obj) { READWRITE(obj.prevout, obj.scriptSig, obj.nSequence); }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    SERIALIZE_METHODS(CTxOut, obj) { READWRITE(obj.nValue, obj.scriptPubKey); }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

struct TransactionSerParams {
    const bool allow_witness;
    SER_PARAMS_OPFUNC
};
static constexpr TransactionSerParams TX_WITH_WITNESS{.allow_witness = true};
static constexpr TransactionSerParams TX_NO_WITNESS{.allow_witness = false};

/**
 * Basic transaction serialization format:
 * - uint32_t version
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format (SegWit, flags & 1):
 * - uint32_t version
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CScriptWitness scriptWitness; (deserialized into CTxIn)
 * - uint32_t nLockTime
 *
 * TX_MLSC format (Ladder Script, full — witness-carrying):
 *   Triggered when (allow_witness && version == 4). Flag byte = 0x02.
 *
 * - uint32_t version (= 4, RUNG_TX_VERSION)
 * - unsigned char dummy = 0x00
 * - unsigned char flags = 0x02
 * - std::vector<CTxIn> vin
 * - uint256 conditions_root (32 bytes — shared across all outputs)
 * - CompactSize n_outputs
 * - per-output:
 *     int64_t nValue (8 bytes)
 *     if nValue == 0:                       (DATA_RETURN marker — reserved)
 *       CompactSize data_len (1..40)
 *       unsigned char data[data_len]
 * - per-input witness stacks
 * - CompactSize qabi_block_len
 * - unsigned char qabi_block[]              (QABIO: tx-level batch block)
 * - CompactSize aggregated_sig_len
 * - unsigned char aggregated_sig[]          (QABIO: FALCON-512 coordinator sig, 1..666 B when present — variable per BIP-FALCON; v0.14 closes audit #9 Finding 4 by carrying the actual length rather than padding to 666 B)
 * - uint32_t nLockTime
 *
 * TX_MLSC format (Ladder Script, stripped — no-witness, used for txid):
 *   Triggered when (!allow_witness && version == 4). No flag byte.
 *
 * - uint32_t version (= 4, RUNG_TX_VERSION)
 * - std::vector<CTxIn> vin
 * - uint256 conditions_root (32 bytes — shared across all outputs)
 * - CompactSize n_outputs
 * - per-output: nValue + (if zero: DATA_RETURN data_len + data), same as above
 * - uint32_t nLockTime
 *
 * Both forms use the compact value-only vout so that weight =
 * stripped × 4 + witness lands at ~8 vB per MLSC output instead of
 * 33.5 vB (the gap that would exist if the stripped form used the
 * standard 33-byte per-output scriptPubKey).
 *
 * DATA_RETURN encoding: consensus requires DATA_RETURN outputs to be
 * zero-value and non-DATA_RETURN MLSC outputs to be ≥ MIN_RUNG_OUTPUT_VALUE
 * (546). So nValue == 0 is a structurally unique wire-level marker for
 * DATA_RETURN. When the deserialiser sees a zero-value output, it reads
 * a data_len varint (1..40) followed by that many bytes of payload, and
 * reconstructs vout[i].scriptPubKey = 0xDF || conditions_root || data.
 * Normal non-zero outputs pay zero overhead for this — the mechanism is
 * free in the common case, so the "cheapest tx type in Bitcoin" claim at
 * N=1 (109 vB vs P2WPKH's 110 vB) is preserved. A DATA_RETURN output
 * pays ~41 vB for 40 bytes of data, close to OP_RETURN's ~43 vB.
 *
 * On deserialization, TX_MLSC outputs are inflated to CTxOut(value, 0xDF + root)
 * for compatibility with all existing code that accesses tx.vout[i].scriptPubKey.
 * DATA_RETURN outputs are inflated to CTxOut(0, 0xDF + root + data).
 */
template<typename Stream, typename TxType>
void UnserializeTransaction(TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;

    s >> tx.version;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    tx.conditions_root.SetNull();
    tx.qabi_block.clear();
    tx.aggregated_sig.clear();
    /* Read vin. For v4 TX_MLSC txs, the body layout is
     * (conditions_root + value-only outputs) in BOTH the stripped form
     * (no witnesses) and the full form (flag 0x02). So the decision
     * between standard and compact vout is driven by tx.version, not
     * by the presence of the witness flag. This keeps the per-output
     * weight at 8 vB instead of 33.5 vB.
     *
     * The "empty vin == witness dummy" SegWit convention still applies
     * and is orthogonal to the vout format. */
    auto read_mlsc_body = [&]() {
        s >> tx.conditions_root;
        uint64_t n_outputs = ReadCompactSize(s);
        tx.vout.resize(n_outputs);
        // Base MLSC scriptPubKey shared by all non-DATA_RETURN outputs.
        CScript mlsc_spk;
        mlsc_spk.push_back(0xDF);
        mlsc_spk.insert(mlsc_spk.end(), tx.conditions_root.begin(), tx.conditions_root.end());
        for (size_t i = 0; i < n_outputs; ++i) {
            s >> tx.vout[i].nValue;
            if (tx.vout[i].nValue == 0) {
                // DATA_RETURN output — data payload follows (1..40 bytes).
                // nValue == 0 is a structurally unique marker because
                // consensus requires non-DATA_RETURN MLSC outputs to be
                // ≥ MIN_RUNG_OUTPUT_VALUE (546).
                uint64_t data_len = ReadCompactSize(s);
                if (data_len == 0 || data_len > 40) {
                    throw std::ios_base::failure(
                        "DATA_RETURN data_len out of range (1..40)");
                }
                std::vector<unsigned char> data_bytes(data_len);
                s.read(MakeWritableByteSpan(data_bytes));
                CScript dr_spk = mlsc_spk;
                dr_spk.insert(dr_spk.end(), data_bytes.begin(), data_bytes.end());
                tx.vout[i].scriptPubKey = dr_spk;
            } else {
                tx.vout[i].scriptPubKey = mlsc_spk;
            }
        }
    };
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags == 0x03) {
            /* Invalid: SegWit (0x01) + TX_MLSC (0x02) combined is not allowed */
            throw std::ios_base::failure("Invalid transaction flag combination 0x03");
        }
        if (flags != 0) {
            s >> tx.vin;
            if (flags == 0x02) {
                if (tx.version != 4 /* RUNG_TX_VERSION */) {
                    throw std::ios_base::failure("TX_MLSC flag 0x02 requires tx version 4");
                }
                read_mlsc_body();
            } else {
                s >> tx.vout;
            }
        }
    } else if (tx.version == 4 /* RUNG_TX_VERSION */) {
        /* Non-empty vin AND version 4 = stripped TX_MLSC (no witness section). */
        read_mlsc_body();
    } else {
        /* Non-empty vin, non-v4: standard vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present (0x01), and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags == 0x02) {
        /* TX_MLSC: read per-input witnesses + qabi_block + aggregated signature */
        flags = 0;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        /* Read QABI tx-level block (QABIO batch data, empty for non-QABIO txs).
         * Hard cap: 256 KB (consensus) — soft cap 64 KB enforced at relay policy. */
        uint64_t qb_len = ReadCompactSize(s);
        if (qb_len > 262144) throw std::ios_base::failure("qabi_block too large");
        tx.qabi_block.resize(qb_len);
        if (qb_len > 0) {
            s.read(MakeWritableByteSpan(tx.qabi_block));
        }
        /* Read aggregated signature (QABIO: coordinator's FALCON-512 sig over SIGHASH_QABO).
         * Length: 1..666 bytes when present (variable-length per BIP-FALCON;
         * v0.14 / audit #9 Finding 4 removed the pre-v0.14 "exactly 666"
         * requirement that left trailing padding as a coordinator-side
         * channel), or 0 when absent. */
        uint64_t agg_len = ReadCompactSize(s);
        if (agg_len > 666) throw std::ios_base::failure("aggregated_sig too large");
        tx.aggregated_sig.resize(agg_len);
        if (agg_len > 0) {
            s.read(MakeWritableByteSpan(tx.aggregated_sig));
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}

template<typename Stream, typename TxType>
void SerializeTransaction(const TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;
    // TX_MLSC wire format is used for every v4 tx, in BOTH the stripped
    // (txid) and full (with-witness) serialisations. Applying it only in
    // the full form would leave the per-output weight at 4 × the full-SPK
    // cost, defeating the point of the value-only vout.
    const bool is_tx_mlsc = (tx.version == 4 /* RUNG_TX_VERSION */);

    s << tx.version;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        if (is_tx_mlsc) {
            flags = 0x02;
        } else if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    if (is_tx_mlsc) {
        /* TX_MLSC: write conditions_root + per-output body.
         * Non-zero outputs are value-only (8 bytes). Zero-value outputs
         * are DATA_RETURN — followed by a data_len varint and the data
         * payload, reconstructed on the other side into the extended
         * 0xDF || root || data scriptPubKey form. */
        s << tx.conditions_root;
        WriteCompactSize(s, tx.vout.size());
        for (const auto& out : tx.vout) {
            s << out.nValue;
            if (out.nValue == 0) {
                // Extract DATA_RETURN payload from the in-memory extended
                // scriptPubKey (0xDF || root || data[]). If the in-memory
                // SPK has no data tail, this is a zero-value output that
                // would be rejected at validation anyway — we write an
                // empty payload so the stream round-trips cleanly, but
                // the deserialiser will reject data_len == 0.
                const CScript& spk = out.scriptPubKey;
                size_t data_len = 0;
                const unsigned char* data_ptr = nullptr;
                if (spk.size() > 33 && spk.size() <= 73 && spk[0] == 0xDF) {
                    data_len = spk.size() - 33;
                    data_ptr = spk.data() + 33;
                }
                WriteCompactSize(s, data_len);
                if (data_len > 0) {
                    s.write(std::as_bytes(std::span<const unsigned char>(data_ptr, data_len)));
                }
            }
        }
    } else {
        s << tx.vout;
    }
    if (flags == 0x02) {
        /* TX_MLSC: per-input witnesses + qabi_block + aggregated sig */
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
        WriteCompactSize(s, tx.qabi_block.size());
        if (!tx.qabi_block.empty()) {
            s.write(MakeByteSpan(tx.qabi_block));
        }
        WriteCompactSize(s, tx.aggregated_sig.size());
        if (!tx.aggregated_sig.empty()) {
            s.write(MakeByteSpan(tx.aggregated_sig));
        }
    } else if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    s << tx.nLockTime;
}

template<typename TxType>
inline CAmount CalculateOutputValue(const TxType& tx)
{
    return std::accumulate(tx.vout.cbegin(), tx.vout.cend(), CAmount{0}, [](CAmount sum, const auto& txout) { return sum + txout.nValue; });
}


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    // Default transaction version.
    static const uint32_t CURRENT_VERSION{2};

    // Ladder Script: Version 4 transactions use typed ladder witnesses
    // instead of raw script. Every witness byte must conform to a typed field.
    // (v4, not v3 — BIP 431 claims v3 for TRUC)
    static const uint32_t RUNG_TX_VERSION{4};

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t version;
    const uint32_t nLockTime;

    // Ladder Script: shared conditions root and witness-carried proofs.
    const uint256 conditions_root;
    const std::vector<uint8_t> qabi_block;      //!< QABIO: serialised QABIBlock (tx-level batch data); empty for non-QABIO txs
    const std::vector<uint8_t> aggregated_sig;  //!< QABIO: FALCON-512 coordinator sig over SIGHASH_QABO; empty for non-QABIO txs

private:
    /** Memory only. */
    const bool m_has_witness;
    const Txid hash;
    const Wtxid m_witness_hash;

    Txid ComputeHash() const;
    Wtxid ComputeWitnessHash() const;

    bool ComputeHasWitness() const;

public:
    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction& tx);
    explicit CTransaction(CMutableTransaction&& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, const TransactionSerParams& params, Stream& s) : CTransaction(CMutableTransaction(deserialize, params, s)) {}
    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const Txid& GetHash() const LIFETIMEBOUND { return hash; }
    const Wtxid& GetWitnessHash() const LIFETIMEBOUND { return m_witness_hash; };

    // Return sum of txouts.
    CAmount GetValueOut() const;

    /**
     * Get the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.GetWitnessHash() == b.GetWitnessHash();
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !operator==(a, b);
    }

    std::string ToString() const;

    bool HasWitness() const { return m_has_witness; }
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t version;
    uint32_t nLockTime;

    // Ladder Script: shared conditions root and tx-level QABIO fields.
    // On wire: conditions_root between inputs and outputs; qabi_block and
    // aggregated_sig after per-input witnesses, in that order.
    // In memory: vout inflated to CTxOut(value, 0xDF + conditions_root) for compatibility.
    uint256 conditions_root;
    std::vector<uint8_t> qabi_block;      //!< QABIO: serialised QABIBlock (tx-level batch data)
    std::vector<uint8_t> aggregated_sig;  //!< QABIO: FALCON-512 coordinator sig over SIGHASH_QABO

    explicit CMutableTransaction();
    explicit CMutableTransaction(const CTransaction& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, const TransactionSerParams& params, Stream& s) {
        UnserializeTransaction(*this, s, params);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    Txid GetHash() const;

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
