// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_TYPES_H
#define BITCOIN_RUNG_TYPES_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rung {

/** Block types for Ladder Script function blocks.
 *  Each block evaluates a single spending condition within a rung.
 *  Encoded as uint16_t in the wire format (little-endian 2 bytes).
 *
 *  Ranges (10 families, 61 block types):
 *    0x0001-0x00FF  Signature family (SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG)
 *    0x0100-0x01FF  Timelock family (CSV, CSV_TIME, CLTV, CLTV_TIME)
 *    0x0200-0x02FF  Hash family (TAGGED_HASH, HASH_GUARDED)
 *    0x0300-0x03FF  Covenant family (CTV, VAULT_LOCK, AMOUNT_LOCK)
 *    0x0400-0x04FF  Recursion family (RECURSE_SAME, _MODIFIED, _UNTIL, _COUNT, _SPLIT, _DECAY)
 *    0x0500-0x05FF  Anchor family (ANCHOR, _CHANNEL, _POOL, _RESERVE, _SEAL, _ORACLE, DATA_RETURN)
 *    0x0600-0x06FF  PLC family (HYSTERESIS_FEE, _VALUE, TIMER_CONTINUOUS, _OFF_DELAY, LATCH_SET, _RESET, COUNTER_DOWN, _PRESET, _UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN [14])
 *                   Note: COSIGN (0x0681) is in the PLC range but functionally is a cross-input signature constraint
 *    0x0700-0x07FF  Compound family (TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG)
 *    0x0800-0x08FF  Governance family (EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK)
 *    0x0900-0x09FF  Legacy family (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT) */
enum class RungBlockType : uint16_t {
    // Signature family
    SIG              = 0x0001, //!< Single signature verification
    MULTISIG         = 0x0002, //!< M-of-N threshold signature
    ADAPTOR_SIG      = 0x0003, //!< Adaptor signature verification
    MUSIG_THRESHOLD  = 0x0004, //!< MuSig2/FROST aggregate threshold signature
    KEY_REF_SIG      = 0x0005, //!< Signature using key commitment from a relay block

    // Timelock family
    CSV              = 0x0101, //!< Relative timelock — block-height (BIP68 sequence)
    CSV_TIME         = 0x0102, //!< Relative timelock — median-time-past
    CLTV             = 0x0103, //!< Absolute timelock — block-height (nLockTime)
    CLTV_TIME        = 0x0104, //!< Absolute timelock — median-time-past

    // Hash family
    RESERVED_0201    = 0x0201, //!< Reserved: was HASH_PREIMAGE, removed
    RESERVED_0202    = 0x0202, //!< Reserved: was HASH160_PREIMAGE, removed
    TAGGED_HASH      = 0x0203, //!< BIP-340 tagged hash verification
    HASH_GUARDED     = 0x0204, //!< Raw SHA256 preimage verification (non-invertible)

    // Covenant family
    CTV              = 0x0301, //!< OP_CHECKTEMPLATEVERIFY covenant
    VAULT_LOCK       = 0x0302, //!< Vault timelock covenant
    AMOUNT_LOCK      = 0x0303, //!< Output amount range check

    // Recursion family
    RECURSE_SAME     = 0x0401, //!< Recursive re-encumber with identical conditions
    RECURSE_MODIFIED = 0x0402, //!< Recursive re-encumber with single mutation
    RECURSE_UNTIL    = 0x0403, //!< Recursive until block height
    RECURSE_COUNT    = 0x0404, //!< Recursive countdown
    RECURSE_SPLIT    = 0x0405, //!< Recursive output splitting
    RECURSE_DECAY    = 0x0406, //!< Recursive parameter decay

    // Anchor/L2 family
    ANCHOR           = 0x0501, //!< Generic anchor
    ANCHOR_CHANNEL   = 0x0502, //!< Lightning channel anchor
    ANCHOR_POOL      = 0x0503, //!< Pool anchor
    ANCHOR_RESERVE   = 0x0504, //!< Reserve anchor (guardian set)
    ANCHOR_SEAL      = 0x0505, //!< Seal anchor
    ANCHOR_ORACLE    = 0x0506, //!< Oracle anchor
    DATA_RETURN      = 0x0507, //!< Unspendable data commitment (max 32 bytes, replaces OP_RETURN)

    // Compound family (collapsed multi-block patterns)
    TIMELOCKED_SIG   = 0x0701, //!< SIG + CSV combined: pubkey + sig + block-height timelock
    HTLC             = 0x0702, //!< Hash + Timelock + Sig: atomic swap / Lightning HTLC
    HASH_SIG         = 0x0703, //!< Hash preimage + SIG combined: atomic swap claim
    PTLC             = 0x0704, //!< ADAPTOR_SIG + CSV combined: point-locked payment channel
    CLTV_SIG         = 0x0705, //!< SIG + CLTV combined: absolute-time locked payment
    TIMELOCKED_MULTISIG = 0x0706, //!< MULTISIG + CSV combined: time-delayed M-of-N

    // Governance family (transaction-level constraints)
    EPOCH_GATE       = 0x0801, //!< Periodic spending window: spendable only in specific block epochs
    WEIGHT_LIMIT     = 0x0802, //!< Maximum transaction weight limit
    INPUT_COUNT      = 0x0803, //!< Input count bounds (min/max inputs in spending tx)
    OUTPUT_COUNT     = 0x0804, //!< Output count bounds (min/max outputs in spending tx)
    RELATIVE_VALUE   = 0x0805, //!< Output value as ratio of input (numerator/denominator)
    ACCUMULATOR      = 0x0806, //!< Merkle accumulator: set membership proof with root update
    OUTPUT_CHECK     = 0x0807, //!< Per-output value and script constraint

    // Legacy family (wrapped Bitcoin transaction types)
    P2PK_LEGACY          = 0x0901, //!< P2PK wrapped: PUBKEY_COMMIT + SCHEME → PUBKEY + SIGNATURE
    P2PKH_LEGACY         = 0x0902, //!< P2PKH wrapped: HASH160 → PUBKEY + SIGNATURE
    P2SH_LEGACY          = 0x0903, //!< P2SH wrapped: HASH160 → PREIMAGE (inner conditions) + inner witness
    P2WPKH_LEGACY        = 0x0904, //!< P2WPKH wrapped: HASH160 → PUBKEY + SIGNATURE (delegates to P2PKH)
    P2WSH_LEGACY         = 0x0905, //!< P2WSH wrapped: HASH256 → PREIMAGE (inner conditions) + inner witness
    P2TR_LEGACY          = 0x0906, //!< P2TR key-path wrapped: PUBKEY_COMMIT + SCHEME → PUBKEY + SIGNATURE
    P2TR_SCRIPT_LEGACY   = 0x0907, //!< P2TR script-path wrapped: HASH256 + PUBKEY_COMMIT → PREIMAGE (inner) + inner witness

    // PLC family
    HYSTERESIS_FEE   = 0x0601, //!< Fee hysteresis band
    HYSTERESIS_VALUE = 0x0602, //!< Value hysteresis band
    TIMER_CONTINUOUS = 0x0611, //!< Continuous timer (consecutive blocks)
    TIMER_OFF_DELAY  = 0x0612, //!< Off-delay timer (hold after trigger)
    LATCH_SET        = 0x0621, //!< Latch set (state activation)
    LATCH_RESET      = 0x0622, //!< Latch reset (state deactivation)
    COUNTER_DOWN     = 0x0631, //!< Down counter (decrement on event)
    COUNTER_PRESET   = 0x0632, //!< Preset counter (approval accumulator)
    COUNTER_UP       = 0x0633, //!< Up counter (increment on event)
    COMPARE          = 0x0641, //!< Comparator (amount vs thresholds)
    SEQUENCER        = 0x0651, //!< Step sequencer
    ONE_SHOT         = 0x0661, //!< One-shot activation window
    RATE_LIMIT       = 0x0671, //!< Rate limiter
    COSIGN           = 0x0681, //!< Co-spend constraint: requires another input with matching conditions hash
};

/** Data types for typed parameters within blocks.
 *  Every byte in a Ladder Script witness must belong to one of these types.
 *  No arbitrary data pushes are possible.
 *  (Renamed from RungFieldType in v1.) */
enum class RungDataType : uint8_t {
    PUBKEY        = 0x01, //!< Public key: 1-2048 bytes (witness-only; folded into Merkle leaf via merkle_pub_key)
    PUBKEY_COMMIT = 0x02, //!< Public key commitment: exactly 32 bytes
    HASH256       = 0x03, //!< SHA-256 hash: exactly 32 bytes
    HASH160       = 0x04, //!< RIPEMD160(SHA256()) hash: exactly 20 bytes
    PREIMAGE      = 0x05, //!< Hash preimage: exactly 32 bytes (SHA256 payment hash preimage)
    SIGNATURE     = 0x06, //!< Signature: 1-50000 bytes (Schnorr 64-65, ECDSA 8-72, PQ up to 49216)
    SPEND_INDEX   = 0x07, //!< Spend index reference: 4 bytes
    NUMERIC       = 0x08, //!< Numeric value (threshold, locktime, etc.): 1-4 bytes
    SCHEME        = 0x09, //!< Signature scheme selector: 1 byte
    SCRIPT_BODY   = 0x0A, //!< Serialized inner conditions: 1-80 bytes (witness-only; node computes hash for conditions)
    DATA          = 0x0B, //!< Opaque data: 1-32 bytes (DATA_RETURN block only)
};

// Backward-compatible alias
using RungFieldType = RungDataType;

/** Returns true if the uint16_t is a known RungBlockType. */
inline bool IsKnownBlockType(uint16_t b)
{
    switch (static_cast<RungBlockType>(b)) {
    // Signature
    case RungBlockType::SIG:
    case RungBlockType::MULTISIG:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::MUSIG_THRESHOLD:
    case RungBlockType::KEY_REF_SIG:
    // Timelock
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
    // Hash
    case RungBlockType::TAGGED_HASH:
    case RungBlockType::HASH_GUARDED:
    // Covenant
    case RungBlockType::CTV:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::AMOUNT_LOCK:
    // Anchor
    case RungBlockType::ANCHOR:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::ANCHOR_POOL:
    case RungBlockType::ANCHOR_RESERVE:
    case RungBlockType::ANCHOR_SEAL:
    case RungBlockType::ANCHOR_ORACLE:
    case RungBlockType::DATA_RETURN:
    // Recursion
    case RungBlockType::RECURSE_SAME:
    case RungBlockType::RECURSE_MODIFIED:
    case RungBlockType::RECURSE_UNTIL:
    case RungBlockType::RECURSE_COUNT:
    case RungBlockType::RECURSE_SPLIT:
    case RungBlockType::RECURSE_DECAY:
    // PLC
    case RungBlockType::HYSTERESIS_FEE:
    case RungBlockType::HYSTERESIS_VALUE:
    case RungBlockType::TIMER_CONTINUOUS:
    case RungBlockType::TIMER_OFF_DELAY:
    case RungBlockType::LATCH_SET:
    case RungBlockType::LATCH_RESET:
    case RungBlockType::COUNTER_DOWN:
    case RungBlockType::COUNTER_PRESET:
    case RungBlockType::COUNTER_UP:
    case RungBlockType::COMPARE:
    case RungBlockType::SEQUENCER:
    case RungBlockType::ONE_SHOT:
    case RungBlockType::RATE_LIMIT:
    case RungBlockType::COSIGN:
    // Compound family
    case RungBlockType::TIMELOCKED_SIG:
    case RungBlockType::HTLC:
    case RungBlockType::HASH_SIG:
    case RungBlockType::PTLC:
    case RungBlockType::CLTV_SIG:
    case RungBlockType::TIMELOCKED_MULTISIG:
    // Governance family
    case RungBlockType::EPOCH_GATE:
    case RungBlockType::WEIGHT_LIMIT:
    case RungBlockType::INPUT_COUNT:
    case RungBlockType::OUTPUT_COUNT:
    case RungBlockType::RELATIVE_VALUE:
    case RungBlockType::ACCUMULATOR:
    case RungBlockType::OUTPUT_CHECK:
    // Legacy family
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2SH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY:
    case RungBlockType::P2WSH_LEGACY:
    case RungBlockType::P2TR_LEGACY:
    case RungBlockType::P2TR_SCRIPT_LEGACY:
        return true;
    }
    return false;
}

/** Returns true if the byte is a known RungDataType. */
inline bool IsKnownDataType(uint8_t b)
{
    return b >= 0x01 && b <= 0x0B;
}

// Backward-compatible alias
inline bool IsKnownFieldType(uint8_t b) { return IsKnownDataType(b); }

/** Consensus: data types that carry high-bandwidth unvalidated data.
 *  Blocked in blocks without implicit layouts (any context) to prevent
 *  data embedding via extra unvalidated fields.
 *  NUMERIC (4 bytes max) and SPEND_INDEX (4 bytes) are too small to be
 *  meaningful data channels and are legitimately needed. */
inline bool IsDataEmbeddingType(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY_COMMIT:  // 32 bytes
    case RungDataType::HASH256:        // 32 bytes
    case RungDataType::HASH160:        // 20 bytes
    case RungDataType::DATA:           // up to 32 bytes
        return true;
    default:
        return false;
    }
}

/** Minimum allowed size for a given data type. Returns 0 for unknown types. */
inline size_t FieldMinSize(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return 1;
    case RungDataType::PUBKEY_COMMIT: return 32;
    case RungDataType::HASH256:       return 32;
    case RungDataType::HASH160:       return 20;
    case RungDataType::PREIMAGE:      return 1;  // P2SH/P2WSH inner conditions can be < 32 bytes
    case RungDataType::SCRIPT_BODY:   return 1;
    case RungDataType::SIGNATURE:     return 1;
    case RungDataType::SPEND_INDEX:   return 4;
    case RungDataType::NUMERIC:       return 1;
    case RungDataType::SCHEME:        return 1;
    case RungDataType::DATA:          return 1;
    }
    return 0;
}

/** Maximum allowed size for a given data type. Returns 0 for unknown types. */
inline size_t FieldMaxSize(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return 2048;
    case RungDataType::PUBKEY_COMMIT: return 32;
    case RungDataType::HASH256:       return 32;
    case RungDataType::HASH160:       return 20;
    case RungDataType::PREIMAGE:      return 32;
    case RungDataType::SCRIPT_BODY:   return 80;
    case RungDataType::SIGNATURE:     return 50000;
    case RungDataType::SPEND_INDEX:   return 4;
    case RungDataType::NUMERIC:       return 8;
    case RungDataType::SCHEME:        return 1;
    case RungDataType::DATA:          return 40;  // hash (32) + protocol metadata (8)
    }
    return 0;
}

/** Returns a human-readable name for a block type. */
inline std::string BlockTypeName(RungBlockType type)
{
    switch (type) {
    case RungBlockType::SIG:              return "SIG";
    case RungBlockType::MULTISIG:         return "MULTISIG";
    case RungBlockType::ADAPTOR_SIG:      return "ADAPTOR_SIG";
    case RungBlockType::MUSIG_THRESHOLD:  return "MUSIG_THRESHOLD";
    case RungBlockType::KEY_REF_SIG:      return "KEY_REF_SIG";
    case RungBlockType::CSV:              return "CSV";
    case RungBlockType::CSV_TIME:         return "CSV_TIME";
    case RungBlockType::CLTV:             return "CLTV";
    case RungBlockType::CLTV_TIME:        return "CLTV_TIME";
    case RungBlockType::RESERVED_0201:    return "RESERVED";
    case RungBlockType::RESERVED_0202:    return "RESERVED";
    case RungBlockType::TAGGED_HASH:      return "TAGGED_HASH";
    case RungBlockType::HASH_GUARDED:     return "HASH_GUARDED";
    case RungBlockType::CTV:              return "CTV";
    case RungBlockType::VAULT_LOCK:       return "VAULT_LOCK";
    case RungBlockType::AMOUNT_LOCK:      return "AMOUNT_LOCK";
    case RungBlockType::RECURSE_SAME:     return "RECURSE_SAME";
    case RungBlockType::RECURSE_MODIFIED: return "RECURSE_MODIFIED";
    case RungBlockType::RECURSE_UNTIL:    return "RECURSE_UNTIL";
    case RungBlockType::RECURSE_COUNT:    return "RECURSE_COUNT";
    case RungBlockType::RECURSE_SPLIT:    return "RECURSE_SPLIT";
    case RungBlockType::RECURSE_DECAY:    return "RECURSE_DECAY";
    case RungBlockType::ANCHOR:           return "ANCHOR";
    case RungBlockType::ANCHOR_CHANNEL:   return "ANCHOR_CHANNEL";
    case RungBlockType::ANCHOR_POOL:      return "ANCHOR_POOL";
    case RungBlockType::ANCHOR_RESERVE:   return "ANCHOR_RESERVE";
    case RungBlockType::ANCHOR_SEAL:      return "ANCHOR_SEAL";
    case RungBlockType::ANCHOR_ORACLE:    return "ANCHOR_ORACLE";
    case RungBlockType::DATA_RETURN:      return "DATA_RETURN";
    case RungBlockType::HYSTERESIS_FEE:   return "HYSTERESIS_FEE";
    case RungBlockType::HYSTERESIS_VALUE: return "HYSTERESIS_VALUE";
    case RungBlockType::TIMER_CONTINUOUS: return "TIMER_CONTINUOUS";
    case RungBlockType::TIMER_OFF_DELAY:  return "TIMER_OFF_DELAY";
    case RungBlockType::LATCH_SET:        return "LATCH_SET";
    case RungBlockType::LATCH_RESET:      return "LATCH_RESET";
    case RungBlockType::COUNTER_DOWN:     return "COUNTER_DOWN";
    case RungBlockType::COUNTER_PRESET:   return "COUNTER_PRESET";
    case RungBlockType::COUNTER_UP:       return "COUNTER_UP";
    case RungBlockType::COMPARE:          return "COMPARE";
    case RungBlockType::SEQUENCER:        return "SEQUENCER";
    case RungBlockType::ONE_SHOT:         return "ONE_SHOT";
    case RungBlockType::RATE_LIMIT:       return "RATE_LIMIT";
    case RungBlockType::COSIGN:           return "COSIGN";
    case RungBlockType::TIMELOCKED_SIG:   return "TIMELOCKED_SIG";
    case RungBlockType::HTLC:             return "HTLC";
    case RungBlockType::HASH_SIG:         return "HASH_SIG";
    case RungBlockType::PTLC:             return "PTLC";
    case RungBlockType::CLTV_SIG:         return "CLTV_SIG";
    case RungBlockType::TIMELOCKED_MULTISIG: return "TIMELOCKED_MULTISIG";
    case RungBlockType::EPOCH_GATE:       return "EPOCH_GATE";
    case RungBlockType::WEIGHT_LIMIT:     return "WEIGHT_LIMIT";
    case RungBlockType::INPUT_COUNT:      return "INPUT_COUNT";
    case RungBlockType::OUTPUT_COUNT:     return "OUTPUT_COUNT";
    case RungBlockType::RELATIVE_VALUE:   return "RELATIVE_VALUE";
    case RungBlockType::ACCUMULATOR:      return "ACCUMULATOR";
    case RungBlockType::OUTPUT_CHECK:     return "OUTPUT_CHECK";
    case RungBlockType::P2PK_LEGACY:      return "P2PK_LEGACY";
    case RungBlockType::P2PKH_LEGACY:     return "P2PKH_LEGACY";
    case RungBlockType::P2SH_LEGACY:      return "P2SH_LEGACY";
    case RungBlockType::P2WPKH_LEGACY:    return "P2WPKH_LEGACY";
    case RungBlockType::P2WSH_LEGACY:     return "P2WSH_LEGACY";
    case RungBlockType::P2TR_LEGACY:      return "P2TR_LEGACY";
    case RungBlockType::P2TR_SCRIPT_LEGACY: return "P2TR_SCRIPT_LEGACY";
    }
    return "UNKNOWN";
}

/** Returns a human-readable name for a data type. */
inline std::string DataTypeName(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return "PUBKEY";
    case RungDataType::PUBKEY_COMMIT: return "PUBKEY_COMMIT";
    case RungDataType::HASH256:       return "HASH256";
    case RungDataType::HASH160:       return "HASH160";
    case RungDataType::PREIMAGE:      return "PREIMAGE";
    case RungDataType::SCRIPT_BODY:   return "SCRIPT_BODY";
    case RungDataType::SIGNATURE:     return "SIGNATURE";
    case RungDataType::SPEND_INDEX:   return "SPEND_INDEX";
    case RungDataType::NUMERIC:       return "NUMERIC";
    case RungDataType::SCHEME:        return "SCHEME";
    case RungDataType::DATA:          return "DATA";
    }
    return "UNKNOWN";
}

// Backward-compatible alias
inline std::string FieldTypeName(RungDataType type) { return DataTypeName(type); }

/** Returns true for block types that consume pubkeys (key-consuming blocks).
 *  These blocks cannot be inverted (garbage pubkey → fail → invert → SATISFIED
 *  would embed arbitrary data in the block witness). With merkle_pub_key, the
 *  pubkeys for these blocks are folded into the Merkle leaf. */
inline bool IsKeyConsumingBlockType(RungBlockType type)
{
    switch (type) {
    case RungBlockType::SIG:
    case RungBlockType::MULTISIG:
    case RungBlockType::TIMELOCKED_SIG:
    case RungBlockType::HTLC:
    case RungBlockType::HASH_SIG:
    case RungBlockType::CLTV_SIG:
    case RungBlockType::PTLC:
    case RungBlockType::TIMELOCKED_MULTISIG:
    case RungBlockType::KEY_REF_SIG:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::MUSIG_THRESHOLD:
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY:
    case RungBlockType::P2TR_LEGACY:
    case RungBlockType::P2TR_SCRIPT_LEGACY:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::ANCHOR_ORACLE:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::LATCH_SET:
    case RungBlockType::LATCH_RESET:
    case RungBlockType::COUNTER_DOWN:
    case RungBlockType::COUNTER_UP:
        return true;
    default:
        return false;
    }
}

/** Returns true for block types that are allowed to be inverted.
 *  Fail-closed allowlist: new block types default to non-invertible.
 *  Key-consuming blocks are never invertible (prevents garbage-pubkey data embedding). */
inline bool IsInvertibleBlockType(RungBlockType type)
{
    switch (type) {
    // Timelock
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
    // Hash
    case RungBlockType::TAGGED_HASH:
    // Covenant
    case RungBlockType::CTV:
    case RungBlockType::AMOUNT_LOCK:
    // Policy / Governance
    case RungBlockType::WEIGHT_LIMIT:
    case RungBlockType::INPUT_COUNT:
    case RungBlockType::OUTPUT_COUNT:
    case RungBlockType::ACCUMULATOR:  // Inverted ACCUMULATOR = blocklist ("NOT in set")
    // Anchor (non-key-consuming only)
    case RungBlockType::ANCHOR:
    case RungBlockType::ANCHOR_POOL:
    case RungBlockType::ANCHOR_RESERVE:
    case RungBlockType::ANCHOR_SEAL:
    case RungBlockType::DATA_RETURN:
    // Recursion
    case RungBlockType::RECURSE_SAME:
    case RungBlockType::RECURSE_MODIFIED:
    case RungBlockType::RECURSE_UNTIL:
    case RungBlockType::RECURSE_COUNT:
    case RungBlockType::RECURSE_SPLIT:
    case RungBlockType::RECURSE_DECAY:
    // PLC (non-key-consuming only)
    case RungBlockType::HYSTERESIS_FEE:
    case RungBlockType::HYSTERESIS_VALUE:
    case RungBlockType::TIMER_CONTINUOUS:
    case RungBlockType::TIMER_OFF_DELAY:
    case RungBlockType::COUNTER_PRESET:
    case RungBlockType::COMPARE:
    case RungBlockType::SEQUENCER:
    case RungBlockType::ONE_SHOT:
    case RungBlockType::RATE_LIMIT:
    // Legacy non-key
    case RungBlockType::P2SH_LEGACY:
    case RungBlockType::P2WSH_LEGACY:
        return true;
    default:
        return false;
    }
}

// PubkeyCountForBlock declared after RungBlock (needs full struct definition)

/** Coil type — determines what this rung unlocks. */
enum class RungCoilType : uint8_t {
    UNLOCK    = 0x01, //!< Standard unlock — spend the output
    UNLOCK_TO = 0x02, //!< Unlock to a specific destination
};

/** Attestation mode for signatures in this rung. */
enum class RungAttestationMode : uint8_t {
    INLINE    = 0x01, //!< Signatures inline in witness
    AGGREGATE = 0x02, //!< Half-aggregated: R per input in witness, aggregated s at tx level
};

/** Signature scheme for this rung. */
enum class RungScheme : uint8_t {
    SCHNORR     = 0x01, //!< BIP-340 Schnorr
    ECDSA       = 0x02, //!< ECDSA (legacy compat)
    FALCON512   = 0x10, //!< FALCON-512 post-quantum
    FALCON1024  = 0x11, //!< FALCON-1024 post-quantum
    DILITHIUM3  = 0x12, //!< Dilithium3 post-quantum
    SPHINCS_SHA = 0x13, //!< SPHINCS+-SHA2-256f post-quantum
};

/** Returns true if the coil type is a known value. */
inline bool IsKnownCoilType(uint8_t c)
{
    switch (static_cast<RungCoilType>(c)) {
    case RungCoilType::UNLOCK:
    case RungCoilType::UNLOCK_TO:
        return true;
    }
    return false;
}

/** Returns true if the attestation mode is a known value. */
inline bool IsKnownAttestationMode(uint8_t a)
{
    switch (static_cast<RungAttestationMode>(a)) {
    case RungAttestationMode::INLINE:
    case RungAttestationMode::AGGREGATE:
        return true;
    }
    return false;
}

/** Returns true if the scheme is a known value. */
inline bool IsKnownScheme(uint8_t s)
{
    switch (static_cast<RungScheme>(s)) {
    case RungScheme::SCHNORR:
    case RungScheme::ECDSA:
    case RungScheme::FALCON512:
    case RungScheme::FALCON1024:
    case RungScheme::DILITHIUM3:
    case RungScheme::SPHINCS_SHA:
        return true;
    }
    return false;
}

/** Returns true if the scheme is a post-quantum scheme. */
inline bool IsPQScheme(RungScheme s)
{
    return static_cast<uint8_t>(s) >= 0x10;
}

/** Coil metadata — attached to each output (LadderWitness), determines unlock semantics.
 *  UNLOCK:    Standard spend to an address.
 *  UNLOCK_TO: Send to an address (coil address field specifies destination). */
struct RungCoil {
    RungCoilType coil_type{RungCoilType::UNLOCK};
    RungAttestationMode attestation{RungAttestationMode::INLINE};
    RungScheme scheme{RungScheme::SCHNORR};
    std::vector<uint8_t> address_hash;         //!< SHA256(destination address) — raw address never on-chain. Empty if none.
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> rung_destinations; //!< Per-rung destination overrides: (rung_index, address_hash). Bounded by MAX_RUNGS.
    uint8_t output_index{0};                   //!< TX_MLSC: which output this rung governs. Committed in Merkle leaf.
};

/** A single typed field within a block. Type constrains the allowed data size. */
struct RungField {
    RungDataType type;
    std::vector<uint8_t> data;

    /** Validate that data size conforms to the field type constraints.
     *  Returns false with reason populated on failure. */
    bool IsValid(std::string& reason) const;
};

/** A function block within a rung. Contains typed fields that the evaluator checks. */
struct RungBlock {
    RungBlockType type;
    std::vector<RungField> fields;
    bool inverted{false}; //!< If true, evaluation result is inverted (SATISFIED↔UNSATISFIED)
};

// CompactRungType, CompactRungData removed — COMPACT_SIG stored PUBKEY_COMMIT
// on the rung, which defeats merkle_pub_key.

/** A single rung in a ladder. All blocks must be satisfied (AND logic). */
struct Rung {
    std::vector<RungBlock> blocks;
    uint8_t rung_id{0};                //!< Rung identifier within the ladder
    std::vector<uint16_t> relay_refs;    //!< Indices into relay array that must be satisfied
};

/** A relay definition: blocks evaluated for cross-referencing, not tied to an output.
 *  Relays enable AND composition across rungs and DRY condition reuse.
 *  Forward-only indexing: relay N can only require relays 0..N-1 (no cycles). */
struct Relay {
    std::vector<RungBlock> blocks;
    std::vector<uint16_t> relay_refs;    //!< Indices of other relays (must be < own index)
};

/** Returns the number of pubkeys consumed by a block type.
 *  Used by merkle_pub_key to determine how many pubkeys to fold into
 *  each block's contribution to the Merkle leaf. */
inline size_t PubkeyCountForBlock(RungBlockType type, const RungBlock& block)
{
    switch (type) {
    // Single pubkey blocks
    case RungBlockType::SIG:
    case RungBlockType::TIMELOCKED_SIG:
    case RungBlockType::HASH_SIG:
    case RungBlockType::CLTV_SIG:
    case RungBlockType::MUSIG_THRESHOLD:
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2TR_LEGACY:
    case RungBlockType::P2TR_SCRIPT_LEGACY:
        return 1;
    // P2PKH/P2WPKH: PUBKEY→HASH160 in conditions (not intercepted to Merkle leaf)
    // Pubkeys are in the witness but NOT in the Merkle leaf — return 0
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY:
        return 0;
    // Two pubkey blocks
    case RungBlockType::HTLC:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::PTLC:
        return 2;
    // Single pubkey blocks (PLC/anchor family)
    case RungBlockType::ANCHOR_ORACLE:
    case RungBlockType::LATCH_SET:
    case RungBlockType::LATCH_RESET:
    case RungBlockType::COUNTER_DOWN:
    case RungBlockType::COUNTER_UP:
        return 1;
    // N pubkey blocks: count PUBKEY fields directly (merkle_pub_key).
    // The witness carries all N pubkeys; they are bound to the Merkle leaf.
    case RungBlockType::MULTISIG:
    case RungBlockType::TIMELOCKED_MULTISIG: {
        size_t pk_count = 0;
        for (const auto& field : block.fields) {
            if (field.type == RungDataType::PUBKEY) ++pk_count;
        }
        return pk_count;
    }
    default:
        return 0;
    }
}

/** A single field-level diff in a witness reference. */
struct WitnessDiff {
    uint16_t rung_index;   //!< Which rung in the inherited witness
    uint16_t block_index;  //!< Which block within that rung
    uint16_t field_index;  //!< Which field within that block
    RungField new_field;   //!< Replacement field data
};

/** Witness reference: rungs/relays inherited from another input's witness with diffs.
 *  Coil is always provided fresh (never inherited — inheriting destination
 *  addresses would be a dangerous footgun). */
struct WitnessReference {
    uint32_t input_index;               //!< Which input's witness to inherit rungs/relays from
    std::vector<WitnessDiff> diffs;     //!< Field-level patches to apply after inheritance
};

/** The complete ladder witness for one output.
 *  Rungs define input conditions (OR logic — first satisfied rung wins).
 *  Coil defines output semantics (destination, constraints).
 *  Relays are shared condition sets referenced via requires (AND composition).
 *
 *  When witness_ref is set (n_rungs == 0 on wire), rungs and relays are
 *  inherited from the referenced input's witness. Only diffs and a fresh
 *  coil are provided. Resolution happens in VerifyRungTx. */
struct LadderWitness {
    std::vector<Rung> rungs;     //!< Input condition rungs
    RungCoil coil;               //!< Output coil (per-output, not per-rung)
    std::vector<Relay> relays;   //!< Relay definitions (shared across outputs)
    std::optional<WitnessReference> witness_ref; //!< Witness inheritance reference

    bool IsEmpty() const { return rungs.empty() && !witness_ref.has_value(); }
    bool IsWitnessRef() const { return witness_ref.has_value(); }
};

// ============================================================================
// Micro-header lookup table (Phase 2: encoding optimization)
// ============================================================================

/** Number of micro-header slots (0x00-0x7F). */
static constexpr size_t MICRO_HEADER_SLOTS = 128;
/** Escape byte: full header follows (not inverted). */
static constexpr uint8_t MICRO_HEADER_ESCAPE = 0x80;
/** Escape byte: full header follows (inverted). */
static constexpr uint8_t MICRO_HEADER_ESCAPE_INV = 0x81;

/** Micro-header lookup table: maps slot index → RungBlockType.
 *  Value 0xFFFF means the slot is unused. */
inline constexpr uint16_t MICRO_HEADER_TABLE[MICRO_HEADER_SLOTS] = {
    // Slot 0-2: Signature family
    0x0001, // 0x00: SIG
    0x0002, // 0x01: MULTISIG
    0x0003, // 0x02: ADAPTOR_SIG
    // Slot 3-6: Timelock family
    0x0101, // 0x03: CSV
    0x0102, // 0x04: CSV_TIME
    0x0103, // 0x05: CLTV
    0x0104, // 0x06: CLTV_TIME
    // Slot 7-9: Hash family (0x07-0x08 reserved)
    0xFFFF, // 0x07: reserved
    0xFFFF, // 0x08: reserved
    0x0203, // 0x09: TAGGED_HASH
    // Slot 10-12: Covenant family
    0x0301, // 0x0A: CTV
    0x0302, // 0x0B: VAULT_LOCK
    0x0303, // 0x0C: AMOUNT_LOCK
    // Slot 13-18: Recursion family
    0x0401, // 0x0D: RECURSE_SAME
    0x0402, // 0x0E: RECURSE_MODIFIED
    0x0403, // 0x0F: RECURSE_UNTIL
    0x0404, // 0x10: RECURSE_COUNT
    0x0405, // 0x11: RECURSE_SPLIT
    0x0406, // 0x12: RECURSE_DECAY
    // Slot 19-24: Anchor family
    0x0501, // 0x13: ANCHOR
    0x0502, // 0x14: ANCHOR_CHANNEL
    0x0503, // 0x15: ANCHOR_POOL
    0x0504, // 0x16: ANCHOR_RESERVE
    0x0505, // 0x17: ANCHOR_SEAL
    0x0506, // 0x18: ANCHOR_ORACLE
    // Slot 25-38: PLC family
    0x0601, // 0x19: HYSTERESIS_FEE
    0x0602, // 0x1A: HYSTERESIS_VALUE
    0x0611, // 0x1B: TIMER_CONTINUOUS
    0x0612, // 0x1C: TIMER_OFF_DELAY
    0x0621, // 0x1D: LATCH_SET
    0x0622, // 0x1E: LATCH_RESET
    0x0631, // 0x1F: COUNTER_DOWN
    0x0632, // 0x20: COUNTER_PRESET
    0x0633, // 0x21: COUNTER_UP
    0x0641, // 0x22: COMPARE
    0x0651, // 0x23: SEQUENCER
    0x0661, // 0x24: ONE_SHOT
    0x0671, // 0x25: RATE_LIMIT
    0x0681, // 0x26: COSIGN
    // Slot 39-44: Compound family
    0x0701, // 0x27: TIMELOCKED_SIG
    0x0702, // 0x28: HTLC
    0x0703, // 0x29: HASH_SIG
    0x0704, // 0x2A: PTLC
    0x0705, // 0x2B: CLTV_SIG
    0x0706, // 0x2C: TIMELOCKED_MULTISIG
    // Slot 45-50: Governance family
    0x0801, // 0x2D: EPOCH_GATE
    0x0802, // 0x2E: WEIGHT_LIMIT
    0x0803, // 0x2F: INPUT_COUNT
    0x0804, // 0x30: OUTPUT_COUNT
    0x0805, // 0x31: RELATIVE_VALUE
    0x0806, // 0x32: ACCUMULATOR
    // Slot 51-52: Late-added Signature family
    0x0004, // 0x33: MUSIG_THRESHOLD
    0x0005, // 0x34: KEY_REF_SIG
    // Slot 53-59: Legacy family
    0x0901, // 0x35: P2PK_LEGACY
    0x0902, // 0x36: P2PKH_LEGACY
    0x0903, // 0x37: P2SH_LEGACY
    0x0904, // 0x38: P2WPKH_LEGACY
    0x0905, // 0x39: P2WSH_LEGACY
    0x0906, // 0x3A: P2TR_LEGACY
    0x0907, // 0x3B: P2TR_SCRIPT_LEGACY
    // Slot 60: Anchor family (late-added)
    0x0507, // 0x3C: DATA_RETURN
    // Slot 61: Hash family (late-added)
    0x0204, // 0x3D: HASH_GUARDED
    // Slot 62: Governance family (late-added)
    0x0807, // 0x3E: OUTPUT_CHECK
    0xFFFF, // 0x3F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x40-0x47
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x48-0x4F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x50-0x57
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x58-0x5F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x60-0x67
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x68-0x6F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x70-0x77
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x78-0x7F
};

/** Reverse lookup: find micro-header slot index for a block type.
 *  Returns -1 if the block type has no micro-header slot. */
inline int MicroHeaderSlot(RungBlockType type)
{
    uint16_t val = static_cast<uint16_t>(type);
    for (size_t i = 0; i < MICRO_HEADER_SLOTS; ++i) {
        if (MICRO_HEADER_TABLE[i] == val) return static_cast<int>(i);
    }
    return -1;
}

// ============================================================================
// Implicit field tables (Phase 2: per-block-type fixed field layouts)
// ============================================================================

/** An entry in an implicit field table: data type + fixed size (0 = variable). */
struct ImplicitFieldEntry {
    RungDataType type;
    uint16_t fixed_size; //!< 0 means variable-length (CompactSize prefix present)
};

/** Maximum implicit fields per block type per context. */
static constexpr size_t MAX_IMPLICIT_FIELDS = 8;

/** An implicit field layout for a block type in a given context. */
struct ImplicitFieldLayout {
    uint8_t count;                                  //!< Number of implicit fields (0 = no implicit table)
    ImplicitFieldEntry fields[MAX_IMPLICIT_FIELDS]; //!< Field entries
};

/** Empty layout — no implicit fields, use explicit encoding. */
inline constexpr ImplicitFieldLayout NO_IMPLICIT = {0, {}};

// -- Conditions context implicit field layouts --

/** SIG conditions: [SCHEME(1)] — pubkey folded into Merkle leaf (merkle_pub_key) */
inline constexpr ImplicitFieldLayout SIG_CONDITIONS = {1, {
    {RungDataType::SCHEME, 1},
}};

/** CSV conditions: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CSV_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0}, // varint encoding, variable
}};

/** CSV_TIME conditions: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CSV_TIME_CONDITIONS = CSV_CONDITIONS;

/** CLTV conditions: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CLTV_CONDITIONS = CSV_CONDITIONS;

/** CLTV_TIME conditions: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CLTV_TIME_CONDITIONS = CSV_CONDITIONS;

// RESERVED_0201/RESERVED_0202: no layout (removed block types)

/** TAGGED_HASH conditions: [HASH256(32), HASH256(32)] */
inline constexpr ImplicitFieldLayout TAGGED_HASH_CONDITIONS = {2, {
    {RungDataType::HASH256, 32},
    {RungDataType::HASH256, 32},
}};

/** HASH_GUARDED conditions: [HASH256(32)] — raw SHA256 hash commitment */
inline constexpr ImplicitFieldLayout HASH_GUARDED_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** CTV conditions: [HASH256(32)] */
inline constexpr ImplicitFieldLayout CTV_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** AMOUNT_LOCK conditions: [NUMERIC(varint), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout AMOUNT_LOCK_CONDITIONS = {2, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
}};

/** COSIGN conditions: [HASH256(32)] */
inline constexpr ImplicitFieldLayout COSIGN_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** TIMELOCKED_SIG conditions: [SCHEME(1), NUMERIC(varint)] — pubkey folded into Merkle leaf */
inline constexpr ImplicitFieldLayout TIMELOCKED_SIG_CONDITIONS = {2, {
    {RungDataType::SCHEME, 1},
    {RungDataType::NUMERIC, 0},
}};

/** HTLC conditions: [HASH256(32), NUMERIC(varint), SCHEME(1)] — pubkeys folded into Merkle leaf */
inline constexpr ImplicitFieldLayout HTLC_CONDITIONS = {3, {
    {RungDataType::HASH256, 32},
    {RungDataType::NUMERIC, 0},
    {RungDataType::SCHEME, 1},
}};

/** HASH_SIG conditions: [HASH256(32), SCHEME(1)] — pubkey folded into Merkle leaf */
inline constexpr ImplicitFieldLayout HASH_SIG_CONDITIONS = {2, {
    {RungDataType::HASH256, 32},
    {RungDataType::SCHEME, 1},
}};

/** CLTV_SIG conditions: [SCHEME(1), NUMERIC(varint)] — pubkey folded into Merkle leaf */
inline constexpr ImplicitFieldLayout CLTV_SIG_CONDITIONS = TIMELOCKED_SIG_CONDITIONS;

/** EPOCH_GATE conditions: [NUMERIC(varint), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout EPOCH_GATE_CONDITIONS = AMOUNT_LOCK_CONDITIONS;

/** MUSIG_THRESHOLD conditions: [NUMERIC(varint M), NUMERIC(varint N)] — pubkey folded into Merkle leaf */
inline constexpr ImplicitFieldLayout MUSIG_THRESHOLD_CONDITIONS = {2, {
    {RungDataType::NUMERIC, 0},  // threshold M
    {RungDataType::NUMERIC, 0},  // group size N
}};

/** ANCHOR_SEAL conditions: [HASH256(32), HASH256(32)] */
inline constexpr ImplicitFieldLayout ANCHOR_SEAL_CONDITIONS = {2, {
    {RungDataType::HASH256, 32},
    {RungDataType::HASH256, 32},
}};

/** P2PKH_LEGACY / P2WPKH_LEGACY conditions: [HASH160(20)] */
inline constexpr ImplicitFieldLayout P2PKH_LEGACY_CONDITIONS = {1, {
    {RungDataType::HASH160, 20},
}};

/** P2WSH_LEGACY conditions: [HASH256(32)] */
inline constexpr ImplicitFieldLayout P2WSH_LEGACY_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** P2TR_SCRIPT_LEGACY conditions: [HASH256(32)] — internal key folded into Merkle leaf */
inline constexpr ImplicitFieldLayout P2TR_SCRIPT_LEGACY_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** DATA_RETURN conditions: [DATA(var, max 80)] — unspendable data commitment */
inline constexpr ImplicitFieldLayout DATA_RETURN_CONDITIONS = {1, {
    {RungDataType::DATA, 0},
}};

// -- Conditions layouts for previously layout-less block types --
// These close the NUMERIC multiplication data channel by enforcing
// exact field count and types for all block types in conditions context.

/** MULTISIG conditions: [NUMERIC(threshold M), SCHEME(1)] — pubkeys in Merkle leaf */
inline constexpr ImplicitFieldLayout MULTISIG_CONDITIONS = {2, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::SCHEME, 1},
}};

/** KEY_REF_SIG conditions: [NUMERIC(relay_index), NUMERIC(block_index)] */
inline constexpr ImplicitFieldLayout KEY_REF_SIG_CONDITIONS = {2, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
}};

/** VAULT_LOCK conditions: [NUMERIC(hot_delay)] — pubkeys in Merkle leaf */
inline constexpr ImplicitFieldLayout VAULT_LOCK_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** RECURSE_SAME conditions: [NUMERIC(max_depth)] */
inline constexpr ImplicitFieldLayout RECURSE_SAME_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** RECURSE_UNTIL conditions: [NUMERIC(until_height)] */
inline constexpr ImplicitFieldLayout RECURSE_UNTIL_CONDITIONS = RECURSE_SAME_CONDITIONS;

/** RECURSE_COUNT conditions: [NUMERIC(max_count)] */
inline constexpr ImplicitFieldLayout RECURSE_COUNT_CONDITIONS = RECURSE_SAME_CONDITIONS;

/** RECURSE_SPLIT conditions: [NUMERIC(max_splits), NUMERIC(min_split_sats)] */
inline constexpr ImplicitFieldLayout RECURSE_SPLIT_CONDITIONS = {2, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
}};

/** ANCHOR_CHANNEL conditions: [NUMERIC(commitment_number)] — pubkeys in Merkle leaf */
inline constexpr ImplicitFieldLayout ANCHOR_CHANNEL_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** ANCHOR_POOL conditions: [HASH256(vtxo_tree_root), NUMERIC(participant_count)] */
inline constexpr ImplicitFieldLayout ANCHOR_POOL_CONDITIONS = {2, {
    {RungDataType::HASH256, 32},
    {RungDataType::NUMERIC, 0},
}};

/** ANCHOR_RESERVE conditions: [NUMERIC(threshold_n), NUMERIC(threshold_m), HASH256(guardian_hash)] */
inline constexpr ImplicitFieldLayout ANCHOR_RESERVE_CONDITIONS = {3, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
    {RungDataType::HASH256, 32},
}};

/** ANCHOR_ORACLE conditions: [NUMERIC(outcome_count)] — oracle pubkey in Merkle leaf */
inline constexpr ImplicitFieldLayout ANCHOR_ORACLE_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** HYSTERESIS_FEE conditions: [NUMERIC(high_sat_vb), NUMERIC(low_sat_vb)] */
inline constexpr ImplicitFieldLayout HYSTERESIS_FEE_CONDITIONS = {2, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
}};

/** HYSTERESIS_VALUE conditions: [NUMERIC(high_sats), NUMERIC(low_sats)] */
inline constexpr ImplicitFieldLayout HYSTERESIS_VALUE_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** TIMER_CONTINUOUS conditions: [NUMERIC(accumulated), NUMERIC(target)] */
inline constexpr ImplicitFieldLayout TIMER_CONTINUOUS_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** TIMER_OFF_DELAY conditions: [NUMERIC(remaining)] */
inline constexpr ImplicitFieldLayout TIMER_OFF_DELAY_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** LATCH_SET conditions: [NUMERIC(state)] — setter key in Merkle leaf */
inline constexpr ImplicitFieldLayout LATCH_SET_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** LATCH_RESET conditions: [NUMERIC(state), NUMERIC(delay)] — resetter key in Merkle leaf */
inline constexpr ImplicitFieldLayout LATCH_RESET_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** COUNTER_DOWN conditions: [NUMERIC(count)] — event signer in Merkle leaf */
inline constexpr ImplicitFieldLayout COUNTER_DOWN_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** COUNTER_PRESET conditions: [NUMERIC(current), NUMERIC(preset)] */
inline constexpr ImplicitFieldLayout COUNTER_PRESET_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** COUNTER_UP conditions: [NUMERIC(current), NUMERIC(target)] — event signer in Merkle leaf */
inline constexpr ImplicitFieldLayout COUNTER_UP_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** SEQUENCER conditions: [NUMERIC(current_step), NUMERIC(total_steps)] */
inline constexpr ImplicitFieldLayout SEQUENCER_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** ONE_SHOT conditions: [NUMERIC(state), HASH256(commitment)] */
inline constexpr ImplicitFieldLayout ONE_SHOT_CONDITIONS = {2, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::HASH256, 32},
}};

/** RATE_LIMIT conditions: [NUMERIC(max_per_block), NUMERIC(accumulation_cap), NUMERIC(refill_blocks)] */
inline constexpr ImplicitFieldLayout RATE_LIMIT_CONDITIONS = {3, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
}};

/** PTLC conditions: [NUMERIC(CSV_sequence)] — adaptor key in Merkle leaf */
inline constexpr ImplicitFieldLayout PTLC_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** TIMELOCKED_MULTISIG conditions: [NUMERIC(threshold_M), NUMERIC(CSV), SCHEME(1)] — pubkeys in Merkle leaf */
inline constexpr ImplicitFieldLayout TIMELOCKED_MULTISIG_CONDITIONS = {3, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
    {RungDataType::SCHEME, 1},
}};

/** WEIGHT_LIMIT conditions: [NUMERIC(max_weight)] */
inline constexpr ImplicitFieldLayout WEIGHT_LIMIT_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** INPUT_COUNT conditions: [NUMERIC(min_inputs), NUMERIC(max_inputs)] */
inline constexpr ImplicitFieldLayout INPUT_COUNT_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** OUTPUT_COUNT conditions: [NUMERIC(min_outputs), NUMERIC(max_outputs)] */
inline constexpr ImplicitFieldLayout OUTPUT_COUNT_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** RELATIVE_VALUE conditions: [NUMERIC(numerator), NUMERIC(denominator)] */
inline constexpr ImplicitFieldLayout RELATIVE_VALUE_CONDITIONS = HYSTERESIS_FEE_CONDITIONS;

/** ACCUMULATOR conditions: [HASH256(merkle_root)] */
inline constexpr ImplicitFieldLayout ACCUMULATOR_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** OUTPUT_CHECK conditions: [NUMERIC(output_index), NUMERIC(min_sats), NUMERIC(max_sats), HASH256(script_hash)] */
inline constexpr ImplicitFieldLayout OUTPUT_CHECK_CONDITIONS = {4, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
    {RungDataType::HASH256, 32},
}};

// -- Previously variable-length blocks, now capped --

// RECURSE_MODIFIED/RECURSE_DECAY: variable field count (2+4*N mutations).
// No implicit layout — protected by IsDataEmbeddingType in DeserializeBlock.

/** ANCHOR conditions: [NUMERIC(anchor_id)] — marker block, single field */
inline constexpr ImplicitFieldLayout ANCHOR_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0},
}};

/** COMPARE conditions: [NUMERIC(operator), NUMERIC(value_b), NUMERIC(value_c)] — 3 NUMERICs */
inline constexpr ImplicitFieldLayout COMPARE_CONDITIONS = {3, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
}};

// -- Witness context implicit field layouts --

/** SIG witness: [PUBKEY(var), SIGNATURE(var)] */
inline constexpr ImplicitFieldLayout SIG_WITNESS = {2, {
    {RungDataType::PUBKEY, 0},
    {RungDataType::SIGNATURE, 0},
}};

/** CSV witness: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CSV_WITNESS = CSV_CONDITIONS;

// RESERVED_0201/RESERVED_0202: no layout (removed block types)

/** TAGGED_HASH witness: [HASH256(32), HASH256(32), PREIMAGE(var)] */
inline constexpr ImplicitFieldLayout TAGGED_HASH_WITNESS = {3, {
    {RungDataType::HASH256, 32},
    {RungDataType::HASH256, 32},
    {RungDataType::PREIMAGE, 0},
}};

/** HASH_GUARDED witness: [PREIMAGE(var)] — raw SHA256 preimage */
inline constexpr ImplicitFieldLayout HASH_GUARDED_WITNESS = {1, {
    {RungDataType::PREIMAGE, 0},
}};

/** CTV witness: [HASH256(32)] */
inline constexpr ImplicitFieldLayout CTV_WITNESS = CTV_CONDITIONS;

/** COSIGN witness: [HASH256(32)] */
inline constexpr ImplicitFieldLayout COSIGN_WITNESS = COSIGN_CONDITIONS;

/** TIMELOCKED_SIG witness: [PUBKEY(var), SIGNATURE(var), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout TIMELOCKED_SIG_WITNESS = {3, {
    {RungDataType::PUBKEY, 0},
    {RungDataType::SIGNATURE, 0},
    {RungDataType::NUMERIC, 0},
}};

/** HTLC witness: [PUBKEY(var), SIGNATURE(var), PUBKEY(var), PREIMAGE(var), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout HTLC_WITNESS = {5, {
    {RungDataType::PUBKEY, 0},
    {RungDataType::SIGNATURE, 0},
    {RungDataType::PUBKEY, 0},
    {RungDataType::PREIMAGE, 0},
    {RungDataType::NUMERIC, 0},
}};

/** HASH_SIG witness: [PUBKEY(var), SIGNATURE(var), PREIMAGE(var)] */
inline constexpr ImplicitFieldLayout HASH_SIG_WITNESS = {3, {
    {RungDataType::PUBKEY, 0},
    {RungDataType::SIGNATURE, 0},
    {RungDataType::PREIMAGE, 0},
}};

/** MUSIG_THRESHOLD witness: [PUBKEY(var), SIGNATURE(var)] */
inline constexpr ImplicitFieldLayout MUSIG_THRESHOLD_WITNESS = SIG_WITNESS;

/** CLTV_SIG witness: [PUBKEY(var), SIGNATURE(var), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CLTV_SIG_WITNESS = TIMELOCKED_SIG_WITNESS;

/** Lookup implicit field layout for a block type and serialization context.
 *  Returns NO_IMPLICIT if no implicit table exists. */
inline const ImplicitFieldLayout& GetImplicitLayout(RungBlockType type, uint8_t ctx)
{
    // ctx: 0 = WITNESS, 1 = CONDITIONS
    if (ctx == 1) {
        // CONDITIONS context
        switch (type) {
        case RungBlockType::SIG:              return SIG_CONDITIONS;
        case RungBlockType::MUSIG_THRESHOLD:  return MUSIG_THRESHOLD_CONDITIONS;
        case RungBlockType::CSV:              return CSV_CONDITIONS;
        case RungBlockType::CSV_TIME:         return CSV_TIME_CONDITIONS;
        case RungBlockType::CLTV:             return CLTV_CONDITIONS;
        case RungBlockType::CLTV_TIME:        return CLTV_TIME_CONDITIONS;
        // RESERVED_0201/RESERVED_0202: removed (no layout)
        case RungBlockType::TAGGED_HASH:      return TAGGED_HASH_CONDITIONS;
        case RungBlockType::HASH_GUARDED:     return HASH_GUARDED_CONDITIONS;
        case RungBlockType::CTV:              return CTV_CONDITIONS;
        case RungBlockType::AMOUNT_LOCK:      return AMOUNT_LOCK_CONDITIONS;
        case RungBlockType::COSIGN:           return COSIGN_CONDITIONS;
        case RungBlockType::TIMELOCKED_SIG:   return TIMELOCKED_SIG_CONDITIONS;
        case RungBlockType::HTLC:             return HTLC_CONDITIONS;
        case RungBlockType::HASH_SIG:         return HASH_SIG_CONDITIONS;
        case RungBlockType::CLTV_SIG:         return CLTV_SIG_CONDITIONS;
        case RungBlockType::EPOCH_GATE:       return EPOCH_GATE_CONDITIONS;
        case RungBlockType::ANCHOR_SEAL:      return ANCHOR_SEAL_CONDITIONS;
        case RungBlockType::DATA_RETURN:      return DATA_RETURN_CONDITIONS;
        // Signature family (previously layout-less)
        case RungBlockType::MULTISIG:         return MULTISIG_CONDITIONS;
        case RungBlockType::KEY_REF_SIG:      return KEY_REF_SIG_CONDITIONS;
        // Covenant family
        case RungBlockType::VAULT_LOCK:       return VAULT_LOCK_CONDITIONS;
        // Recursion family
        case RungBlockType::RECURSE_SAME:     return RECURSE_SAME_CONDITIONS;
        // RECURSE_MODIFIED/RECURSE_DECAY: variable field count (2+4*N mutations)
        // Stay NO_IMPLICIT — protected by IsDataEmbeddingType in DeserializeBlock
        case RungBlockType::RECURSE_UNTIL:    return RECURSE_UNTIL_CONDITIONS;
        case RungBlockType::RECURSE_COUNT:    return RECURSE_COUNT_CONDITIONS;
        case RungBlockType::RECURSE_SPLIT:    return RECURSE_SPLIT_CONDITIONS;
        // Anchor family
        case RungBlockType::ANCHOR:           return ANCHOR_CONDITIONS;
        case RungBlockType::ANCHOR_CHANNEL:   return ANCHOR_CHANNEL_CONDITIONS;
        case RungBlockType::ANCHOR_POOL:      return ANCHOR_POOL_CONDITIONS;
        case RungBlockType::ANCHOR_RESERVE:   return ANCHOR_RESERVE_CONDITIONS;
        case RungBlockType::ANCHOR_ORACLE:    return ANCHOR_ORACLE_CONDITIONS;
        // PLC family
        case RungBlockType::HYSTERESIS_FEE:   return HYSTERESIS_FEE_CONDITIONS;
        case RungBlockType::HYSTERESIS_VALUE: return HYSTERESIS_VALUE_CONDITIONS;
        case RungBlockType::TIMER_CONTINUOUS: return TIMER_CONTINUOUS_CONDITIONS;
        case RungBlockType::TIMER_OFF_DELAY:  return TIMER_OFF_DELAY_CONDITIONS;
        case RungBlockType::LATCH_SET:        return LATCH_SET_CONDITIONS;
        case RungBlockType::LATCH_RESET:      return LATCH_RESET_CONDITIONS;
        case RungBlockType::COUNTER_DOWN:     return COUNTER_DOWN_CONDITIONS;
        case RungBlockType::COUNTER_PRESET:   return COUNTER_PRESET_CONDITIONS;
        case RungBlockType::COUNTER_UP:       return COUNTER_UP_CONDITIONS;
        case RungBlockType::SEQUENCER:        return SEQUENCER_CONDITIONS;
        case RungBlockType::ONE_SHOT:         return ONE_SHOT_CONDITIONS;
        case RungBlockType::RATE_LIMIT:       return RATE_LIMIT_CONDITIONS;
        // Compound family
        case RungBlockType::PTLC:             return PTLC_CONDITIONS;
        case RungBlockType::TIMELOCKED_MULTISIG: return TIMELOCKED_MULTISIG_CONDITIONS;
        // Governance family
        case RungBlockType::WEIGHT_LIMIT:     return WEIGHT_LIMIT_CONDITIONS;
        case RungBlockType::INPUT_COUNT:      return INPUT_COUNT_CONDITIONS;
        case RungBlockType::OUTPUT_COUNT:     return OUTPUT_COUNT_CONDITIONS;
        case RungBlockType::RELATIVE_VALUE:   return RELATIVE_VALUE_CONDITIONS;
        case RungBlockType::ACCUMULATOR:      return ACCUMULATOR_CONDITIONS;
        case RungBlockType::OUTPUT_CHECK:     return OUTPUT_CHECK_CONDITIONS;
        case RungBlockType::COMPARE:          return COMPARE_CONDITIONS;
        // Legacy family
        case RungBlockType::P2PK_LEGACY:      return SIG_CONDITIONS;
        case RungBlockType::P2PKH_LEGACY:     return P2PKH_LEGACY_CONDITIONS;
        case RungBlockType::P2SH_LEGACY:      return P2PKH_LEGACY_CONDITIONS;
        case RungBlockType::P2WPKH_LEGACY:    return P2PKH_LEGACY_CONDITIONS;
        case RungBlockType::P2WSH_LEGACY:     return P2WSH_LEGACY_CONDITIONS;
        case RungBlockType::P2TR_LEGACY:      return SIG_CONDITIONS;
        case RungBlockType::P2TR_SCRIPT_LEGACY: return P2TR_SCRIPT_LEGACY_CONDITIONS;
        default: return NO_IMPLICIT;
        }
    } else {
        // WITNESS context
        switch (type) {
        case RungBlockType::SIG:              return SIG_WITNESS;
        case RungBlockType::MUSIG_THRESHOLD:  return MUSIG_THRESHOLD_WITNESS;
        case RungBlockType::CSV:              return CSV_WITNESS;
        case RungBlockType::CSV_TIME:         return CSV_WITNESS;
        case RungBlockType::CLTV:             return CSV_WITNESS;
        case RungBlockType::CLTV_TIME:        return CSV_WITNESS;
        // RESERVED_0201/RESERVED_0202: removed (no layout)
        case RungBlockType::TAGGED_HASH:      return TAGGED_HASH_WITNESS;
        case RungBlockType::HASH_GUARDED:     return HASH_GUARDED_WITNESS;
        case RungBlockType::CTV:              return CTV_WITNESS;
        case RungBlockType::COSIGN:           return COSIGN_WITNESS;
        case RungBlockType::TIMELOCKED_SIG:   return TIMELOCKED_SIG_WITNESS;
        case RungBlockType::HTLC:             return HTLC_WITNESS;
        case RungBlockType::HASH_SIG:         return HASH_SIG_WITNESS;
        case RungBlockType::CLTV_SIG:         return CLTV_SIG_WITNESS;
        // Legacy family
        case RungBlockType::P2PK_LEGACY:      return SIG_WITNESS;
        case RungBlockType::P2PKH_LEGACY:     return SIG_WITNESS;
        case RungBlockType::P2WPKH_LEGACY:    return SIG_WITNESS;
        case RungBlockType::P2TR_LEGACY:      return SIG_WITNESS;
        // P2SH, P2WSH, P2TR_SCRIPT: no implicit witness (variable inner conditions)
        default: return NO_IMPLICIT;
        }
    }
}

/** Check whether a block's fields match its implicit layout exactly.
 *  Returns true if the block can use implicit encoding (field count and types omitted). */
inline bool MatchesImplicitLayout(const RungBlock& block, const ImplicitFieldLayout& layout)
{
    if (layout.count == 0) return false;
    if (block.fields.size() != layout.count) return false;
    for (uint8_t i = 0; i < layout.count; ++i) {
        if (block.fields[i].type != layout.fields[i].type) return false;
    }
    return true;
}

// ============================================================================
// Block Descriptor Table (single source of truth for all block type metadata)
// ============================================================================

/** Compile-time descriptor for a block type. */
struct BlockDescriptor {
    RungBlockType type;
    const char* name;
    bool known;
    bool invertible;
    bool key_consuming;
    uint8_t pubkey_count;  //!< Fixed pubkey count; 255 = variable (count PUBKEY fields)
    const ImplicitFieldLayout* conditions_layout;
    const ImplicitFieldLayout* witness_layout;
    bool conditions_only;  //!< Has conditions layout but no witness layout
};

/** Lookup a block descriptor by type. Returns nullptr if not found. */
inline const BlockDescriptor* LookupBlockDescriptor(RungBlockType type)
{
    // Static table of all block descriptors
    static const BlockDescriptor BLOCK_DESCRIPTORS[] = {
        // Signature family
        {RungBlockType::SIG, "SIG", true, false, true, 1, &SIG_CONDITIONS, &SIG_WITNESS, false},
        {RungBlockType::MULTISIG, "MULTISIG", true, false, true, 255, &MULTISIG_CONDITIONS, nullptr, true},
        {RungBlockType::ADAPTOR_SIG, "ADAPTOR_SIG", true, false, true, 2, nullptr, nullptr, false},
        {RungBlockType::MUSIG_THRESHOLD, "MUSIG_THRESHOLD", true, false, true, 1, &MUSIG_THRESHOLD_CONDITIONS, &MUSIG_THRESHOLD_WITNESS, false},
        {RungBlockType::KEY_REF_SIG, "KEY_REF_SIG", true, false, true, 0, &KEY_REF_SIG_CONDITIONS, nullptr, true},
        // Timelock family
        {RungBlockType::CSV, "CSV", true, true, false, 0, &CSV_CONDITIONS, &CSV_WITNESS, false},
        {RungBlockType::CSV_TIME, "CSV_TIME", true, true, false, 0, &CSV_TIME_CONDITIONS, &CSV_WITNESS, false},
        {RungBlockType::CLTV, "CLTV", true, true, false, 0, &CLTV_CONDITIONS, &CSV_WITNESS, false},
        {RungBlockType::CLTV_TIME, "CLTV_TIME", true, true, false, 0, &CLTV_TIME_CONDITIONS, &CSV_WITNESS, false},
        // Hash family
        {RungBlockType::TAGGED_HASH, "TAGGED_HASH", true, true, false, 0, &TAGGED_HASH_CONDITIONS, &TAGGED_HASH_WITNESS, false},
        {RungBlockType::HASH_GUARDED, "HASH_GUARDED", true, false, false, 0, &HASH_GUARDED_CONDITIONS, &HASH_GUARDED_WITNESS, false},
        // Covenant family
        {RungBlockType::CTV, "CTV", true, true, false, 0, &CTV_CONDITIONS, &CTV_WITNESS, true},
        {RungBlockType::VAULT_LOCK, "VAULT_LOCK", true, true, true, 2, &VAULT_LOCK_CONDITIONS, nullptr, true},
        {RungBlockType::AMOUNT_LOCK, "AMOUNT_LOCK", true, true, false, 0, &AMOUNT_LOCK_CONDITIONS, nullptr, true},
        // Recursion family
        {RungBlockType::RECURSE_SAME, "RECURSE_SAME", true, true, false, 0, &RECURSE_SAME_CONDITIONS, nullptr, true},
        {RungBlockType::RECURSE_MODIFIED, "RECURSE_MODIFIED", true, true, false, 0, nullptr, nullptr, false},
        {RungBlockType::RECURSE_UNTIL, "RECURSE_UNTIL", true, true, false, 0, &RECURSE_UNTIL_CONDITIONS, nullptr, true},
        {RungBlockType::RECURSE_COUNT, "RECURSE_COUNT", true, true, false, 0, &RECURSE_COUNT_CONDITIONS, nullptr, true},
        {RungBlockType::RECURSE_SPLIT, "RECURSE_SPLIT", true, true, false, 0, &RECURSE_SPLIT_CONDITIONS, nullptr, true},
        {RungBlockType::RECURSE_DECAY, "RECURSE_DECAY", true, true, false, 0, nullptr, nullptr, false},
        // Anchor family
        {RungBlockType::ANCHOR, "ANCHOR", true, true, false, 0, &ANCHOR_CONDITIONS, nullptr, true},
        {RungBlockType::ANCHOR_CHANNEL, "ANCHOR_CHANNEL", true, true, true, 2, &ANCHOR_CHANNEL_CONDITIONS, nullptr, true},
        {RungBlockType::ANCHOR_POOL, "ANCHOR_POOL", true, true, false, 0, &ANCHOR_POOL_CONDITIONS, nullptr, true},
        {RungBlockType::ANCHOR_RESERVE, "ANCHOR_RESERVE", true, true, false, 0, &ANCHOR_RESERVE_CONDITIONS, nullptr, true},
        {RungBlockType::ANCHOR_SEAL, "ANCHOR_SEAL", true, true, false, 0, &ANCHOR_SEAL_CONDITIONS, nullptr, true},
        {RungBlockType::ANCHOR_ORACLE, "ANCHOR_ORACLE", true, true, true, 1, &ANCHOR_ORACLE_CONDITIONS, nullptr, true},
        {RungBlockType::DATA_RETURN, "DATA_RETURN", true, true, false, 0, &DATA_RETURN_CONDITIONS, nullptr, true},
        // PLC family
        {RungBlockType::HYSTERESIS_FEE, "HYSTERESIS_FEE", true, true, false, 0, &HYSTERESIS_FEE_CONDITIONS, nullptr, true},
        {RungBlockType::HYSTERESIS_VALUE, "HYSTERESIS_VALUE", true, true, false, 0, &HYSTERESIS_VALUE_CONDITIONS, nullptr, true},
        {RungBlockType::TIMER_CONTINUOUS, "TIMER_CONTINUOUS", true, true, false, 0, &TIMER_CONTINUOUS_CONDITIONS, nullptr, true},
        {RungBlockType::TIMER_OFF_DELAY, "TIMER_OFF_DELAY", true, true, false, 0, &TIMER_OFF_DELAY_CONDITIONS, nullptr, true},
        {RungBlockType::LATCH_SET, "LATCH_SET", true, true, true, 1, &LATCH_SET_CONDITIONS, nullptr, true},
        {RungBlockType::LATCH_RESET, "LATCH_RESET", true, true, true, 1, &LATCH_RESET_CONDITIONS, nullptr, true},
        {RungBlockType::COUNTER_DOWN, "COUNTER_DOWN", true, true, true, 1, &COUNTER_DOWN_CONDITIONS, nullptr, true},
        {RungBlockType::COUNTER_PRESET, "COUNTER_PRESET", true, true, false, 0, &COUNTER_PRESET_CONDITIONS, nullptr, true},
        {RungBlockType::COUNTER_UP, "COUNTER_UP", true, true, true, 1, &COUNTER_UP_CONDITIONS, nullptr, true},
        {RungBlockType::COMPARE, "COMPARE", true, true, false, 0, &COMPARE_CONDITIONS, nullptr, true},
        {RungBlockType::SEQUENCER, "SEQUENCER", true, true, false, 0, &SEQUENCER_CONDITIONS, nullptr, true},
        {RungBlockType::ONE_SHOT, "ONE_SHOT", true, true, false, 0, &ONE_SHOT_CONDITIONS, nullptr, true},
        {RungBlockType::RATE_LIMIT, "RATE_LIMIT", true, true, false, 0, &RATE_LIMIT_CONDITIONS, nullptr, true},
        {RungBlockType::COSIGN, "COSIGN", true, false, true, 0, &COSIGN_CONDITIONS, &COSIGN_WITNESS, false},
        // Compound family
        {RungBlockType::TIMELOCKED_SIG, "TIMELOCKED_SIG", true, false, true, 1, &TIMELOCKED_SIG_CONDITIONS, &TIMELOCKED_SIG_WITNESS, false},
        {RungBlockType::HTLC, "HTLC", true, false, true, 2, &HTLC_CONDITIONS, &HTLC_WITNESS, false},
        {RungBlockType::HASH_SIG, "HASH_SIG", true, false, true, 1, &HASH_SIG_CONDITIONS, &HASH_SIG_WITNESS, false},
        {RungBlockType::PTLC, "PTLC", true, false, true, 2, &PTLC_CONDITIONS, nullptr, true},
        {RungBlockType::CLTV_SIG, "CLTV_SIG", true, false, true, 1, &CLTV_SIG_CONDITIONS, &CLTV_SIG_WITNESS, false},
        {RungBlockType::TIMELOCKED_MULTISIG, "TIMELOCKED_MULTISIG", true, false, true, 255, &TIMELOCKED_MULTISIG_CONDITIONS, nullptr, true},
        // Governance family
        {RungBlockType::EPOCH_GATE, "EPOCH_GATE", true, false, false, 0, &EPOCH_GATE_CONDITIONS, nullptr, true},
        {RungBlockType::WEIGHT_LIMIT, "WEIGHT_LIMIT", true, true, false, 0, &WEIGHT_LIMIT_CONDITIONS, nullptr, true},
        {RungBlockType::INPUT_COUNT, "INPUT_COUNT", true, true, false, 0, &INPUT_COUNT_CONDITIONS, nullptr, true},
        {RungBlockType::OUTPUT_COUNT, "OUTPUT_COUNT", true, true, false, 0, &OUTPUT_COUNT_CONDITIONS, nullptr, true},
        {RungBlockType::RELATIVE_VALUE, "RELATIVE_VALUE", true, false, false, 0, &RELATIVE_VALUE_CONDITIONS, nullptr, true},
        {RungBlockType::ACCUMULATOR, "ACCUMULATOR", true, true, false, 0, &ACCUMULATOR_CONDITIONS, nullptr, true},
        {RungBlockType::OUTPUT_CHECK, "OUTPUT_CHECK", true, false, false, 0, &OUTPUT_CHECK_CONDITIONS, nullptr, true},
        // Legacy family
        {RungBlockType::P2PK_LEGACY, "P2PK_LEGACY", true, false, true, 1, &SIG_CONDITIONS, &SIG_WITNESS, false},
        {RungBlockType::P2PKH_LEGACY, "P2PKH_LEGACY", true, false, true, 0, &P2PKH_LEGACY_CONDITIONS, &SIG_WITNESS, false},
        {RungBlockType::P2SH_LEGACY, "P2SH_LEGACY", true, true, false, 0, &P2PKH_LEGACY_CONDITIONS, nullptr, true},
        {RungBlockType::P2WPKH_LEGACY, "P2WPKH_LEGACY", true, false, true, 0, &P2PKH_LEGACY_CONDITIONS, &SIG_WITNESS, false},
        {RungBlockType::P2WSH_LEGACY, "P2WSH_LEGACY", true, true, false, 0, &P2WSH_LEGACY_CONDITIONS, nullptr, true},
        {RungBlockType::P2TR_LEGACY, "P2TR_LEGACY", true, false, true, 1, &SIG_CONDITIONS, &SIG_WITNESS, false},
        {RungBlockType::P2TR_SCRIPT_LEGACY, "P2TR_SCRIPT_LEGACY", true, false, true, 1, &P2TR_SCRIPT_LEGACY_CONDITIONS, nullptr, true},
    };
    static const size_t N_DESCRIPTORS = sizeof(BLOCK_DESCRIPTORS) / sizeof(BLOCK_DESCRIPTORS[0]);
    for (size_t i = 0; i < N_DESCRIPTORS; ++i) {
        if (BLOCK_DESCRIPTORS[i].type == type) return &BLOCK_DESCRIPTORS[i];
    }
    return nullptr;
}

/** Runtime check that every block type with a CONDITIONS implicit layout also
 *  has a WITNESS implicit layout (or the block is one of the explicitly-listed
 *  types that intentionally have no implicit witness: P2SH, P2WSH, P2TR_SCRIPT,
 *  EPOCH_GATE, ANCHOR_SEAL, AMOUNT_LOCK, CTV).
 *  Call once at init to catch layout pairing mistakes early. */
inline bool VerifyImplicitLayoutPairing()
{
    // Block types that intentionally have conditions-only implicit layouts
    // (no implicit witness layout — witness uses explicit encoding)
    static constexpr RungBlockType conditions_only[] = {
        // Original conditions-only types
        RungBlockType::P2SH_LEGACY, RungBlockType::P2WSH_LEGACY,
        RungBlockType::P2TR_SCRIPT_LEGACY,
        RungBlockType::EPOCH_GATE, RungBlockType::ANCHOR_SEAL,
        RungBlockType::AMOUNT_LOCK, RungBlockType::CTV,
        RungBlockType::DATA_RETURN,
        // Newly added conditions layouts (witness layouts not yet defined)
        RungBlockType::MULTISIG, RungBlockType::KEY_REF_SIG,
        RungBlockType::VAULT_LOCK,
        RungBlockType::RECURSE_SAME, RungBlockType::RECURSE_UNTIL,
        RungBlockType::RECURSE_COUNT, RungBlockType::RECURSE_SPLIT,
        RungBlockType::ANCHOR_CHANNEL, RungBlockType::ANCHOR_POOL,
        RungBlockType::ANCHOR_RESERVE, RungBlockType::ANCHOR_ORACLE,
        RungBlockType::HYSTERESIS_FEE, RungBlockType::HYSTERESIS_VALUE,
        RungBlockType::TIMER_CONTINUOUS, RungBlockType::TIMER_OFF_DELAY,
        RungBlockType::LATCH_SET, RungBlockType::LATCH_RESET,
        RungBlockType::COUNTER_DOWN, RungBlockType::COUNTER_PRESET,
        RungBlockType::COUNTER_UP, RungBlockType::SEQUENCER,
        RungBlockType::ONE_SHOT, RungBlockType::RATE_LIMIT,
        RungBlockType::PTLC, RungBlockType::TIMELOCKED_MULTISIG,
        RungBlockType::WEIGHT_LIMIT, RungBlockType::INPUT_COUNT,
        RungBlockType::OUTPUT_COUNT, RungBlockType::RELATIVE_VALUE,
        RungBlockType::ACCUMULATOR,
        RungBlockType::ANCHOR, RungBlockType::COMPARE,
        RungBlockType::OUTPUT_CHECK,
    };

    for (uint32_t code = 0; code <= 0x0FFF; ++code) {
        uint16_t tc = static_cast<uint16_t>(code);
        if (!IsKnownBlockType(tc)) continue;
        auto bt = static_cast<RungBlockType>(tc);
        const auto& cond_layout = GetImplicitLayout(bt, 1);
        const auto& wit_layout = GetImplicitLayout(bt, 0);
        if (cond_layout.count > 0 && wit_layout.count == 0) {
            // Must be in the conditions_only whitelist
            bool whitelisted = false;
            for (auto exempt : conditions_only) {
                if (bt == exempt) { whitelisted = true; break; }
            }
            if (!whitelisted) return false;
        }
    }
    return true;
}

} // namespace rung

#endif // BITCOIN_RUNG_TYPES_H

