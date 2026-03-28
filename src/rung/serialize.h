// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_SERIALIZE_H
#define BITCOIN_RUNG_SERIALIZE_H

#include <rung/types.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>

#include <cstdint>
#include <string>
#include <vector>

namespace rung {

/** Maximum number of rungs per ladder witness.
 *  16 rungs provides sufficient spending-path diversity for institutional custody
 *  (multisig tiers, PQ fallbacks, timelocked recovery, inheritance paths, governance
 *  overrides) with only 1 additional Merkle proof hash vs 8 rungs. */
static constexpr size_t MAX_RUNGS = 16;
/** Maximum number of blocks per rung. */
static constexpr size_t MAX_BLOCKS_PER_RUNG = 8;
/** Maximum number of fields per block. */
static constexpr size_t MAX_FIELDS_PER_BLOCK = 16;
/** Maximum total ladder witness size in bytes (must accommodate PQ signatures). */
static constexpr size_t MAX_LADDER_WITNESS_SIZE = 100000;
/** Maximum number of PREIMAGE/SCRIPT_BODY fields per ladder witness (fast reject).
 *  Counts all PREIMAGE and SCRIPT_BODY fields across all block types including
 *  compounds (HTLC, HASH_SIG, P2SH_LEGACY, P2WSH_LEGACY, P2TR_SCRIPT_LEGACY)
 *  and hash-preimage binding for anchor/one-shot blocks.
 *  Per-witness check is a fast reject; the binding constraint is per-transaction. */
static constexpr size_t MAX_PREIMAGE_FIELDS_PER_WITNESS = 2;
/** Maximum number of PREIMAGE/SCRIPT_BODY fields per transaction (consensus).
 *  Summed across ALL inputs. Prevents multi-input data embedding attacks where
 *  an attacker creates N inputs each carrying preimage data. Legitimate use cases
 *  (HTLC, atomic swap, HASH_SIG) never need >2 preimages per transaction. */
static constexpr size_t MAX_PREIMAGE_FIELDS_PER_TX = 2;
/** Minimum output value for non-DATA_RETURN MLSC outputs (consensus).
 *  Prevents UTXO set bloat and cheap output-layer spam.
 *  Matches current Bitcoin dust threshold for witness outputs. */
static constexpr int64_t MIN_RUNG_OUTPUT_VALUE = 546;
/** Coil address is carried as SHA256(raw_address) — 32 bytes, fixed.
 *  Raw address never goes on-chain. Wire format: 0 (no address) or 32 (hash). */
static constexpr size_t COIL_ADDRESS_HASH_SIZE = 32;
/** Maximum number of relays per ladder witness. */
static constexpr size_t MAX_RELAYS = 8;
/** Maximum number of relay requirements per rung or relay. */
static constexpr size_t MAX_REQUIRES = 8;
/** Maximum transitive relay chain depth (relay requiring relay requiring relay...). */
static constexpr size_t MAX_RELAY_DEPTH = 4;
/** Compact coil sentinel: 0x00 + output_index(1) = 2 bytes total.
 *  Expands to default coil: UNLOCK + INLINE + SCHNORR + no address + no rung_destinations. */
static constexpr uint8_t COMPACT_COIL_SENTINEL = 0x00;

/** Serialization context — determines which implicit field table to use. */
enum class SerializationContext : uint8_t {
    WITNESS,     //!< Witness (spending) side — SIGNATURE, PREIMAGE allowed
    CONDITIONS,  //!< Conditions (locking) side — only condition data types
};

/** Deserialize a LadderWitness from raw witness bytes.
 *  Performs full type and size validation during deserialization.
 *  Returns false with error message on any malformed data.
 *
 *  Wire format (v4 — micro-header + varint NUMERIC + implicit fields):
 *    [n_rungs: varint]
 *    for each rung:
 *      [n_blocks: varint]
 *      for each block:
 *        [micro_header: uint8_t]    -- 0x00-0x7F = lookup table index
 *                                   -- 0x80 = escape (full header follows, not inverted)
 *                                   -- 0x81 = escape (full header follows, inverted)
 *        if escape: [block_type: uint16_t LE]
 *        if micro-header with implicit field table for context:
 *          -- field count and type bytes omitted
 *          for each implicit field:
 *            if NUMERIC: [value: CompactSize]
 *            else: [data_len: CompactSize] [data: bytes]
 *        else:
 *          [n_fields: varint]
 *          for each field:
 *            [data_type: uint8_t]
 *            if NUMERIC: [value: CompactSize]
 *            else: [data_len: CompactSize] [data: bytes]
 *    [coil_type: uint8_t]
 *    [attestation: uint8_t]
 *    [scheme: uint8_t]
 *    [address_len: varint]
 *    [address: bytes]              (raw scriptPubKey, 0 len = no address)
 *    [n_coil_conditions: varint]   (must be 0 — coil conditions removed)
 */
bool DeserializeLadderWitness(const std::vector<uint8_t>& witness_bytes,
                              LadderWitness& ladder_out,
                              std::string& error,
                              SerializationContext ctx = SerializationContext::WITNESS);

/** Serialize a LadderWitness to raw bytes. */
std::vector<uint8_t> SerializeLadderWitness(const LadderWitness& ladder,
                                             SerializationContext ctx = SerializationContext::WITNESS);

/** Deserialize a single block from a DataStream.
 *  Handles micro-headers, implicit field layouts, strict field enforcement,
 *  IsConditionDataType gating (CONDITIONS context), IsDataEmbeddingType
 *  rejection for layout-less blocks, and DATA-type restriction.
 *  Shared by DeserializeLadderWitness and DeserializeMLSCProof. */
bool DeserializeBlock(DataStream& ss, RungBlock& block_out,
                      uint8_t ctx, std::string& error);

/** Serialize a single rung's blocks + relay_refs to bytes (for MLSC Merkle leaf computation).
 *  Format: CompactSize(n_blocks) + blocks + CompactSize(n_relay_refs) + relay_ref indices.
 *  Uses the standard wire format (micro-headers + implicit fields) in the given context. */
std::vector<uint8_t> SerializeRungBlocks(const Rung& rung, SerializationContext ctx);

/** Serialize coil metadata to bytes (for MLSC Merkle leaf computation).
 *  Format: coil_type(1) + attestation(1) + scheme(1) + address_len(varint) + address +
 *          n_conditions(varint, always 0) + rung_destinations. */
std::vector<uint8_t> SerializeCoilData(const RungCoil& coil);

/** Serialize a relay's blocks + relay_refs to bytes (for MLSC Merkle leaf computation).
 *  Format: CompactSize(n_blocks) + blocks + CompactSize(n_relay_refs) + relay_ref indices. */
std::vector<uint8_t> SerializeRelayBlocks(const Relay& relay, SerializationContext ctx);

} // namespace rung

#endif // BITCOIN_RUNG_SERIALIZE_H
