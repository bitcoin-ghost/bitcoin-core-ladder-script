// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/serialize.h>
#include <rung/conditions.h>

#include <streams.h>
#include <util/strencodings.h>

#include <ios>
#include <set>

namespace rung {

// ============================================================================
// Helper: data type allowed in witness context
// ============================================================================

// IsDataEmbeddingType moved to types.h (shared with conditions.cpp)

// ============================================================================
// Helper: serialize a single field (varint NUMERIC optimization)
// ============================================================================

static void SerializeField(DataStream& ss, const RungField& field, bool write_type)
{
    if (write_type) {
        ss << static_cast<uint8_t>(field.type);
    }
    if (field.type == RungDataType::NUMERIC) {
        // Varint NUMERIC: encode LE value directly as CompactSize (no length prefix)
        uint32_t val = 0;
        for (size_t i = 0; i < field.data.size(); ++i) {
            val |= static_cast<uint32_t>(field.data[i]) << (8 * i);
        }
        WriteCompactSize(ss, val);
    } else if (field.type == RungDataType::SCHEME && field.data.size() == 1) {
        // Fixed 1-byte field: write data directly, no length prefix needed
        // when using implicit layout (write_type == false and fixed_size > 0).
        // But when write_type is true, we still need the length.
        if (write_type) {
            WriteCompactSize(ss, field.data.size());
            ss.write(MakeByteSpan(field.data));
        } else {
            // Implicit: fixed_size is known, write data only
            ss.write(MakeByteSpan(field.data));
        }
    } else {
        // Standard: length-prefixed data
        if (!write_type) {
            // Implicit: caller knows the type, but we still need length for variable fields
            // Fixed-size fields skip the length prefix (handled by caller via fixed_size)
            WriteCompactSize(ss, field.data.size());
            if (!field.data.empty()) {
                ss.write(MakeByteSpan(field.data));
            }
        } else {
            WriteCompactSize(ss, field.data.size());
            if (!field.data.empty()) {
                ss.write(MakeByteSpan(field.data));
            }
        }
    }
}

/** Serialize a field with implicit layout knowledge (fixed_size optimization). */
static void SerializeImplicitField(DataStream& ss, const RungField& field, uint16_t fixed_size)
{
    if (field.type == RungDataType::NUMERIC) {
        // Varint NUMERIC
        uint32_t val = 0;
        for (size_t i = 0; i < field.data.size(); ++i) {
            val |= static_cast<uint32_t>(field.data[i]) << (8 * i);
        }
        WriteCompactSize(ss, val);
    } else if (fixed_size > 0) {
        // Fixed-size: write data directly (no length prefix)
        ss.write(MakeByteSpan(field.data));
    } else {
        // Variable-size: write length + data
        WriteCompactSize(ss, field.data.size());
        if (!field.data.empty()) {
            ss.write(MakeByteSpan(field.data));
        }
    }
}

// ============================================================================
// Helper: serialize a block (micro-header + implicit fields)
// ============================================================================

static void SerializeBlock(DataStream& ss, const RungBlock& block, uint8_t ctx)
{
    int slot = MicroHeaderSlot(block.type);
    const auto& layout = GetImplicitLayout(block.type, ctx);
    // Use micro-header only when:
    // - Not inverted, AND
    // - Either fields match implicit layout, or no implicit layout exists for this context
    //   (if an implicit layout exists but fields don't match, we must escape to
    //    avoid ambiguity — deserializer uses layout presence as the signal)
    bool fields_match = MatchesImplicitLayout(block, layout);
    bool can_use_micro = (slot >= 0) && !block.inverted &&
                         (fields_match || layout.count == 0);
    // Implicit field encoding is only used with micro-header + matching layout
    bool use_implicit = can_use_micro && fields_match;

    if (can_use_micro) {
        // Micro-header: 1-byte slot index
        ss << static_cast<uint8_t>(slot);
    } else if (!block.inverted) {
        // Escape 0x80 + type
        ss << MICRO_HEADER_ESCAPE;
        uint16_t btype = static_cast<uint16_t>(block.type);
        ss << static_cast<uint8_t>(btype & 0xFF);
        ss << static_cast<uint8_t>((btype >> 8) & 0xFF);
    } else {
        // Escape 0x81 + type (inverted)
        ss << MICRO_HEADER_ESCAPE_INV;
        uint16_t btype = static_cast<uint16_t>(block.type);
        ss << static_cast<uint8_t>(btype & 0xFF);
        ss << static_cast<uint8_t>((btype >> 8) & 0xFF);
    }

    if (use_implicit) {
        // Implicit fields: no field count, no type bytes
        for (uint8_t i = 0; i < layout.count; ++i) {
            SerializeImplicitField(ss, block.fields[i], layout.fields[i].fixed_size);
        }
    } else {
        // Explicit fields: field count + type byte + data per field
        WriteCompactSize(ss, block.fields.size());
        for (const auto& field : block.fields) {
            SerializeField(ss, field, /*write_type=*/true);
        }
    }
}

// ============================================================================
// Helper: deserialize a single field
// ============================================================================

static bool DeserializeField(DataStream& ss, RungField& field_out,
                             RungDataType type, uint16_t fixed_size,
                             std::string& error)
{
    field_out.type = type;

    if (type == RungDataType::NUMERIC) {
        // Varint NUMERIC: read CompactSize as value (not size), convert to 4-byte LE
        uint64_t val = ReadCompactSize(ss, false); // range_check=false: values can exceed MAX_SIZE
        if (val > 0xFFFFFFFF) {
            error = "NUMERIC value exceeds uint32 max";
            return false;
        }
        // Always store as 4-byte LE for evaluator compatibility
        // (evaluators and recursion checks compare field.data byte-by-byte)
        field_out.data.resize(4);
        field_out.data[0] = static_cast<uint8_t>(val & 0xFF);
        field_out.data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
        field_out.data[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
        field_out.data[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    } else if (fixed_size > 0) {
        // Fixed-size field: read exactly fixed_size bytes (no length prefix)
        field_out.data.resize(fixed_size);
        ss.read(MakeWritableByteSpan(field_out.data));
    } else {
        // Variable-size field: read CompactSize length + data
        uint64_t data_len = ReadCompactSize(ss);
        size_t min_sz = FieldMinSize(type);
        size_t max_sz = FieldMaxSize(type);
        if (data_len < min_sz) {
            error = DataTypeName(type) + " too small: " + std::to_string(data_len) +
                    " < " + std::to_string(min_sz);
            return false;
        }
        if (data_len > max_sz) {
            error = DataTypeName(type) + " too large: " + std::to_string(data_len) +
                    " > " + std::to_string(max_sz);
            return false;
        }
        field_out.data.resize(data_len);
        if (data_len > 0) {
            ss.read(MakeWritableByteSpan(field_out.data));
        }
    }

    // Validate field content
    std::string field_reason;
    if (!field_out.IsValid(field_reason)) {
        error = field_reason;
        return false;
    }
    return true;
}

// ============================================================================
// Helper: deserialize a block (micro-header + implicit fields)
// ============================================================================

bool DeserializeBlock(DataStream& ss, RungBlock& block_out,
                      uint8_t ctx, std::string& error)
{
    uint8_t first_byte;
    ss >> first_byte;

    if (first_byte < MICRO_HEADER_ESCAPE) {
        // Micro-header: lookup block type from table
        if (MICRO_HEADER_TABLE[first_byte] == 0xFFFF) {
            error = "unused micro-header slot: 0x" + HexStr(std::span<const uint8_t>{&first_byte, 1});
            return false;
        }
        uint16_t block_type_val = MICRO_HEADER_TABLE[first_byte];
        if (!IsKnownBlockType(block_type_val)) {
            error = "unknown block type from micro-header: 0x" + HexStr(std::vector<uint8_t>{
                static_cast<uint8_t>(block_type_val & 0xFF),
                static_cast<uint8_t>((block_type_val >> 8) & 0xFF)});
            return false;
        }
        block_out.type = static_cast<RungBlockType>(block_type_val);
        block_out.inverted = false;
    } else if (first_byte == MICRO_HEADER_ESCAPE || first_byte == MICRO_HEADER_ESCAPE_INV) {
        // Full header escape: read block_type uint16_t LE
        uint8_t lo, hi;
        ss >> lo >> hi;
        uint16_t block_type_val = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
        if (!IsKnownBlockType(block_type_val)) {
            error = "unknown block type: 0x" + HexStr(std::vector<uint8_t>{lo, hi});
            return false;
        }
        block_out.type = static_cast<RungBlockType>(block_type_val);
        block_out.inverted = (first_byte == MICRO_HEADER_ESCAPE_INV);
    } else {
        error = "invalid header byte: 0x" + HexStr(std::span<const uint8_t>{&first_byte, 1});
        return false;
    }

    // Reject inverted key-consuming blocks (selective inversion removal)
    if (block_out.inverted && !IsInvertibleBlockType(block_out.type)) {
        error = "block type cannot be inverted: " + BlockTypeName(block_out.type);
        return false;
    }

    // Check for implicit field layout
    const auto& layout = GetImplicitLayout(block_out.type, ctx);

    if (layout.count > 0 && first_byte < MICRO_HEADER_ESCAPE) {
        // Try implicit encoding: peek to see if field count follows
        // Implicit blocks have no field count — first byte is field data.
        // We use the micro-header as the signal: micro-header + implicit layout = implicit fields.
        block_out.fields.resize(layout.count);
        for (uint8_t i = 0; i < layout.count; ++i) {
            if (!DeserializeField(ss, block_out.fields[i], layout.fields[i].type,
                                  layout.fields[i].fixed_size, error)) {
                return false;
            }
        }
    } else {
        // Explicit fields: read field count + per-field type + data
        uint64_t n_fields = ReadCompactSize(ss);
        if (n_fields > MAX_FIELDS_PER_BLOCK) {
            error = "block has too many fields: " + std::to_string(n_fields);
            return false;
        }

        // Strict field enforcement (consensus): if this block type has an
        // implicit layout, the explicit field count and types must match exactly.
        // For blocks with NO_IMPLICIT (count=0, not in switch), the check below
        // is skipped — IsDataEmbeddingType catches high-bandwidth abuse instead.
        // ADAPTOR_SIG: no condition fields, enforce n_fields == 0 in conditions context.
        const auto& expected = GetImplicitLayout(block_out.type, ctx);
        if (expected.count > 0) {
            if (n_fields != expected.count) {
                error = "block " + BlockTypeName(block_out.type) +
                        " field count mismatch: got " + std::to_string(n_fields) +
                        ", expected " + std::to_string(expected.count);
                return false;
            }
        }
        // ADAPTOR_SIG has no condition fields — reject any in conditions context
        if (block_out.type == RungBlockType::ADAPTOR_SIG &&
            ctx == static_cast<uint8_t>(SerializationContext::CONDITIONS) &&
            n_fields > 0) {
            error = "ADAPTOR_SIG has no condition fields: got " + std::to_string(n_fields);
            return false;
        }
        // ACCUMULATOR: cap at 10 HASH256 fields (root + 8 proof nodes + leaf)
        if (block_out.type == RungBlockType::ACCUMULATOR && n_fields > 10) {
            error = "ACCUMULATOR too many fields: " + std::to_string(n_fields) + " > 10";
            return false;
        }

        block_out.fields.resize(n_fields);
        for (uint64_t f = 0; f < n_fields; ++f) {
            uint8_t data_type_byte;
            ss >> data_type_byte;
            if (!IsKnownDataType(data_type_byte)) {
                error = "unknown data type: 0x" + HexStr(std::span<const uint8_t>{&data_type_byte, 1});
                return false;
            }
            RungDataType dtype = static_cast<RungDataType>(data_type_byte);

            // CONDITIONS context: reject witness-only data types
            if (ctx == static_cast<uint8_t>(SerializationContext::CONDITIONS) &&
                !IsConditionDataType(dtype)) {
                error = "witness-only data type in conditions: " + DataTypeName(dtype);
                return false;
            }

            // Consensus: for blocks with NO implicit layout (any context), reject
            // high-bandwidth data types that could carry unvalidated payload.
            // This closes the ANCHOR/RECURSE_MODIFIED/RECURSE_DECAY/COMPARE gap
            // where layout-less blocks could carry 16 x DATA(80) = 1280 bytes.
            // ACCUMULATOR: HASH256 fields carry Merkle proof (variable count).
            // Whitelisted from the data-embedding check.
            if (expected.count == 0 && IsDataEmbeddingType(dtype) &&
                block_out.type != RungBlockType::ACCUMULATOR) {
                error = "data-embedding type " + DataTypeName(dtype) +
                        " not allowed in block without implicit layout: " +
                        BlockTypeName(block_out.type);
                return false;
            }

            // DATA type restricted to DATA_RETURN blocks only
            if (dtype == RungDataType::DATA &&
                block_out.type != RungBlockType::DATA_RETURN) {
                error = "DATA type only allowed in DATA_RETURN blocks";
                return false;
            }

            // Strict field enforcement: validate field type matches expected layout
            if (expected.count > 0 && f < expected.count) {
                if (dtype != expected.fields[f].type) {
                    error = "block " + BlockTypeName(block_out.type) +
                            " field " + std::to_string(f) + " type mismatch: got " +
                            DataTypeName(dtype) + ", expected " +
                            DataTypeName(expected.fields[f].type);
                    return false;
                }
            }

            if (!DeserializeField(ss, block_out.fields[f], dtype, 0, error)) {
                return false;
            }
        }
    }

    return true;
}

// ============================================================================
// Public API
// ============================================================================

bool DeserializeLadderWitness(const std::vector<uint8_t>& witness_bytes,
                              LadderWitness& ladder_out,
                              std::string& error,
                              SerializationContext ctx)
{
    if (witness_bytes.empty()) {
        error = "empty ladder witness";
        return false;
    }

    if (witness_bytes.size() > MAX_LADDER_WITNESS_SIZE) {
        error = "ladder witness exceeds maximum size";
        return false;
    }

    DataStream ss{witness_bytes};
    uint8_t ctx_val = static_cast<uint8_t>(ctx);

    try {
        uint64_t n_rungs = ReadCompactSize(ss);
        if (n_rungs == 0) {
            // Diff witness mode: rungs/relays inherited from another input
            uint64_t input_index = ReadCompactSize(ss);
            if (input_index > 0xFFFFFFFF) {
                error = "diff witness input_index too large";
                return false;
            }

            uint64_t n_diffs = ReadCompactSize(ss);
            // Cap: total possible fields across all rungs
            static constexpr size_t MAX_DIFFS = MAX_FIELDS_PER_BLOCK * MAX_BLOCKS_PER_RUNG * MAX_RUNGS;
            if (n_diffs > MAX_DIFFS) {
                error = "diff witness too many diffs: " + std::to_string(n_diffs);
                return false;
            }

            WitnessReference ref;
            ref.input_index = static_cast<uint32_t>(input_index);
            ref.diffs.resize(n_diffs);

            for (uint64_t d = 0; d < n_diffs; ++d) {
                uint64_t ri = ReadCompactSize(ss);
                uint64_t bi = ReadCompactSize(ss);
                uint64_t fi = ReadCompactSize(ss);
                if (ri > MAX_RUNGS || bi > MAX_BLOCKS_PER_RUNG || fi > MAX_FIELDS_PER_BLOCK) {
                    error = "diff witness index out of range at diff " + std::to_string(d);
                    return false;
                }
                ref.diffs[d].rung_index = static_cast<uint16_t>(ri);
                ref.diffs[d].block_index = static_cast<uint16_t>(bi);
                ref.diffs[d].field_index = static_cast<uint16_t>(fi);

                // Read diff field: type byte + data
                uint8_t type_byte;
                ss >> type_byte;
                if (!IsKnownDataType(type_byte)) {
                    error = "diff witness unknown data type: 0x" +
                            HexStr(std::span<const uint8_t>{&type_byte, 1});
                    return false;
                }
                RungDataType dtype = static_cast<RungDataType>(type_byte);

                // Diff fields must be witness-side types (PUBKEY, SIGNATURE, PREIMAGE, SCRIPT_BODY, SCHEME)
                if (dtype != RungDataType::PUBKEY &&
                    dtype != RungDataType::SIGNATURE &&
                    dtype != RungDataType::PREIMAGE &&
                    dtype != RungDataType::SCRIPT_BODY &&
                    dtype != RungDataType::SCHEME) {
                    error = "diff witness field type " + DataTypeName(dtype) +
                            " not allowed (must be PUBKEY, SIGNATURE, PREIMAGE, SCRIPT_BODY, or SCHEME)";
                    return false;
                }

                if (!DeserializeField(ss, ref.diffs[d].new_field, dtype, 0, error)) {
                    return false;
                }
            }

            // Count PREIMAGE/SCRIPT_BODY fields in diffs (defense-in-depth)
            size_t diff_preimage_count = 0;
            for (const auto& diff : ref.diffs) {
                if (diff.new_field.type == RungDataType::PREIMAGE ||
                    diff.new_field.type == RungDataType::SCRIPT_BODY) {
                    diff_preimage_count++;
                }
            }
            if (diff_preimage_count > MAX_PREIMAGE_FIELDS_PER_WITNESS) {
                error = "diff witness too many PREIMAGE/SCRIPT_BODY fields: " +
                        std::to_string(diff_preimage_count) + " > " +
                        std::to_string(MAX_PREIMAGE_FIELDS_PER_WITNESS);
                return false;
            }

            ladder_out.witness_ref = std::move(ref);

            // Read fresh coil (same code as normal path, with compact coil support)
            uint8_t ref_coil_type_byte;
            ss >> ref_coil_type_byte;

            if (ref_coil_type_byte == COMPACT_COIL_SENTINEL) {
                // Compact default coil
                ladder_out.coil.coil_type = RungCoilType::UNLOCK;
                ladder_out.coil.attestation = RungAttestationMode::INLINE;
                ladder_out.coil.scheme = RungScheme::SCHNORR;
                uint8_t output_index_byte;
                ss >> output_index_byte;
                ladder_out.coil.output_index = output_index_byte;
            } else {
                uint8_t attestation_byte, scheme_byte;
                ss >> attestation_byte >> scheme_byte;
                if (!IsKnownCoilType(ref_coil_type_byte)) {
                    error = "unknown coil type: 0x" + HexStr(std::span<const uint8_t>{&ref_coil_type_byte, 1});
                    return false;
                }
                if (!IsKnownAttestationMode(attestation_byte)) {
                    error = "unknown attestation mode: 0x" + HexStr(std::span<const uint8_t>{&attestation_byte, 1});
                    return false;
                }
                if (!IsKnownScheme(scheme_byte)) {
                    error = "unknown coil scheme: 0x" + HexStr(std::span<const uint8_t>{&scheme_byte, 1});
                    return false;
                }
                ladder_out.coil.coil_type = static_cast<RungCoilType>(ref_coil_type_byte);
                ladder_out.coil.attestation = static_cast<RungAttestationMode>(attestation_byte);
                ladder_out.coil.scheme = static_cast<RungScheme>(scheme_byte);

                uint8_t output_index_byte;
                ss >> output_index_byte;
                ladder_out.coil.output_index = output_index_byte;

                uint64_t addr_len = ReadCompactSize(ss);
                if (addr_len != 0 && addr_len != 32) {
                    error = "coil address_hash must be 0 or 32 bytes, got " + std::to_string(addr_len);
                    return false;
                }
                if (addr_len > 0) {
                    ladder_out.coil.address_hash.resize(addr_len);
                    ss.read(MakeWritableByteSpan(ladder_out.coil.address_hash));
                }

                uint64_t n_coil_rungs = ReadCompactSize(ss);
                if (n_coil_rungs != 0) {
                    error = "coil conditions not supported: n_coil_conditions must be 0, got " + std::to_string(n_coil_rungs);
                    return false;
                }

                if (!ss.empty()) {
                    uint64_t n_rung_dests = ReadCompactSize(ss);
                    if (n_rung_dests > MAX_RUNGS) {
                        error = "too many rung_destinations: " + std::to_string(n_rung_dests);
                        return false;
                    }
                    ladder_out.coil.rung_destinations.resize(n_rung_dests);
                    std::set<uint16_t> seen_indices;
                    for (uint64_t rd = 0; rd < n_rung_dests; ++rd) {
                        uint8_t lo, hi;
                    ss >> lo >> hi;
                    uint16_t rung_idx = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
                    if (!seen_indices.insert(rung_idx).second) {
                        error = "duplicate rung_destination index: " + std::to_string(rung_idx);
                        return false;
                    }
                    ladder_out.coil.rung_destinations[rd].first = rung_idx;
                        ladder_out.coil.rung_destinations[rd].second.resize(32);
                        ss.read(MakeWritableByteSpan(ladder_out.coil.rung_destinations[rd].second));
                    }
                }
            } // end else (full coil encoding)

            // No relays section — inherited from source

            if (!ss.empty()) {
                error = "trailing bytes in diff witness";
                return false;
            }
            return true;
        }
        if (n_rungs > MAX_RUNGS) {
            error = "too many rungs: " + std::to_string(n_rungs);
            return false;
        }

        // Consensus: count PREIMAGE fields across all blocks (including compounds)
        size_t preimage_field_count = 0;

        ladder_out.rungs.resize(n_rungs);
        for (uint64_t r = 0; r < n_rungs; ++r) {
            uint64_t n_blocks = ReadCompactSize(ss);
            if (n_blocks == 0) {
                error = "rung " + std::to_string(r) + " has zero blocks (compact rungs deprecated)";
                return false;
            }
            if (n_blocks > MAX_BLOCKS_PER_RUNG) {
                error = "rung " + std::to_string(r) + " has too many blocks: " + std::to_string(n_blocks);
                return false;
            }

            ladder_out.rungs[r].blocks.resize(n_blocks);
            for (uint64_t b = 0; b < n_blocks; ++b) {
                if (!DeserializeBlock(ss, ladder_out.rungs[r].blocks[b], ctx_val, error)) {
                    return false;
                }
            }
        }

        // Read coil (per-ladder, after all rungs)
        // Compact coil: 0x00 sentinel + output_index = 2 bytes for default (UNLOCK, INLINE, SCHNORR, no address)
        uint8_t coil_type_byte;
        ss >> coil_type_byte;

        if (coil_type_byte == COMPACT_COIL_SENTINEL) {
            // Compact default coil: UNLOCK + INLINE + SCHNORR + no address + no conditions
            ladder_out.coil.coil_type = RungCoilType::UNLOCK;
            ladder_out.coil.attestation = RungAttestationMode::INLINE;
            ladder_out.coil.scheme = RungScheme::SCHNORR;
            uint8_t output_index_byte2;
            ss >> output_index_byte2;
            ladder_out.coil.output_index = output_index_byte2;
            // No address, no conditions, no rung_destinations
        } else {
            // Full coil encoding
            uint8_t attestation_byte, scheme_byte;
            ss >> attestation_byte >> scheme_byte;
            if (!IsKnownCoilType(coil_type_byte)) {
                error = "unknown coil type: 0x" + HexStr(std::span<const uint8_t>{&coil_type_byte, 1});
                return false;
            }
            if (!IsKnownAttestationMode(attestation_byte)) {
                error = "unknown attestation mode: 0x" + HexStr(std::span<const uint8_t>{&attestation_byte, 1});
                return false;
            }
            if (!IsKnownScheme(scheme_byte)) {
                error = "unknown coil scheme: 0x" + HexStr(std::span<const uint8_t>{&scheme_byte, 1});
                return false;
            }
            ladder_out.coil.coil_type = static_cast<RungCoilType>(coil_type_byte);
            ladder_out.coil.attestation = static_cast<RungAttestationMode>(attestation_byte);
            ladder_out.coil.scheme = static_cast<RungScheme>(scheme_byte);

            // TX_MLSC: read output_index
            uint8_t output_index_byte2;
            ss >> output_index_byte2;
            ladder_out.coil.output_index = output_index_byte2;

            // Read coil address hash (0 = no address, 32 = SHA256 of raw address)
            uint64_t addr_len = ReadCompactSize(ss);
            if (addr_len != 0 && addr_len != 32) {
                error = "coil address_hash must be 0 or 32 bytes, got " + std::to_string(addr_len);
                return false;
            }
            if (addr_len > 0) {
                ladder_out.coil.address_hash.resize(addr_len);
                ss.read(MakeWritableByteSpan(ladder_out.coil.address_hash));
            }

            // Read coil condition count — must be 0 (coil conditions removed, reject non-zero)
            uint64_t n_coil_rungs = ReadCompactSize(ss);
            if (n_coil_rungs != 0) {
                error = "coil conditions not supported: n_coil_conditions must be 0, got " + std::to_string(n_coil_rungs);
                return false;
            }

            // Read per-rung destinations (0 = none, backward compatible)
            if (!ss.empty()) {
                uint64_t n_rung_dests = ReadCompactSize(ss);
                if (n_rung_dests > MAX_RUNGS) {
                    error = "too many rung_destinations: " + std::to_string(n_rung_dests);
                    return false;
                }
                if (n_rung_dests > 0) {
                    ladder_out.coil.rung_destinations.resize(n_rung_dests);
                    std::set<uint16_t> seen_indices;
                    for (uint64_t rd = 0; rd < n_rung_dests; ++rd) {
                        uint8_t lo, hi;
                        ss >> lo >> hi;
                        uint16_t rung_idx = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
                        if (!seen_indices.insert(rung_idx).second) {
                            error = "duplicate rung_destination index: " + std::to_string(rung_idx);
                            return false;
                        }
                        ladder_out.coil.rung_destinations[rd].first = rung_idx;
                        ladder_out.coil.rung_destinations[rd].second.resize(32);
                        ss.read(MakeWritableByteSpan(ladder_out.coil.rung_destinations[rd].second));
                    }
                }
            }
        }

        // Read relays (optional — backward compatible, 0 relays if EOF)
        if (!ss.empty()) {
            uint64_t n_relays = ReadCompactSize(ss);
            if (n_relays > MAX_RELAYS) {
                error = "too many relays: " + std::to_string(n_relays);
                return false;
            }

            ladder_out.relays.resize(n_relays);
            for (uint64_t rl = 0; rl < n_relays; ++rl) {
                // Read relay blocks
                uint64_t n_rblocks = ReadCompactSize(ss);
                if (n_rblocks == 0) {
                    error = "relay " + std::to_string(rl) + " has zero blocks";
                    return false;
                }
                if (n_rblocks > MAX_BLOCKS_PER_RUNG) {
                    error = "relay " + std::to_string(rl) + " has too many blocks: " + std::to_string(n_rblocks);
                    return false;
                }

                ladder_out.relays[rl].blocks.resize(n_rblocks);
                for (uint64_t rb = 0; rb < n_rblocks; ++rb) {
                    if (!DeserializeBlock(ss, ladder_out.relays[rl].blocks[rb], ctx_val, error)) {
                        return false;
                    }
                }

                // Read relay relay_refs (indices of other relays)
                uint64_t n_relay_reqs = ReadCompactSize(ss);
                if (n_relay_reqs > MAX_REQUIRES) {
                    error = "relay " + std::to_string(rl) + " has too many relay_refs";
                    return false;
                }
                ladder_out.relays[rl].relay_refs.resize(n_relay_reqs);
                for (uint64_t rr = 0; rr < n_relay_reqs; ++rr) {
                    uint64_t req_idx = ReadCompactSize(ss);
                    if (req_idx >= rl) {
                        error = "relay " + std::to_string(rl) + " requires forward/self reference: " + std::to_string(req_idx);
                        return false;
                    }
                    ladder_out.relays[rl].relay_refs[rr] = static_cast<uint16_t>(req_idx);
                }
            }

            // Read per-rung relay_refs
            if (!ss.empty()) {
                uint64_t n_rung_reqs = ReadCompactSize(ss);
                if (n_rung_reqs != ladder_out.rungs.size()) {
                    error = "rung relay_refs count mismatch: " + std::to_string(n_rung_reqs) +
                            " vs " + std::to_string(ladder_out.rungs.size()) + " rungs";
                    return false;
                }
                for (uint64_t rq = 0; rq < n_rung_reqs; ++rq) {
                    uint64_t n_reqs = ReadCompactSize(ss);
                    if (n_reqs > MAX_REQUIRES) {
                        error = "rung " + std::to_string(rq) + " has too many relay_refs";
                        return false;
                    }
                    ladder_out.rungs[rq].relay_refs.resize(n_reqs);
                    for (uint64_t ri = 0; ri < n_reqs; ++ri) {
                        uint64_t req_idx = ReadCompactSize(ss);
                        if (req_idx >= ladder_out.relays.size()) {
                            error = "rung " + std::to_string(rq) + " relay_refs invalid relay index: " + std::to_string(req_idx);
                            return false;
                        }
                        ladder_out.rungs[rq].relay_refs[ri] = static_cast<uint16_t>(req_idx);
                    }
                }
            }
        }

        // Consensus: count PREIMAGE and SCRIPT_BODY fields across all blocks in
        // all rungs and relays. Both are user-chosen data channels and share a
        // combined limit to bound total embeddable data per witness.
        for (const auto& rung : ladder_out.rungs) {
            for (const auto& block : rung.blocks) {
                for (const auto& field : block.fields) {
                    if (field.type == RungDataType::PREIMAGE ||
                        field.type == RungDataType::SCRIPT_BODY) {
                        preimage_field_count++;
                    }
                }
            }
        }
        for (const auto& relay : ladder_out.relays) {
            for (const auto& block : relay.blocks) {
                for (const auto& field : block.fields) {
                    if (field.type == RungDataType::PREIMAGE ||
                        field.type == RungDataType::SCRIPT_BODY) {
                        preimage_field_count++;
                    }
                }
            }
        }
        if (preimage_field_count > MAX_PREIMAGE_FIELDS_PER_WITNESS) {
            error = "too many PREIMAGE/SCRIPT_BODY fields: " + std::to_string(preimage_field_count) +
                    " > " + std::to_string(MAX_PREIMAGE_FIELDS_PER_WITNESS);
            return false;
        }

        // Consensus: validate relay chain depth
        if (!ladder_out.relays.empty()) {
            std::vector<size_t> depths(ladder_out.relays.size(), 0);
            for (size_t rl = 0; rl < ladder_out.relays.size(); ++rl) {
                for (uint16_t req : ladder_out.relays[rl].relay_refs) {
                    depths[rl] = std::max(depths[rl], depths[req] + 1);
                }
                if (depths[rl] > MAX_RELAY_DEPTH) {
                    error = "relay chain depth exceeded: " + std::to_string(depths[rl]);
                    return false;
                }
            }
        }

        // Reject trailing bytes — no extra data allowed
        if (!ss.empty()) {
            error = "trailing bytes in ladder witness";
            return false;
        }

    } catch (const std::ios_base::failure& e) {
        error = std::string("deserialization failure: ") + e.what();
        return false;
    }

    return true;
}

std::vector<uint8_t> SerializeLadderWitness(const LadderWitness& ladder,
                                             SerializationContext ctx)
{
    DataStream ss{};
    uint8_t ctx_val = static_cast<uint8_t>(ctx);

    if (ladder.IsWitnessRef()) {
        // Diff witness mode
        WriteCompactSize(ss, 0); // sentinel: n_rungs == 0
        WriteCompactSize(ss, ladder.witness_ref->input_index);
        WriteCompactSize(ss, ladder.witness_ref->diffs.size());
        for (const auto& diff : ladder.witness_ref->diffs) {
            WriteCompactSize(ss, diff.rung_index);
            WriteCompactSize(ss, diff.block_index);
            WriteCompactSize(ss, diff.field_index);
            // Write field: type byte + data
            SerializeField(ss, diff.new_field, true);
        }

        // Write fresh coil (same as normal path, with compact encoding)
        bool is_ref_default_coil = (ladder.coil.coil_type == RungCoilType::UNLOCK &&
                                    ladder.coil.attestation == RungAttestationMode::INLINE &&
                                    ladder.coil.scheme == RungScheme::SCHNORR &&
                                    ladder.coil.address_hash.empty() &&
                                    ladder.coil.rung_destinations.empty());
        if (is_ref_default_coil) {
            ss << COMPACT_COIL_SENTINEL;
            ss << ladder.coil.output_index;
        } else {
            ss << static_cast<uint8_t>(ladder.coil.coil_type);
            ss << static_cast<uint8_t>(ladder.coil.attestation);
            ss << static_cast<uint8_t>(ladder.coil.scheme);
            ss << ladder.coil.output_index; // TX_MLSC: which output this rung governs
            WriteCompactSize(ss, ladder.coil.address_hash.size());
            if (!ladder.coil.address_hash.empty()) {
                ss.write(MakeByteSpan(ladder.coil.address_hash));
            }
            WriteCompactSize(ss, 0); // n_coil_conditions: always 0 (wire format compat)
            // Write per-rung destinations
            WriteCompactSize(ss, ladder.coil.rung_destinations.size());
            for (const auto& [rung_idx, addr_hash] : ladder.coil.rung_destinations) {
                ss << static_cast<uint8_t>(rung_idx & 0xFF);
                ss << static_cast<uint8_t>((rung_idx >> 8) & 0xFF);
                ss.write(MakeByteSpan(addr_hash));
            }
        }

        // No relays section — inherited from source

        std::vector<uint8_t> result(ss.size());
        ss.read(MakeWritableByteSpan(result));
        return result;
    }

    WriteCompactSize(ss, ladder.rungs.size());
    for (const auto& rung : ladder.rungs) {
        WriteCompactSize(ss, rung.blocks.size());
        for (const auto& block : rung.blocks) {
            SerializeBlock(ss, block, ctx_val);
        }
    }

    // Write coil (per-ladder, after all rungs)
    // Compact coil: default (UNLOCK, INLINE, SCHNORR, no address, no destinations) = 0x00 + output_index
    bool is_default_coil = (ladder.coil.coil_type == RungCoilType::UNLOCK &&
                            ladder.coil.attestation == RungAttestationMode::INLINE &&
                            ladder.coil.scheme == RungScheme::SCHNORR &&
                            ladder.coil.address_hash.empty() &&
                            ladder.coil.rung_destinations.empty());
    if (is_default_coil) {
        ss << COMPACT_COIL_SENTINEL;
        ss << ladder.coil.output_index;
    } else {
        ss << static_cast<uint8_t>(ladder.coil.coil_type);
        ss << static_cast<uint8_t>(ladder.coil.attestation);
        ss << static_cast<uint8_t>(ladder.coil.scheme);
        ss << ladder.coil.output_index; // TX_MLSC: which output this rung governs

        // Write coil address
        WriteCompactSize(ss, ladder.coil.address_hash.size());
        if (!ladder.coil.address_hash.empty()) {
            ss.write(MakeByteSpan(ladder.coil.address_hash));
        }

        // Write coil condition count: always 0 (wire format compat)
        WriteCompactSize(ss, 0);

        // Write per-rung destinations
        WriteCompactSize(ss, ladder.coil.rung_destinations.size());
        for (const auto& [rung_idx, addr_hash] : ladder.coil.rung_destinations) {
            ss << static_cast<uint8_t>(rung_idx & 0xFF);
            ss << static_cast<uint8_t>((rung_idx >> 8) & 0xFF);
            ss.write(MakeByteSpan(addr_hash));
        }
    }

    // Write relays (only if any relays or rung relay_refs exist)
    bool has_relay_refs = !ladder.relays.empty();
    if (!has_relay_refs) {
        for (const auto& rung : ladder.rungs) {
            if (!rung.relay_refs.empty()) { has_relay_refs = true; break; }
        }
    }

    if (has_relay_refs) {
        WriteCompactSize(ss, ladder.relays.size());
        for (const auto& relay : ladder.relays) {
            WriteCompactSize(ss, relay.blocks.size());
            for (const auto& block : relay.blocks) {
                SerializeBlock(ss, block, ctx_val);
            }
            // Write relay relay_refs
            WriteCompactSize(ss, relay.relay_refs.size());
            for (uint16_t req : relay.relay_refs) {
                WriteCompactSize(ss, req);
            }
        }

        // Write per-rung relay_refs
        WriteCompactSize(ss, ladder.rungs.size());
        for (const auto& rung : ladder.rungs) {
            WriteCompactSize(ss, rung.relay_refs.size());
            for (uint16_t req : rung.relay_refs) {
                WriteCompactSize(ss, req);
            }
        }
    }

    // Extract serialized bytes
    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

std::vector<uint8_t> SerializeRungBlocks(const Rung& rung, SerializationContext ctx)
{
    DataStream ss{};

    uint8_t ctx_val = static_cast<uint8_t>(ctx);

    WriteCompactSize(ss, rung.blocks.size());
    for (const auto& block : rung.blocks) {
        SerializeBlock(ss, block, ctx_val);
    }

    // Include relay_refs in leaf data (committed via Merkle tree)
    WriteCompactSize(ss, rung.relay_refs.size());
    for (uint16_t ref : rung.relay_refs) {
        WriteCompactSize(ss, ref);
    }

    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

std::vector<uint8_t> SerializeCoilData(const RungCoil& coil)
{
    DataStream ss{};

    ss << static_cast<uint8_t>(coil.coil_type);
    ss << static_cast<uint8_t>(coil.attestation);
    ss << static_cast<uint8_t>(coil.scheme);
    ss << coil.output_index; // Committed in Merkle leaf — binds rung to output

    WriteCompactSize(ss, coil.address_hash.size());
    if (!coil.address_hash.empty()) {
        ss.write(MakeByteSpan(coil.address_hash));
    }

    WriteCompactSize(ss, 0); // n_coil_conditions: always 0 (wire format compat)

    // Per-rung destinations (0 = none, backward compatible)
    WriteCompactSize(ss, coil.rung_destinations.size());
    for (const auto& [rung_idx, addr_hash] : coil.rung_destinations) {
        ss << static_cast<uint8_t>(rung_idx & 0xFF);
        ss << static_cast<uint8_t>((rung_idx >> 8) & 0xFF);
        ss.write(MakeByteSpan(addr_hash));
    }

    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

std::vector<uint8_t> SerializeRelayBlocks(const Relay& relay, SerializationContext ctx)
{
    DataStream ss{};
    uint8_t ctx_val = static_cast<uint8_t>(ctx);

    WriteCompactSize(ss, relay.blocks.size());
    for (const auto& block : relay.blocks) {
        SerializeBlock(ss, block, ctx_val);
    }

    // Include relay_refs in leaf data
    WriteCompactSize(ss, relay.relay_refs.size());
    for (uint16_t ref : relay.relay_refs) {
        WriteCompactSize(ss, ref);
    }

    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

} // namespace rung
