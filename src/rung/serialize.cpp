// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// ============================================================================
// REVIEWER BLOCK — Wire-format serialisation for LadderWitness and MLSCProof
// ============================================================================
//
// PURPOSE
//   Serialize/deserialize the per-input witness stream. This is the consensus
//   parser — anything that gets past it is considered structurally valid.
//
// KEY SYMBOLS
//   DeserializeLadderWitness / SerializeLadderWitness
//     Full witness stream (rungs + relays + MLSC proof).
//   DeserializeBlock / SerializeBlock
//     Shared by witness parsing and MLSC-proof revealed_rung parsing.
//     Accepts micro-header (1 byte, table-indexed) or explicit encoding.
//   DeserializeRelay / DeserializeMutationTarget
//     Subcomponent parsers.
//
// LOAD-BEARING INVARIANTS
//   1. Size caps are consensus rules:
//        MAX_RUNGS, MAX_BLOCKS_PER_RUNG, MAX_FIELDS_PER_BLOCK,
//        MAX_LADDER_WITNESS_SIZE, MAX_PREIMAGE_FIELDS_PER_WITNESS,
//        MAX_PREIMAGE_FIELDS_PER_TX, MAX_RELAYS, MAX_RELAY_DEPTH.
//      Changing any changes anti-spam posture.
//   2. Fail-closed on every unknown or malformed input:
//        - unknown block type → reject
//        - unknown data type → reject
//        - non-invertible type with inverted=true → reject
//        - data-embedding type in a block without implicit layout → reject
//        - trailing bytes after the expected end → reject
//        - deprecated blocks (e.g. 0x0201/0x0202 reserved slots) → reject
//   3. PREIMAGE/SCRIPT_BODY caps: max 2 per witness, max 2 per transaction
//      (binding). This closes the data-embedding vector that would otherwise
//      allow unbounded payload via preimage reveal.
//   4. Micro-header slot must match ImplicitLayoutFor(type, context); runtime
//      init check (VerifyImplicitLayoutPairing in types.h) enforces this.
//   5. Diff witness (n_rungs == 0 in witness stream): template reference to
//      another input's conditions with per-field diff overlays. Diffs
//      restricted to witness-side types (PUBKEY/SIGNATURE/PREIMAGE/SCRIPT_BODY/
//      SCHEME) to prevent condition-field smuggling.
//
// OPTIONAL / REMOVABLE
//   - Micro-header encoding is a size optimisation (~2 bytes per block). A
//     minimum-viable BIP could specify explicit-only encoding. If dropped,
//     VerifyImplicitLayoutPairing can also be stripped.
//   - Diff witness mode (template reference) is only needed for the
//     cross-input condition-sharing optimisation. Can be removed if every
//     input carries full conditions.
//
// REFERENCES
//   Wire format: doc/ladder-script/RUNG_TX_SPEC.md
//   Reviewer guide: doc/ladder-script/REVIEW_GUIDE.md (Part 3, serialize section).
// ============================================================================

#include <rung/serialize.h>
#include <rung/conditions.h>

#include <streams.h>
#include <util/strencodings.h>

#include <ios>
#include <set>
#include <tuple>

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
        // MULTISIG / TIMELOCKED_MULTISIG witness: K × (PUBKEY, MERKLE_PROOF,
        // SIGNATURE) triplets, K ≤ MAX_PUBKEYS_PER_MULTISIG. Use the wider cap.
        const bool is_multisig_witness =
            ctx == static_cast<uint8_t>(SerializationContext::WITNESS) &&
            (block_out.type == RungBlockType::MULTISIG ||
             block_out.type == RungBlockType::TIMELOCKED_MULTISIG);
        const size_t fields_cap = is_multisig_witness
                                      ? MAX_MULTISIG_WITNESS_FIELDS
                                      : MAX_FIELDS_PER_BLOCK;
        if (n_fields > fields_cap) {
            error = "block has too many fields: " + std::to_string(n_fields);
            return false;
        }
        // Witness side must carry an integer number of triplets, > 0.
        if (is_multisig_witness && (n_fields == 0 || n_fields % 3 != 0)) {
            error = "MULTISIG witness must be K × (PUBKEY, MERKLE_PROOF, SIGNATURE) triplets, got " +
                    std::to_string(n_fields) + " fields";
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
        // ACCUMULATOR v2 witness: exactly [NUMERIC(element_id), MERKLE_PROOF].
        // The legacy v1 shape (1 root HASH256 + up to 8 sibling HASH256 + 1
        // leaf HASH256, all attacker-chosen) carried up to 9 × 32 = 288 B of
        // attacker payload per spend — fixed at v0.6.
        const bool is_accumulator_witness =
            ctx == static_cast<uint8_t>(SerializationContext::WITNESS) &&
            block_out.type == RungBlockType::ACCUMULATOR;
        if (is_accumulator_witness && n_fields != 2) {
            error = "ACCUMULATOR witness must be [NUMERIC(element_id), MERKLE_PROOF], got " +
                    std::to_string(n_fields) + " fields";
            return false;
        }

        // v0.17 (E-019): close the witness-side embedding channel for
        // conditions-only block types whose evaluators don't validate
        // witness field counts. ~30 block types under types.h:1628's
        // `conditions_only` whitelist (ANCHOR family, RECURSE_*, PLC,
        // EPOCH_GATE/WEIGHT_LIMIT/INPUT_COUNT/OUTPUT_COUNT/
        // RELATIVE_VALUE/OUTPUT_CHECK, CTV, AMOUNT_LOCK) consume only
        // condition-side fields; their evaluators (anchor.cpp,
        // recursion.cpp, governance.cpp, plc.cpp, covenant.cpp) use
        // FindField/FindAllFields and silently ignore extras. Pre-fix
        // the deserialiser allowed up to 16 PUBKEY (≤2048 B) / SIGNATURE
        // (≤50000 B) fields per such block — ≈32 KB attacker-chosen bytes
        // per block, capped only by MAX_LADDER_WITNESS_SIZE = 100 KB per
        // input.
        //
        // Exempt the conditions_only types whose witness IS legitimately
        // explicit and content-bound elsewhere: MULTISIG /
        // TIMELOCKED_MULTISIG (triplet enforcement above), ACCUMULATOR
        // ([NUMERIC, MERKLE_PROOF] enforcement above), P2SH/P2WSH/P2TR_
        // SCRIPT_LEGACY (SCRIPT_BODY hash-bound + inner-script CleanStack
        // semantics consume push data), DATA_RETURN (eval rejects all
        // spends, so witness bytes never land on-chain).
        // E-019/E-022/E-023: pre-loop reject for cases where conditions-only
        // blocks must have a strictly empty witness (no PUBKEY/PREIMAGE
        // either). These are blocks whose evaluator reads zero fields from
        // the witness side AND whose leaf reconstruction does not need a
        // revealed pubkey — i.e. PubkeyCountForBlock == 0 AND no hash-binding.
        // The fine-grained per-field-type check after the loop handles
        // conditions-only blocks that *do* legitimately carry PUBKEY (for
        // leaf reconstruction) or PREIMAGE (for hash-binding).
        const bool recurse_explicit_must_be_empty =
            block_out.type == RungBlockType::RECURSE_MODIFIED ||
            block_out.type == RungBlockType::RECURSE_DECAY;
        if (ctx == static_cast<uint8_t>(SerializationContext::WITNESS)
            && n_fields > 0 && recurse_explicit_must_be_empty) {
            error = "block " + std::string(BlockTypeName(block_out.type)) +
                    " witness must carry no fields, got " + std::to_string(n_fields);
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

            // CONDITIONS context: reject witness-only data types.
            // QABI_SPEND carves out PUBKEY_COMMIT at the 5th field
            // (owner_id = SHA256(FALCON pk)) — it's a 32-byte
            // commitment, not a writable field, and the rule in
            // ParseBlockSpec at the RPC layer explicitly allows it
            // for QABI_SPEND only. Mirror that carve-out here so the
            // on-wire deserialiser accepts the same blocks the RPC
            // layer produces (needed for MLSC proof mutation targets
            // that reveal a QABI_SPEND rung to the QABI_PRIME
            // covenant check).
            if (ctx == static_cast<uint8_t>(SerializationContext::CONDITIONS) &&
                !IsConditionDataType(dtype)) {
                const bool qabi_spend_pubkey_commit_ok =
                    block_out.type == RungBlockType::QABI_SPEND &&
                    dtype == RungDataType::PUBKEY_COMMIT;
                if (!qabi_spend_pubkey_commit_ok) {
                    error = "witness-only data type in conditions: " + DataTypeName(dtype);
                    return false;
                }
            }

            // ACCUMULATOR v2 witness: enforce field shape [NUMERIC, MERKLE_PROOF].
            // ACCUMULATOR conditions are still 1×HASH256 enforced via implicit
            // layout (ACCUMULATOR_CONDITIONS).
            if (is_accumulator_witness) {
                static constexpr RungDataType kAccumWitnessTypes[2] = {
                    RungDataType::NUMERIC,
                    RungDataType::MERKLE_PROOF,
                };
                if (dtype != kAccumWitnessTypes[f]) {
                    error = "ACCUMULATOR witness field " + std::to_string(f) +
                            " type mismatch: got " + DataTypeName(dtype) +
                            ", expected " + DataTypeName(kAccumWitnessTypes[f]);
                    return false;
                }
            }

            // Consensus: for blocks with NO implicit layout (any context), reject
            // high-bandwidth data types that could carry unvalidated payload.
            // This closes the ANCHOR/RECURSE_MODIFIED/RECURSE_DECAY/COMPARE gap
            // where layout-less blocks could carry 16 x DATA(80) = 1280 bytes.
            if (expected.count == 0 && IsDataEmbeddingType(dtype) &&
                !is_accumulator_witness) {
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

            // MULTISIG witness: enforce repeating (PUBKEY, MERKLE_PROOF, SIGNATURE)
            // triplet pattern. This closes the K<N data-embedding bypass — only
            // these three types are legal in the witness, any other type rejects.
            if (is_multisig_witness) {
                static constexpr RungDataType kTripletTypes[3] = {
                    RungDataType::PUBKEY,
                    RungDataType::MERKLE_PROOF,
                    RungDataType::SIGNATURE,
                };
                RungDataType expected_t = kTripletTypes[f % 3];
                if (dtype != expected_t) {
                    error = "MULTISIG witness field " + std::to_string(f) +
                            " type mismatch: got " + DataTypeName(dtype) +
                            ", expected " + DataTypeName(expected_t);
                    return false;
                }
            }
            // MERKLE_PROOF legal only inside MULTISIG/TIMELOCKED_MULTISIG witness
            // (inner pubkey-Merkle proofs) and ACCUMULATOR v2 witness (set-membership
            // proofs). Reject elsewhere so it cannot be a generic embedding vector.
            if (dtype == RungDataType::MERKLE_PROOF &&
                !is_multisig_witness && !is_accumulator_witness) {
                error = "MERKLE_PROOF only allowed in MULTISIG/TIMELOCKED_MULTISIG/"
                        "ACCUMULATOR witness, got block type " +
                        BlockTypeName(block_out.type);
                return false;
            }

            if (!DeserializeField(ss, block_out.fields[f], dtype, 0, error)) {
                return false;
            }
        }
    }

    // E-023: post-loop type whitelist for `conditions_only` block
    // witnesses. Pre-fix the wire-format rejected any non-empty witness for
    // these block types, but several legitimately need the witness to reveal
    // a PUBKEY (for Merkle-leaf reconstruction via `merkle_pub_key`) or a
    // PREIMAGE (for HASH256 hash-binding in ANCHOR_POOL/RESERVE/SEAL etc.).
    // Allow only PUBKEY (≤ PubkeyCountForBlock) and PREIMAGE (≤2 per block;
    // the global per-tx PREIMAGE cap is 2 so a per-block 2 is never
    // amplifying). Reject every other field type. This keeps the embedding
    // ceiling tight — PUBKEY content is bound to the leaf hash, PREIMAGE
    // content is bound to a HASH256 in conditions.
    if (ctx == static_cast<uint8_t>(SerializationContext::WITNESS)
        && !block_out.fields.empty()) {
        const BlockDescriptor* desc = LookupBlockDescriptor(block_out.type);
        const bool exempt =
            block_out.type == RungBlockType::MULTISIG ||
            block_out.type == RungBlockType::TIMELOCKED_MULTISIG ||
            block_out.type == RungBlockType::ACCUMULATOR ||
            block_out.type == RungBlockType::P2SH_LEGACY ||
            block_out.type == RungBlockType::P2WSH_LEGACY ||
            block_out.type == RungBlockType::P2TR_SCRIPT_LEGACY ||
            block_out.type == RungBlockType::DATA_RETURN;
        if (desc && desc->conditions_only && !exempt) {
            size_t pk_count = 0;
            size_t preimage_count = 0;
            for (const auto& field : block_out.fields) {
                if (field.type == RungDataType::PUBKEY) {
                    ++pk_count;
                } else if (field.type == RungDataType::PREIMAGE) {
                    ++preimage_count;
                } else {
                    error = "block " + std::string(BlockTypeName(block_out.type)) +
                            " is conditions-only; witness can only carry PUBKEY/PREIMAGE, got " +
                            DataTypeName(field.type);
                    return false;
                }
            }
            const size_t allowed_pks = PubkeyCountForBlock(block_out.type, block_out);
            if (pk_count > allowed_pks) {
                error = "block " + std::string(BlockTypeName(block_out.type)) +
                        " witness has " + std::to_string(pk_count) +
                        " PUBKEY fields, max " + std::to_string(allowed_pks);
                return false;
            }
            if (preimage_count > 2) {
                error = "block " + std::string(BlockTypeName(block_out.type)) +
                        " witness has " + std::to_string(preimage_count) +
                        " PREIMAGE fields, max 2";
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

            // v0.9 (D-1): track (rung_index, block_index, field_index) triples
            // to reject duplicates. Without this, a spender can pad with N
            // no-op diffs targeting the same field (~6 B each) for ~12 KB of
            // witness inflation. Last-write-wins makes the duplicates silent.
            std::set<std::tuple<uint16_t, uint16_t, uint16_t>> seen_targets;

            for (uint64_t d = 0; d < n_diffs; ++d) {
                uint64_t ri = ReadCompactSize(ss);
                uint64_t bi = ReadCompactSize(ss);
                uint64_t fi = ReadCompactSize(ss);
                if (ri >= MAX_RUNGS || bi >= MAX_BLOCKS_PER_RUNG || fi >= MAX_FIELDS_PER_BLOCK) {
                    error = "diff witness index out of range at diff " + std::to_string(d);
                    return false;
                }
                ref.diffs[d].rung_index = static_cast<uint16_t>(ri);
                ref.diffs[d].block_index = static_cast<uint16_t>(bi);
                ref.diffs[d].field_index = static_cast<uint16_t>(fi);

                auto target = std::make_tuple(ref.diffs[d].rung_index,
                                              ref.diffs[d].block_index,
                                              ref.diffs[d].field_index);
                if (!seen_targets.insert(target).second) {
                    error = "diff witness duplicate target at diff " + std::to_string(d);
                    return false;
                }

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
                // v0.8: address_hash, n_coil_conditions, rung_destinations all
                // dropped from the wire format (E-009/E-010). Coil now ends here.
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
                error = "rung " + std::to_string(r) + " has zero blocks";
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
            // v0.8: address_hash, n_coil_conditions, rung_destinations all
            // dropped from the wire format (E-009/E-010). Coil now ends here.
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
                // v0.10 (F-4): require strict ascending order, no duplicates.
                // Without this, [0,0] / [1,0] / [0,1,0] all eval-equivalent
                // (set semantics) but produce different leaf hashes — funder
                // gets a free embedding channel via the chosen encoding.
                ladder_out.relays[rl].relay_refs.resize(n_relay_reqs);
                int64_t prev = -1;
                for (uint64_t rr = 0; rr < n_relay_reqs; ++rr) {
                    uint64_t req_idx = ReadCompactSize(ss);
                    if (req_idx >= rl) {
                        error = "relay " + std::to_string(rl) + " requires forward/self reference: " + std::to_string(req_idx);
                        return false;
                    }
                    if (static_cast<int64_t>(req_idx) <= prev) {
                        error = "relay " + std::to_string(rl) +
                                " relay_refs not strict ascending at index " + std::to_string(rr);
                        return false;
                    }
                    prev = static_cast<int64_t>(req_idx);
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
                    // v0.10 (F-4): strict ascending unique. The leaf binds
                    // relay_refs positionally (R-1, v0.9), so without a
                    // canonical encoding the funder picks among multiple
                    // distinct on-chain commitments for the same set.
                    ladder_out.rungs[rq].relay_refs.resize(n_reqs);
                    int64_t prev = -1;
                    for (uint64_t ri = 0; ri < n_reqs; ++ri) {
                        uint64_t req_idx = ReadCompactSize(ss);
                        if (req_idx >= ladder_out.relays.size()) {
                            error = "rung " + std::to_string(rq) + " relay_refs invalid relay index: " + std::to_string(req_idx);
                            return false;
                        }
                        if (static_cast<int64_t>(req_idx) <= prev) {
                            error = "rung " + std::to_string(rq) +
                                    " relay_refs not strict ascending at index " + std::to_string(ri);
                            return false;
                        }
                        prev = static_cast<int64_t>(req_idx);
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

        // Consensus (v0.6): bound ACCUMULATOR blocks per rung. Per-tx cap is
        // enforced separately in evaluator.cpp alongside the PREIMAGE per-tx
        // counter. Closes E-001 second half — without this
        // cap a single rung could hold 8 ACCUMULATORs ≈ 1 KB of payload.
        for (const auto& rung : ladder_out.rungs) {
            size_t acc_count = 0;
            for (const auto& block : rung.blocks) {
                if (block.type == RungBlockType::ACCUMULATOR) ++acc_count;
            }
            if (acc_count > MAX_ACCUMULATOR_BLOCKS_PER_RUNG) {
                error = "rung has too many ACCUMULATOR blocks: " +
                        std::to_string(acc_count) + " > " +
                        std::to_string(MAX_ACCUMULATOR_BLOCKS_PER_RUNG);
                return false;
            }
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

        // v0.8: coil is just type + attestation + scheme + output_index
        // (address_hash + rung_destinations dropped — E-009/E-010).
        bool is_ref_default_coil = (ladder.coil.coil_type == RungCoilType::UNLOCK &&
                                    ladder.coil.attestation == RungAttestationMode::INLINE &&
                                    ladder.coil.scheme == RungScheme::SCHNORR);
        if (is_ref_default_coil) {
            ss << COMPACT_COIL_SENTINEL;
            ss << ladder.coil.output_index;
        } else {
            ss << static_cast<uint8_t>(ladder.coil.coil_type);
            ss << static_cast<uint8_t>(ladder.coil.attestation);
            ss << static_cast<uint8_t>(ladder.coil.scheme);
            ss << ladder.coil.output_index;
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

    // v0.8: coil is just type + attestation + scheme + output_index
    // (address_hash + rung_destinations dropped — E-009/E-010).
    // Compact coil sentinel = default (UNLOCK + INLINE + SCHNORR) + output_index = 2 bytes.
    bool is_default_coil = (ladder.coil.coil_type == RungCoilType::UNLOCK &&
                            ladder.coil.attestation == RungAttestationMode::INLINE &&
                            ladder.coil.scheme == RungScheme::SCHNORR);
    if (is_default_coil) {
        ss << COMPACT_COIL_SENTINEL;
        ss << ladder.coil.output_index;
    } else {
        ss << static_cast<uint8_t>(ladder.coil.coil_type);
        ss << static_cast<uint8_t>(ladder.coil.attestation);
        ss << static_cast<uint8_t>(ladder.coil.scheme);
        ss << ladder.coil.output_index;
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
    // v0.8: 4 bytes — type + attestation + scheme + output_index.
    // address_hash + rung_destinations dropped (E-009/E-010).
    DataStream ss{};
    ss << static_cast<uint8_t>(coil.coil_type);
    ss << static_cast<uint8_t>(coil.attestation);
    ss << static_cast<uint8_t>(coil.scheme);
    ss << coil.output_index;
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
