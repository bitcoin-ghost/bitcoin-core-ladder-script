// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// QABIO (BIP-YYYY) reference implementation. This translation unit is
// compiled in only when ENABLE_QABIO is defined. The CMakeLists.txt in
// this directory already excludes qabi.cpp from the source list when
// the option is off, but the #ifdef guard here is belt-and-braces: if
// someone manually compiles qabi.cpp without the flag (e.g. a custom
// build script), it produces an empty object file rather than a
// half-compiled mess.
#ifdef ENABLE_QABIO

#include <rung/qabi.h>
#include <rung/api.h>
#include <rung/serialize.h>
#include <rung/types.h>
#include <rung/write_helpers.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rung {

const HashWriter HASHER_QABOSIGHASH{TaggedHash("QABOSighash")};

/* ---------------- Serialise ---------------- */

std::vector<uint8_t> SerializeQABIBlock(const QABIBlock& block)
{
    DataStream s;

    // Header
    s << block.version;
    s << block.batch_id;

    // Coordinator pubkey — length-prefixed for safety, though size is fixed at
    // QABI_COORDINATOR_PUBKEY_SIZE for FALCON-512. Future versions may use other
    // PQ schemes with different sizes.
    WriteCompactSize(s, block.coordinator_pubkey.size());
    s.write(MakeByteSpan(block.coordinator_pubkey));

    s << block.prime_expiry_height;

    // Outputs conditions root (32 bytes). Pins the spend tx's tx.conditions_root,
    // which in turn structurally pins every destination scriptPubKey
    // (= 0xDF + tx.conditions_root for v4 MLSC outputs).
    s << block.outputs_conditions_root;

    // Entries
    WriteCompactSize(s, block.entries.size());
    for (const auto& e : block.entries) {
        s << e.participant_id;
        s << e.contribution;
        WriteCompactSize(s, e.destination_index);
    }

    // Per-output values (8 bytes each — int64 sats). The destination
    // scriptPubKey is implicit (= 0xDF + outputs_conditions_root) and not
    // carried on the wire.
    WriteCompactSize(s, block.output_values.size());
    for (const int64_t v : block.output_values) {
        s << v;
    }

    std::vector<uint8_t> result(s.size());
    s.read(MakeWritableByteSpan(result));
    return result;
}

/* ---------------- Parse (strict) ---------------- */

static bool ReadCompactSizeChecked(DataStream& s, uint64_t max_value, uint64_t& out, std::string& err)
{
    try {
        out = ReadCompactSize(s);
    } catch (const std::exception& e) {
        err = std::string("read CompactSize failed: ") + e.what();
        return false;
    }
    if (out > max_value) {
        err = "CompactSize exceeds cap";
        return false;
    }
    return true;
}

std::optional<QABIBlock> ParseQABIBlock(const std::vector<uint8_t>& bytes, std::string& error_out)
{
    if (bytes.empty()) {
        error_out = "empty qabi_block";
        return std::nullopt;
    }
    if (bytes.size() > QABI_BLOCK_MAX_HARD) {
        error_out = "qabi_block exceeds hard cap";
        return std::nullopt;
    }

    DataStream s(bytes);
    QABIBlock block;

    try {
        // Version byte — only 0x01 supported for now.
        s >> block.version;
        if (block.version != QABI_BLOCK_VERSION_CURRENT) {
            error_out = "unsupported qabi_block version";
            return std::nullopt;
        }

        // Batch ID
        s >> block.batch_id;

        // Coordinator pubkey — must be exactly FALCON-512 pubkey size for v1.
        uint64_t pk_len;
        if (!ReadCompactSizeChecked(s, QABI_COORDINATOR_PUBKEY_SIZE, pk_len, error_out)) {
            return std::nullopt;
        }
        if (pk_len != QABI_COORDINATOR_PUBKEY_SIZE) {
            error_out = "coordinator_pubkey size != FALCON-512 expected";
            return std::nullopt;
        }
        block.coordinator_pubkey.resize(pk_len);
        s.read(MakeWritableByteSpan(block.coordinator_pubkey));

        // Expiry
        s >> block.prime_expiry_height;

        // Outputs conditions root (32 bytes).
        s >> block.outputs_conditions_root;

        // Entries
        uint64_t n_entries;
        if (!ReadCompactSizeChecked(s, QABI_BLOCK_MAX_HARD, n_entries, error_out)) {
            return std::nullopt;
        }
        if (n_entries == 0) {
            error_out = "qabi_block has zero entries";
            return std::nullopt;
        }
        // v0.12 (audit 8b F6/F7): entries must be in strict ascending order by
        // participant_id with no duplicates. Closes both:
        //   - duplicate participant_id channel (~44 B/duplicate)
        //   - log2(N!) permutation channel from coordinator-chosen order
        block.entries.reserve(n_entries);
        for (uint64_t i = 0; i < n_entries; ++i) {
            QABIEntry e;
            s >> e.participant_id;
            s >> e.contribution;
            if (e.contribution < 0) {
                error_out = "entry contribution is negative";
                return std::nullopt;
            }
            uint64_t dest_idx;
            if (!ReadCompactSizeChecked(s, std::numeric_limits<uint32_t>::max(), dest_idx, error_out)) {
                return std::nullopt;
            }
            e.destination_index = static_cast<uint32_t>(dest_idx);
            if (i > 0) {
                const auto& prev = block.entries.back();
                if (std::memcmp(prev.participant_id.data(),
                                e.participant_id.data(), 32) >= 0) {
                    error_out = "qabi_block entries not strict ascending by participant_id";
                    return std::nullopt;
                }
            }
            block.entries.push_back(e);
        }

        // Per-output values
        uint64_t n_outputs;
        if (!ReadCompactSizeChecked(s, QABI_BLOCK_MAX_HARD, n_outputs, error_out)) {
            return std::nullopt;
        }
        if (n_outputs == 0) {
            error_out = "qabi_block has zero outputs";
            return std::nullopt;
        }
        block.output_values.reserve(n_outputs);
        for (uint64_t i = 0; i < n_outputs; ++i) {
            int64_t v;
            s >> v;
            if (v < 0) {
                error_out = "output value is negative";
                return std::nullopt;
            }
            block.output_values.push_back(v);
        }

        // No trailing data allowed.
        if (!s.empty()) {
            error_out = "trailing bytes after qabi_block";
            return std::nullopt;
        }

        // Validate destination_index bounds for every entry.
        for (const auto& e : block.entries) {
            if (e.destination_index >= block.output_values.size()) {
                error_out = "entry destination_index out of range";
                return std::nullopt;
            }
        }

        // v0.12 (audit 8b F8): batch_id is currently 32 free bytes chosen
        // by the coordinator — a 32 B/batch coordinator-side data channel.
        // The audit recommended canonical derivation
        //   batch_id = SHA256(coordinator_pubkey || outputs_conditions_root || prime_expiry_height)
        // and this file ships ComputeCanonicalBatchId() / ApplyCanonicalBatchId()
        // helpers for wallets and signers. Enforcing it at parse time would
        // break ~15 existing QABI test fixtures that use predictable
        // memset() patterns; tightening to a hard reject is queued for the
        // QABIO v2 release alongside fixture updates. Until then, the
        // channel is documented and the canonical-derivation helpers are
        // available for tooling that wants to opt in early.
    } catch (const std::exception& ex) {
        error_out = std::string("qabi_block parse failed: ") + ex.what();
        return std::nullopt;
    }

    return block;
}

/* ---------------- Root computation ---------------- */

uint256 ComputeQABIRoot(const std::vector<uint8_t>& serialised_block_bytes)
{
    // v1: flat SHA256 of the serialised bytes.
    // Future versions may use a Merkle tree over entries + header.
    CSHA256 hasher;
    hasher.Write(serialised_block_bytes.data(), serialised_block_bytes.size());
    uint256 out;
    hasher.Finalize(out.begin());
    return out;
}

uint256 ComputeQABIRoot(const QABIBlock& block)
{
    return ComputeQABIRoot(SerializeQABIBlock(block));
}

uint256 ComputeCanonicalBatchId(std::span<const uint8_t> coordinator_pubkey,
                                 const uint256& outputs_conditions_root,
                                 uint32_t prime_expiry_height)
{
    // v0.12 (audit 8b F8): batch_id is canonically derived so it can't carry
    // coordinator-side attacker bytes. The derivation binds three already-
    // committed fields: the coordinator's pubkey, the outputs commitment, and
    // the expiry height. Two different qabi_blocks producing the same
    // batch_id would have to collide on all three inputs — every QABI batch
    // commits the same three fields, so derived equality means functional
    // equality.
    HashWriter hw{};
    wire::WriteBytes(hw, coordinator_pubkey.data(), coordinator_pubkey.size());
    wire::WriteBytes(hw, outputs_conditions_root.data(), 32);
    wire::WriteU32LE(hw, prime_expiry_height);
    return hw.GetSHA256();
}

void ApplyCanonicalBatchId(QABIBlock& block)
{
    block.batch_id = ComputeCanonicalBatchId(block.coordinator_pubkey,
                                              block.outputs_conditions_root,
                                              block.prime_expiry_height);
}

/* ---------------- Wallet / builder helpers ---------------- */

uint256 ComputeAuthChainTip(std::span<const uint8_t> auth_seed, uint32_t chain_length)
{
    unsigned char current[CSHA256::OUTPUT_SIZE];
    if (auth_seed.size() != 32) {
        // Spec requires 32-byte seed. Return zero on misuse rather than throwing —
        // caller should verify seed size at a higher layer.
        return uint256::ZERO;
    }
    std::memcpy(current, auth_seed.data(), 32);
    for (uint32_t i = 0; i < chain_length; ++i) {
        unsigned char next[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(current, 32).Finalize(next);
        std::memcpy(current, next, 32);
    }
    uint256 out;
    std::memcpy(out.data(), current, 32);
    return out;
}

bool ComputeAuthChainPreimageAt(std::span<const uint8_t> auth_seed,
                                 uint32_t chain_length,
                                 uint32_t depth,
                                 uint256& preimage_out)
{
    if (auth_seed.size() != 32) return false;
    if (depth > chain_length) return false;

    // depth d ⇒ reveal h_{N-d} ⇒ apply SHA-256 (N-d) times starting from seed.
    unsigned char current[CSHA256::OUTPUT_SIZE];
    std::memcpy(current, auth_seed.data(), 32);
    const uint32_t iterations = chain_length - depth;
    for (uint32_t i = 0; i < iterations; ++i) {
        unsigned char next[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(current, 32).Finalize(next);
        std::memcpy(current, next, 32);
    }
    std::memcpy(preimage_out.data(), current, 32);
    return true;
}

static RungField MakeNumericField(int64_t value)
{
    RungField f;
    f.type = RungDataType::NUMERIC;
    // Store canonical 4-byte LE form — matches what the deserializer produces
    // and what the evaluator's ReadNumeric expects.
    uint32_t v = static_cast<uint32_t>(value);
    f.data.push_back(static_cast<uint8_t>(v & 0xFF));
    f.data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    f.data.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    f.data.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    return f;
}

static RungField MakeHash256Field(const uint256& h)
{
    RungField f;
    f.type = RungDataType::HASH256;
    f.data.assign(h.data(), h.data() + 32);
    return f;
}

static RungField MakePubkeyCommitField(const uint256& h)
{
    RungField f;
    f.type = RungDataType::PUBKEY_COMMIT;
    f.data.assign(h.data(), h.data() + 32);
    return f;
}

static RungField MakePreimageField(std::span<const uint8_t> bytes)
{
    RungField f;
    f.type = RungDataType::PREIMAGE;
    f.data.assign(bytes.begin(), bytes.end());
    return f;
}

RungBlock BuildQABIPrimeBlock(const uint256& new_committed_root,
                               int64_t prime_depth,
                               uint32_t new_committed_expiry,
                               std::span<const uint8_t> prime_preimage)
{
    RungBlock block;
    block.type = RungBlockType::QABI_PRIME;
    block.inverted = false;
    block.fields.push_back(MakeHash256Field(new_committed_root));
    block.fields.push_back(MakeNumericField(prime_depth));
    block.fields.push_back(MakeNumericField(static_cast<int64_t>(new_committed_expiry)));
    block.fields.push_back(MakePreimageField(prime_preimage));
    return block;
}

RungBlock BuildQABISpendBlock(const uint256& auth_tip,
                               const uint256& committed_root,
                               int64_t committed_depth,
                               uint32_t committed_expiry,
                               const uint256& owner_id,
                               std::span<const uint8_t> spend_preimage)
{
    RungBlock block;
    block.type = RungBlockType::QABI_SPEND;
    block.inverted = false;
    block.fields.push_back(MakeHash256Field(auth_tip));
    block.fields.push_back(MakeHash256Field(committed_root));
    block.fields.push_back(MakeNumericField(committed_depth));
    block.fields.push_back(MakeNumericField(static_cast<int64_t>(committed_expiry)));
    block.fields.push_back(MakePubkeyCommitField(owner_id));
    block.fields.push_back(MakePreimageField(spend_preimage));
    return block;
}

std::vector<uint8_t> SerializeSingleBlockWitness(const RungBlock& block)
{
    LadderWitness ladder;
    Rung rung;
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);
    return SerializeLadderWitness(ladder);
}

/* ---------------- SIGHASH_QABO ---------------- */

namespace api {

uint256 ComputeSighashQABO(const LadderTxView& tx)
{
    // Domain-separated tagged hash. Bytes written manually to stay
    // independent of Bitcoin Core's serialize framework — the digest
    // is byte-identical to the prior << operator form for equivalent
    // input data (version, prevouts, outputs, conditions_root,
    // qabi_block, witness stacks, locktime).
    //
    // Coverage (see qabi.h for the rationale):
    //   - tx.version, tx.lock_time
    //   - every input's (prevout, sequence) in order
    //   - every output (value + scriptPubKey) in order
    //   - tx.conditions_root (32 bytes)
    //   - tx.qabi_block (CompactSize-prefixed, opaque blob)
    //   - every input's scriptWitness.stack (CompactSize(count) +
    //     CompactSize(len)+bytes per element) — closes byte-level
    //     witness malleability
    //   - EXCLUDES tx.aggregated_sig itself (chicken-and-egg: the sig
    //     signs this hash)
    HashWriter ss{HASHER_QABOSIGHASH};

    wire::WriteS32LE(ss, tx.version);

    for (size_t i = 0; i < tx.input_count; ++i) {
        wire::WriteLadderOutPoint(ss, tx.inputs[i].prevout);
        wire::WriteU32LE(ss, tx.inputs[i].sequence);
    }

    for (size_t i = 0; i < tx.output_count; ++i) {
        wire::WriteLadderOutput(ss, tx.outputs[i]);
    }

    // conditions_root — 32-byte field on the tx.
    static constexpr uint8_t ZERO_ROOT[32] = {};
    if (tx.conditions_root) {
        wire::WriteBytes(ss, tx.conditions_root, 32);
    } else {
        wire::WriteBytes(ss, ZERO_ROOT, 32);
    }

    // qabi_block — Bitcoin Core serialises std::vector<uint8_t> as
    // CompactSize(len) + bytes, so match that layout exactly.
    wire::WriteCompactSize(ss, tx.qabi_block_size);
    wire::WriteBytes(ss, tx.qabi_block, tx.qabi_block_size);

    // Witness stacks — per-input std::vector<std::vector<uint8_t>>
    // = CompactSize(count) + for each element CompactSize(len) + bytes.
    for (size_t i = 0; i < tx.input_count; ++i) {
        wire::WriteLadderWitnessStack(ss, tx.inputs[i].witness);
    }

    wire::WriteU32LE(ss, tx.lock_time);

    return ss.GetSHA256();
}

}  // namespace api

} // namespace rung

#endif // ENABLE_QABIO
