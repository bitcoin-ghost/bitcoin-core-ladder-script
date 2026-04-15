// Copyright (c) 2026 The Ladder Script developers
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
#include <rung/serialize.h>
#include <rung/types.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
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

uint256 ComputeSighashQABO(const CTransaction& tx)
{
    // Domain-separated tagged hash — same HashWriter pattern as the rest
    // of the Ladder Script sighash family (HASHER_LADDERSIGHASH,
    // HASHER_LADDERKEYPATH). The `<<` operator routes through the standard
    // Bitcoin Core serializer which encodes integers little-endian on every
    // supported architecture, so the resulting digest is portable.
    //
    // Coverage (see qabi.h for the rationale):
    //   - tx.version, tx.nLockTime
    //   - every vin's (prevout, nSequence) in order
    //   - every vout (value + scriptPubKey) in order
    //   - tx.conditions_root
    //   - tx.qabi_block (length-prefixed, opaque blob)
    //   - every vin's scriptWitness.stack (length-prefixed vector of
    //     length-prefixed elements) — closes byte-level witness malleability
    //     per the Phase 18 hardening
    //   - EXCLUDES tx.aggregated_sig itself (chicken-and-egg: the sig signs
    //     this hash)
    HashWriter ss{HASHER_QABOSIGHASH};

    ss << tx.version;

    for (const auto& in : tx.vin) {
        ss << in.prevout;
        ss << in.nSequence;
    }

    for (const auto& o : tx.vout) {
        ss << o;
    }

    ss << tx.conditions_root;
    ss << tx.qabi_block;

    for (const auto& in : tx.vin) {
        ss << in.scriptWitness.stack;
    }

    ss << tx.nLockTime;

    return ss.GetSHA256();
}

} // namespace rung

#endif // ENABLE_QABIO
