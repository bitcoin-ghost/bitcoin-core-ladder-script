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

    // Entries
    WriteCompactSize(s, block.entries.size());
    for (const auto& e : block.entries) {
        s << e.participant_id;
        s << e.contribution;
        WriteCompactSize(s, e.destination_index);
    }

    // Outputs — reuse CTxOut serialisation (value + scriptPubKey).
    WriteCompactSize(s, block.outputs.size());
    for (const auto& o : block.outputs) {
        s << o;
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

        // Outputs
        uint64_t n_outputs;
        if (!ReadCompactSizeChecked(s, QABI_BLOCK_MAX_HARD, n_outputs, error_out)) {
            return std::nullopt;
        }
        if (n_outputs == 0) {
            error_out = "qabi_block has zero outputs";
            return std::nullopt;
        }
        block.outputs.reserve(n_outputs);
        for (uint64_t i = 0; i < n_outputs; ++i) {
            CTxOut o;
            s >> o;
            block.outputs.push_back(o);
        }

        // No trailing data allowed.
        if (!s.empty()) {
            error_out = "trailing bytes after qabi_block";
            return std::nullopt;
        }

        // Validate destination_index bounds for every entry.
        for (const auto& e : block.entries) {
            if (e.destination_index >= block.outputs.size()) {
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
    // See qabi.h for the full coverage decision. Summary: covers tx intent
    // (version, vin, vout, conditions_root, qabi_block, nLockTime) AND the
    // per-input witness stacks. Excludes only tx.aggregated_sig itself
    // (chicken-and-egg) and tx.creation_proof.
    //
    // Per-input witness coverage added in Phase 18 as defence-in-depth
    // against byte-level witness malleability: a third party cannot modify
    // the witness bytes of any primed input (LadderWitness framing, spend
    // preimage, Merkle proofs, extra stack padding) without invalidating
    // the coordinator's FALCON signature.
    CSHA256 hasher;

    // Version
    uint32_t ver = tx.version;
    hasher.Write(reinterpret_cast<const uint8_t*>(&ver), sizeof(ver));

    // vin (outpoints + sequences, in order)
    for (const auto& in : tx.vin) {
        hasher.Write(reinterpret_cast<const unsigned char*>(in.prevout.hash.begin()), 32);
        uint32_t n = in.prevout.n;
        hasher.Write(reinterpret_cast<const uint8_t*>(&n), sizeof(n));
        uint32_t seq = in.nSequence;
        hasher.Write(reinterpret_cast<const uint8_t*>(&seq), sizeof(seq));
    }

    // vout (value + scriptPubKey, in order)
    for (const auto& o : tx.vout) {
        int64_t v = o.nValue;
        hasher.Write(reinterpret_cast<const uint8_t*>(&v), sizeof(v));
        uint64_t spk_size = o.scriptPubKey.size();
        hasher.Write(reinterpret_cast<const uint8_t*>(&spk_size), sizeof(spk_size));
        if (!o.scriptPubKey.empty()) {
            hasher.Write(o.scriptPubKey.data(), o.scriptPubKey.size());
        }
    }

    // Ladder Script tx-level fields (excluding aggregated_sig)
    hasher.Write(reinterpret_cast<const unsigned char*>(tx.conditions_root.begin()), 32);
    uint64_t qb_size = tx.qabi_block.size();
    hasher.Write(reinterpret_cast<const uint8_t*>(&qb_size), sizeof(qb_size));
    if (!tx.qabi_block.empty()) {
        hasher.Write(tx.qabi_block.data(), tx.qabi_block.size());
    }

    // Per-input witness stacks (closes byte-level witness malleability).
    // For each input, we hash: stack_count || (for each element: length || bytes).
    // Length-prefixing prevents boundary-ambiguity attacks.
    for (const auto& in : tx.vin) {
        uint64_t stack_count = in.scriptWitness.stack.size();
        hasher.Write(reinterpret_cast<const uint8_t*>(&stack_count), sizeof(stack_count));
        for (const auto& element : in.scriptWitness.stack) {
            uint64_t elem_size = element.size();
            hasher.Write(reinterpret_cast<const uint8_t*>(&elem_size), sizeof(elem_size));
            if (!element.empty()) {
                hasher.Write(element.data(), element.size());
            }
        }
    }

    // nLockTime
    uint32_t lt = tx.nLockTime;
    hasher.Write(reinterpret_cast<const uint8_t*>(&lt), sizeof(lt));

    uint256 out;
    hasher.Finalize(out.begin());
    return out;
}

} // namespace rung

#endif // ENABLE_QABIO
