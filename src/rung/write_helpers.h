// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

#ifndef BITCOIN_RUNG_WRITE_HELPERS_H
#define BITCOIN_RUNG_WRITE_HELPERS_H

// ============================================================================
// Byte-level serialisation helpers for libladder sighashes.
//
// These produce EXACTLY the same bytes Bitcoin Core's << operator would
// write for the equivalent types (int32, uint32, uint64, COutPoint,
// CTxOut, CompactSize). Consensus equivalence depends on this.
//
// Library-internal header — not part of the public API. Consumed by
// sighash.cpp and qabi.cpp only.
// ============================================================================

#include <rung/api.h>

#include <hash.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace rung::wire {

inline void WriteBytes(HashWriter& ss, const uint8_t* data, size_t size) {
    ss.write(std::span<const std::byte>{reinterpret_cast<const std::byte*>(data), size});
}

inline void WriteU8(HashWriter& ss, uint8_t v) {
    WriteBytes(ss, &v, 1);
}

inline void WriteU32LE(HashWriter& ss, uint32_t v) {
    uint8_t buf[4] = {
        static_cast<uint8_t>(v),
        static_cast<uint8_t>(v >> 8),
        static_cast<uint8_t>(v >> 16),
        static_cast<uint8_t>(v >> 24),
    };
    WriteBytes(ss, buf, 4);
}

inline void WriteS32LE(HashWriter& ss, int32_t v) {
    WriteU32LE(ss, static_cast<uint32_t>(v));
}

inline void WriteU64LE(HashWriter& ss, uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>(v >> (8 * i));
    WriteBytes(ss, buf, 8);
}

inline void WriteS64LE(HashWriter& ss, int64_t v) {
    WriteU64LE(ss, static_cast<uint64_t>(v));
}

inline void WriteCompactSize(HashWriter& ss, uint64_t n) {
    if (n < 253) {
        WriteU8(ss, static_cast<uint8_t>(n));
    } else if (n <= 0xFFFF) {
        WriteU8(ss, 253);
        uint8_t buf[2] = { static_cast<uint8_t>(n), static_cast<uint8_t>(n >> 8) };
        WriteBytes(ss, buf, 2);
    } else if (n <= 0xFFFFFFFFULL) {
        WriteU8(ss, 254);
        WriteU32LE(ss, static_cast<uint32_t>(n));
    } else {
        WriteU8(ss, 255);
        WriteU64LE(ss, n);
    }
}

inline void WriteLadderOutPoint(HashWriter& ss, const api::LadderOutPoint& op) {
    WriteBytes(ss, op.txid, 32);
    WriteU32LE(ss, op.n);
}

inline void WriteLadderOutput(HashWriter& ss, const api::LadderOutputView& out) {
    WriteS64LE(ss, out.value);
    WriteCompactSize(ss, out.script_pub_key.size);
    WriteBytes(ss, out.script_pub_key.data, out.script_pub_key.size);
}

// Serialise a std::vector<std::vector<uint8_t>> (witness stack) —
// CompactSize(count) followed by, for each element, CompactSize(len) + bytes.
// Matches Bitcoin Core's `ss << witness.stack` output bytes.
inline void WriteLadderWitnessStack(HashWriter& ss, const api::LadderWitnessStack& stack) {
    WriteCompactSize(ss, stack.count);
    for (size_t i = 0; i < stack.count; ++i) {
        WriteCompactSize(ss, stack.elements[i].size);
        WriteBytes(ss, stack.elements[i].data, stack.elements[i].size);
    }
}

}  // namespace rung::wire

#endif  // BITCOIN_RUNG_WRITE_HELPERS_H
