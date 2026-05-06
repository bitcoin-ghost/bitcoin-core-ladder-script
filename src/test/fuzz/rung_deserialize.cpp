// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// libFuzzer harness for the v4 RUNG_TX wire-format deserialisers.
//
// Complements `rung_verify.cpp` (which exercises the whole verify
// pipeline) by hammering the parse path directly. Each iteration
// feeds the same buffer into three independent deserialisers so the
// fuzzer can converge on parse-side bugs without first having to
// build a structurally valid transaction wrapper.
//
// Targeted code:
//   - DeserializeLadderWitness: per-input witness stream (rungs +
//     blocks + coil + relays + MLSC proof)
//   - DeserializeMLSCProof: stack[1] proof structure (FULL_LEAVES,
//     MERKLE_PATH, SHARED, mutation targets)
//   - DeserializeRungConditions: scriptPubKey-context conditions
//     (used by P2SH/P2WSH/P2TR_SCRIPT inner-conditions evaluation)
//
// Fuzz invariant: no crash, no UB, no infinite loop. Every parse must
// either return false (with `error` populated) or return true with
// internally-consistent output. Per-block field-count enforcement,
// micro-header decoding, IsConditionDataType gating, IsDataEmbeddingType
// rejection, MAX_LADDER_WITNESS_SIZE / MAX_RUNGS / MAX_BLOCKS_PER_RUNG
// caps, and CompactSize canonicalisation all live in this surface.

#include <rung/conditions.h>
#include <rung/serialize.h>
#include <rung/types.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

FUZZ_TARGET(rung_deserialize)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // Bound a single iteration to avoid pathological inputs from
    // dominating runtime. The caps are large enough to exercise every
    // structural-limit check (MAX_LADDER_WITNESS_SIZE = 100 KB).
    static constexpr size_t MAX_FUZZ_INPUT = 200'000;

    // (1) DeserializeLadderWitness — random byte stream as full witness.
    {
        const size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_FUZZ_INPUT);
        std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(n);
        rung::LadderWitness ladder;
        std::string error;
        // Both contexts exist on the wire (WITNESS for stack[0],
        // CONDITIONS for inner-script-body parsing in legacy
        // wrappers). Fuzz both to cover the IsConditionDataType /
        // IsDataEmbeddingType gating differences.
        (void)rung::DeserializeLadderWitness(bytes, ladder, error,
                                              rung::SerializationContext::WITNESS);
        rung::LadderWitness ladder_c;
        (void)rung::DeserializeLadderWitness(bytes, ladder_c, error,
                                              rung::SerializationContext::CONDITIONS);
    }

    if (fdp.remaining_bytes() == 0) return;

    // (2) DeserializeMLSCProof — random byte stream as proof structure.
    {
        const size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_FUZZ_INPUT);
        std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(n);
        rung::MLSCProof proof;
        std::string error;
        (void)rung::DeserializeMLSCProof(bytes, proof, error);
    }

    if (fdp.remaining_bytes() == 0) return;

    // (3) DeserializeRungConditions — random byte stream as
    // scriptPubKey-context conditions. Span-based, so wrap.
    {
        const size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_FUZZ_INPUT);
        std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(n);
        rung::RungConditions conditions;
        std::string error;
        (void)rung::api::DeserializeRungConditions(
            std::span<const uint8_t>(bytes.data(), bytes.size()),
            conditions, error);
    }
}
