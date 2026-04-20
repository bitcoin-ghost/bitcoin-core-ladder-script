// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

// Ladder Script block family: hash.
// Evaluators + registry function. The top-level dispatcher calls each
// registered evaluator via `rung::LookupBlockEvaluator`.
//
// REVIEWER NOTE — Hash family (0x0203..0x0204)
//   Members: TAGGED_HASH (BIP-340), HASH_GUARDED (raw SHA-256 preimage).
//   Reserved slots 0x0201/0x0202 are never to be reused — documented in
//   types.h. HASH_GUARDED is non-invertible (see IsInvertibleBlockType).
//   Optional for MVP: HASH_GUARDED can be removed (compose via PREIMAGE +
//   HASH256 if needed). TAGGED_HASH is used by PTLC and is recommended.

#include <rung/block_dispatch.h>
#include <rung/block_helpers.h>
#include <rung/evaluator.h>

#include <rung/conditions.h>
#include <rung/pq_verify.h>
#include <rung/qabi.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung_shims.h>

#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>

namespace rung {
using namespace api;

EvalResult EvalTaggedHashBlock(const RungBlock& block)
{
    // BIP-340 tagged hash verification:
    // Requires two HASH256 fields: tag_hash and expected_hash
    // Plus a PREIMAGE field from witness
    auto hashes = FindAllFields(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);

    if (hashes.size() < 2 || !preimage_field) {
        return EvalResult::ERROR;
    }

    // First HASH256 is the tag hash, second is the expected result
    const RungField* tag_hash = hashes[0];
    const RungField* expected_hash = hashes[1];

    if (tag_hash->data.size() != 32 || expected_hash->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute TaggedHash(tag, preimage) = SHA256(SHA256(tag) || SHA256(tag) || preimage)
    // The tag_hash field IS SHA256(tag) already, so we compute:
    // SHA256(tag_hash || tag_hash || preimage)
    unsigned char computed[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(tag_hash->data.data(), 32)
        .Write(tag_hash->data.data(), 32)
        .Write(preimage_field->data.data(), preimage_field->data.size())
        .Finalize(computed);

    if (memcmp(computed, expected_hash->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalHashGuardedBlock(const RungBlock& block)
{
    // Raw SHA256 preimage verification (non-invertible).
    // Conditions: HASH256 (committed hash). Witness: PREIMAGE (raw preimage).
    // SATISFIED when SHA256(preimage) == committed_hash.
    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);

    if (!hash_field || !preimage_field) {
        return EvalResult::ERROR;
    }

    if (hash_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute SHA256(preimage) and compare to committed hash
    unsigned char computed[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(preimage_field->data.data(), preimage_field->data.size())
        .Finalize(computed);

    if (memcmp(computed, hash_field->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

void register_hash_blocks()
{
    RegisterBlock(RungBlockType::TAGGED_HASH, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalTaggedHashBlock(b);
    });
    RegisterBlock(RungBlockType::HASH_GUARDED, [](const RungBlock& b, const BlockDispatchContext&) {
        return EvalHashGuardedBlock(b);
    });
}

} // namespace rung
