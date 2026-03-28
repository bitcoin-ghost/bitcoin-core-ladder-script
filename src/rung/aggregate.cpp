// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/aggregate.h>

#include <logging.h>

namespace rung {

bool VerifyAggregateSpend(const AggregateProof& proof,
                           uint32_t spend_index,
                           const uint256& pubkey_commit)
{
    // Verify: spend_index is within range and pubkey_commit matches
    if (spend_index >= proof.pubkey_commits.size()) {
        return false;
    }
    if (proof.pubkey_commits[spend_index] != pubkey_commit) {
        return false;
    }
    // IMPORTANT: This function only verifies spend inclusion — the aggregate
    // signature over the entire batch must be verified separately at the block
    // level via proof.aggregate_sig before calling this. Callers must not treat
    // a true return as full signature verification.
    if (!proof.verified) {
        return false; // Aggregate sig must be verified before checking inclusion
    }
    return true;
}

bool VerifyDeferredAttestation(const uint256& template_hash)
{
    // Deferred attestation is not yet supported. Fail closed to prevent
    // any code path from silently accepting unverified attestations.
    LogPrintf("AGGREGATE: Rejected deferred attestation for template %s — not yet supported\n",
              template_hash.ToString());
    return false;
}

} // namespace rung
