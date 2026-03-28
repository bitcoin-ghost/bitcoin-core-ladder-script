// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/policy.h>
#include <rung/conditions.h>
#include <rung/serialize.h>
#include <rung/types.h>

#include <algorithm>

namespace rung {

bool IsBaseBlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::SIG:
    case RungBlockType::MULTISIG:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::MUSIG_THRESHOLD:
    case RungBlockType::KEY_REF_SIG:
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
    case RungBlockType::TAGGED_HASH:
    // Compound family (collapsed multi-block patterns)
    case RungBlockType::TIMELOCKED_SIG:
    case RungBlockType::HTLC:
    case RungBlockType::HASH_SIG:
    case RungBlockType::PTLC:
    case RungBlockType::CLTV_SIG:
    case RungBlockType::TIMELOCKED_MULTISIG:
    // Legacy family (wrapped Bitcoin transaction types)
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2SH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY:
    case RungBlockType::P2WSH_LEGACY:
    case RungBlockType::P2TR_LEGACY:
    case RungBlockType::P2TR_SCRIPT_LEGACY:
    // Utility family
    case RungBlockType::DATA_RETURN:
        return true;
    default:
        return false;
    }
}

bool IsCovenantBlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::CTV:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::AMOUNT_LOCK:
    case RungBlockType::ANCHOR:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::ANCHOR_POOL:
    case RungBlockType::ANCHOR_RESERVE:
    case RungBlockType::ANCHOR_SEAL:
    case RungBlockType::ANCHOR_ORACLE:
    // Governance family (transaction-level constraints)
    case RungBlockType::EPOCH_GATE:
    case RungBlockType::WEIGHT_LIMIT:
    case RungBlockType::INPUT_COUNT:
    case RungBlockType::OUTPUT_COUNT:
    case RungBlockType::RELATIVE_VALUE:
    case RungBlockType::ACCUMULATOR:
    case RungBlockType::OUTPUT_CHECK:
        return true;
    default:
        return false;
    }
}

bool IsStatefulBlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::RECURSE_SAME:
    case RungBlockType::RECURSE_MODIFIED:
    case RungBlockType::RECURSE_UNTIL:
    case RungBlockType::RECURSE_COUNT:
    case RungBlockType::RECURSE_SPLIT:
    case RungBlockType::RECURSE_DECAY:
    case RungBlockType::HYSTERESIS_FEE:
    case RungBlockType::HYSTERESIS_VALUE:
    case RungBlockType::TIMER_CONTINUOUS:
    case RungBlockType::TIMER_OFF_DELAY:
    case RungBlockType::LATCH_SET:
    case RungBlockType::LATCH_RESET:
    case RungBlockType::COUNTER_DOWN:
    case RungBlockType::COUNTER_PRESET:
    case RungBlockType::COUNTER_UP:
    case RungBlockType::COMPARE:
    case RungBlockType::SEQUENCER:
    case RungBlockType::ONE_SHOT:
    case RungBlockType::RATE_LIMIT:
    case RungBlockType::COSIGN:
        return true;
    default:
        return false;
    }
}

bool IsStandardRungTx(const CTransaction& tx, std::string& reason)
{
    // All structural validation is enforced at consensus in DeserializeLadderWitness
    // (serialize.cpp) and ValidateRungOutputs (evaluator.cpp). Policy only needs to
    // verify the witness deserializes — rejecting garbage early before consensus
    // spends CPU on Merkle proof verification and block evaluation.

    // Note: per-input witness deserialization is NOT checked here.
    // V4 txs can have mixed inputs (standard P2WPKH bootstrap + MLSC ladder).
    // Standard P2WPKH witnesses have 2 stack elements (sig + pubkey), same as
    // ladder witnesses (LadderWitness + MLSCProof), so they cannot be
    // distinguished without access to spent outputs.
    // Full witness validation is done at consensus level in VerifyRungTx,
    // which has access to spent outputs and only validates MLSC inputs.

    // Output validation is consensus (ValidateRungOutputs in VerifyRungTx).
    // Run it here too for early mempool rejection.
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& spk = tx.vout[i].scriptPubKey;
        if (!IsMLSCScript(spk)) {
            reason = "rung-non-mlsc-output";
            return false;
        }
    }

    return true;
}

// IsStandardRungOutput removed — inline conditions (0xC1) are dead.
// Output validation is consensus: ValidateRungOutputs in VerifyRungTx.

} // namespace rung
