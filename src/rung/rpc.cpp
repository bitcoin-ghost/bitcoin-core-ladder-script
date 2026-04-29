// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/adaptor.h>
#include <rung/conditions.h>
#include <rung/descriptor.h>
#include <rung/evaluator.h>
#include <rung/policy.h>
#include <rung/pq_verify.h>
#include <rung/qabi.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung/types.h>
#include <rung_shims.h>

#include <core_io.h>
#include <node/context.h>
#include <node/transaction.h>
#include <rpc/server_util.h>
#include <validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <random.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <algorithm>
#include <cstring>
#include <set>

using rung::RungBlockType;
using rung::RungDataType;
using rung::RungConditions;
using rung::LadderWitness;
using rung::RungBlock;
using rung::RungField;
using rung::Rung;
using rung::Relay;
using rung::RungCoil;
using rung::RungCoilType;
using rung::RungAttestationMode;
using rung::RungScheme;
using rung::WitnessReference;
using rung::WitnessDiff;

/** Convert blocks to JSON array (shared between input rungs and coil condition rungs). */
static UniValue BlocksToJSON(const std::vector<RungBlock>& blocks)
{
    UniValue arr(UniValue::VARR);
    for (const auto& block : blocks) {
        UniValue block_obj(UniValue::VOBJ);
        block_obj.pushKV("type", rung::BlockTypeName(block.type));
        uint16_t btype = static_cast<uint16_t>(block.type);
        std::vector<uint8_t> type_bytes = {static_cast<uint8_t>(btype & 0xFF), static_cast<uint8_t>((btype >> 8) & 0xFF)};
        block_obj.pushKV("type_hex", HexStr(type_bytes));
        block_obj.pushKV("inverted", block.inverted);

        UniValue fields_arr(UniValue::VARR);
        for (const auto& field : block.fields) {
            UniValue field_obj(UniValue::VOBJ);
            field_obj.pushKV("type", rung::DataTypeName(field.type));
            field_obj.pushKV("size", static_cast<int>(field.data.size()));
            field_obj.pushKV("hex", HexStr(field.data));
            fields_arr.push_back(field_obj);
        }
        block_obj.pushKV("fields", fields_arr);
        arr.push_back(block_obj);
    }
    return arr;
}

/** Convert a coil to JSON. */
static UniValue CoilToJSON(const RungCoil& coil)
{
    UniValue obj(UniValue::VOBJ);
    switch (coil.coil_type) {
    case RungCoilType::UNLOCK:    obj.pushKV("type", "UNLOCK"); break;
    case RungCoilType::UNLOCK_TO: obj.pushKV("type", "UNLOCK_TO"); break;
    default: obj.pushKV("type", "UNKNOWN"); break;
    }
    switch (coil.attestation) {
    case RungAttestationMode::INLINE: obj.pushKV("attestation", "INLINE"); break;
    default: obj.pushKV("attestation", "UNKNOWN"); break;
    }
    switch (coil.scheme) {
    case RungScheme::SCHNORR:     obj.pushKV("scheme", "SCHNORR"); break;
    case RungScheme::ECDSA:       obj.pushKV("scheme", "ECDSA"); break;
    case RungScheme::FALCON512:   obj.pushKV("scheme", "FALCON512"); break;
    case RungScheme::FALCON1024:  obj.pushKV("scheme", "FALCON1024"); break;
    case RungScheme::DILITHIUM3:  obj.pushKV("scheme", "DILITHIUM3"); break;
    case RungScheme::SPHINCS_SHA: obj.pushKV("scheme", "SPHINCS_SHA"); break;
    default: obj.pushKV("scheme", "UNKNOWN"); break;
    }
    // v0.8: address_hash + rung_destinations dropped from on-wire coil
    // (E-009/E-010). Wallet metadata lives off-chain.
    return obj;
}

/** Convert a LadderWitness to JSON for RPC display.
 *  Returns an object with "rungs" array and "coil" object. */
static UniValue RelayRefsToJSON(const std::vector<uint16_t>& refs)
{
    UniValue arr(UniValue::VARR);
    for (uint16_t ref : refs) {
        arr.push_back(static_cast<int>(ref));
    }
    return arr;
}

static UniValue LadderWitnessToJSON(const LadderWitness& ladder)
{
    UniValue result(UniValue::VOBJ);

    // Diff witness mode
    if (ladder.IsWitnessRef()) {
        const auto& ref = *ladder.witness_ref;
        result.pushKV("witness_ref", true);
        result.pushKV("source_input", static_cast<int>(ref.input_index));

        UniValue diffs_arr(UniValue::VARR);
        for (const auto& diff : ref.diffs) {
            UniValue diff_obj(UniValue::VOBJ);
            diff_obj.pushKV("rung_index", static_cast<int>(diff.rung_index));
            diff_obj.pushKV("block_index", static_cast<int>(diff.block_index));
            diff_obj.pushKV("field_index", static_cast<int>(diff.field_index));

            UniValue field_obj(UniValue::VOBJ);
            field_obj.pushKV("type", rung::DataTypeName(diff.new_field.type));
            field_obj.pushKV("size", static_cast<int>(diff.new_field.data.size()));
            field_obj.pushKV("hex", HexStr(diff.new_field.data));
            diff_obj.pushKV("field", field_obj);

            diffs_arr.push_back(diff_obj);
        }
        result.pushKV("diffs", diffs_arr);
        result.pushKV("coil", CoilToJSON(ladder.coil));
        return result;
    }

    // Normal witness mode
    if (!ladder.relays.empty()) {
        UniValue relays_arr(UniValue::VARR);
        for (size_t i = 0; i < ladder.relays.size(); ++i) {
            UniValue relay_obj(UniValue::VOBJ);
            relay_obj.pushKV("relay_index", static_cast<int>(i));
            relay_obj.pushKV("blocks", BlocksToJSON(ladder.relays[i].blocks));
            if (!ladder.relays[i].relay_refs.empty()) {
                relay_obj.pushKV("relay_refs", RelayRefsToJSON(ladder.relays[i].relay_refs));
            }
            relays_arr.push_back(relay_obj);
        }
        result.pushKV("relays", relays_arr);
    }

    UniValue rungs_arr(UniValue::VARR);
    for (size_t r = 0; r < ladder.rungs.size(); ++r) {
        UniValue rung_obj(UniValue::VOBJ);
        rung_obj.pushKV("rung_index", static_cast<int>(r));
        rung_obj.pushKV("blocks", BlocksToJSON(ladder.rungs[r].blocks));
        if (!ladder.rungs[r].relay_refs.empty()) {
            rung_obj.pushKV("relay_refs", RelayRefsToJSON(ladder.rungs[r].relay_refs));
        }
        rungs_arr.push_back(rung_obj);
    }
    result.pushKV("rungs", rungs_arr);
    result.pushKV("coil", CoilToJSON(ladder.coil));

    return result;
}

/** Parse a block type string to enum. Returns false on unknown type. */
static bool ParseBlockType(const std::string& name, RungBlockType& out)
{
    // Signature family
    if (name == "SIG")              { out = RungBlockType::SIG; return true; }
    if (name == "MULTISIG")         { out = RungBlockType::MULTISIG; return true; }
    if (name == "ADAPTOR_SIG")      { out = RungBlockType::ADAPTOR_SIG; return true; }
    if (name == "MUSIG_THRESHOLD")  { out = RungBlockType::MUSIG_THRESHOLD; return true; }
    if (name == "KEY_REF_SIG")      { out = RungBlockType::KEY_REF_SIG; return true; }
    // Timelock family
    if (name == "CSV")              { out = RungBlockType::CSV; return true; }
    if (name == "CSV_TIME")         { out = RungBlockType::CSV_TIME; return true; }
    if (name == "CLTV")             { out = RungBlockType::CLTV; return true; }
    if (name == "CLTV_TIME")        { out = RungBlockType::CLTV_TIME; return true; }
    // Hash family
    if (name == "TAGGED_HASH")      { out = RungBlockType::TAGGED_HASH; return true; }
    if (name == "HASH_GUARDED")     { out = RungBlockType::HASH_GUARDED; return true; }
    // Compound family
    if (name == "TIMELOCKED_SIG")   { out = RungBlockType::TIMELOCKED_SIG; return true; }
    if (name == "HTLC")             { out = RungBlockType::HTLC; return true; }
    if (name == "HASH_SIG")         { out = RungBlockType::HASH_SIG; return true; }
    if (name == "PTLC")             { out = RungBlockType::PTLC; return true; }
    if (name == "CLTV_SIG")         { out = RungBlockType::CLTV_SIG; return true; }
    if (name == "TIMELOCKED_MULTISIG") { out = RungBlockType::TIMELOCKED_MULTISIG; return true; }
    if (name == "ANCHOR_FEE")       { out = RungBlockType::ANCHOR_FEE; return true; }
    // Covenant family
    if (name == "CTV")              { out = RungBlockType::CTV; return true; }
    if (name == "VAULT_LOCK")       { out = RungBlockType::VAULT_LOCK; return true; }
    if (name == "AMOUNT_LOCK")      { out = RungBlockType::AMOUNT_LOCK; return true; }
    // Anchor family
    if (name == "ANCHOR")           { out = RungBlockType::ANCHOR; return true; }
    if (name == "ANCHOR_CHANNEL")   { out = RungBlockType::ANCHOR_CHANNEL; return true; }
    if (name == "ANCHOR_POOL")      { out = RungBlockType::ANCHOR_POOL; return true; }
    if (name == "ANCHOR_RESERVE")   { out = RungBlockType::ANCHOR_RESERVE; return true; }
    if (name == "ANCHOR_SEAL")      { out = RungBlockType::ANCHOR_SEAL; return true; }
    if (name == "ANCHOR_ORACLE")    { out = RungBlockType::ANCHOR_ORACLE; return true; }
    // Governance family
    if (name == "EPOCH_GATE")       { out = RungBlockType::EPOCH_GATE; return true; }
    if (name == "WEIGHT_LIMIT")     { out = RungBlockType::WEIGHT_LIMIT; return true; }
    if (name == "INPUT_COUNT")      { out = RungBlockType::INPUT_COUNT; return true; }
    if (name == "OUTPUT_COUNT")     { out = RungBlockType::OUTPUT_COUNT; return true; }
    if (name == "RELATIVE_VALUE")   { out = RungBlockType::RELATIVE_VALUE; return true; }
    if (name == "ACCUMULATOR")      { out = RungBlockType::ACCUMULATOR; return true; }
    if (name == "OUTPUT_CHECK")     { out = RungBlockType::OUTPUT_CHECK; return true; }
    // Recursion family
    if (name == "RECURSE_SAME")     { out = RungBlockType::RECURSE_SAME; return true; }
    if (name == "RECURSE_MODIFIED") { out = RungBlockType::RECURSE_MODIFIED; return true; }
    if (name == "RECURSE_UNTIL")    { out = RungBlockType::RECURSE_UNTIL; return true; }
    if (name == "RECURSE_COUNT")    { out = RungBlockType::RECURSE_COUNT; return true; }
    if (name == "RECURSE_SPLIT")    { out = RungBlockType::RECURSE_SPLIT; return true; }
    if (name == "RECURSE_DECAY")    { out = RungBlockType::RECURSE_DECAY; return true; }
    // PLC family
    if (name == "HYSTERESIS_FEE")   { out = RungBlockType::HYSTERESIS_FEE; return true; }
    if (name == "HYSTERESIS_VALUE") { out = RungBlockType::HYSTERESIS_VALUE; return true; }
    if (name == "TIMER_CONTINUOUS") { out = RungBlockType::TIMER_CONTINUOUS; return true; }
    if (name == "TIMER_OFF_DELAY")  { out = RungBlockType::TIMER_OFF_DELAY; return true; }
    if (name == "LATCH_SET")        { out = RungBlockType::LATCH_SET; return true; }
    if (name == "LATCH_RESET")      { out = RungBlockType::LATCH_RESET; return true; }
    if (name == "COUNTER_DOWN")     { out = RungBlockType::COUNTER_DOWN; return true; }
    if (name == "COUNTER_PRESET")   { out = RungBlockType::COUNTER_PRESET; return true; }
    if (name == "COUNTER_UP")       { out = RungBlockType::COUNTER_UP; return true; }
    if (name == "COMPARE")          { out = RungBlockType::COMPARE; return true; }
    if (name == "SEQUENCER")        { out = RungBlockType::SEQUENCER; return true; }
    if (name == "ONE_SHOT")         { out = RungBlockType::ONE_SHOT; return true; }
    if (name == "RATE_LIMIT")       { out = RungBlockType::RATE_LIMIT; return true; }
    if (name == "COSIGN")           { out = RungBlockType::COSIGN; return true; }
    // Legacy family
    if (name == "P2PK_LEGACY")      { out = RungBlockType::P2PK_LEGACY; return true; }
    if (name == "P2PKH_LEGACY")     { out = RungBlockType::P2PKH_LEGACY; return true; }
    if (name == "P2SH_LEGACY")      { out = RungBlockType::P2SH_LEGACY; return true; }
    if (name == "P2WPKH_LEGACY")    { out = RungBlockType::P2WPKH_LEGACY; return true; }
    if (name == "P2WSH_LEGACY")     { out = RungBlockType::P2WSH_LEGACY; return true; }
    if (name == "P2TR_LEGACY")      { out = RungBlockType::P2TR_LEGACY; return true; }
    if (name == "P2TR_SCRIPT_LEGACY") { out = RungBlockType::P2TR_SCRIPT_LEGACY; return true; }
    // Utility family
    if (name == "DATA_RETURN")        { out = RungBlockType::DATA_RETURN; return true; }
    // QABI family
    if (name == "QABI_PRIME")         { out = RungBlockType::QABI_PRIME; return true; }
    if (name == "QABI_SPEND")         { out = RungBlockType::QABI_SPEND; return true; }
    if (name == "PQ_BATCH")           { out = RungBlockType::PQ_BATCH; return true; }
    // Backward compat aliases
    if (name == "HASHLOCK") {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "HASHLOCK is removed. Use HTLC or HASH_SIG instead");
    }
    if (name == "ANCHOR_BOND")      { out = RungBlockType::ANCHOR_SEAL; return true; }
    if (name == "ANCHOR_ESCROW")    { out = RungBlockType::ANCHOR_ORACLE; return true; }
    if (name == "RECURSE_COLLECT")  { out = RungBlockType::RECURSE_COUNT; return true; }
    if (name == "RECURSE_MERGE")    { out = RungBlockType::RECURSE_SPLIT; return true; }
    if (name == "RECURSE_SWEEP")    { out = RungBlockType::RECURSE_DECAY; return true; }
    return false;
}

/** Parse a data type string to enum. Returns false on unknown type. */
static bool ParseDataType(const std::string& name, RungDataType& out)
{
    if (name == "PUBKEY")        { out = RungDataType::PUBKEY; return true; }
    if (name == "PUBKEY_COMMIT") { out = RungDataType::PUBKEY_COMMIT; return true; }
    if (name == "HASH256")       { out = RungDataType::HASH256; return true; }
    if (name == "HASH160")       { out = RungDataType::HASH160; return true; }
    if (name == "PREIMAGE")      { out = RungDataType::PREIMAGE; return true; }
    if (name == "SIGNATURE")     { out = RungDataType::SIGNATURE; return true; }
    if (name == "SPEND_INDEX")   { out = RungDataType::SPEND_INDEX; return true; }
    if (name == "NUMERIC")       { out = RungDataType::NUMERIC; return true; }
    if (name == "SCHEME")        { out = RungDataType::SCHEME; return true; }
    if (name == "SCRIPT_BODY")   { out = RungDataType::SCRIPT_BODY; return true; }
    if (name == "DATA")          { out = RungDataType::DATA; return true; }
    // Backward compat: accept old name LOCKTIME as alias for NUMERIC
    if (name == "LOCKTIME")      { out = RungDataType::NUMERIC; return true; }
    return false;
}

/** Parse a block spec from JSON (shared between input and coil conditions). */
static RungBlock ParseBlockSpec(const UniValue& block_obj, bool conditions_only,
                                 std::vector<std::vector<uint8_t>>* pubkeys_out = nullptr)
{
    RungBlock block;
    std::string type_str = block_obj["type"].get_str();
    if (!ParseBlockType(type_str, block.type)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown block type: " + type_str);
    }
    if (block_obj.exists("inverted") && block_obj["inverted"].get_bool()) {
        if (!rung::IsInvertibleBlockType(block.type)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Block type " + type_str + " cannot be inverted");
        }
        block.inverted = true;
    }
    // MULTISIG v2 / TIMELOCKED_MULTISIG v2: snapshot the pubkeys_out length
    // before per-field collection so we can compute the inner pubkey-Merkle
    // root over only THIS block's pubkeys at the end.
    const size_t multisig_pk_start = (pubkeys_out ? pubkeys_out->size() : 0);
    const UniValue& fields_arr = block_obj["fields"].get_array();
    for (size_t f = 0; f < fields_arr.size(); ++f) {
        const UniValue& field_obj = fields_arr[f];
        RungField field;
        std::string ftype_str = field_obj["type"].get_str();
        if (!ParseDataType(ftype_str, field.type)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown data type: " + ftype_str);
        }
        std::string hex_data = field_obj["hex"].get_str();
        field.data = ParseHex(hex_data);
        std::string reason;
        if (!field.IsValid(reason)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid field: " + reason);
        }
        // Reject raw hash fields in conditions — users must provide source data
        // (PUBKEY or PREIMAGE) and the node computes the hash. Default-deny for
        // HASH256: only whitelisted block types may accept raw hashes.
        if (conditions_only) {
            if (field.type == RungDataType::HASH160) {
                if (block.type == RungBlockType::P2PKH_LEGACY ||
                    block.type == RungBlockType::P2WPKH_LEGACY) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Use PUBKEY instead of HASH160 for P2PKH/P2WPKH; the node computes HASH160 automatically");
                }
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Use PREIMAGE instead of HASH160 for " + type_str + "; the node computes the hash automatically");
            }
            // HASH256: reject for blocks where the hash should be auto-computed
            // from a PREIMAGE field. Allow for blocks where HASH256 is an external
            // commitment in the conditions layout (the user provides it directly).
            // HASH256: blanket rejection with whitelist for block types where
            // the hash is an external commitment (not a preimage hash).
            // All other blocks must use PREIMAGE — the node computes the hash.
            if (field.type == RungDataType::HASH256) {
                if (block.type != RungBlockType::CTV &&
                    block.type != RungBlockType::TAGGED_HASH &&
                    block.type != RungBlockType::ACCUMULATOR &&
                    block.type != RungBlockType::COSIGN &&
                    block.type != RungBlockType::OUTPUT_CHECK &&
                    // QABI_SPEND carries auth_tip and committed_root as external
                    // commitments — the user provides them directly, not as
                    // preimages.
                    block.type != RungBlockType::QABI_SPEND &&
                    // PQ_BATCH carries SHA256(pubkey) as an external commitment
                    // (the pubkey is revealed at spend, not hashed as a preimage).
                    block.type != RungBlockType::PQ_BATCH) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Use PREIMAGE instead of HASH256 for " + type_str +
                        "; the node computes the hash commitment automatically");
                }
            }
            // PUBKEY_COMMIT: normally not a condition field (pubkeys are folded
            // into Merkle leaves via merkle_pub_key). Exception: QABI_SPEND
            // carries owner_id as an explicit 32-byte commitment.
            if (field.type == RungDataType::PUBKEY_COMMIT) {
                if (block.type != RungBlockType::QABI_SPEND) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "PUBKEY_COMMIT is only allowed in QABI_SPEND conditions; "
                        "other blocks fold pubkeys into the Merkle leaf — use PUBKEY instead.");
                }
            }
        }
        // Auto-convert PUBKEY in conditions:
        // P2PKH/P2WPKH legacy: PUBKEY → HASH160 (RIPEMD160(SHA256(pubkey))) — these use HASH160 in conditions
        // MULTISIG/TIMELOCKED_MULTISIG (v2): collected locally into a per-block list,
        //   committed via HASH256(pubkey_root) post-pass — NOT pushed to the
        //   positional pubkeys_out (PubkeyCountForBlock returns 0, so the verifier
        //   would not consume them and leaf hashes would diverge).
        // All other key-consuming blocks: raw pubkey is collected into pubkeys_out
        //   for Merkle leaf computation (not stored in block.fields).
        if (conditions_only && field.type == RungDataType::PUBKEY) {
            if (block.type == RungBlockType::P2PKH_LEGACY ||
                block.type == RungBlockType::P2WPKH_LEGACY) {
                RungField commit_field;
                commit_field.type = RungDataType::HASH160;
                commit_field.data.resize(CHash160::OUTPUT_SIZE);
                CHash160().Write(field.data).Finalize(commit_field.data);
                block.fields.push_back(std::move(commit_field));
            } else if (block.type == RungBlockType::MULTISIG ||
                       block.type == RungBlockType::TIMELOCKED_MULTISIG) {
                // Stash on the block temporarily via the inverted-flag-as-marker
                // trick is fragile — instead, the post-pass below reads PUBKEY
                // fields directly from a side buffer. Use a single ms_pubkeys
                // vector kept in scope for the function (declared later).
                auto pk = field.data;
                if (pk.size() == 32) pk.insert(pk.begin(), 0x02);
                // Push into pubkeys_out so the post-pass can slice [start..end);
                // the post-pass will pop them back off after computing the root.
                if (pubkeys_out) pubkeys_out->push_back(std::move(pk));
            } else if (pubkeys_out) {
                // Normalize x-only (32 bytes) → compressed (33 bytes, even-Y)
                // so the Merkle leaf binds a canonical pubkey encoding regardless
                // of whether the client sent x-only or compressed.
                auto pk = field.data;
                if (pk.size() == 32) {
                    pk.insert(pk.begin(), 0x02);
                }
                pubkeys_out->push_back(std::move(pk));
            }
            continue;
        }
        // Auto-convert PREIMAGE to hash commitment in conditions (node-computed, closes data-stuffing vector).
        // User provides the preimage, node computes the hash — user never writes to the hash field directly.
        // P2SH: PREIMAGE → HASH160 (RIPEMD160(SHA256(preimage)))
        // P2WSH/P2TR_SCRIPT/HASH_SIG/HTLC/TAGGED_HASH/HASH_GUARDED: PREIMAGE → HASH256 (SHA256(preimage))
        if (conditions_only && field.type == RungDataType::PREIMAGE) {
            RungField hash_field;
            if (block.type == RungBlockType::P2SH_LEGACY) {
                hash_field.type = RungDataType::HASH160;
                hash_field.data.resize(CHash160::OUTPUT_SIZE);
                CHash160().Write(field.data).Finalize(hash_field.data);
            } else {
                hash_field.type = RungDataType::HASH256;
                hash_field.data.resize(CSHA256::OUTPUT_SIZE);
                CSHA256().Write(field.data.data(), field.data.size()).Finalize(hash_field.data.data());
            }
            block.fields.push_back(std::move(hash_field));
            continue;
        }
        // Auto-convert SCRIPT_BODY to hash commitment in conditions (same as PREIMAGE, max 80 bytes).
        // Used for P2SH/P2WSH/P2TR_SCRIPT legacy inner conditions.
        if (conditions_only && field.type == RungDataType::SCRIPT_BODY) {
            RungField hash_field;
            if (block.type == RungBlockType::P2SH_LEGACY) {
                hash_field.type = RungDataType::HASH160;
                hash_field.data.resize(CHash160::OUTPUT_SIZE);
                CHash160().Write(field.data).Finalize(hash_field.data);
            } else {
                hash_field.type = RungDataType::HASH256;
                hash_field.data.resize(CSHA256::OUTPUT_SIZE);
                CSHA256().Write(field.data.data(), field.data.size()).Finalize(hash_field.data.data());
            }
            block.fields.push_back(std::move(hash_field));
            continue;
        }
        if (conditions_only && !rung::IsConditionDataType(field.type)) {
            // QABI_SPEND bypass: its conditions layout legitimately carries
            // PUBKEY_COMMIT as an explicit owner identity commitment. The
            // consensus deserialiser accepts it via the implicit layout path
            // (QABI_SPEND_CONDITIONS), so we accept it here too.
            const bool qabi_spend_pubkey_commit =
                block.type == RungBlockType::QABI_SPEND &&
                field.type == RungDataType::PUBKEY_COMMIT;
            if (!qabi_spend_pubkey_commit) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Data type " + ftype_str + " not allowed in conditions (witness-only)");
            }
        }
        block.fields.push_back(std::move(field));
    }

    // Auto-add default SCHEME for blocks whose implicit CONDITIONS layout
    // includes SCHEME, when the user didn't provide one explicitly.
    // With merkle_pub_key, PUBKEY is intercepted — SCHEME may be the only
    // condition field remaining. Ensure it's present and in the right position.
    if (conditions_only) {
        bool has_scheme = false;
        for (const auto& f : block.fields) {
            if (f.type == RungDataType::SCHEME) { has_scheme = true; break; }
        }
        if (!has_scheme) {
            const auto& layout = GetImplicitLayout(block.type,
                static_cast<uint8_t>(rung::SerializationContext::CONDITIONS));
            // Find where SCHEME appears in the layout and insert there
            for (uint8_t i = 0; i < layout.count; ++i) {
                if (layout.fields[i].type == RungDataType::SCHEME) {
                    size_t insert_pos = std::min(static_cast<size_t>(i), block.fields.size());
                    block.fields.insert(block.fields.begin() + insert_pos,
                        RungField{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
                    break;
                }
            }
        }
    }

    // MULTISIG v2 / TIMELOCKED_MULTISIG v2: compute the inner pubkey-Merkle
    // root over the pubkeys collected for this block, append HASH256(root) as
    // the final conditions field, then POP those pubkeys back off pubkeys_out.
    // The outer leaf hash MUST NOT fold them in (PubkeyCountForBlock returns
    // 0); leaving them in pubkeys_out would cause a fund/spend leaf mismatch
    // because the verifier's ExtractBlockPubkeys would skip MULTISIG entirely.
    // The spender supplies the N pubkeys explicitly via signrungtx's
    // 'pubkeys' field so SignMultiKey can rebuild proofs.
    if (conditions_only && pubkeys_out &&
        (block.type == RungBlockType::MULTISIG ||
         block.type == RungBlockType::TIMELOCKED_MULTISIG)) {
        const size_t pk_end = pubkeys_out->size();
        if (pk_end <= multisig_pk_start) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                type_str + " requires at least one PUBKEY field");
        }
        const size_t n_pks = pk_end - multisig_pk_start;
        if (n_pks > rung::MAX_PUBKEYS_PER_MULTISIG) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                type_str + " has " + std::to_string(n_pks) +
                " pubkeys, max " + std::to_string(rung::MAX_PUBKEYS_PER_MULTISIG));
        }
        std::vector<std::vector<uint8_t>> ms_pubkeys(
            pubkeys_out->begin() + multisig_pk_start, pubkeys_out->end());
        uint256 pubkey_root = rung::BuildPubkeyMerkleRoot(ms_pubkeys);
        RungField root_field{RungDataType::HASH256,
            std::vector<uint8_t>(pubkey_root.begin(), pubkey_root.end())};
        block.fields.push_back(std::move(root_field));
        // Stash on the block as a non-wire side hint so descriptor printers
        // and wallet signer-derive paths can recover the N-pubkey list.
        block.merkle_pubkeys = ms_pubkeys;
        // Remove the staged MULTISIG pubkeys from the positional list.
        pubkeys_out->resize(multisig_pk_start);
    }

    // Fund-time strict layout enforcement. Mirrors the spend-time
    // DeserializeBlock check at serialize.cpp:324-331. Without this, a
    // client can commit a conditions_root where the target rung has a
    // non-canonical field order (e.g. [NUMERIC, SCHEME] instead of
    // [SCHEME, NUMERIC] for CLTV_SIG) — the fund succeeds silently but
    // every spend attempt fails "field type mismatch" at script-verify.
    // Catch mis-ordered conditions at fund time instead.
    if (conditions_only) {
        const auto& expected = GetImplicitLayout(block.type,
            static_cast<uint8_t>(rung::SerializationContext::CONDITIONS));
        if (expected.count > 0) {
            if (block.fields.size() != expected.count) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Block " + type_str + " field count mismatch: got " +
                    std::to_string(block.fields.size()) + ", expected " +
                    std::to_string(expected.count) +
                    " per implicit layout for " + type_str + "_CONDITIONS");
            }
            for (uint8_t i = 0; i < expected.count; ++i) {
                if (block.fields[i].type != expected.fields[i].type) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Block " + type_str + " field " + std::to_string(i) +
                        " type mismatch: got " + DataTypeName(block.fields[i].type) +
                        ", expected " + DataTypeName(expected.fields[i].type) +
                        " per implicit layout");
                }
            }
        }
    }

    return block;
}

/** Parse coil from JSON. Defaults to UNLOCK/INLINE/SCHNORR. */
static RungCoil ParseCoil(const UniValue& obj)
{
    RungCoil coil;
    if (obj.isNull() || !obj.isObject()) return coil;

    if (obj.exists("type")) {
        std::string t = obj["type"].get_str();
        if (t == "UNLOCK")    coil.coil_type = RungCoilType::UNLOCK;
        else if (t == "UNLOCK_TO") coil.coil_type = RungCoilType::UNLOCK_TO;
    }
    if (obj.exists("scheme")) {
        std::string s = obj["scheme"].get_str();
        if (s == "SCHNORR") coil.scheme = RungScheme::SCHNORR;
        else if (s == "ECDSA") coil.scheme = RungScheme::ECDSA;
        else if (s == "FALCON512") coil.scheme = RungScheme::FALCON512;
        else if (s == "FALCON1024") coil.scheme = RungScheme::FALCON1024;
        else if (s == "DILITHIUM3") coil.scheme = RungScheme::DILITHIUM3;
        else if (s == "SPHINCS_SHA") coil.scheme = RungScheme::SPHINCS_SHA;
    }
    // v0.8: 'address' and 'rung_destinations' are no longer accepted. They were
    // unbound spender data channels (E-009/E-010). Wallets that need destination
    // metadata must track it locally.
    if (obj.exists("address")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "coil.address was removed in v0.8 (E-009). Track destination metadata off-chain.");
    }
    if (obj.exists("rung_destinations")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "coil.rung_destinations was removed in v0.8 (E-010). Track per-rung destinations off-chain.");
    }
    if (obj.exists("conditions") && !obj["conditions"].get_array().empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Coil conditions are reserved and not currently active. "
            "Use covenant/recursion block types (CTV, RECURSE_*, VAULT_LOCK, AMOUNT_LOCK) on rungs instead.");
    }
    return coil;
}

static RPCHelpMan decoderung()
{
    return RPCHelpMan{
        "decoderung",
        "Decode a ladder witness from hex and display its typed structure.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The ladder witness in hex."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "num_rungs", "Number of rungs (0 for diff witness)"},
            {RPCResult::Type::BOOL, "witness_ref", /*optional=*/ true, "True if this is a diff witness reference"},
            {RPCResult::Type::NUM, "source_input", /*optional=*/ true, "Source input index for diff witness"},
            {RPCResult::Type::ARR, "diffs", /*optional=*/ true, "Field-level diffs applied to source witness",
                {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "rung_index", "Target rung index"},
                        {RPCResult::Type::NUM, "block_index", "Target block index"},
                        {RPCResult::Type::NUM, "field_index", "Target field index"},
                        {RPCResult::Type::OBJ, "field", "Replacement field data",
                            {
                                {RPCResult::Type::STR, "type", "Data type name"},
                                {RPCResult::Type::NUM, "size", "Field data size"},
                                {RPCResult::Type::STR_HEX, "hex", "Field data hex"},
                            }},
                    }},
                }},
            {RPCResult::Type::ARR, "rungs", /*optional=*/ true, "The rungs (normal witness only)",
                {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "rung_index", "Rung index"},
                        {RPCResult::Type::ARR, "blocks", "Function blocks in this rung",
                            {
                                {RPCResult::Type::OBJ, "", "", {
                                    {RPCResult::Type::STR, "type", "Block type name"},
                                    {RPCResult::Type::STR_HEX, "type_hex", "Block type (2 bytes LE)"},
                                    {RPCResult::Type::BOOL, "inverted", "Whether block is inverted"},
                                    {RPCResult::Type::ARR, "fields", "Typed fields",
                                        {
                                            {RPCResult::Type::OBJ, "", "", {
                                                {RPCResult::Type::STR, "type", "Data type name"},
                                                {RPCResult::Type::NUM, "size", "Field data size"},
                                                {RPCResult::Type::STR_HEX, "hex", "Field data hex"},
                                            }},
                                        }},
                                }},
                            }},
                    }},
                }},
            {RPCResult::Type::OBJ, "coil", "Coil metadata (per-output)",
                {
                    {RPCResult::Type::STR, "type", "Coil type"},
                    {RPCResult::Type::STR, "attestation", "Attestation mode"},
                    {RPCResult::Type::STR, "scheme", "Signature scheme"},
                }},
        }},
        RPCExamples{
            HelpExampleCli("decoderung", "010101012103abcdef...0240deadbeef...")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string hex_str = self.Arg<std::string>("hex");
    auto witness_bytes = ParseHex(hex_str);
    if (witness_bytes.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hex string");
    }

    LadderWitness ladder;
    std::string error;
    if (!rung::DeserializeLadderWitness(witness_bytes, ladder, error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode ladder witness: " + error);
    }

    UniValue result = LadderWitnessToJSON(ladder);
    result.pushKV("num_rungs", static_cast<int>(ladder.rungs.size()));
    return result;
},
    };
}

static RPCHelpMan createrung()
{
    return RPCHelpMan{
        "createrung",
        "Create a ladder witness from a JSON specification.\n"
        "Returns the serialized ladder witness as hex.\n",
        {
            {"rungs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of rung specifications",
                {
                    {"rung", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A single rung",
                        {
                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of block specifications",
                                {
                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A function block",
                                        {
                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                            {"inverted", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Invert evaluation result (default false)"},
                                            {"fields", RPCArg::Type::ARR, RPCArg::Optional::NO, "Typed fields for this block",
                                                {
                                                    {"field", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A typed field",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Data type"},
                                                            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Field data in hex"},
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            {"coil", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Coil metadata (default UNLOCK/SCHNORR).",
                {
                    {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "UNLOCK or UNLOCK_TO"},
                    {"scheme", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SCHNORR or ECDSA"},
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The serialized ladder witness hex"},
            {RPCResult::Type::NUM, "size", "Size in bytes"},
        }},
        RPCExamples{
            HelpExampleCli("createrung", "'[{\"blocks\":[{\"type\":\"SIG\",\"fields\":[{\"type\":\"PUBKEY\",\"hex\":\"03...\"},{\"type\":\"SIGNATURE\",\"hex\":\"...\"}]}]}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& rungs_arr = request.params[0].get_array();
    LadderWitness ladder;

    for (size_t r = 0; r < rungs_arr.size(); ++r) {
        const UniValue& rung_obj = rungs_arr[r];
        Rung rung;

        const UniValue& blocks_arr = rung_obj["blocks"].get_array();
        for (size_t b = 0; b < blocks_arr.size(); ++b) {
            rung.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/false));
        }

        ladder.rungs.push_back(std::move(rung));
    }

    // Parse optional coil (per-ladder, not per-rung)
    if (!request.params[1].isNull()) {
        ladder.coil = ParseCoil(request.params[1]);
    }

    auto serialized = rung::SerializeLadderWitness(ladder);
    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", HexStr(serialized));
    result.pushKV("size", static_cast<int>(serialized.size()));
    return result;
},
    };
}

/** serialiseconditions: serialise a LadderWitness in CONDITIONS context.
 *
 *  Returns the bytes that would be committed at fund time for use as a
 *  P2SH_LEGACY / P2WSH_LEGACY / P2TR_SCRIPT_LEGACY inner script body.
 *  EvalInnerConditions deserialises with SerializationContext::CONDITIONS,
 *  so the engine needs a way to produce that exact byte sequence when
 *  building legacy-script-hash wrappers. createrung uses WITNESS context
 *  (which emits PUBKEY/SIGNATURE fields), which doesn't match — hence this
 *  dedicated RPC. Future work item #12, 2026-04-24.
 */
static RPCHelpMan serialiseconditions()
{
    return RPCHelpMan{
        "serialiseconditions",
        "Serialise a LadderWitness in CONDITIONS context.\n"
        "Returns the bytes suitable as a P2SH/P2WSH/P2TR_SCRIPT inner-script preimage.\n"
        "Fields are parsed with conditions_only=true (PUBKEYs fold into merkle_pub_key,\n"
        "PREIMAGE/SCRIPT_BODY auto-hash to HASH256/HASH160, SCHEME is auto-inserted).\n",
        {
            {"rungs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of rung specifications",
                {
                    {"rung", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A single rung",
                        {
                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of block specifications",
                                {
                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A function block",
                                        {
                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                            {"inverted", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Invert evaluation result"},
                                            {"fields", RPCArg::Type::ARR, RPCArg::Optional::NO, "Typed fields for this block",
                                                {
                                                    {"field", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A typed field",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Data type"},
                                                            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Field data in hex"},
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The serialised conditions bytes as hex (suitable for script_body/preimage in P2SH/P2WSH/P2TR_SCRIPT witness)"},
            {RPCResult::Type::NUM, "size", "Size in bytes"},
        }},
        RPCExamples{
            HelpExampleCli("serialiseconditions", "'[{\"blocks\":[{\"type\":\"SIG\",\"fields\":[{\"type\":\"PUBKEY\",\"hex\":\"03...\"}]}]}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& rungs_arr = request.params[0].get_array();
    LadderWitness ladder;

    for (size_t r = 0; r < rungs_arr.size(); ++r) {
        const UniValue& rung_obj = rungs_arr[r];
        Rung rung;
        const UniValue& blocks_arr = rung_obj["blocks"].get_array();
        for (size_t b = 0; b < blocks_arr.size(); ++b) {
            rung.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/true));
        }
        ladder.rungs.push_back(std::move(rung));
    }

    auto serialized = rung::SerializeLadderWitness(ladder, rung::SerializationContext::CONDITIONS);
    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", HexStr(serialized));
    result.pushKV("size", static_cast<int>(serialized.size()));
    return result;
},
    };
}

static RPCHelpMan validateladder()
{
    return RPCHelpMan{
        "validateladder",
        "Validate a raw v4 RUNG_TX transaction's ladder witnesses.\n"
        "Checks that all input witnesses are valid ladder witnesses\n"
        "and pass policy rules.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw transaction hex."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", "Whether all ladder witnesses are valid"},
            {RPCResult::Type::STR, "error", /*optional=*/ true, "Error message if invalid"},
            {RPCResult::Type::NUM, "version", "Transaction version"},
            {RPCResult::Type::NUM, "num_inputs", "Number of inputs"},
            {RPCResult::Type::ARR, "inputs", "Per-input validation results",
                {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "index", "Input index"},
                        {RPCResult::Type::BOOL, "valid", "Whether this input's ladder witness is valid"},
                        {RPCResult::Type::STR, "error", /*optional=*/ true, "Error if invalid"},
                        {RPCResult::Type::NUM, "num_rungs", /*optional=*/ true, "Number of rungs"},
                    }},
                }},
        }},
        RPCExamples{
            HelpExampleCli("validateladder", "0300000001...")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string hex_str = self.Arg<std::string>("hex");
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex_str)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode transaction");
    }

    CTransaction tx(mtx);

    UniValue result(UniValue::VOBJ);
    result.pushKV("version", static_cast<int>(tx.version));
    result.pushKV("num_inputs", static_cast<int>(tx.vin.size()));

    if (tx.version != CTransaction::RUNG_TX_VERSION) {
        result.pushKV("valid", false);
        result.pushKV("error", "Not a v4 RUNG_TX (version=" + std::to_string(tx.version) + ")");
        result.pushKV("inputs", UniValue(UniValue::VARR));
        return result;
    }

    // Check policy
    std::string policy_reason;
    bool policy_ok = rung::IsStandardRungTx(tx, policy_reason);

    UniValue inputs_arr(UniValue::VARR);
    bool all_valid = true;

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        UniValue input_obj(UniValue::VOBJ);
        input_obj.pushKV("index", static_cast<int>(i));

        const auto& witness = tx.vin[i].scriptWitness;
        if (witness.stack.empty()) {
            input_obj.pushKV("valid", false);
            input_obj.pushKV("error", "missing witness");
            all_valid = false;
        } else {
            LadderWitness ladder;
            std::string error;
            if (!rung::DeserializeLadderWitness(witness.stack[0], ladder, error)) {
                input_obj.pushKV("valid", false);
                input_obj.pushKV("error", error);
                all_valid = false;
            } else {
                input_obj.pushKV("valid", true);
                input_obj.pushKV("num_rungs", static_cast<int>(ladder.rungs.size()));
            }
        }
        inputs_arr.push_back(input_obj);
    }

    result.pushKV("valid", all_valid && policy_ok);
    if (!policy_ok) {
        result.pushKV("error", policy_reason);
    }
    result.pushKV("inputs", inputs_arr);
    return result;
},
    };
}

/** Helper: parse relay_refs from a JSON array of integers. */
static std::vector<uint16_t> ParseRelayRefs(const UniValue& arr)
{
    std::vector<uint16_t> refs;
    for (size_t i = 0; i < arr.size(); ++i) {
        refs.push_back(static_cast<uint16_t>(arr[i].getInt<int>()));
    }
    return refs;
}

/** Helper: parse a conditions JSON spec into a RungConditions struct.
 *  rungs_arr is the array of rung specs; coil_obj is the optional coil spec (per-output).
 *  relays_arr is the optional relays array (top-level, shared across outputs).
 *  rung_output_indices_out collects per-rung output_index values (0xFF = unspecified,
 *  caller should fall back to spent_vout). Used at spend time to rebuild Merkle leaves
 *  with the same coil.output_index that was committed at fund time. */
static RungConditions ParseConditionsSpec(const UniValue& rungs_arr,
                                          const UniValue& coil_obj,
                                          const UniValue& relays_arr,
                                          std::vector<std::vector<std::vector<uint8_t>>>& rung_pubkeys_out,
                                          std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys_out,
                                          std::vector<uint8_t>* rung_output_indices_out = nullptr)
{
    RungConditions conditions;

    if (!relays_arr.isNull() && relays_arr.isArray()) {
        for (size_t i = 0; i < relays_arr.size(); ++i) {
            const UniValue& relay_obj = relays_arr[i];
            Relay relay;

            std::vector<std::vector<uint8_t>> relay_pks;
            const UniValue& blocks_arr = relay_obj["blocks"].get_array();
            for (size_t b = 0; b < blocks_arr.size(); ++b) {
                relay.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/true, &relay_pks));
            }

            if (relay_obj.exists("relay_refs")) {
                relay.relay_refs = ParseRelayRefs(relay_obj["relay_refs"].get_array());
            }

            conditions.relays.push_back(std::move(relay));
            relay_pubkeys_out.push_back(std::move(relay_pks));
        }
    }

    for (size_t r = 0; r < rungs_arr.size(); ++r) {
        const UniValue& rung_obj = rungs_arr[r];
        Rung rung;

        // Backward compat: "compact_type": "COMPACT_SIG" now builds a normal SIG block
        if (rung_obj.exists("compact_type")) {
            std::string ctype = rung_obj["compact_type"].get_str();
            if (ctype != "COMPACT_SIG") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown compact_type: " + ctype);
            }
            // Accept both "pubkey" (preferred) and "pubkey_commit" (backward compat)
            std::string pubkey_field = rung_obj.exists("pubkey") ? "pubkey" : "pubkey_commit";
            auto pubkey_bytes = ParseHex(rung_obj[pubkey_field].get_str());
            size_t pk_size = pubkey_bytes.size();
            if (pk_size == 33) {
                if (pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "33-byte pubkey must be compressed secp256k1 (prefix 0x02 or 0x03)");
                }
            } else if (pk_size != 32 && pk_size != 897 && pk_size != 1793 &&
                       pk_size != 1952 && pk_size < 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Invalid pubkey size " + std::to_string(pk_size) +
                    ". Expected: 32 (x-only), 33 (compressed), 897 (FALCON512), "
                    "1793 (FALCON1024), 1952 (DILITHIUM3), or 32+ (SPHINCS+)");
            }

            // Collect raw pubkey into per-rung pubkey list for Merkle leaf computation
            std::vector<std::vector<uint8_t>> rung_pks;
            rung_pks.push_back(pubkey_bytes);

            RungBlock sig_block;
            sig_block.type = RungBlockType::SIG;

            // SCHEME field (optional)
            if (rung_obj.exists("scheme")) {
                std::string scheme_str = rung_obj["scheme"].get_str();
                RungScheme scheme;
                if (scheme_str == "SCHNORR") scheme = RungScheme::SCHNORR;
                else if (scheme_str == "ECDSA") scheme = RungScheme::ECDSA;
                else if (scheme_str == "FALCON512") scheme = RungScheme::FALCON512;
                else if (scheme_str == "FALCON1024") scheme = RungScheme::FALCON1024;
                else if (scheme_str == "DILITHIUM3") scheme = RungScheme::DILITHIUM3;
                else if (scheme_str == "SPHINCS_SHA") scheme = RungScheme::SPHINCS_SHA;
                else throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scheme: " + scheme_str);
                RungField scheme_field;
                scheme_field.type = RungDataType::SCHEME;
                scheme_field.data = {static_cast<uint8_t>(scheme)};
                sig_block.fields.push_back(std::move(scheme_field));
            }

            rung.blocks.push_back(std::move(sig_block));
            conditions.rungs.push_back(std::move(rung));
            rung_pubkeys_out.push_back(std::move(rung_pks));
            if (rung_output_indices_out) {
                uint8_t oi = 0xFF;
                if (rung_obj.exists("output_index")) {
                    oi = static_cast<uint8_t>(rung_obj["output_index"].getInt<int>());
                }
                rung_output_indices_out->push_back(oi);
            }
            continue;
        }

        std::vector<std::vector<uint8_t>> rung_pks;
        const UniValue& blocks_arr = rung_obj["blocks"].get_array();
        for (size_t b = 0; b < blocks_arr.size(); ++b) {
            rung.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/true, &rung_pks));
        }

        if (rung_obj.exists("relay_refs")) {
            rung.relay_refs = ParseRelayRefs(rung_obj["relay_refs"].get_array());
        }

        conditions.rungs.push_back(std::move(rung));
        rung_pubkeys_out.push_back(std::move(rung_pks));
        if (rung_output_indices_out) {
            uint8_t oi = 0xFF;
            if (rung_obj.exists("output_index")) {
                oi = static_cast<uint8_t>(rung_obj["output_index"].getInt<int>());
            }
            rung_output_indices_out->push_back(oi);
        }
    }

    // Parse coil at output level (not per-rung)
    if (!coil_obj.isNull() && coil_obj.isObject()) {
        conditions.coil = ParseCoil(coil_obj);
    }

    return conditions;
}

/** Determine if a PQ scheme string is valid. Returns the scheme enum if so. */
static bool ParsePQScheme(const std::string& s, RungScheme& out)
{
    if (s == "FALCON512")  { out = RungScheme::FALCON512; return true; }
    if (s == "FALCON1024") { out = RungScheme::FALCON1024; return true; }
    if (s == "DILITHIUM3") { out = RungScheme::DILITHIUM3; return true; }
    if (s == "SPHINCS_SHA") { out = RungScheme::SPHINCS_SHA; return true; }
    return false;
}

/** Push an externally-supplied pubkey into a spend block, normalizing
 *  x-only (32-byte) keys to compressed (33-byte, even-Y) so the spend-time
 *  leaf hash matches the fund-time leaf produced by createrungtx (which
 *  does the same normalization on rung-level pubkeys). */
static void PushWitnessPubkey(RungBlock& block, std::vector<uint8_t> pk)
{
    if (pk.size() == 32) {
        pk.insert(pk.begin(), 0x02);
    }
    block.fields.push_back({RungDataType::PUBKEY, std::move(pk)});
}

/** Sign with PQ or Schnorr, routing based on block_spec fields.
 *  - If "pq_privkey" + "scheme" → PQ sign, push PUBKEY (if pq_pubkey given) + SIGNATURE.
 *  - If "privkey" → Schnorr sign, push PUBKEY + SIGNATURE.
 *  - If "scheme" is a PQ scheme but pq_privkey is missing → ERROR (prevents silent fallback).
 *  Returns true if signing was handled. */
static void SignSingleKey(const UniValue& block_spec,
                          RungBlock& block,
                          const CMutableTransaction& mtx,
                          unsigned int input_idx,
                          const PrecomputedTransactionData& txdata,
                          const RungConditions& conditions,
                          const char* block_name)
{
    // Check for PQ scheme
    if (block_spec.exists("scheme")) {
        std::string scheme_str = block_spec["scheme"].get_str();
        RungScheme scheme;
        if (ParsePQScheme(scheme_str, scheme)) {
            // PQ scheme declared — require pq_privkey
            if (!block_spec.exists("pq_privkey")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("%s: PQ scheme %s requires 'pq_privkey' (hex), not 'privkey' (WIF)", block_name, scheme_str));
            }
            if (!rung::HasPQSupport()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    strprintf("%s: PQ signing requires liboqs support (not compiled in)", block_name));
            }

            auto pq_privkey = ParseHex(block_spec["pq_privkey"].get_str());
            if (pq_privkey.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s: Empty pq_privkey", block_name));
            }

            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Failed to compute sighash", block_name));
            }

            // Push PQ pubkey for Merkle-bound key verification
            if (block_spec.exists("pq_pubkey")) {
                auto pubkey_bytes = ParseHex(block_spec["pq_pubkey"].get_str());
                if (pubkey_bytes.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s: Empty pq_pubkey", block_name));
                }
                block.fields.push_back({RungDataType::PUBKEY, std::move(pubkey_bytes)});
            }

            std::vector<uint8_t> pq_sig;
            std::span<const uint8_t> msg{sighash.begin(), 32};
            if (!rung::SignPQ(scheme, pq_privkey, msg, pq_sig)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: PQ signing failed", block_name));
            }
            block.fields.push_back({RungDataType::SIGNATURE, std::move(pq_sig)});
            return;
        }
        // SCHNORR / ECDSA scheme strings fall through to classical path
    }

    // Classical Schnorr path
    if (!block_spec.exists("privkey")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s: requires 'privkey' (WIF)", block_name));
    }
    std::string wif = block_spec["privkey"].get_str();
    CKey privkey = DecodeSecret(wif);
    if (!privkey.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s: Invalid private key", block_name));
    }

    uint256 sighash;
    if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Failed to compute sighash", block_name));
    }
    CPubKey pubkey = privkey.GetPubKey();
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(pubkey.begin(), pubkey.end())});

    unsigned char sig_buf[64];
    uint256 aux_rand = GetRandHash();
    if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Schnorr signing failed", block_name));
    }
    block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
}

/** Push a (PUBKEY, MERKLE_PROOF, SIGNATURE) triplet for one signer. */
static void PushMultisigTriplet(RungBlock& block,
                                 const std::vector<uint8_t>& pubkey,
                                 const std::vector<uint256>& proof,
                                 std::vector<uint8_t> signature)
{
    block.fields.push_back({RungDataType::PUBKEY, pubkey});
    std::vector<uint8_t> proof_bytes;
    proof_bytes.reserve(proof.size() * 32);
    for (const auto& sib : proof) {
        proof_bytes.insert(proof_bytes.end(), sib.begin(), sib.end());
    }
    block.fields.push_back({RungDataType::MERKLE_PROOF, std::move(proof_bytes)});
    block.fields.push_back({RungDataType::SIGNATURE, std::move(signature)});
}

/** PQ-aware multi-key signing for MULTISIG v2 and TIMELOCKED_MULTISIG v2.
 *  Emits K × (PUBKEY, MERKLE_PROOF, SIGNATURE) triplets. The full N-pubkey
 *  list must be supplied by the caller (`pubkeys` for classical or
 *  `pq_pubkeys` for PQ) so we can derive each signer's index in the
 *  inner pubkey-Merkle tree and produce the inclusion proof. */
static void SignMultiKey(const UniValue& block_spec,
                         RungBlock& block,
                         const CMutableTransaction& mtx,
                         unsigned int input_idx,
                         const PrecomputedTransactionData& txdata,
                         const RungConditions& conditions,
                         const char* block_name)
{
    auto find_pubkey_index = [&](const std::vector<std::vector<uint8_t>>& haystack,
                                 const std::vector<uint8_t>& needle) -> std::optional<size_t> {
        for (size_t i = 0; i < haystack.size(); ++i) {
            if (haystack[i] == needle) return i;
        }
        return std::nullopt;
    };

    // v0.8 (E-018b): collect (pubkey, proof, sig) triplets and emit them in
    // strict ascending pubkey-lex order. Consensus rejects any other order
    // — closes ~log2(K!) bits/spend of permutation channel.
    struct Triplet {
        std::vector<uint8_t> pubkey;
        std::vector<uint256> proof;
        std::vector<uint8_t> signature;
    };
    std::vector<Triplet> triplets;

    auto flush_sorted = [&]() {
        std::sort(triplets.begin(), triplets.end(),
                  [](const Triplet& a, const Triplet& b) { return a.pubkey < b.pubkey; });
        for (auto& t : triplets) {
            PushMultisigTriplet(block, t.pubkey, t.proof, std::move(t.signature));
        }
    };

    // PQ scheme path
    if (block_spec.exists("scheme")) {
        std::string scheme_str = block_spec["scheme"].get_str();
        RungScheme scheme;
        if (ParsePQScheme(scheme_str, scheme)) {
            if (!block_spec.exists("pq_privkeys") || !block_spec.exists("pq_pubkeys")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                    "%s: PQ scheme %s requires both 'pq_privkeys' and 'pq_pubkeys' (full N-key list, hex)",
                    block_name, scheme_str));
            }
            if (!rung::HasPQSupport()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf(
                    "%s: PQ signing requires liboqs support (not compiled in)", block_name));
            }
            const UniValue& pq_privkeys_arr = block_spec["pq_privkeys"].get_array();
            const UniValue& pq_pubkeys_arr = block_spec["pq_pubkeys"].get_array();
            if (pq_privkeys_arr.empty() || pq_pubkeys_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                    "%s: requires at least one pq_privkey and one pq_pubkey", block_name));
            }
            if (pq_pubkeys_arr.size() > rung::MAX_PUBKEYS_PER_MULTISIG) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                    "%s: pq_pubkeys size %d > MAX_PUBKEYS_PER_MULTISIG (%d)",
                    block_name, (int)pq_pubkeys_arr.size(), (int)rung::MAX_PUBKEYS_PER_MULTISIG));
            }

            std::vector<std::vector<uint8_t>> all_pubkeys;
            all_pubkeys.reserve(pq_pubkeys_arr.size());
            for (size_t p = 0; p < pq_pubkeys_arr.size(); ++p) {
                all_pubkeys.push_back(ParseHex(pq_pubkeys_arr[p].get_str()));
            }

            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Failed to compute sighash", block_name));
            }
            std::span<const uint8_t> msg{sighash.begin(), 32};

            for (size_t s = 0; s < pq_privkeys_arr.size(); ++s) {
                auto pq_privkey = ParseHex(pq_privkeys_arr[s].get_str());
                std::vector<uint8_t> pq_sig;
                if (!rung::SignPQ(scheme, pq_privkey, msg, pq_sig)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf(
                        "%s: PQ signing failed for key %d", block_name, s));
                }
                // Derive the public key from the private key via a probe sign+verify
                // is not generic — the caller must keep pq_privkeys and pq_pubkeys
                // index-aligned for the first pq_privkeys.size() entries.
                if (s >= all_pubkeys.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                        "%s: pq_privkeys index %d has no matching pq_pubkeys entry",
                        block_name, s));
                }
                std::vector<uint256> proof = rung::BuildPubkeyMerkleProof(all_pubkeys, s);
                triplets.push_back({all_pubkeys[s], std::move(proof), std::move(pq_sig)});
            }
            flush_sorted();
            return;
        }
    }

    // Classical path
    if (!block_spec.exists("privkeys") || !block_spec.exists("pubkeys")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "%s v2: requires both 'privkeys' (K signers) and 'pubkeys' (full N-key list)",
            block_name));
    }
    const UniValue& privkeys_arr = block_spec["privkeys"].get_array();
    const UniValue& pubkeys_arr = block_spec["pubkeys"].get_array();
    if (privkeys_arr.empty() || pubkeys_arr.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "%s: requires at least one privkey and one pubkey", block_name));
    }
    if (pubkeys_arr.size() > rung::MAX_PUBKEYS_PER_MULTISIG) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "%s: pubkeys size %d > MAX_PUBKEYS_PER_MULTISIG (%d)",
            block_name, (int)pubkeys_arr.size(), (int)rung::MAX_PUBKEYS_PER_MULTISIG));
    }

    std::vector<std::vector<uint8_t>> all_pubkeys;
    all_pubkeys.reserve(pubkeys_arr.size());
    for (size_t p = 0; p < pubkeys_arr.size(); ++p) {
        auto pk = ParseHex(pubkeys_arr[p].get_str());
        if (pk.size() == 32) pk.insert(pk.begin(), 0x02); // x-only → compressed (even-Y)
        all_pubkeys.push_back(std::move(pk));
    }

    uint256 sighash;
    if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Failed to compute sighash", block_name));
    }

    for (size_t s = 0; s < privkeys_arr.size(); ++s) {
        CKey privkey = DecodeSecret(privkeys_arr[s].get_str());
        if (!privkey.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf(
                "%s: Invalid private key at index %d", block_name, s));
        }
        CPubKey pubkey = privkey.GetPubKey();
        std::vector<uint8_t> pk_bytes(pubkey.begin(), pubkey.end());
        auto idx_opt = find_pubkey_index(all_pubkeys, pk_bytes);
        if (!idx_opt) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                "%s: privkey at index %d does not match any 'pubkeys' entry", block_name, s));
        }
        std::vector<uint256> proof = rung::BuildPubkeyMerkleProof(all_pubkeys, *idx_opt);
        unsigned char sig_buf[64];
        uint256 aux_rand = GetRandHash();
        if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf(
                "%s: Schnorr signing failed for key %d", block_name, s));
        }
        std::vector<uint8_t> sig(sig_buf, sig_buf + 64);
        triplets.push_back({all_pubkeys[*idx_opt], std::move(proof), std::move(sig)});
    }
    flush_sorted();
}

/** Build a witness block for a single signing spec entry. */
static RungBlock BuildWitnessBlock(const UniValue& block_spec,
                                   const CMutableTransaction& mtx,
                                   unsigned int input_idx,
                                   const PrecomputedTransactionData& txdata,
                                   const RungConditions& conditions)
{
    std::string type_str = block_spec["type"].get_str();
    RungBlockType btype;
    if (!ParseBlockType(type_str, btype)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown block type: " + type_str);
    }

    RungBlock block;
    block.type = btype;

    switch (btype) {
    case RungBlockType::SIG: {
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "SIG");
        break;
    }
    case RungBlockType::MULTISIG: {
        SignMultiKey(block_spec, block, mtx, input_idx, txdata, conditions, "MULTISIG");
        break;
    }
    case RungBlockType::ADAPTOR_SIG: {
        // Adaptor signature: privkey + adaptor_secret → adapted Schnorr sig (no PQ support)
        if (block_spec.exists("scheme")) {
            std::string scheme_str = block_spec["scheme"].get_str();
            RungScheme scheme;
            if (ParsePQScheme(scheme_str, scheme)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ADAPTOR_SIG does not support PQ schemes (Schnorr-only)");
            }
        }
        if (block_spec.exists("privkey")) {
            std::string wif = block_spec["privkey"].get_str();
            CKey privkey = DecodeSecret(wif);
            if (!privkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            }
            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
            }
            // Include signing PUBKEY for Merkle-bound key verification
            CPubKey pubkey = privkey.GetPubKey();
            block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(pubkey.begin(), pubkey.end())});
            if (block_spec.exists("adaptor_secret")) {
                // Adapted signing: tweak the nonce by the adaptor secret
                auto secret_bytes = ParseHex(block_spec["adaptor_secret"].get_str());
                if (secret_bytes.size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "adaptor_secret must be 32 bytes hex");
                }
                std::vector<uint8_t> sig_out(64);
                if (!rung::CreateAdaptedSignature(privkey, sighash, secret_bytes, sig_out)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Adapted Schnorr signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, sig_out});
            } else {
                // Plain Schnorr (pre-signature without adaptor — useful for testing)
                unsigned char sig_buf[64];
                uint256 aux_rand = GetRandHash();
                if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Schnorr signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
            }
        }
        // v0.7: dropped the v0.6 trailing PUBKEY loop (adaptor_point slot is gone).
        break;
    }
    case RungBlockType::MUSIG_THRESHOLD: {
        // MuSig2/FROST aggregate threshold: Schnorr-only (no PQ path).
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "MUSIG_THRESHOLD");
        break;
    }
    case RungBlockType::ANCHOR_FEE: {
        // ANCHOR_FEE witness: 2 PUBKEYs + 2 SIGNATUREs (2-of-2 sig check by eval).
        // Spec: { "privkeys": [wif1, wif2], "pubkeys": [pk1_hex, pk2_hex] }.
        if (!block_spec.exists("privkeys") || !block_spec.exists("pubkeys")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "ANCHOR_FEE requires 'privkeys' and 'pubkeys' arrays");
        }
        const UniValue& pk_arr = block_spec["pubkeys"].get_array();
        const UniValue& sk_arr = block_spec["privkeys"].get_array();
        if (pk_arr.size() != 2 || sk_arr.size() != 2) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "ANCHOR_FEE 'pubkeys' and 'privkeys' must each have exactly 2 entries");
        }
        for (size_t i = 0; i < 2; ++i) {
            PushWitnessPubkey(block, ParseHex(pk_arr[i].get_str()));
        }
        uint256 sighash;
        if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ANCHOR_FEE: failed to compute sighash");
        }
        for (size_t i = 0; i < 2; ++i) {
            CKey key = DecodeSecret(sk_arr[i].get_str());
            if (!key.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "ANCHOR_FEE: invalid privkey");
            }
            unsigned char sig_buf[64];
            uint256 aux_rand = GetRandHash();
            if (!key.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ANCHOR_FEE: Schnorr signing failed");
            }
            block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
        }
        break;
    }
    case RungBlockType::VAULT_LOCK: {
        // VAULT_LOCK v0.8 witness: implicit [PUBKEY(recovery), PUBKEY(hot),
        // SIGNATURE]. NUMERIC(delay) is a CONDITIONS field — arrives via
        // the merge step, never on the witness wire (E-018a).
        if (block_spec.exists("pubkeys")) {
            const UniValue& pk_arr = block_spec["pubkeys"].get_array();
            for (size_t i = 0; i < pk_arr.size(); ++i) {
                PushWitnessPubkey(block, ParseHex(pk_arr[i].get_str()));
            }
        }
        // Sign with the provided key
        if (block_spec.exists("privkey")) {
            std::string wif = block_spec["privkey"].get_str();
            CKey privkey = DecodeSecret(wif);
            if (!privkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "VAULT_LOCK: Invalid private key");
            }
            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "VAULT_LOCK: Failed to compute sighash");
            }
            unsigned char sig_buf[64];
            uint256 aux_rand = GetRandHash();
            if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "VAULT_LOCK: Schnorr signing failed");
            }
            block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
        }
        break;
    }
    case RungBlockType::TAGGED_HASH: {
        // TAGGED_HASH witness: [HASH256(tag), HASH256(expected), PREIMAGE]
        // Auto-populate HASH256 fields from conditions
        for (const auto& rung : conditions.rungs) {
            for (const auto& cblk : rung.blocks) {
                if (cblk.type == RungBlockType::TAGGED_HASH) {
                    for (const auto& f : cblk.fields) {
                        if (f.type == RungDataType::HASH256) {
                            block.fields.push_back(f);
                        }
                    }
                    goto tagged_hash_done;
                }
            }
        }
        tagged_hash_done:;
        if (block_spec.exists("preimage")) {
            std::string preimage_hex = block_spec["preimage"].get_str();
            auto preimage_data = ParseHex(preimage_hex);
            if (preimage_data.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "TAGGED_HASH requires non-empty preimage hex");
            }
            block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        }
        break;
    }
    case RungBlockType::CTV: {
        // CTV witness: [HASH256]. Copy from conditions.
        for (const auto& rung : conditions.rungs) {
            for (const auto& cblk : rung.blocks) {
                if (cblk.type == RungBlockType::CTV) {
                    for (const auto& f : cblk.fields) {
                        if (f.type == RungDataType::HASH256) {
                            block.fields.push_back(f);
                            goto ctv_done;
                        }
                    }
                }
            }
        }
        ctv_done:;
        break;
    }
    case RungBlockType::COSIGN: {
        // COSIGN witness: [HASH256]. Copy from conditions.
        for (const auto& rung : conditions.rungs) {
            for (const auto& cblk : rung.blocks) {
                if (cblk.type == RungBlockType::COSIGN) {
                    for (const auto& f : cblk.fields) {
                        if (f.type == RungDataType::HASH256) {
                            block.fields.push_back(f);
                            goto cosign_done;
                        }
                    }
                }
            }
        }
        cosign_done:;
        break;
    }
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME: {
        // Witness implicit layout requires [NUMERIC]. Auto-populate from
        // conditions or user-provided value for the timelock.
        if (block_spec.exists("value")) {
            auto val_hex = block_spec["value"].get_str();
            block.fields.push_back({RungDataType::NUMERIC, ParseHex(val_hex)});
        } else {
            // Copy NUMERIC from conditions (same value echoed in witness)
            for (const auto& rung : conditions.rungs) {
                for (const auto& cblk : rung.blocks) {
                    if (cblk.type == btype) {
                        for (const auto& f : cblk.fields) {
                            if (f.type == RungDataType::NUMERIC) {
                                block.fields.push_back(f);
                                goto csv_done;
                            }
                        }
                    }
                }
            }
            // Fallback: add 0 if no matching condition found
            block.fields.push_back({RungDataType::NUMERIC, {0x00, 0x00, 0x00, 0x00}});
            csv_done:;
        }
        break;
    }
    case RungBlockType::TIMELOCKED_SIG: {
        // Compound SIG + CSV: PQ or Schnorr sign, CSV timelock from conditions
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "TIMELOCKED_SIG");
        // Add CSV NUMERIC from conditions (witness layout: PUBKEY, SIGNATURE, NUMERIC)
        for (const auto& rung : conditions.rungs) {
            for (const auto& cblk : rung.blocks) {
                if (cblk.type == RungBlockType::TIMELOCKED_SIG) {
                    for (const auto& f : cblk.fields) {
                        if (f.type == RungDataType::NUMERIC) {
                            block.fields.push_back(f);
                            goto timelocked_sig_done;
                        }
                    }
                }
            }
        }
        timelocked_sig_done:
        break;
    }
    case RungBlockType::HASH_SIG: {
        // Witness layout: [PUBKEY, SIGNATURE, PREIMAGE]
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "HASH_SIG");
        std::string preimage_hex = block_spec["preimage"].get_str();
        auto preimage_data = ParseHex(preimage_hex);
        if (preimage_data.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HASH_SIG requires non-empty preimage hex");
        }
        block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        break;
    }
    case RungBlockType::HTLC: {
        // HTLC v0.7 witness: [PUBKEY(receiver), PUBKEY(sender), SIGNATURE, PREIMAGE, NUMERIC(path)]
        // Spec: { "path": 0|1, "privkey": <wif of the path's signer>,
        //         "pubkeys": [receiver_pk_hex, sender_pk_hex],
        //         "preimage": <hex>  (required when path=0, must be empty/absent when path=1) }
        if (!block_spec.exists("path")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC requires 'path' (0=receiver, 1=sender/refund)");
        }
        int64_t path = block_spec["path"].getInt<int64_t>();
        if (path != 0 && path != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC 'path' must be 0 or 1");
        }
        if (!block_spec.exists("pubkeys")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC requires 'pubkeys': [receiver, sender]");
        }
        const UniValue& pk_arr = block_spec["pubkeys"].get_array();
        if (pk_arr.size() != 2) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC 'pubkeys' array must have exactly 2 entries");
        }
        // PUBKEY(receiver), PUBKEY(sender)
        for (size_t i = 0; i < 2; ++i) {
            PushWitnessPubkey(block, ParseHex(pk_arr[i].get_str()));
        }
        // SIGNATURE — sign with the privkey for the chosen path.
        if (!block_spec.exists("privkey")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC requires 'privkey'");
        }
        CKey privkey = DecodeSecret(block_spec["privkey"].get_str());
        if (!privkey.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }
        uint256 sighash;
        if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
        }
        unsigned char sig_buf[64];
        uint256 aux_rand = GetRandHash();
        if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "HTLC Schnorr signing failed");
        }
        block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
        // PREIMAGE — non-empty for receiver path, empty for refund.
        std::vector<uint8_t> preimage_data;
        if (path == 0) {
            if (!block_spec.exists("preimage")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC receiver path requires 'preimage'");
            }
            preimage_data = ParseHex(block_spec["preimage"].get_str());
            if (preimage_data.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC 'preimage' must be non-empty for receiver path");
            }
        }
        block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        // NUMERIC(path) — 4-byte little-endian
        {
            uint32_t p = static_cast<uint32_t>(path);
            std::vector<uint8_t> path_bytes = {
                static_cast<uint8_t>(p & 0xFF),
                static_cast<uint8_t>((p >> 8) & 0xFF),
                static_cast<uint8_t>((p >> 16) & 0xFF),
                static_cast<uint8_t>((p >> 24) & 0xFF),
            };
            block.fields.push_back({RungDataType::NUMERIC, path_bytes});
        }
        break;
    }
    case RungBlockType::PTLC: {
        // Compound ADAPTOR_SIG + CSV: adaptor sign, CSV from conditions (no PQ support)
        if (block_spec.exists("scheme")) {
            std::string scheme_str = block_spec["scheme"].get_str();
            RungScheme scheme;
            if (ParsePQScheme(scheme_str, scheme)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PTLC does not support PQ schemes (Schnorr-only adaptor signatures)");
            }
        }
        if (block_spec.exists("privkey")) {
            std::string wif = block_spec["privkey"].get_str();
            CKey privkey = DecodeSecret(wif);
            if (!privkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            }
            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
            }
            // Include PUBKEY for Merkle-bound key verification
            CPubKey pubkey = privkey.GetPubKey();
            block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(pubkey.begin(), pubkey.end())});
            if (block_spec.exists("adaptor_secret")) {
                auto secret_bytes = ParseHex(block_spec["adaptor_secret"].get_str());
                if (secret_bytes.size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "adaptor_secret must be 32 bytes hex");
                }
                std::vector<uint8_t> sig_out(64);
                if (!rung::CreateAdaptedSignature(privkey, sighash, secret_bytes, sig_out)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "PTLC adapted signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, sig_out});
            } else {
                unsigned char sig_buf[64];
                uint256 aux_rand = GetRandHash();
                if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "PTLC Schnorr signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
            }
        }
        // v0.7: dropped the v0.6 trailing PUBKEY loop (adaptor_point slot is gone).
        break;
    }
    case RungBlockType::CLTV_SIG: {
        // Witness layout: [PUBKEY, SIGNATURE, NUMERIC]
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "CLTV_SIG");
        // Add CLTV NUMERIC from conditions
        for (const auto& rung : conditions.rungs) {
            for (const auto& cblk : rung.blocks) {
                if (cblk.type == RungBlockType::CLTV_SIG) {
                    for (const auto& f : cblk.fields) {
                        if (f.type == RungDataType::NUMERIC) {
                            block.fields.push_back(f);
                            goto cltv_sig_done;
                        }
                    }
                }
            }
        }
        cltv_sig_done:
        break;
    }
    case RungBlockType::TIMELOCKED_MULTISIG: {
        // Compound MULTISIG + CSV: PQ or Schnorr multi-sign, CSV from conditions (NO_IMPLICIT witness)
        SignMultiKey(block_spec, block, mtx, input_idx, txdata, conditions, "TIMELOCKED_MULTISIG");
        break;
    }
    case RungBlockType::KEY_REF_SIG: {
        // KEY_REF_SIG v0.8 witness: implicit [SIGNATURE] only. The pubkey
        // is resolved from the referenced relay block at evaluation time —
        // any pubkey on the witness side would be unbound spender-controlled
        // bytes (E-018a), so emit only the signature here.
        if (!block_spec.exists("privkey")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "KEY_REF_SIG: requires 'privkey' (WIF)");
        }
        std::string wif = block_spec["privkey"].get_str();
        CKey privkey = DecodeSecret(wif);
        if (!privkey.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "KEY_REF_SIG: Invalid private key");
        }
        uint256 sighash;
        if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "KEY_REF_SIG: Failed to compute sighash");
        }
        unsigned char sig_buf[64];
        uint256 aux_rand = GetRandHash();
        if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "KEY_REF_SIG: Schnorr signing failed");
        }
        block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
        break;
    }
    case RungBlockType::ACCUMULATOR: {
        // ACCUMULATOR v2 witness: NUMERIC(element_id) + MERKLE_PROOF(siblings).
        // Signer args:
        //   element_id (int): position of the proven element in the committed set
        //   proof (array of hex): sibling hashes from leaf to root, each 32 B
        if (!block_spec.exists("element_id") || !block_spec.exists("proof")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "ACCUMULATOR v2 requires both 'element_id' (int) and 'proof' (array of 32-byte hex sibling hashes)");
        }
        int64_t eid = block_spec["element_id"].getInt<int64_t>();
        if (eid < 0 || static_cast<uint64_t>(eid) > rung::MAX_ACCUMULATOR_ELEMENT_ID) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "ACCUMULATOR element_id out of range [0, " +
                std::to_string(rung::MAX_ACCUMULATOR_ELEMENT_ID) + "]");
        }
        // 4-byte LE NUMERIC for element_id (consistent with descriptor parser).
        std::vector<uint8_t> eid_bytes(4);
        eid_bytes[0] = static_cast<uint8_t>(eid & 0xFF);
        eid_bytes[1] = static_cast<uint8_t>((eid >> 8) & 0xFF);
        eid_bytes[2] = static_cast<uint8_t>((eid >> 16) & 0xFF);
        eid_bytes[3] = static_cast<uint8_t>((eid >> 24) & 0xFF);
        block.fields.push_back({RungDataType::NUMERIC, std::move(eid_bytes)});

        const UniValue& proof_arr = block_spec["proof"].get_array();
        if (proof_arr.size() > rung::MAX_ACCUMULATOR_PROOF_DEPTH) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "ACCUMULATOR proof depth " + std::to_string(proof_arr.size()) +
                " > MAX_ACCUMULATOR_PROOF_DEPTH (" +
                std::to_string(rung::MAX_ACCUMULATOR_PROOF_DEPTH) + ")");
        }
        std::vector<uint8_t> proof_bytes;
        proof_bytes.reserve(proof_arr.size() * 32);
        for (size_t i = 0; i < proof_arr.size(); ++i) {
            auto h = ParseHex(proof_arr[i].get_str());
            if (h.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "ACCUMULATOR proof sibling at index " + std::to_string(i) +
                    " must be exactly 32 bytes");
            }
            proof_bytes.insert(proof_bytes.end(), h.begin(), h.end());
        }
        block.fields.push_back({RungDataType::MERKLE_PROOF, std::move(proof_bytes)});
        break;
    }
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2TR_LEGACY: {
        // Delegates to EvalSigBlock — same witness as SIG (PUBKEY + SIGNATURE)
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions,
                      btype == RungBlockType::P2PK_LEGACY ? "P2PK_LEGACY" : "P2TR_LEGACY");
        break;
    }
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY: {
        // Witness: PUBKEY + SIGNATURE (evaluator checks HASH160(pubkey) == committed hash)
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions,
                      btype == RungBlockType::P2PKH_LEGACY ? "P2PKH_LEGACY" : "P2WPKH_LEGACY");
        break;
    }
    case RungBlockType::P2SH_LEGACY: {
        // Witness: SCRIPT_BODY (serialized inner conditions) + inner witness fields
        // The SCRIPT_BODY is the serialized Ladder conditions that hash to the committed HASH160.
        // Use SCRIPT_BODY (1-80 bytes) instead of PREIMAGE (fixed 32 bytes) since inner
        // conditions can be any size.
        if (block_spec.exists("preimage")) {
            auto preimage_data = ParseHex(block_spec["preimage"].get_str());
            if (preimage_data.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "P2SH_LEGACY requires non-empty preimage hex");
            }
            block.fields.push_back({RungDataType::SCRIPT_BODY, preimage_data});
        }
        if (block_spec.exists("privkey")) {
            SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "P2SH_LEGACY");
        }
        break;
    }
    case RungBlockType::P2WSH_LEGACY: {
        // Witness: SCRIPT_BODY (serialized inner conditions) + inner witness fields
        if (block_spec.exists("preimage")) {
            auto preimage_data = ParseHex(block_spec["preimage"].get_str());
            if (preimage_data.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "P2WSH_LEGACY requires non-empty preimage hex");
            }
            block.fields.push_back({RungDataType::SCRIPT_BODY, preimage_data});
        }
        if (block_spec.exists("privkey")) {
            SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "P2WSH_LEGACY");
        }
        break;
    }
    case RungBlockType::P2TR_SCRIPT_LEGACY: {
        // Witness: SCRIPT_BODY (revealed script leaf) + inner witness fields
        if (block_spec.exists("preimage")) {
            auto preimage_data = ParseHex(block_spec["preimage"].get_str());
            if (preimage_data.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "P2TR_SCRIPT_LEGACY requires non-empty preimage hex");
            }
            block.fields.push_back({RungDataType::SCRIPT_BODY, preimage_data});
        }
        if (block_spec.exists("privkey")) {
            SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "P2TR_SCRIPT_LEGACY");
        }
        break;
    }
#ifdef ENABLE_QABIO
    case RungBlockType::QABI_PRIME: {
        // QABI priming witness: 4 fields in the exact order the evaluator
        // expects (matching QABI_PRIME_WITNESS implicit layout):
        //   [0] HASH256  new_committed_root
        //   [1] NUMERIC  prime_depth
        //   [2] NUMERIC  new_committed_expiry
        //   [3] PREIMAGE prime_preimage
        //
        // The caller provides:
        //   new_committed_root   (hex, 32 bytes)
        //   prime_depth          (int)
        //   new_committed_expiry (int)
        //   And either:
        //     prime_preimage     (hex, 32 bytes — pre-derived), or
        //     auth_seed + chain_length (hex + int — for in-RPC derivation)
        //
        // Convenience: supplying auth_seed + chain_length lets the wallet
        // pass its secret and have the preimage derived server-side.
        if (!block_spec.exists("new_committed_root")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "QABI_PRIME requires new_committed_root hex");
        }
        auto new_root = ParseHex(block_spec["new_committed_root"].get_str());
        if (new_root.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "new_committed_root must be exactly 32 bytes");
        }
        if (!block_spec.exists("prime_depth")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "QABI_PRIME requires prime_depth");
        }
        int64_t prime_depth = block_spec["prime_depth"].getInt<int64_t>();
        if (prime_depth <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "prime_depth must be > 0");
        }
        if (!block_spec.exists("new_committed_expiry")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "QABI_PRIME requires new_committed_expiry");
        }
        int64_t new_expiry = block_spec["new_committed_expiry"].getInt<int64_t>();
        if (new_expiry < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "new_committed_expiry must be >= 0");
        }

        // Derive or accept the preimage.
        std::vector<uint8_t> preimage_bytes;
        if (block_spec.exists("prime_preimage")) {
            preimage_bytes = ParseHex(block_spec["prime_preimage"].get_str());
            if (preimage_bytes.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "prime_preimage must be exactly 32 bytes");
            }
        } else if (block_spec.exists("auth_seed") && block_spec.exists("chain_length")) {
            auto seed = ParseHex(block_spec["auth_seed"].get_str());
            if (seed.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "auth_seed must be exactly 32 bytes");
            }
            uint32_t chain_length = block_spec["chain_length"].getInt<uint32_t>();
            uint256 preimage_u256;
            if (!rung::ComputeAuthChainPreimageAt(
                    std::span<const uint8_t>(seed), chain_length,
                    static_cast<uint32_t>(prime_depth), preimage_u256)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "failed to derive preimage (bad depth or chain length)");
            }
            preimage_bytes.assign(preimage_u256.data(), preimage_u256.data() + 32);
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "QABI_PRIME requires either prime_preimage OR (auth_seed + chain_length)");
        }

        // Assemble the 4 witness fields in exact layout order.
        block.fields.push_back({RungDataType::HASH256, new_root});
        {
            RungField f;
            f.type = RungDataType::NUMERIC;
            uint32_t v = static_cast<uint32_t>(prime_depth);
            f.data.push_back(static_cast<uint8_t>(v & 0xFF));
            f.data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            f.data.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
            f.data.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
            block.fields.push_back(f);
        }
        {
            RungField f;
            f.type = RungDataType::NUMERIC;
            uint32_t v = static_cast<uint32_t>(new_expiry);
            f.data.push_back(static_cast<uint8_t>(v & 0xFF));
            f.data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            f.data.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
            f.data.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
            block.fields.push_back(f);
        }
        block.fields.push_back({RungDataType::PREIMAGE, preimage_bytes});
        break;
    }
    case RungBlockType::QABI_SPEND: {
        // QABI_SPEND witness: only the spend_preimage goes into the wire-format
        // witness block. The 5 committed conditions fields live in the conditions
        // tree and are combined by MergeConditionsAndWitness at evaluation time
        // (conditions 5 + witness 1 = merged 6 fields, matching the evaluator).
        //
        // Caller provides either:
        //   spend_preimage / preimage  (hex, 32 bytes), or
        //   auth_seed + chain_length   (in-RPC derivation at committed_depth+1)

        std::vector<uint8_t> preimage_bytes;
        if (block_spec.exists("spend_preimage")) {
            preimage_bytes = ParseHex(block_spec["spend_preimage"].get_str());
        } else if (block_spec.exists("preimage")) {
            preimage_bytes = ParseHex(block_spec["preimage"].get_str());
        } else if (block_spec.exists("auth_seed") && block_spec.exists("chain_length")) {
            // Find committed_depth from conditions tree for derivation.
            const RungBlock* cond_block = nullptr;
            for (const auto& rung : conditions.rungs) {
                for (const auto& cb : rung.blocks) {
                    if (cb.type == RungBlockType::QABI_SPEND) { cond_block = &cb; break; }
                }
                if (cond_block) break;
            }
            if (!cond_block || cond_block->fields.size() < 3) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "QABI_SPEND: need QABI_SPEND in conditions to derive preimage");
            }
            auto seed = ParseHex(block_spec["auth_seed"].get_str());
            if (seed.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "QABI_SPEND: auth_seed must be 32 bytes");
            }
            uint32_t chain_length = block_spec["chain_length"].getInt<uint32_t>();
            const auto& df = cond_block->fields[2];
            if (df.data.size() != 4) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "QABI_SPEND: bad committed_depth");
            }
            uint32_t cd = static_cast<uint32_t>(df.data[0]) |
                          (static_cast<uint32_t>(df.data[1]) << 8) |
                          (static_cast<uint32_t>(df.data[2]) << 16) |
                          (static_cast<uint32_t>(df.data[3]) << 24);
            uint256 pre;
            if (!rung::ComputeAuthChainPreimageAt(
                    std::span<const uint8_t>(seed), chain_length, cd + 1, pre)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "QABI_SPEND: preimage derivation failed");
            }
            preimage_bytes.assign(pre.data(), pre.data() + 32);
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "QABI_SPEND requires spend_preimage/preimage OR (auth_seed + chain_length)");
        }
        if (preimage_bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "QABI_SPEND: preimage must be 32 bytes");
        }
        block.fields.push_back({RungDataType::PREIMAGE, preimage_bytes});
        break;
    }
    case RungBlockType::PQ_BATCH: {
        // PQ_BATCH witness (anchor input only): [PUBKEY, SIGNATURE].
        // Non-anchor inputs pass an empty witness spec (no pubkey/signature
        // fields) and rely on the tx-level PQBatchCache populated by the
        // anchor input's earlier verification.
        //
        // Two signing paths:
        //  1. In-band: pass {scheme, pq_pubkey, pq_privkey} — SignSingleKey
        //     computes the per-input ladder sighash and PQ-signs it.
        //  2. Pre-signed: pass {pubkey, signature} hex directly — used when
        //     the caller signed externally (e.g. cold-storage HSM).
        if (block_spec.exists("pq_privkey")) {
            SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "PQ_BATCH");
            break;
        }
        if (block_spec.exists("pubkey")) {
            PushWitnessPubkey(block, ParseHex(block_spec["pubkey"].get_str()));
        }
        if (block_spec.exists("signature")) {
            block.fields.push_back({
                RungDataType::SIGNATURE,
                ParseHex(block_spec["signature"].get_str())});
        }
        break;
    }
#endif // ENABLE_QABIO
    default: {
        // Blocks without specific signing logic: auto-populate witness fields.
        // For key-consuming blocks (ANCHOR_CHANNEL, VAULT_LOCK, PLC blocks with pubkeys),
        // the witness needs PUBKEY fields for evaluation. Copy from user-provided pubkeys.
        if (block_spec.exists("pubkeys")) {
            const UniValue& pk_arr = block_spec["pubkeys"].get_array();
            for (size_t i = 0; i < pk_arr.size(); ++i) {
                PushWitnessPubkey(block, ParseHex(pk_arr[i].get_str()));
            }
        } else if (block_spec.exists("pubkey")) {
            PushWitnessPubkey(block, ParseHex(block_spec["pubkey"].get_str()));
        }
        // Do NOT auto-copy condition fields — MergeConditionsAndWitness combines
        // conditions + witness, so copying would duplicate fields. Only add
        // user-provided data (pubkeys, preimages) that the evaluator needs
        // in addition to what's already in conditions.
        // Copy PREIMAGE fields if user provides them (for hash-bound blocks)
        if (block_spec.exists("preimages")) {
            const UniValue& pi_arr = block_spec["preimages"].get_array();
            for (size_t i = 0; i < pi_arr.size(); ++i) {
                auto pi = ParseHex(pi_arr[i].get_str());
                block.fields.push_back({RungDataType::PREIMAGE, std::move(pi)});
            }
        } else if (block_spec.exists("preimage")) {
            auto preimage_data = ParseHex(block_spec["preimage"].get_str());
            block.fields.push_back({RungDataType::PREIMAGE, std::move(preimage_data)});
        }
        break;
    }
    }

    return block;
}

static RPCHelpMan signrungtx()
{
    return RPCHelpMan{
        "signrungtx",
        "Sign a v4 RUNG_TX transaction's inputs.\n"
        "Supports two formats:\n"
        "  Legacy: [{\"privkey\":\"cVt...\",\"input\":0}] — single SIG block\n"
        "  Full:   [{\"input\":0,\"blocks\":[{\"type\":\"SIG\",\"privkey\":\"cVt...\"},...]}] — any block types\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The unsigned v4 transaction hex"},
            {"signers", RPCArg::Type::ARR, RPCArg::Optional::NO, "Per-input signing specifications",
                {
                    {"signer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A signing spec",
                        {
                            {"input", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index to sign"},
                            {"privkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "WIF key (legacy SIG-only format)"},
                            {"rung", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Target rung index for multi-rung conditions (default 0)"},
                            {"blocks", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                                "Block signing specs as JSON array. Single-key blocks: [{type,privkey,preimage}]. "
                                "MULTISIG/TIMELOCKED_MULTISIG v2: [{type:'MULTISIG',privkeys:[wif,...],pubkeys:[hex,...]}] — "
                                "'pubkeys' MUST be the full N-key list (in commitment order); "
                                "'privkeys' is the K subset of signing keys. The signer derives Merkle "
                                "inclusion proofs from 'pubkeys' and emits (PUBKEY, MERKLE_PROOF, SIGNATURE) triplets."},
                            {"relay_blocks", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Per-relay signing specs as JSON array [{blocks:[{type,privkey}]}]"},
                            {"conditions", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Full conditions as JSON string of rung array [{blocks:[{type,fields:[{type,hex}]}]}]. Required for MLSC inputs."},
                            {"diff_witness", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Diff witness as JSON: {source_input, diffs:[{rung_index, block_index, field_index, field:{type,hex,privkey}}]}"},
                        },
                    },
                },
            },
            {"spent_outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs being spent (for sighash computation)",
                {
                    {"spent_output", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A spent output",
                        {
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in BTC"},
                            {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scriptPubKey hex"},
                        },
                    },
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The signed transaction hex"},
            {RPCResult::Type::BOOL, "complete", "Whether all inputs are signed"},
        }},
        RPCExamples{
            HelpExampleCli("signrungtx", "<txhex> '[{\"privkey\":\"cVt...\",\"input\":0}]' '[{\"amount\":0.001,\"scriptPubKey\":\"c1...\"}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string hex_str = self.Arg<std::string>("hex");
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex_str)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode transaction");
    }

    if (mtx.version != CTransaction::RUNG_TX_VERSION) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction is not v4 RUNG_TX");
    }

    const UniValue& signers_arr = request.params[1].get_array();
    const UniValue& spent_arr = request.params[2].get_array();

    if (spent_arr.size() != mtx.vin.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "spent_outputs count (" + std::to_string(spent_arr.size()) +
            ") must match input count (" + std::to_string(mtx.vin.size()) + ")");
    }

    // Build spent outputs vector
    std::vector<CTxOut> spent_outputs;
    for (size_t i = 0; i < spent_arr.size(); ++i) {
        const UniValue& so = spent_arr[i];
        CTxOut txout;
        txout.nValue = AmountFromValue(so["amount"]);
        auto spk_bytes = ParseHex(so["scriptPubKey"].get_str());
        txout.scriptPubKey = CScript(spk_bytes.begin(), spk_bytes.end());
        spent_outputs.push_back(txout);
    }

    // Precompute transaction data
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>(spent_outputs));

    bool all_signed = true;

    for (size_t k = 0; k < signers_arr.size(); ++k) {
        const UniValue& signer_obj = signers_arr[k];
        unsigned int input_idx = signer_obj["input"].getInt<unsigned int>();

        if (input_idx >= mtx.vin.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Input index " + std::to_string(input_idx) + " out of range");
        }

        // Determine conditions from spent output
        RungConditions conditions;
        std::string cond_error;
        bool is_mlsc = rung::IsMLSCScript(spent_outputs[input_idx].scriptPubKey);
        bool has_conditions = false;
        std::vector<std::vector<std::vector<uint8_t>>> rung_pubkeys2, relay_pubkeys2;
        std::vector<uint8_t> rung_output_indices2;

        if (is_mlsc) {
            // MLSC: conditions must be provided by the signer (not on-chain)
            if (!signer_obj.exists("conditions")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "MLSC input " + std::to_string(input_idx) +
                    " requires 'conditions' array (conditions are not on-chain)");
            }
            UniValue coil_val = signer_obj.exists("coil") ? signer_obj["coil"] : UniValue();
            UniValue relays_val2 = signer_obj.exists("relays") ? signer_obj["relays"] : UniValue();
            conditions = ParseConditionsSpec(signer_obj["conditions"].get_array(), coil_val, relays_val2, rung_pubkeys2, relay_pubkeys2, &rung_output_indices2);

            // Set the conditions_root from the spent output
            uint256 root;
            rung::GetMLSCRoot(spent_outputs[input_idx].scriptPubKey, root);
            conditions.conditions_root = root;
            has_conditions = true;
        } else {
            // Non-MLSC input (standard Bitcoin output — bootstrap path).
            // signrungtx only signs Ladder Script inputs. Standard inputs
            // must be signed separately (e.g., by the wallet or MiniWallet).
            // Skip this input — it should already have a witness.
            continue;
        }

        LadderWitness ladder;
        unsigned int target_rung = 0; // declared here for visibility across all signing paths

        if (signer_obj.exists("privkey") && !signer_obj.exists("blocks")) {
            // Legacy format: single SIG block
            std::string wif = signer_obj["privkey"].get_str();
            CKey privkey = DecodeSecret(wif);
            if (!privkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key: " + wif);
            }

            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash for input " + std::to_string(input_idx));
            }

            unsigned char sig_buf[64];
            uint256 aux_rand = GetRandHash();
            if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Schnorr signing failed for input " + std::to_string(input_idx));
            }
            std::vector<unsigned char> sig(sig_buf, sig_buf + 64);

            CPubKey pubkey = privkey.GetPubKey();
            std::vector<uint8_t> pubkey_data(pubkey.begin(), pubkey.end());

            Rung rung;
            RungBlock block;
            block.type = RungBlockType::SIG;
            block.fields.push_back({RungDataType::PUBKEY, pubkey_data});
            block.fields.push_back({RungDataType::SIGNATURE, sig});
            rung.blocks.push_back(std::move(block));
            ladder.rungs.push_back(std::move(rung));
        } else if (signer_obj.exists("blocks")) {
            const UniValue& blocks_arr = signer_obj["blocks"].get_array();

            if (signer_obj.exists("rung")) {
                target_rung = signer_obj["rung"].getInt<unsigned int>();
            }

            if (has_conditions) {

                if (is_mlsc) {
                    // MLSC: build witness for only the target rung (1 rung in witness)
                    if (target_rung >= conditions.rungs.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "target rung " + std::to_string(target_rung) +
                            " out of range (conditions have " + std::to_string(conditions.rungs.size()) + " rungs)");
                    }

                    const auto& cond_target = conditions.rungs[target_rung];
                    if (blocks_arr.size() != cond_target.blocks.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "blocks count (" + std::to_string(blocks_arr.size()) +
                            ") must match conditions rung " + std::to_string(target_rung) +
                            " block count (" + std::to_string(cond_target.blocks.size()) + ")");
                    }
                    Rung wit_rung;
                    for (size_t b = 0; b < blocks_arr.size(); ++b) {
                        wit_rung.blocks.push_back(
                            BuildWitnessBlock(blocks_arr[b], mtx, input_idx, txdata, conditions));
                    }
                    ladder.rungs.push_back(std::move(wit_rung));
                } else {
                    // Legacy: build witness for all rungs (target gets real data, others get dummies)
                    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
                        Rung wit_rung;

                        if (r == target_rung) {
                            const auto& cond_r = conditions.rungs[r];
                            if (blocks_arr.size() != cond_r.blocks.size()) {
                                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                    "blocks count (" + std::to_string(blocks_arr.size()) +
                                    ") must match conditions rung " + std::to_string(r) +
                                    " block count (" + std::to_string(cond_r.blocks.size()) + ")");
                            }
                            for (size_t b = 0; b < blocks_arr.size(); ++b) {
                                wit_rung.blocks.push_back(
                                    BuildWitnessBlock(blocks_arr[b], mtx, input_idx, txdata, conditions));
                            }
                        } else {
                            // Dummy: correct types, empty fields
                            const auto& cond_r = conditions.rungs[r];
                            for (const auto& cond_block : cond_r.blocks) {
                                RungBlock dummy;
                                dummy.type = cond_block.type;
                                wit_rung.blocks.push_back(std::move(dummy));
                            }
                        }
                        ladder.rungs.push_back(std::move(wit_rung));
                    }
                }
            } else {
                // Bootstrap spend
                Rung rung;
                for (size_t b = 0; b < blocks_arr.size(); ++b) {
                    rung.blocks.push_back(
                        BuildWitnessBlock(blocks_arr[b], mtx, input_idx, txdata, conditions));
                }
                ladder.rungs.push_back(std::move(rung));
            }
        } else if (signer_obj.exists("diff_witness")) {
            // Diff witness mode: inherit from source input, apply diffs
            const UniValue& dw_obj = signer_obj["diff_witness"].get_obj();
            uint32_t source_input = dw_obj["source_input"].getInt<uint32_t>();

            WitnessReference ref;
            ref.input_index = source_input;

            if (dw_obj.exists("diffs")) {
                const UniValue& diffs_arr = dw_obj["diffs"].get_array();
                for (size_t d = 0; d < diffs_arr.size(); ++d) {
                    const UniValue& diff_obj = diffs_arr[d].get_obj();
                    WitnessDiff wd;
                    wd.rung_index = diff_obj["rung_index"].getInt<uint16_t>();
                    wd.block_index = diff_obj["block_index"].getInt<uint16_t>();
                    wd.field_index = diff_obj["field_index"].getInt<uint16_t>();

                    const UniValue& field_obj = diff_obj["field"].get_obj();
                    RungDataType dtype;
                    if (!ParseDataType(field_obj["type"].get_str(), dtype)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Unknown diff field type: " + field_obj["type"].get_str());
                    }

                    if (field_obj.exists("privkey")) {
                        CKey dkey = DecodeSecret(field_obj["privkey"].get_str());
                        if (!dkey.IsValid()) {
                            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                "Invalid diff privkey at diff " + std::to_string(d));
                        }
                        if (dtype == RungDataType::SIGNATURE) {
                            uint256 sighash;
                            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                    "Failed to compute sighash for diff witness input " + std::to_string(input_idx));
                            }
                            unsigned char sig_buf[64];
                            uint256 aux_rand = GetRandHash();
                            if (!dkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                    "Schnorr signing failed for diff witness input " + std::to_string(input_idx));
                            }
                            wd.new_field.type = RungDataType::SIGNATURE;
                            wd.new_field.data.assign(sig_buf, sig_buf + 64);
                        } else if (dtype == RungDataType::PUBKEY) {
                            CPubKey pub = dkey.GetPubKey();
                            wd.new_field.type = RungDataType::PUBKEY;
                            wd.new_field.data.assign(pub.begin(), pub.end());
                        } else {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "privkey auto-derive only supported for SIGNATURE and PUBKEY diff types");
                        }
                    } else if (field_obj.exists("hex")) {
                        wd.new_field.type = dtype;
                        wd.new_field.data = ParseHex(field_obj["hex"].get_str());
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Diff field must have either 'hex' or 'privkey'");
                    }

                    ref.diffs.push_back(std::move(wd));
                }
            }

            ladder.witness_ref = std::move(ref);
            // Skip relay building — diff witnesses inherit relays from source
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Signer entry must have 'privkey' (legacy), 'blocks' (new format), or 'diff_witness'");
        }

        // Build relay witnesses if conditions have relays (skip for diff witness)
        if (!ladder.IsWitnessRef() && has_conditions && !conditions.relays.empty()) {
            if (signer_obj.exists("relay_blocks")) {
                const UniValue& relay_blocks_arr = signer_obj["relay_blocks"].get_array();
                if (relay_blocks_arr.size() != conditions.relays.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "relay_blocks count (" + std::to_string(relay_blocks_arr.size()) +
                        ") must match conditions relay count (" + std::to_string(conditions.relays.size()) + ")");
                }
                for (size_t rl = 0; rl < relay_blocks_arr.size(); ++rl) {
                    Relay wit_relay;
                    wit_relay.relay_refs = conditions.relays[rl].relay_refs;
                    const UniValue& relay_spec = relay_blocks_arr[rl];
                    if (relay_spec.isNull() || !relay_spec.exists("blocks")) {
                        // Dummy relay — correct types, empty fields
                        for (const auto& cond_block : conditions.relays[rl].blocks) {
                            RungBlock dummy;
                            dummy.type = cond_block.type;
                            wit_relay.blocks.push_back(std::move(dummy));
                        }
                    } else {
                        const UniValue& rb_arr = relay_spec["blocks"].get_array();
                        if (rb_arr.size() != conditions.relays[rl].blocks.size()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "relay_blocks[" + std::to_string(rl) + "] block count (" +
                                std::to_string(rb_arr.size()) + ") must match conditions relay " +
                                std::to_string(rl) + " block count (" +
                                std::to_string(conditions.relays[rl].blocks.size()) + ")");
                        }
                        for (size_t b = 0; b < rb_arr.size(); ++b) {
                            wit_relay.blocks.push_back(
                                BuildWitnessBlock(rb_arr[b], mtx, input_idx, txdata, conditions));
                        }
                    }
                    ladder.relays.push_back(std::move(wit_relay));
                }
            } else {
                // No relay_blocks provided — build relay witness blocks with
                // pubkeys from relay_pubkeys (needed for key-consuming relay
                // blocks like SIG in KEY_REF_SIG patterns).
                for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
                    Relay wit_relay;
                    wit_relay.relay_refs = conditions.relays[rl].relay_refs;
                    size_t rpk_cursor = 0;
                    const auto& rpks = (rl < relay_pubkeys2.size())
                        ? relay_pubkeys2[rl]
                        : std::vector<std::vector<uint8_t>>{};
                    for (const auto& cond_block : conditions.relays[rl].blocks) {
                        RungBlock wit_block;
                        wit_block.type = cond_block.type;
                        // Add pubkeys for key-consuming blocks (merkle_pub_key)
                        size_t n_pk = rung::PubkeyCountForBlock(cond_block.type, cond_block);
                        if (n_pk == 0 && rung::IsKeyConsumingBlockType(cond_block.type) &&
                            rpk_cursor < rpks.size()) {
                            n_pk = rpks.size() - rpk_cursor;
                        }
                        for (size_t p = 0; p < n_pk && (rpk_cursor + p) < rpks.size(); ++p) {
                            wit_block.fields.push_back({RungDataType::PUBKEY, rpks[rpk_cursor + p]});
                        }
                        rpk_cursor += n_pk;
                        // Relay witness blocks must match the witness implicit layout.
                        // For SIG-family blocks, produce a real SIGNATURE (the relay
                        // is evaluated by EvalLadder — its SIG block must be SATISFIED
                        // for KEY_REF_SIG rungs that reference it).
                        if (rung::IsKeyConsumingBlockType(cond_block.type) && n_pk > 0) {
                            const auto& wit_layout = rung::GetImplicitLayout(
                                cond_block.type, 0 /*WITNESS*/);
                            for (uint8_t wl = 0; wl < wit_layout.count; ++wl) {
                                if (wit_layout.fields[wl].type == RungDataType::SIGNATURE) {
                                    // Sign with the relay's key (find matching privkey)
                                    bool signed_relay = false;
                                    // Find a privkey matching the relay's pubkey from
                                    // the signer's block specs
                                    if (rpk_cursor > 0 && (rpk_cursor - n_pk) < rpks.size()) {
                                        const auto& rpk = rpks[rpk_cursor - n_pk];
                                        // Search signer blocks for a matching privkey
                                        if (signer_obj.exists("blocks")) {
                                            const auto& sblocks = signer_obj["blocks"].get_array();
                                            for (size_t sb = 0; sb < sblocks.size() && !signed_relay; ++sb) {
                                                if (!sblocks[sb].exists("privkey")) continue;
                                                CKey k = DecodeSecret(sblocks[sb]["privkey"].get_str());
                                                if (!k.IsValid()) continue;
                                                CPubKey pub = k.GetPubKey();
                                                if (std::vector<uint8_t>(pub.begin(), pub.end()) == rpk) {
                                                    uint256 sighash;
                                                    if (rung::SignatureHashLadder(txdata, mtx, input_idx,
                                                            SIGHASH_DEFAULT, conditions, sighash)) {
                                                        unsigned char rsig[64];
                                                        uint256 raux = GetRandHash();
                                                        if (k.SignSchnorr(sighash, rsig, nullptr, raux)) {
                                                            wit_block.fields.push_back({RungDataType::SIGNATURE,
                                                                std::vector<uint8_t>(rsig, rsig + 64)});
                                                            signed_relay = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if (!signed_relay) {
                                        // Fallback: dummy signature (relay eval will fail)
                                        wit_block.fields.push_back({RungDataType::SIGNATURE,
                                            std::vector<uint8_t>(64, 0x00)});
                                    }
                                }
                            }
                        }
                        wit_relay.blocks.push_back(std::move(wit_block));
                    }
                    ladder.relays.push_back(std::move(wit_relay));
                }
            }
            // Copy relay_refs from the target rung's conditions to the witness rung.
            // For MLSC spends, ladder has exactly 1 rung (the target).
            if (!ladder.rungs.empty() && target_rung < conditions.rungs.size()) {
                ladder.rungs[0].relay_refs = conditions.rungs[target_rung].relay_refs;
            }
        }

        // Set witness coil from conditions (must match fund-time coil for Merkle leaf).
        // For MLSC the witness's coil.output_index must equal the spent vout —
        // consensus checks this AND uses it when reconstructing my_leaf, so it
        // must match what was committed at fund time for the rung being revealed.
        if (has_conditions) {
            ladder.coil = conditions.coil;
            if (is_mlsc) {
                ladder.coil.output_index = static_cast<uint8_t>(mtx.vin[input_idx].prevout.n);
            }
        }

        auto witness_bytes = rung::SerializeLadderWitness(ladder);
        mtx.vin[input_idx].scriptWitness.stack.clear();
        mtx.vin[input_idx].scriptWitness.stack.push_back(witness_bytes);

        // MLSC: build and push Merkle proof as stack[1]
        if (is_mlsc && has_conditions) {
            unsigned int target_rung = 0;
            if (signer_obj.exists("rung")) {
                target_rung = signer_obj["rung"].getInt<unsigned int>();
            }

            rung::MLSCProof mlsc_proof;
            mlsc_proof.total_rungs = static_cast<uint16_t>(conditions.rungs.size());
            mlsc_proof.total_relays = static_cast<uint16_t>(conditions.relays.size());
            mlsc_proof.rung_index = static_cast<uint16_t>(target_rung);

            mlsc_proof.revealed_rung = conditions.rungs[target_rung];

            // Reveal relays referenced by the target rung
            for (uint16_t ref : conditions.rungs[target_rung].relay_refs) {
                if (ref < conditions.relays.size()) {
                    mlsc_proof.revealed_relays.push_back({ref, conditions.relays[ref]});
                }
            }

            // Detect cross-rung mutation targets (RECURSE_MODIFIED/DECAY with rung_idx != target_rung)
            auto read_numeric = [](const RungField& f) -> uint32_t {
                uint32_t val = 0;
                for (size_t i = 0; i < f.data.size() && i < 4; ++i)
                    val |= static_cast<uint32_t>(f.data[i]) << (8 * i);
                return val;
            };
            for (const auto& blk : conditions.rungs[target_rung].blocks) {
                if (blk.type != rung::RungBlockType::RECURSE_MODIFIED &&
                    blk.type != rung::RungBlockType::RECURSE_DECAY) continue;
                // Collect NUMERIC fields
                std::vector<const RungField*> numerics;
                for (const auto& f : blk.fields) {
                    if (f.type == rung::RungDataType::NUMERIC) numerics.push_back(&f);
                }
                if (numerics.size() < 4) continue;
                // Legacy format (4-5 numerics): single mutation at rung 0
                // New format (6+ numerics): numerics[1]=num_mutations, 4 per mutation
                size_t start = 1, count = 1;
                if (numerics.size() >= 6) {
                    count = read_numeric(*numerics[1]);
                    start = 2;
                }
                for (size_t m = 0; m < count; ++m) {
                    size_t base = (numerics.size() >= 6) ? (start + 4 * m) : 1;
                    if (base >= numerics.size()) break;
                    uint32_t rung_idx_val = read_numeric(*numerics[base]);
                    if (rung_idx_val != target_rung && rung_idx_val < conditions.rungs.size()) {
                        bool already_added = false;
                        for (const auto& target : mlsc_proof.revealed_mutation_targets) {
                            if (target.idx == rung_idx_val) { already_added = true; break; }
                        }
                        if (!already_added) {
                            rung::MLSCMutationTarget mt;
                            mt.idx = static_cast<uint16_t>(rung_idx_val);
                            mt.rung = conditions.rungs[rung_idx_val];
                            if (rung_idx_val < rung_pubkeys2.size()) {
                                mt.pubkeys = rung_pubkeys2[rung_idx_val];
                            }
                            mlsc_proof.revealed_mutation_targets.push_back(std::move(mt));
                        }
                    }
                }
            }

#ifdef ENABLE_QABIO
            // QABI_PRIME cross-rung reveal: the covenant check in
            // EvalQABIPrimeBlock rebuilds a mutated conditions tree and
            // recomputes its MLSC root, comparing against the output
            // UTXO's committed root. That rebuild needs full tree
            // visibility — every rung's content plus its pubkey list.
            // Reveal every non-target rung as a mutation target with
            // its pubkey set inline so consensus can recompute leaf
            // hashes for SIG (or any other key-consuming) rungs.
            bool target_has_qabi_prime = false;
            for (const auto& blk : conditions.rungs[target_rung].blocks) {
                if (blk.type == rung::RungBlockType::QABI_PRIME) {
                    target_has_qabi_prime = true;
                    break;
                }
            }
            if (target_has_qabi_prime) {
                for (uint16_t r = 0; r < conditions.rungs.size(); ++r) {
                    if (r == target_rung) continue;
                    bool already_added = false;
                    for (const auto& target : mlsc_proof.revealed_mutation_targets) {
                        if (target.idx == r) { already_added = true; break; }
                    }
                    if (!already_added) {
                        rung::MLSCMutationTarget mt;
                        mt.idx = r;
                        mt.rung = conditions.rungs[r];
                        if (r < rung_pubkeys2.size()) {
                            mt.pubkeys = rung_pubkeys2[r];
                        }
                        mlsc_proof.revealed_mutation_targets.push_back(std::move(mt));
                    }
                }
            }
#endif // ENABLE_QABIO

            // TX_MLSC: build all leaves and compute O(log N) Merkle path.
            // v0.7: leaf order = [rung_leaf[0..N-1], relay_leaf[0..M-1]].
            // Each rung's coil.output_index must match what was committed at fund time.
            // For multi-output trees, sibling leaves are bound to other outputs and
            // must use their original output_index, not the spent vout.
            {
                std::vector<uint256> all_leaves;
                uint8_t spent_vout = static_cast<uint8_t>(mtx.vin[input_idx].prevout.n);
                for (uint16_t r = 0; r < conditions.rungs.size(); ++r) {
                    rung::CreationProofRung cp_rung;
                    for (const auto& block : conditions.rungs[r].blocks) {
                        cp_rung.blocks.push_back({
                            static_cast<uint16_t>(block.type),
                            static_cast<uint8_t>(block.inverted ? 1 : 0)
                        });
                    }
                    cp_rung.coil = conditions.coil;
                    uint8_t oi = (r < rung_output_indices2.size() && rung_output_indices2[r] != 0xFF)
                                     ? rung_output_indices2[r]
                                     : spent_vout;
                    cp_rung.coil.output_index = oi;
                    std::vector<std::vector<uint8_t>> rpks;
                    if (r < rung_pubkeys2.size()) rpks = rung_pubkeys2[r];
                    cp_rung.value_commitment = rung::ComputeValueCommitment(conditions.rungs[r], rpks);
                    all_leaves.push_back(rung::ComputeTxMLSCLeaf(cp_rung));
                }
                // v0.7: append relay leaves so the tree size matches what the
                // verifier reconstructs (total_rungs + total_relays).
                for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
                    rung::CreationProofRelay cp_relay;
                    for (const auto& blk : conditions.relays[rl].blocks) {
                        cp_relay.blocks.push_back({static_cast<uint16_t>(blk.type),
                                                    static_cast<uint8_t>(blk.inverted ? 1 : 0)});
                    }
                    cp_relay.relay_refs = conditions.relays[rl].relay_refs;
                    std::vector<std::vector<uint8_t>> rpks =
                        (rl < relay_pubkeys2.size()) ? relay_pubkeys2[rl]
                                                     : std::vector<std::vector<uint8_t>>{};
                    rung::Rung tmp; tmp.blocks = conditions.relays[rl].blocks;
                    cp_relay.value_commitment = rung::ComputeValueCommitment(tmp, rpks);
                    all_leaves.push_back(rung::ComputeTxMLSCRelayLeaf(cp_relay));
                }
                mlsc_proof.proof_mode = rung::MLSCProofMode::MERKLE_PATH;
                mlsc_proof.proof_hashes = rung::BuildMerklePath(all_leaves, target_rung);
            }

            auto proof_bytes = rung::SerializeMLSCProof(mlsc_proof);
            mtx.vin[input_idx].scriptWitness.stack.push_back(proof_bytes);

            // Auto-tweak detection: when all rungs were single-block SIG with the
            // same pubkey at fund time, createrungtx tweaked the conditions_root
            // for key-path spending. The verifier then needs the internal_pubkey
            // as a 3rd witness element to recompute the tweak. Mirror createrungtx's
            // detection logic here so the spend witness is shaped correctly.
            {
                uint256 raw_merkle = uint256();
                {
                    std::vector<uint256> leaves_for_root;
                    uint8_t spent_vout = static_cast<uint8_t>(mtx.vin[input_idx].prevout.n);
                    for (uint16_t r = 0; r < conditions.rungs.size(); ++r) {
                        rung::CreationProofRung cp_rung;
                        for (const auto& block : conditions.rungs[r].blocks) {
                            cp_rung.blocks.push_back({
                                static_cast<uint16_t>(block.type),
                                static_cast<uint8_t>(block.inverted ? 1 : 0)
                            });
                        }
                        cp_rung.coil = conditions.coil;
                        uint8_t oi = (r < rung_output_indices2.size() && rung_output_indices2[r] != 0xFF)
                                         ? rung_output_indices2[r]
                                         : spent_vout;
                        cp_rung.coil.output_index = oi;
                        std::vector<std::vector<uint8_t>> rpks;
                        if (r < rung_pubkeys2.size()) rpks = rung_pubkeys2[r];
                        cp_rung.value_commitment = rung::ComputeValueCommitment(conditions.rungs[r], rpks);
                        leaves_for_root.push_back(rung::ComputeTxMLSCLeaf(cp_rung));
                    }
                    raw_merkle = rung::BuildMerkleTree(std::move(leaves_for_root));
                }

                bool all_single_sig = !rung_pubkeys2.empty();
                std::vector<uint8_t> first_pk;
                for (size_t r = 0; r < conditions.rungs.size() && all_single_sig; ++r) {
                    if (conditions.rungs[r].blocks.size() != 1 ||
                        conditions.rungs[r].blocks[0].type != rung::RungBlockType::SIG) {
                        all_single_sig = false;
                        break;
                    }
                    if (r < rung_pubkeys2.size() && rung_pubkeys2[r].size() == 1) {
                        if (first_pk.empty()) {
                            first_pk = rung_pubkeys2[r][0];
                        } else if (first_pk != rung_pubkeys2[r][0]) {
                            all_single_sig = false;
                            break;
                        }
                    } else {
                        all_single_sig = false;
                        break;
                    }
                }

                if (all_single_sig && !first_pk.empty() && conditions.conditions_root.has_value() &&
                    *conditions.conditions_root != raw_merkle) {
                    std::vector<uint8_t> internal_pk = first_pk;
                    if (internal_pk.size() == 33) {
                        internal_pk.assign(first_pk.begin() + 1, first_pk.end());
                    }
                    if (internal_pk.size() == 32) {
                        auto tweaked = rung::ComputeTweakedConditionsRoot(internal_pk, raw_merkle);
                        if (tweaked && tweaked->first == *conditions.conditions_root) {
                            mtx.vin[input_idx].scriptWitness.stack.push_back(internal_pk);
                        }
                    }
                }
            }
        }
    }

    // Check if all inputs have witnesses
    for (const auto& vin : mtx.vin) {
        if (vin.scriptWitness.stack.empty()) {
            all_signed = false;
            break;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("complete", all_signed);
    return result;
},
    };
}

static RPCHelpMan computectvhash()
{
    return RPCHelpMan{
        "computectvhash",
        "Compute the BIP-119 CTV template hash for a v4 RUNG_TX transaction.\n"
        "The hash commits to the transaction's version, locktime, inputs, outputs, and input index.\n"
        "Use this to create CTV conditions that constrain how an output can be spent.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The spending transaction hex (the tx that will spend the CTV output)"},
            {"input_index", RPCArg::Type::NUM, RPCArg::Default{0}, "The input index being constrained by CTV"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "The 32-byte CTV template hash"},
            }
        },
        RPCExamples{
            HelpExampleCli("computectvhash", "\"0300000001...\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode transaction hex");
            }

            uint32_t input_index = 0;
            if (!request.params[1].isNull()) {
                input_index = request.params[1].getInt<uint32_t>();
            }

            if (input_index >= mtx.vin.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "input_index " + std::to_string(input_index) + " out of range (tx has " +
                    std::to_string(mtx.vin.size()) + " inputs)");
            }

            CTransaction tx(mtx);
            uint256 hash = rung::ComputeCTVHash(tx, input_index);

            UniValue result(UniValue::VOBJ);
            result.pushKV("hash", HexStr(hash));
            return result;
        },
    };
}

static RPCHelpMan generatepqkeypair()
{
    return RPCHelpMan{
        "generatepqkeypair",
        "Generate a post-quantum keypair for the specified scheme.\n"
        "Requires liboqs support.\n",
        {
            {"scheme", RPCArg::Type::STR, RPCArg::Optional::NO,
             "PQ scheme: FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "scheme", "The scheme used"},
            {RPCResult::Type::STR_HEX, "pubkey", "The public key (hex)"},
            {RPCResult::Type::STR_HEX, "privkey", "The private key (hex)"},
        }},
        RPCExamples{
            HelpExampleCli("generatepqkeypair", "FALCON512")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::string scheme_str = self.Arg<std::string>("scheme");
        RungScheme scheme;
        if (scheme_str == "FALCON512") scheme = RungScheme::FALCON512;
        else if (scheme_str == "FALCON1024") scheme = RungScheme::FALCON1024;
        else if (scheme_str == "DILITHIUM3") scheme = RungScheme::DILITHIUM3;
        else if (scheme_str == "SPHINCS_SHA") scheme = RungScheme::SPHINCS_SHA;
        else throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown PQ scheme: " + scheme_str);

        if (!rung::HasPQSupport()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ keygen requires liboqs support (not compiled in)");
        }

        std::vector<uint8_t> pubkey, privkey;
        if (!rung::GeneratePQKeypair(scheme, pubkey, privkey)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ keypair generation failed");
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("scheme", scheme_str);
        result.pushKV("pubkey", HexStr(pubkey));
        result.pushKV("privkey", HexStr(privkey));
        return result;
    },
    };
}

static RPCHelpMan pqpubkeycommit()
{
    return RPCHelpMan{
        "pqpubkeycommit",
        "Compute the SHA256 commitment hash of a post-quantum public key.\n"
        "Informational tool — createrungtx computes commitments automatically from pubkey fields.\n"
        "Use this to inspect what commitment a given key will produce.\n",
        {
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The full PQ public key (hex)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "commit", "The 32-byte SHA256 commitment hash"},
        }},
        RPCExamples{
            HelpExampleCli("pqpubkeycommit", "\"<897-byte falcon512 pubkey hex>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pubkey = ParseHex(self.Arg<std::string>("pubkey"));
        if (pubkey.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Empty pubkey");
        }

        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(hash);

        UniValue result(UniValue::VOBJ);
        result.pushKV("commit", HexStr(std::span<const unsigned char>(hash, CSHA256::OUTPUT_SIZE)));
        return result;
    },
    };
}

static RPCHelpMan extractadaptorsecret()
{
    return RPCHelpMan{
        "extractadaptorsecret",
        "Extract the adaptor secret from a pre-signature and adapted signature.\n"
        "Computes t = s_adapted - s_pre (scalar subtraction mod n).\n",
        {
            {"pre_sig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte pre-signature hex"},
            {"adapted_sig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte adapted signature hex"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "secret", "The 32-byte adaptor secret"},
        }},
        RPCExamples{
            HelpExampleCli("extractadaptorsecret", "\"<pre_sig_hex>\" \"<adapted_sig_hex>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pre_sig = ParseHex(self.Arg<std::string>("pre_sig"));
        auto adapted_sig = ParseHex(self.Arg<std::string>("adapted_sig"));

        if (pre_sig.size() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "pre_sig must be 64 bytes");
        }
        if (adapted_sig.size() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "adapted_sig must be 64 bytes");
        }

        std::vector<uint8_t> secret;
        if (!rung::ExtractAdaptorSecret(pre_sig, adapted_sig, secret)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to extract adaptor secret");
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("secret", HexStr(secret));
        return result;
    },
    };
}

static RPCHelpMan verifyadaptorpresig()
{
    return RPCHelpMan{
        "verifyadaptorpresig",
        "Verify an adaptor pre-signature.\n"
        "Checks that s'*G == R + e*P where e = H(R+T||P||m).\n",
        {
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte x-only public key hex"},
            {"adaptor_point", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte x-only adaptor point hex"},
            {"pre_sig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte pre-signature hex"},
            {"sighash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte sighash hex"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", "Whether the pre-signature is valid"},
        }},
        RPCExamples{
            HelpExampleCli("verifyadaptorpresig", "\"<pubkey>\" \"<adaptor_point>\" \"<pre_sig>\" \"<sighash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pubkey = ParseHex(self.Arg<std::string>("pubkey"));
        auto adaptor_point = ParseHex(self.Arg<std::string>("adaptor_point"));
        auto pre_sig = ParseHex(self.Arg<std::string>("pre_sig"));
        auto sighash_bytes = ParseHex(self.Arg<std::string>("sighash"));

        if (pubkey.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "pubkey must be 32 bytes (x-only)");
        }
        if (adaptor_point.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "adaptor_point must be 32 bytes (x-only)");
        }
        if (pre_sig.size() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "pre_sig must be 64 bytes");
        }
        if (sighash_bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "sighash must be 32 bytes");
        }

        uint256 sighash;
        std::memcpy(sighash.begin(), sighash_bytes.data(), 32);

        bool valid = rung::VerifyAdaptorPreSignature(pubkey, adaptor_point, pre_sig, sighash);

        UniValue result(UniValue::VOBJ);
        result.pushKV("valid", valid);
        return result;
    },
    };
}

static RPCHelpMan parseladder()
{
    return RPCHelpMan{"parseladder",
        "Parse a Ladder Script descriptor into conditions hex and MLSC root.\n",
        {
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The Ladder Script descriptor string"},
            {"keys", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Key alias map as JSON: {\"alias\": \"pubkey_hex\", ...}"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "conditions_hex", "Serialized conditions"},
                {RPCResult::Type::STR_HEX, "mlsc_root", "MLSC Merkle root"},
                {RPCResult::Type::NUM, "n_rungs", "Number of rungs"},
            },
        },
        RPCExamples{
            HelpExampleCli("parseladder", "\"ladder(sig(@alice))\" '{\"alice\": \"02...\"}'")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::string desc = request.params[0].get_str();

        std::map<std::string, std::vector<uint8_t>> keys;
        if (!request.params[1].isNull()) {
            UniValue keys_obj(UniValue::VOBJ);
            if (request.params[1].isObject()) {
                keys_obj = request.params[1];
            } else {
                keys_obj.read(request.params[1].get_str());
            }
            for (const auto& key : keys_obj.getKeys()) {
                keys[key] = ParseHex(keys_obj[key].get_str());
            }
        }

        rung::RungConditions conditions;
        std::vector<std::vector<std::vector<uint8_t>>> pubkeys;
        std::string error;
        if (!rung::ParseDescriptor(desc, keys, conditions, pubkeys, error)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "descriptor parse error: " + error);
        }

        // Serialize conditions
        rung::LadderWitness ladder;
        ladder.rungs = conditions.rungs;
        auto bytes = rung::SerializeLadderWitness(ladder, rung::SerializationContext::CONDITIONS);

        // Compute MLSC root via TX_MLSC leaf computation (must match VerifyRungTx)
        std::vector<rung::CreationProofRung> cp_rungs;
        for (size_t r = 0; r < conditions.rungs.size(); ++r) {
            rung::CreationProofRung cp_rung;
            for (const auto& block : conditions.rungs[r].blocks) {
                cp_rung.blocks.push_back({
                    static_cast<uint16_t>(block.type),
                    static_cast<uint8_t>(block.inverted ? 1 : 0)
                });
            }
            cp_rung.coil = conditions.coil;
            std::vector<std::vector<uint8_t>> rpks;
            if (r < pubkeys.size()) rpks = pubkeys[r];
            cp_rung.value_commitment = rung::ComputeValueCommitment(conditions.rungs[r], rpks);
            cp_rungs.push_back(std::move(cp_rung));
        }
        uint256 root = rung::ComputeTxMLSCRoot(cp_rungs);

        UniValue result(UniValue::VOBJ);
        result.pushKV("conditions_hex", HexStr(bytes));
        result.pushKV("mlsc_root", root.GetHex());
        result.pushKV("n_rungs", static_cast<int>(conditions.rungs.size()));
        return result;
    },
    };
}

static RPCHelpMan formatladder()
{
    return RPCHelpMan{"formatladder",
        "Format serialized conditions as a descriptor string.\n",
        {
            {"conditions_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized conditions hex"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "descriptor", "The descriptor string"},
            },
        },
        RPCExamples{
            HelpExampleCli("formatladder", "\"01...\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto bytes = ParseHex(request.params[0].get_str());
        rung::LadderWitness ladder;
        std::string error;
        if (!rung::DeserializeLadderWitness(bytes, ladder, error, rung::SerializationContext::CONDITIONS)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "deserialization error: " + error);
        }

        rung::RungConditions conditions;
        conditions.rungs = ladder.rungs;
        conditions.relays = ladder.relays;
        conditions.coil = ladder.coil;

        std::string desc = rung::FormatDescriptor(conditions);

        UniValue result(UniValue::VOBJ);
        result.pushKV("descriptor", desc);
        return result;
    },
    };
}

static RPCHelpMan computemutation()
{
    return RPCHelpMan{"computemutation",
        "Compute the expected output conditions after applying a RECURSE_MODIFIED or RECURSE_DECAY mutation.\n"
        "Takes the input descriptor, key map, and returns the mutated conditions hex + MLSC root.\n",
        {
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "Input descriptor"},
            {"keys", RPCArg::Type::STR, RPCArg::Optional::NO, "Key alias map JSON: {\"alias\": \"pubkey_hex\", ...}"},
            {"decay", RPCArg::Type::BOOL, RPCArg::DefaultHint{"false"}, "True for RECURSE_DECAY (negate deltas)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "conditions_hex", "Mutated conditions hex"},
            {RPCResult::Type::STR_HEX, "mlsc_root", "Expected output MLSC root"},
        }},
        RPCExamples{
            HelpExampleCli("computemutation",
                "\"ladder(and(sig(@a), amount_lock(10, 1000000000), recurse_modified(10, 1, 0, 1)))\" "
                "'{\"a\":\"02...\"}'")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::string desc = request.params[0].get_str();
        UniValue keys_val(UniValue::VOBJ);
        if (request.params[1].isObject()) keys_val = request.params[1];
        else keys_val.read(request.params[1].get_str());

        bool is_decay = !request.params[2].isNull() && request.params[2].get_bool();

        std::map<std::string, std::vector<uint8_t>> pubkey_map;
        for (const auto& alias : keys_val.getKeys()) {
            pubkey_map[alias] = ParseHex(keys_val[alias].get_str());
        }

        rung::RungConditions conditions;
        std::vector<std::vector<std::vector<uint8_t>>> rung_pubkeys;
        std::string error;
        if (!rung::ParseDescriptor(desc, pubkey_map, conditions, rung_pubkeys, error)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "parse error: " + error);
        }

        // Find RECURSE_MODIFIED or RECURSE_DECAY block, extract mutation specs
        for (auto& rung : conditions.rungs) {
            for (auto& blk : rung.blocks) {
                if (blk.type != RungBlockType::RECURSE_MODIFIED &&
                    blk.type != RungBlockType::RECURSE_DECAY) continue;

                // Parse mutation: numerics = [depth, block_idx, param_idx, delta]
                std::vector<RungField*> numerics;
                for (auto& f : blk.fields) {
                    if (f.type == RungDataType::NUMERIC) numerics.push_back(&f);
                }
                if (numerics.size() < 4) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "mutation block needs 4 NUMERIC fields");
                }

                auto read_num = [](const RungField& f) -> int64_t {
                    int64_t val = 0;
                    for (size_t i = 0; i < f.data.size() && i < 4; ++i)
                        val |= static_cast<int64_t>(f.data[i]) << (8 * i);
                    return val;
                };
                auto write_num = [](RungField& f, int64_t val) {
                    f.data.clear();
                    for (int i = 0; i < 4; ++i)
                        f.data.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xFF));
                };

                int64_t block_idx = read_num(*numerics[1]);
                int64_t param_idx = read_num(*numerics[2]);
                int64_t delta = read_num(*numerics[3]);
                if (is_decay || blk.type == RungBlockType::RECURSE_DECAY) delta = -delta;

                // Apply mutation to the target block's param_idx-th condition field
                if (block_idx < 0 || static_cast<size_t>(block_idx) >= rung.blocks.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "block_idx out of range");
                }
                auto& target_blk = rung.blocks[block_idx];
                size_t cond_idx = 0;
                bool applied = false;
                for (auto& f : target_blk.fields) {
                    if (!rung::IsConditionDataType(f.type)) continue;
                    if (static_cast<int64_t>(cond_idx) == param_idx) {
                        if (f.type != RungDataType::NUMERIC) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "mutation target is not NUMERIC");
                        }
                        write_num(f, read_num(f) + delta);
                        applied = true;
                        break;
                    }
                    ++cond_idx;
                }
                if (!applied) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "mutation param_idx not found");
                }
                goto done;
            }
        }
        throw JSONRPCError(RPC_INVALID_PARAMETER, "no RECURSE_MODIFIED or RECURSE_DECAY block found");
        done:

        // Compute mutated root via TX_MLSC leaf computation (must match VerifyRungTx)
        std::vector<rung::CreationProofRung> cp_rungs;
        for (size_t r = 0; r < conditions.rungs.size(); ++r) {
            rung::CreationProofRung cp_rung;
            for (const auto& block : conditions.rungs[r].blocks) {
                cp_rung.blocks.push_back({
                    static_cast<uint16_t>(block.type),
                    static_cast<uint8_t>(block.inverted ? 1 : 0)
                });
            }
            cp_rung.coil = conditions.coil;
            std::vector<std::vector<uint8_t>> rpks;
            if (r < rung_pubkeys.size()) rpks = rung_pubkeys[r];
            cp_rung.value_commitment = rung::ComputeValueCommitment(conditions.rungs[r], rpks);
            cp_rungs.push_back(std::move(cp_rung));
        }
        uint256 root = rung::ComputeTxMLSCRoot(cp_rungs);

        // Serialize mutated conditions
        rung::LadderWitness ladder;
        ladder.rungs = conditions.rungs;
        auto bytes = rung::SerializeLadderWitness(ladder, rung::SerializationContext::CONDITIONS);

        UniValue result(UniValue::VOBJ);
        result.pushKV("conditions_hex", HexStr(bytes));
        result.pushKV("mlsc_root", root.GetHex());
        return result;
    },
    };
}

static RPCHelpMan signladder()
{
    return RPCHelpMan{"signladder",
        "Sign a v4 RUNG_TX using descriptor notation.\n"
        "The descriptor defines the spending conditions. The keys map provides WIF private keys.\n"
        "The RPC handles all serialization, Merkle proof construction, and witness building.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The unsigned v4 transaction hex"},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "Ladder Script descriptor (same as parseladder)"},
            {"keys", RPCArg::Type::STR, RPCArg::Optional::NO, "Key alias map as JSON: {\"alias\": \"cWIF_privkey\", ...}"},
            {"spent_outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs being spent",
                {
                    {"spent_output", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A spent output",
                        {
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in BTC"},
                            {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scriptPubKey hex"},
                        },
                    },
                },
            },
            {"input_index", RPCArg::Type::NUM, RPCArg::DefaultHint{"0"}, "Input index to sign"},
            {"rung_index", RPCArg::Type::NUM, RPCArg::DefaultHint{"0"}, "Target rung index (for multi-rung conditions)"},
            {"keypath_key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "WIF private key for key-path spending. When provided, produces a 1-element witness (signature only)."},
            {"keypath_merkle_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte Merkle root hex for key-path spending with script tree. Omit for key-path-only (no conditions)."},
            {"shared_source", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Input index of an already-signed input from the same source tx. Uses SHARED proof mode (compact, references existing proof)."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The signed transaction hex"},
            {RPCResult::Type::BOOL, "complete", "Whether signing succeeded"},
        }},
        RPCExamples{
            HelpExampleCli("signladder",
                "<txhex> \"ladder(sig(@alice))\" '{\"alice\": \"cVt...\"}' "
                "'[{\"amount\":0.001,\"scriptPubKey\":\"c2...\"}]'")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        // 1. Decode transaction
        std::string hex_str = self.Arg<std::string>("hex");
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, hex_str)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode transaction");
        }
        if (mtx.version != CTransaction::RUNG_TX_VERSION) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction is not v4 RUNG_TX");
        }

        // Key-path signing: produce 1-element witness (signature only)
        // The keypath_key WIF is the INTERNAL private key. The signing uses the
        // tweaked key: internal_privkey + H_LadderTweak(internal_pubkey || merkle_root).
        // When merkle_root is null (key-path-only, no conditions tree), the tweak is
        // H_LadderTweak(internal_pubkey).
        if (!request.params[6].isNull() && !request.params[6].get_str().empty()) {
            CKey keypath_key = DecodeSecret(request.params[6].get_str());
            if (!keypath_key.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid keypath_key WIF");
            }

            unsigned int input_idx = 0;
            if (!request.params[4].isNull()) {
                input_idx = request.params[4].getInt<unsigned int>();
            }
            if (input_idx >= mtx.vin.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "input_index out of range");
            }

            // Parse spent outputs for sighash computation
            const UniValue& spent_arr = request.params[3].get_array();
            std::vector<CTxOut> spent_outputs;
            for (size_t i = 0; i < spent_arr.size(); ++i) {
                CTxOut out;
                out.nValue = AmountFromValue(spent_arr[i]["amount"]);
                auto spk_hex = spent_arr[i]["scriptPubKey"].get_str();
                auto spk_bytes = ParseHex(spk_hex);
                out.scriptPubKey = CScript(spk_bytes.begin(), spk_bytes.end());
                spent_outputs.push_back(out);
            }

            // Build precomputed transaction data
            CTransaction ctx(mtx);
            PrecomputedTransactionData txdata;
            txdata.Init(ctx, std::move(spent_outputs), true);

            // Compute key-path sighash
            uint256 sighash;
            if (!rung::SignatureHashLadderKeyPath(txdata, ctx, input_idx, SIGHASH_DEFAULT, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute key-path sighash");
            }

            // Sign with the INTERNAL key tweaked by LadderTweak. Caller passes
            // the optional keypath_merkle_root (param 7) when the output was
            // created with createrungtx + internal_pubkey + a script tree —
            // SignSchnorrLadder applies the tweak via ComputeLadderTweakHash.
            // For pure key-path-only outputs the merkle_root is null.
            std::vector<unsigned char> sig(64);
            uint256 aux; // zero aux for deterministic signing

            uint256 merkle_root; // default = null (key-path-only)
            const uint256* mr_ptr = &merkle_root;
            if (!request.params[7].isNull() && !request.params[7].get_str().empty()) {
                auto mr_opt = uint256::FromHex(request.params[7].get_str());
                if (!mr_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid keypath_merkle_root hex");
                }
                merkle_root = *mr_opt;
                mr_ptr = &merkle_root;
            }

            if (!keypath_key.SignSchnorrLadder(sighash, sig, mr_ptr, aux)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Schnorr signing failed");
            }

            // Set 1-element witness (key-path)
            mtx.vin[input_idx].scriptWitness.stack.clear();
            mtx.vin[input_idx].scriptWitness.stack.push_back(sig);

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
            result.pushKV("complete", true);
            return result;
        }

        // 2. Parse keys — WIF private keys, derive pubkeys
        std::string desc_str = request.params[1].get_str();
        UniValue keys_val(UniValue::VOBJ);
        if (request.params[2].isObject()) {
            keys_val = request.params[2];
        } else {
            keys_val.read(request.params[2].get_str());
        }

        // Build pubkey map (for ParseDescriptor) and privkey map (for signing).
        // Aliases prefixed with '_' are treated as raw hex data (e.g. preimages)
        // rather than WIF private keys, stored in data_map for witness building.
        std::map<std::string, std::vector<uint8_t>> pubkey_map;
        std::map<std::string, CKey> privkey_map;
        std::map<std::string, std::vector<uint8_t>> data_map;
        for (const auto& alias : keys_val.getKeys()) {
            std::string val = keys_val[alias].get_str();
            if (!alias.empty() && alias[0] == '_') {
                // '_'-prefixed alias: raw hex data (preimage, etc.)
                if (!IsHex(val)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Data alias _" + alias.substr(1) + " must be hex-encoded");
                }
                data_map[alias.substr(1)] = ParseHex(val);
                continue;
            }
            CKey key = DecodeSecret(val);
            if (!key.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    "Invalid WIF key for alias @" + alias);
            }
            CPubKey pub = key.GetPubKey();
            pubkey_map[alias] = std::vector<uint8_t>(pub.begin(), pub.end());
            privkey_map[alias] = key;
        }

        // 3. Parse descriptor → conditions + pubkeys
        rung::RungConditions conditions;
        std::vector<std::vector<std::vector<uint8_t>>> rung_pubkeys;
        std::string parse_error;
        if (!rung::ParseDescriptor(desc_str, pubkey_map, conditions, rung_pubkeys, parse_error)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "descriptor parse error: " + parse_error);
        }

        // 4. Build spent outputs
        const UniValue& spent_arr = request.params[3].get_array();
        if (spent_arr.size() != mtx.vin.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "spent_outputs count must match input count");
        }
        std::vector<CTxOut> spent_outputs;
        for (size_t i = 0; i < spent_arr.size(); ++i) {
            CTxOut txout;
            txout.nValue = AmountFromValue(spent_arr[i]["amount"]);
            auto spk = ParseHex(spent_arr[i]["scriptPubKey"].get_str());
            txout.scriptPubKey = CScript(spk.begin(), spk.end());
            spent_outputs.push_back(txout);
        }

        unsigned int input_idx = 0;
        if (!request.params[4].isNull()) {
            input_idx = request.params[4].getInt<unsigned int>();
        }
        unsigned int target_rung = 0;
        if (!request.params[5].isNull()) {
            target_rung = request.params[5].getInt<unsigned int>();
        }

        if (input_idx >= mtx.vin.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "input_index out of range");
        }
        if (target_rung >= conditions.rungs.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "rung_index out of range");
        }

        // Set conditions_root from spent output
        bool is_mlsc = rung::IsMLSCScript(spent_outputs[input_idx].scriptPubKey);
        if (is_mlsc) {
            uint256 root;
            rung::GetMLSCRoot(spent_outputs[input_idx].scriptPubKey, root);
            conditions.conditions_root = root;
        }

        // Auto key-path: if single-SIG rung and the root is a tweaked key, use key-path
        if (is_mlsc && conditions.rungs.size() == 1 &&
            conditions.rungs[0].blocks.size() == 1 &&
            conditions.rungs[0].blocks[0].type == rung::RungBlockType::SIG &&
            target_rung < rung_pubkeys.size() && rung_pubkeys[target_rung].size() == 1) {
            // Check if conditions_root is a tweaked version of the pubkey
            auto& pk = rung_pubkeys[target_rung][0];
            std::vector<uint8_t> xonly_pk;
            if (pk.size() == 33) xonly_pk.assign(pk.begin() + 1, pk.end());
            else xonly_pk = pk;

            if (conditions.conditions_root.has_value()) {
                XOnlyPubKey output_key;
                std::memcpy(output_key.begin(), conditions.conditions_root->data(), 32);
                XOnlyPubKey internal_key;
                std::memcpy(internal_key.begin(), xonly_pk.data(), 32);

                // Compute the Merkle root from the conditions for tweak verification
                // For single-rung: leaf == merkle_root
                rung::CreationProofRung cp_rung;
                for (const auto& block : conditions.rungs[0].blocks) {
                    cp_rung.blocks.push_back({
                        static_cast<uint16_t>(block.type),
                        static_cast<uint8_t>(block.inverted ? 1 : 0)
                    });
                }
                cp_rung.coil = conditions.coil;
                cp_rung.coil.output_index = mtx.vin[input_idx].prevout.n;
                cp_rung.value_commitment = rung::ComputeValueCommitment(
                    conditions.rungs[0], rung_pubkeys[target_rung]);
                uint256 leaf = rung::ComputeTxMLSCLeaf(cp_rung);

                // Check tweak both parities
                if (output_key.CheckLadderTweak(internal_key, leaf, false) ||
                    output_key.CheckLadderTweak(internal_key, leaf, true)) {
                    // Key-path viable! Find the privkey
                    for (const auto& [alias, key] : privkey_map) {
                        CPubKey pub = key.GetPubKey();
                        std::vector<uint8_t> pub_bytes(pub.begin(), pub.end());
                        if (pub_bytes == pk) {
                            // Compute key-path sighash
                            PrecomputedTransactionData kp_txdata;
                            kp_txdata.Init(mtx, std::vector<CTxOut>(spent_outputs), true);
                            uint256 kp_sighash;
                            if (rung::SignatureHashLadderKeyPath(kp_txdata, mtx, input_idx, SIGHASH_DEFAULT, kp_sighash)) {
                                std::vector<unsigned char> sig(64);
                                uint256 aux = GetRandHash();
                                if (key.SignSchnorrLadder(kp_sighash, sig, &leaf, aux)) {
                                    mtx.vin[input_idx].scriptWitness.stack.clear();
                                    mtx.vin[input_idx].scriptWitness.stack.push_back(sig);

                                    UniValue result(UniValue::VOBJ);
                                    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
                                    result.pushKV("complete", true);
                                    result.pushKV("spend_type", "key-path");
                                    return result;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5. Precompute transaction data (script-path fallback)
        PrecomputedTransactionData txdata;
        txdata.Init(mtx, std::vector<CTxOut>(spent_outputs));

        // 6. Compute sighash
        uint256 sighash;
        if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
        }

        // 7. Build witness for the target rung via BuildWitnessBlock
        // Convert descriptor keys to JSON block specs and use the existing
        // BuildWitnessBlock code path (same as signrungtx).
        const auto& target_cond_rung = conditions.rungs[target_rung];
        LadderWitness ladder;
        Rung wit_rung;

        size_t pk_cursor = 0;
        const auto& rung_pks = (target_rung < rung_pubkeys.size()) ? rung_pubkeys[target_rung] : std::vector<std::vector<uint8_t>>{};

        for (size_t b = 0; b < target_cond_rung.blocks.size(); ++b) {
            const auto& cond_block = target_cond_rung.blocks[b];
            size_t n_pks = rung::PubkeyCountForBlock(cond_block.type, cond_block);

            // Build a JSON block spec that BuildWitnessBlock understands
            UniValue block_spec(UniValue::VOBJ);
            block_spec.pushKV("type", rung::BlockTypeName(cond_block.type));

            // MULTISIG v2 / TIMELOCKED_MULTISIG v2: pubkeys live in
            // cond_block.merkle_pubkeys (parser side hint), not in the
            // positional rung_pks list. Pull them straight from there and
            // match privkey_map entries by deriving each candidate's pubkey.
            // Only add up to K privkeys — the threshold lives in the first
            // NUMERIC conditions field (or first NUMERIC for MULTISIG, second
            // NUMERIC is CSV for TIMELOCKED_MULTISIG; both have K at index 0).
            if (cond_block.type == RungBlockType::MULTISIG ||
                cond_block.type == RungBlockType::TIMELOCKED_MULTISIG) {
                uint32_t threshold = 0;
                if (!cond_block.fields.empty() &&
                    cond_block.fields[0].type == RungDataType::NUMERIC) {
                    for (size_t i = 0; i < cond_block.fields[0].data.size() && i < 4; ++i)
                        threshold |= static_cast<uint32_t>(cond_block.fields[0].data[i]) << (8 * i);
                }
                UniValue pk_arr(UniValue::VARR);
                UniValue priv_arr(UniValue::VARR);
                for (const auto& pk_bytes : cond_block.merkle_pubkeys) {
                    pk_arr.push_back(HexStr(pk_bytes));
                }
                // Pick K matching privkeys (first-match order over merkle_pubkeys).
                for (const auto& pk_bytes : cond_block.merkle_pubkeys) {
                    if (priv_arr.size() >= threshold) break;
                    for (const auto& [alias, key] : privkey_map) {
                        CPubKey pub = key.GetPubKey();
                        if (std::vector<uint8_t>(pub.begin(), pub.end()) == pk_bytes) {
                            priv_arr.push_back(EncodeSecret(key));
                            break;
                        }
                    }
                }
                block_spec.pushKV("pubkeys", pk_arr);
                block_spec.pushKV("privkeys", priv_arr);
                wit_rung.blocks.push_back(
                    BuildWitnessBlock(block_spec, mtx, input_idx, txdata, conditions));
                continue; // MULTISIG handled — skip the generic per-block flow.
            }

            bool is_sig = rung::IsKeyConsumingBlockType(cond_block.type);

            // P2PKH/P2WPKH_LEGACY: pubkey_count=0 but key_consuming=true.
            // Keys aren't in rung_pks (they're HASH160'd in conditions).
            // Match by computing HASH160(pubkey) for each privkey and comparing.
            if (n_pks == 0 && is_sig &&
                (cond_block.type == RungBlockType::P2PKH_LEGACY ||
                 cond_block.type == RungBlockType::P2WPKH_LEGACY)) {
                // Find HASH160 field in conditions block
                const rung::RungField* h160 = nullptr;
                for (const auto& f : cond_block.fields) {
                    if (f.type == RungDataType::HASH160) { h160 = &f; break; }
                }
                if (h160 && h160->data.size() == 20) {
                    for (const auto& [alias, key] : privkey_map) {
                        CPubKey pub = key.GetPubKey();
                        std::vector<uint8_t> computed(CHash160::OUTPUT_SIZE);
                        CHash160().Write(std::span<const uint8_t>(pub.begin(), pub.end())).Finalize(computed);
                        if (computed == h160->data) {
                            block_spec.pushKV("privkey", EncodeSecret(key));
                            break;
                        }
                    }
                }
            }

            if (n_pks >= 1 && pk_cursor < rung_pks.size()) {
                // Add privkey for signature blocks
                if (is_sig) {
                    const auto& pk_bytes = rung_pks[pk_cursor];
                    for (const auto& [alias, key] : privkey_map) {
                        CPubKey pub = key.GetPubKey();
                        if (std::vector<uint8_t>(pub.begin(), pub.end()) == pk_bytes) {
                            block_spec.pushKV("privkey", EncodeSecret(key));
                            break;
                        }
                    }
                }

                // Add pubkeys for blocks with pubkey_count > 1.
                // All blocks (incl. HTLC v0.7): pass ALL pubkeys; the per-block
                // handler reads them positionally.
                if (n_pks >= 2) {
                    UniValue pk_arr(UniValue::VARR);
                    for (size_t p = 0; p < n_pks && (pk_cursor + p) < rung_pks.size(); ++p) {
                        pk_arr.push_back(HexStr(rung_pks[pk_cursor + p]));
                    }
                    block_spec.pushKV("pubkeys", pk_arr);

                    if (cond_block.type == RungBlockType::MUSIG_THRESHOLD) {
                        // MUSIG_THRESHOLD wants a `privkeys` array too. MULTISIG
                        // and TIMELOCKED_MULTISIG already returned above via
                        // their dedicated merkle_pubkeys branch.
                        UniValue privkeys_arr(UniValue::VARR);
                        for (size_t p = 0; p < n_pks && (pk_cursor + p) < rung_pks.size(); ++p) {
                            for (const auto& [alias, key] : privkey_map) {
                                CPubKey pub = key.GetPubKey();
                                if (std::vector<uint8_t>(pub.begin(), pub.end()) == rung_pks[pk_cursor + p]) {
                                    privkeys_arr.push_back(EncodeSecret(key));
                                    break;
                                }
                            }
                        }
                        block_spec.pushKV("privkeys", privkeys_arr);
                    }
                } else if (n_pks == 1) {
                    // Single pubkey blocks: add pubkey hex for witness (merkle_pub_key).
                    // For SIG-family blocks, SignSingleKey adds it from privkey;
                    // for PLC/anchor blocks, the default handler reads it from here.
                    block_spec.pushKV("pubkey", HexStr(rung_pks[pk_cursor]));
                }
                pk_cursor += n_pks;
            }

            // Preimage-bearing blocks: require preimage in the witness block.
            // User provides via '_preimage' (single) or '_preimage', '_preimage2' etc.
            // Multi-hash blocks (ANCHOR_SEAL) need multiple preimages passed as '_preimages' JSON array.
            if (cond_block.type == RungBlockType::HASH_SIG ||
                cond_block.type == RungBlockType::HTLC ||
                cond_block.type == RungBlockType::HASH_GUARDED ||
                cond_block.type == RungBlockType::TAGGED_HASH ||
                cond_block.type == RungBlockType::ANCHOR_POOL ||
                cond_block.type == RungBlockType::ANCHOR_RESERVE ||
                cond_block.type == RungBlockType::ANCHOR_SEAL) {
                // Check for preimages array first (multi-hash blocks)
                auto it_arr = data_map.find("preimages");
                if (it_arr != data_map.end()) {
                    // _preimages is a JSON array hex-encoded as a single hex blob.
                    // Not ideal — use individual _preimage entries instead.
                }
                auto it = data_map.find("preimage");
                if (it != data_map.end()) {
                    block_spec.pushKV("preimage", HexStr(it->second));
                }
                // Additional preimages: _preimage2, _preimage3 etc.
                auto it2 = data_map.find("preimage2");
                if (it2 != data_map.end()) {
                    // Build preimages array for multi-hash blocks
                    UniValue pi_arr(UniValue::VARR);
                    pi_arr.push_back(HexStr(it->second));
                    pi_arr.push_back(HexStr(it2->second));
                    auto it3 = data_map.find("preimage3");
                    if (it3 != data_map.end()) pi_arr.push_back(HexStr(it3->second));
                    block_spec.pushKV("preimages", pi_arr);
                    // Remove single preimage to avoid conflict
                    // (default handler checks preimages first, then preimage)
                }
            }

            // Use BuildWitnessBlock (the tested code path from signrungtx)
            wit_rung.blocks.push_back(
                BuildWitnessBlock(block_spec, mtx, input_idx, txdata, conditions));
        }

        ladder.rungs.push_back(std::move(wit_rung));
        ladder.coil = conditions.coil;

        // TX_MLSC: output_index comes from the spent prevout
        if (is_mlsc) {
            ladder.coil.output_index = mtx.vin[input_idx].prevout.n;
            conditions.coil.output_index = mtx.vin[input_idx].prevout.n;
        }

        // 8. Serialize witness
        auto witness_bytes = rung::SerializeLadderWitness(ladder);
        mtx.vin[input_idx].scriptWitness.stack.clear();
        mtx.vin[input_idx].scriptWitness.stack.push_back(witness_bytes);

        // 9. Build MLSC proof (or SHARED proof if shared_source is specified)
        if (is_mlsc) {
            // Check for shared_source parameter (param index 8)
            if (!request.params[8].isNull()) {
                unsigned int shared_src = request.params[8].getInt<unsigned int>();
                if (shared_src >= mtx.vin.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "shared_source out of range");
                }
                if (shared_src == input_idx) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "shared_source cannot reference self");
                }
                // Build SHARED proof: reference the source input's full proof
                rung::MLSCProof shared_proof;
                shared_proof.proof_mode = rung::MLSCProofMode::SHARED;
                shared_proof.shared_source_input = static_cast<uint16_t>(shared_src);
                shared_proof.total_rungs = static_cast<uint16_t>(conditions.rungs.size());
                shared_proof.total_relays = 0;
                shared_proof.rung_index = static_cast<uint16_t>(target_rung);
                shared_proof.revealed_rung = conditions.rungs[target_rung];

                auto proof_bytes = rung::SerializeMLSCProof(shared_proof);
                mtx.vin[input_idx].scriptWitness.stack.push_back(proof_bytes);

                UniValue result(UniValue::VOBJ);
                result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
                result.pushKV("complete", true);
                return result;
            }

            rung::MLSCProof mlsc_proof;
            mlsc_proof.rung_index = static_cast<uint16_t>(target_rung);
            mlsc_proof.revealed_rung = conditions.rungs[target_rung];
            mlsc_proof.total_rungs = static_cast<uint16_t>(conditions.rungs.size());
            mlsc_proof.total_relays = static_cast<uint16_t>(conditions.relays.size());

            // Reveal relays referenced by target rung
            for (uint16_t ref : conditions.rungs[target_rung].relay_refs) {
                if (ref < conditions.relays.size()) {
                    mlsc_proof.revealed_relays.push_back({ref, conditions.relays[ref]});
                }
            }

            // Build all rung leaves from the descriptor for Merkle path computation.
            // Each rung's coil.output_index must match what was used at creation time.
            // v0.7: also append relay leaves so the tree size = total_rungs + total_relays.
            uint32_t spent_vout = mtx.vin[input_idx].prevout.n;
            std::vector<uint256> all_leaves;
            for (uint16_t r = 0; r < conditions.rungs.size(); ++r) {
                rung::CreationProofRung cp_rung;
                for (const auto& block : conditions.rungs[r].blocks) {
                    cp_rung.blocks.push_back({
                        static_cast<uint16_t>(block.type),
                        static_cast<uint8_t>(block.inverted ? 1 : 0)
                    });
                }
                cp_rung.coil = conditions.coil;
                cp_rung.coil.output_index = spent_vout;
                std::vector<std::vector<uint8_t>> rpks;
                if (r < rung_pubkeys.size()) rpks = rung_pubkeys[r];
                cp_rung.value_commitment = rung::ComputeValueCommitment(conditions.rungs[r], rpks);
                all_leaves.push_back(rung::ComputeTxMLSCLeaf(cp_rung));
            }
            // signladder (descriptor-based) doesn't currently emit relays, so
            // conditions.relays is empty here and the relay-leaf loop is a no-op.
            // If/when descriptors gain relay syntax, populate relay pubkeys
            // alongside ParseDescriptor and append CreationProofRelay leaves.
            for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
                rung::CreationProofRelay cp_relay;
                for (const auto& blk : conditions.relays[rl].blocks) {
                    cp_relay.blocks.push_back({static_cast<uint16_t>(blk.type),
                                                static_cast<uint8_t>(blk.inverted ? 1 : 0)});
                }
                cp_relay.relay_refs = conditions.relays[rl].relay_refs;
                rung::Rung tmp; tmp.blocks = conditions.relays[rl].blocks;
                cp_relay.value_commitment = rung::ComputeValueCommitment(tmp, {});
                all_leaves.push_back(rung::ComputeTxMLSCRelayLeaf(cp_relay));
            }

            // Build O(log N) Merkle path
            mlsc_proof.proof_mode = rung::MLSCProofMode::MERKLE_PATH;
            mlsc_proof.proof_hashes = rung::BuildMerklePath(all_leaves, target_rung);

            auto proof_bytes = rung::SerializeMLSCProof(mlsc_proof);
            mtx.vin[input_idx].scriptWitness.stack.push_back(proof_bytes);
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
        result.pushKV("complete", true);
        return result;
    },
    };
}

// ============================================================================
// TX_MLSC: Create a transaction with shared condition tree
// ============================================================================

static RPCHelpMan createrungtx()
{
    return RPCHelpMan{
        "createrungtx",
        "Create an unsigned v4 RUNG_TX transaction with a shared condition tree.\n"
        "One conditions_root for the entire transaction. Outputs are value-only on the wire (TX_MLSC format).\n"
        "Each rung's coil specifies which output it governs (output_index).\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Transaction inputs",
                {
                    {"input", RPCArg::Type::OBJ, RPCArg::Optional::NO, "An input",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output index"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "nSequence value"},
                        },
                    },
                },
            },
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Output values (satoshi amounts)",
                {
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in BTC for this output"},
                },
            },
            {"rungs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Rung definitions for the shared tree",
                {
                    {"rung", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A rung in the shared tree",
                        {
                            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Which output this rung governs (0-based)"},
                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Block specs",
                                {
                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A block",
                                        {
                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                            {"inverted", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Invert evaluation"},
                                            {"fields", RPCArg::Type::ARR, RPCArg::Optional::NO, "Fields",
                                                {
                                                    {"field", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A field",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Data type"},
                                                            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Field data hex"},
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            {"coil", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Coil metadata",
                                {
                                    {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "UNLOCK or UNLOCK_TO"},
                                    {"scheme", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SCHNORR or ECDSA"},
                                },
                            },
                        },
                    },
                },
            },
            {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Transaction nLockTime (default 0)"},
            {"internal_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte x-only internal pubkey for key-path spending. When provided, conditions_root is tweaked."},
            {"qabi_block", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                "Optional serialised QABIBlock bytes (hex). Present iff this is a QABIO batch tx. "
                "When non-empty, tx.qabi_block is populated, which marks the tx as a QABIO carrier. "
                "Use qabi_buildblock to construct the serialised bytes."},
            {"relays", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                "Shared relay blocks (v0.7). Each relay carries a list of blocks (typically a SIG block "
                "whose pubkey is referenced by KEY_REF_SIG in one or more rungs). Relays are folded into "
                "the conditions_root tree at positions [N..N+M-1].",
                {
                    {"relay", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "A relay",
                        {
                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Relay block specs",
                                {
                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A block",
                                        {
                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                            {"fields", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Fields",
                                                {
                                                    {"field", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A field",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Data type"},
                                                            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Field data hex"},
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            {"relay_refs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Relay indices this relay depends on",
                                {
                                    {"i", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
                                },
                            },
                        },
                    },
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The unsigned TX_MLSC transaction hex"},
            {RPCResult::Type::STR_HEX, "conditions_root", "The shared conditions root (tweaked if internal_pubkey provided)"},
            {RPCResult::Type::STR_HEX, "merkle_root", "The raw Merkle root (before tweaking)"},
            {RPCResult::Type::NUM, "n_rungs", "Total rungs in the shared tree"},
            {RPCResult::Type::BOOL, "key_path", "Whether key-path spending is enabled (auto-detected or explicit)"},
            {RPCResult::Type::STR_HEX, "internal_pubkey", /*optional=*/ true, "Internal pubkey used for tweak (if key_path is true)"},
            {RPCResult::Type::STR_HEX, "scriptPubKey", /*optional=*/ true, "The shared MLSC scriptPubKey hex (0xDF + root)"},
        }},
        RPCExamples{
            HelpExampleCli("createrungtx",
                "'[{\"txid\":\"...\",\"vout\":0}]' "
                "'[0.001, 0.002]' "
                "'[{\"output_index\":0,\"blocks\":[{\"type\":\"SIG\",\"fields\":[{\"type\":\"SCHEME\",\"hex\":\"01\"}]}]},"
                "{\"output_index\":1,\"blocks\":[{\"type\":\"SIG\",\"fields\":[{\"type\":\"SCHEME\",\"hex\":\"01\"}]}]}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& inputs_arr = request.params[0].get_array();
    const UniValue& outputs_arr = request.params[1].get_array();
    const UniValue& rungs_arr = request.params[2].get_array();

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    if (!request.params[3].isNull()) {
        mtx.nLockTime = request.params[3].getInt<uint32_t>();
    }

    // Parse inputs
    for (size_t i = 0; i < inputs_arr.size(); ++i) {
        const UniValue& inp = inputs_arr[i];
        CTxIn txin;
        auto hash = uint256::FromHex(inp["txid"].get_str());
        if (!hash) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txid");
        txin.prevout.hash = Txid::FromUint256(*hash);
        txin.prevout.n = inp["vout"].getInt<uint32_t>();
        if (inp.exists("sequence")) {
            txin.nSequence = inp["sequence"].getInt<uint32_t>();
        } else {
            txin.nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
        }
        mtx.vin.push_back(txin);
    }

    // Parse output values
    for (size_t i = 0; i < outputs_arr.size(); ++i) {
        CTxOut txout;
        txout.nValue = AmountFromValue(outputs_arr[i]);
        // scriptPubKey will be set by the serializer (inflation from conditions_root)
        mtx.vout.push_back(txout);
    }

    // Parse rungs and compute conditions root
    std::vector<rung::CreationProofRung> cp_rungs;
    std::vector<rung::Rung> all_rungs;
    std::vector<std::vector<std::vector<uint8_t>>> all_rung_pubkeys;

    for (size_t r = 0; r < rungs_arr.size(); ++r) {
        const UniValue& rung_obj = rungs_arr[r];
        uint8_t output_index = rung_obj["output_index"].getInt<int>();

        if (output_index >= outputs_arr.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Rung " + std::to_string(r) + ": output_index " +
                std::to_string(output_index) + " >= n_outputs " +
                std::to_string(outputs_arr.size()));
        }

        // Parse blocks as CONDITIONS (no witness fields like PUBKEY/SIGNATURE).
        // This matches what the spending descriptor produces at spend time.
        const UniValue& blocks_arr = rung_obj["blocks"].get_array();
        rung::Rung rung;
        std::vector<std::vector<uint8_t>> rung_pks;
        for (size_t b = 0; b < blocks_arr.size(); ++b) {
            rung.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/true, &rung_pks));
        }

        // TX_MLSC: pubkeys for merkle_pub_key binding (folded into value_commitment).
        // Provided separately since they're witness-side, not in conditions fields.
        // If x-only (32 bytes), prepend 0x02 to match the compressed format used
        // in the witness (merkle_pub_key binds compressed pubkeys, not x-only).
        if (rung_obj.exists("pubkeys")) {
            const UniValue& pks_arr = rung_obj["pubkeys"].get_array();
            for (size_t p = 0; p < pks_arr.size(); ++p) {
                auto pk = ParseHex(pks_arr[p].get_str());
                if (pk.size() == 32) {
                    pk.insert(pk.begin(), 0x02); // x-only → compressed (even Y)
                }
                rung_pks.push_back(std::move(pk));
            }
        }

        all_rungs.push_back(rung);
        all_rung_pubkeys.push_back(rung_pks);

        // Build creation proof rung
        rung::CreationProofRung cp_rung;
        for (const auto& block : rung.blocks) {
            cp_rung.blocks.push_back({
                static_cast<uint16_t>(block.type),
                static_cast<uint8_t>(block.inverted ? 1 : 0)
            });
        }

        // Coil: full parse so scheme/attestation/address bind into the leaf
        // at fund time. Previously only coil.type was read here, which meant
        // a FALCON512/DILITHIUM3 rung committed to the default SCHNORR
        // coil — and a spend-time reconstruction with the real scheme would
        // produce a different leaf and fail Merkle verification.
        if (rung_obj.exists("coil")) {
            cp_rung.coil = ParseCoil(rung_obj["coil"]);
        }
        cp_rung.coil.output_index = output_index;

        // Compute value_commitment = SHA256(field_values || pubkeys)
        cp_rung.value_commitment = rung::ComputeValueCommitment(rung, rung_pks);

        cp_rungs.push_back(std::move(cp_rung));
    }

    // v0.7: parse optional relays (params[6]) and build relay leaves.
    // Relays are folded into the same shared conditions_root tree as rungs,
    // closing the KEY_REF_SIG relay-pubkey-swap bug (E-008).
    std::vector<rung::CreationProofRelay> cp_relays;
    std::vector<rung::Relay> all_relays;
    std::vector<std::vector<std::vector<uint8_t>>> all_relay_pubkeys;
    if (request.params.size() > 6 && !request.params[6].isNull()) {
        const UniValue& relays_arr = request.params[6].get_array();
        if (relays_arr.size() > rung::MAX_RELAYS) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "createrungtx: relays count " + std::to_string(relays_arr.size()) +
                " exceeds MAX_RELAYS = " + std::to_string(rung::MAX_RELAYS));
        }
        for (size_t r = 0; r < relays_arr.size(); ++r) {
            const UniValue& relay_obj = relays_arr[r];
            const UniValue& blocks_arr = relay_obj["blocks"].get_array();
            rung::Relay relay;
            std::vector<std::vector<uint8_t>> relay_pks;
            for (size_t b = 0; b < blocks_arr.size(); ++b) {
                relay.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/true, &relay_pks));
            }
            if (relay_obj.exists("relay_refs")) {
                const UniValue& refs = relay_obj["relay_refs"].get_array();
                for (size_t i = 0; i < refs.size(); ++i) {
                    relay.relay_refs.push_back(refs[i].getInt<uint16_t>());
                }
            }
            all_relays.push_back(relay);
            all_relay_pubkeys.push_back(relay_pks);
            // Build CreationProofRelay
            rung::CreationProofRelay cp_relay;
            for (const auto& blk : relay.blocks) {
                cp_relay.blocks.push_back({static_cast<uint16_t>(blk.type),
                                            static_cast<uint8_t>(blk.inverted ? 1 : 0)});
            }
            cp_relay.relay_refs = relay.relay_refs;
            rung::Rung tmp; tmp.blocks = relay.blocks;
            cp_relay.value_commitment = rung::ComputeValueCommitment(tmp, relay_pks);
            cp_relays.push_back(std::move(cp_relay));
        }
    }

    // Compute raw Merkle root from rung leaves + relay leaves
    uint256 merkle_root = rung::ComputeTxMLSCRoot(cp_rungs, cp_relays);

    // Key-path tweak: auto-detect or use explicit internal_pubkey.
    // If all rungs are single-SIG with the same pubkey, auto-tweak for key-path spending.
    bool has_explicit_pubkey = !request.params[4].isNull() && !request.params[4].get_str().empty();
    std::vector<uint8_t> internal_pubkey_bytes;

    if (has_explicit_pubkey) {
        internal_pubkey_bytes = ParseHex(request.params[4].get_str());
        if (internal_pubkey_bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "internal_pubkey must be 32 bytes (x-only)");
        }
    } else if (all_rung_pubkeys.size() > 0) {
        // Auto-detect: all rungs are single-block SIG with the same pubkey
        bool all_single_sig = true;
        std::vector<uint8_t> first_pk;
        for (size_t r = 0; r < all_rungs.size(); ++r) {
            if (all_rungs[r].blocks.size() != 1 ||
                all_rungs[r].blocks[0].type != rung::RungBlockType::SIG) {
                all_single_sig = false;
                break;
            }
            if (r < all_rung_pubkeys.size() && all_rung_pubkeys[r].size() == 1) {
                if (first_pk.empty()) {
                    first_pk = all_rung_pubkeys[r][0];
                } else if (first_pk != all_rung_pubkeys[r][0]) {
                    all_single_sig = false;
                    break;
                }
            }
        }
        if (all_single_sig && !first_pk.empty()) {
            // Strip 0x02/0x03 prefix if compressed (33 bytes → 32 x-only)
            if (first_pk.size() == 33) {
                internal_pubkey_bytes.assign(first_pk.begin() + 1, first_pk.end());
            } else {
                internal_pubkey_bytes = first_pk;
            }
        }
    }

    if (!internal_pubkey_bytes.empty()) {
        auto tweaked = rung::ComputeTweakedConditionsRoot(internal_pubkey_bytes, merkle_root);
        if (!tweaked) {
            if (has_explicit_pubkey) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to compute tweaked key from internal_pubkey");
            }
            // Auto-tweak failed — fall back to plain root
            mtx.conditions_root = merkle_root;
        } else {
            mtx.conditions_root = tweaked->first;
        }
    } else {
        mtx.conditions_root = merkle_root;
    }

    // Inflate outputs with the shared MLSC scriptPubKey so downstream
    // tooling that reads vout[i].scriptPubKey sees the expected 0xDF form.
    // For DATA_RETURN outputs (single rung with one DATA_RETURN block,
    // value == 0), the data payload is appended to the SPK so the wire-
    // format serialiser writes the data_len + data bytes that the
    // TX_MLSC DATA_RETURN encoding requires.
    CScript mlsc_spk;
    mlsc_spk.push_back(0xDF);
    mlsc_spk.insert(mlsc_spk.end(), mtx.conditions_root.begin(), mtx.conditions_root.end());
    for (size_t oi = 0; oi < mtx.vout.size(); ++oi) {
        std::vector<uint8_t> data_payload;
        for (size_t r = 0; r < cp_rungs.size(); ++r) {
            if (cp_rungs[r].coil.output_index != oi) continue;
            if (all_rungs[r].blocks.size() != 1) continue;
            const auto& blk = all_rungs[r].blocks[0];
            if (blk.type != rung::RungBlockType::DATA_RETURN) continue;
            if (blk.fields.empty() || blk.fields[0].type != rung::RungDataType::DATA) continue;
            data_payload = blk.fields[0].data;
            break;
        }
        if (!data_payload.empty()) {
            mtx.vout[oi].scriptPubKey = rung::CreateMLSCScript(mtx.conditions_root, data_payload);
        } else {
            mtx.vout[oi].scriptPubKey = mlsc_spk;
        }
    }

    // QABIO: optional qabi_block tx-level field. When set, this tx is a
    // QABIO batch carrier and the coordinator will later sign via
    // qabi_signqabo (which populates tx.aggregated_sig).
#ifdef ENABLE_QABIO
    if (!request.params[5].isNull()) {
        auto qb_bytes = ParseHex(request.params[5].get_str());
        if (qb_bytes.size() > rung::QABI_BLOCK_MAX_HARD) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "qabi_block exceeds QABI_BLOCK_MAX_HARD");
        }
        // Strict parse check: the bytes must be a well-formed QABIBlock.
        if (!qb_bytes.empty()) {
            std::string parse_err;
            auto parsed = rung::ParseQABIBlock(qb_bytes, parse_err);
            if (!parsed) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "qabi_block parse failed: " + parse_err);
            }
        }
        mtx.qabi_block = std::move(qb_bytes);
    }
#else
    if (!request.params[5].isNull() && !request.params[5].get_str().empty()) {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND,
            "qabi_block parameter requires QABIO support — rebuild with -DENABLE_QABIO=ON");
    }
#endif // ENABLE_QABIO

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("conditions_root", mtx.conditions_root.GetHex());
    result.pushKV("merkle_root", merkle_root.GetHex());
    if (!internal_pubkey_bytes.empty()) {
        result.pushKV("internal_pubkey", HexStr(internal_pubkey_bytes));
        result.pushKV("key_path", true);
    } else {
        result.pushKV("key_path", false);
    }
    // Output the scriptPubKey hex for use in signladder spent_outputs.
    // This is the raw bytes (0xDF + root in wire order), NOT GetHex() which reverses.
    CScript mlsc_spk_out = rung::CreateMLSCScript(mtx.conditions_root);
    result.pushKV("scriptPubKey", HexStr(mlsc_spk_out));
    result.pushKV("n_rungs", (int)cp_rungs.size());
    return result;
},
    };
}

// ============================================================================
// QABI RPC commands (BIP-YYYY). Gated on ENABLE_QABIO — when the
// extension is disabled, these commands are not registered and the
// qabi_* RPC family returns "method not found" to callers.
// ============================================================================
#ifdef ENABLE_QABIO

static RPCHelpMan qabi_buildblock()
{
    return RPCHelpMan{
        "qabi_buildblock",
        "Build a QABIBlock from the given participants and outputs, and return\n"
        "its canonical serialised bytes and SHA256 root. Used by coordinators\n"
        "to construct the batch structure before distributing to participants.\n",
        {
            {"coordinator_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Coordinator's FALCON-512 public key (897 bytes, hex)"},
            {"prime_expiry_height", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "Max block height at which the QABIO tx may execute"},
            {"batch_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Unique batch identifier (32 bytes, hex)"},
            {"entries", RPCArg::Type::ARR, RPCArg::Optional::NO, "Participant list",
                {
                    {"entry", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One participant",
                        {
                            {"participant_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                                "SHA256(participant's Rung 0 FALCON pubkey), 32 bytes hex"},
                            {"contribution", RPCArg::Type::AMOUNT, RPCArg::Optional::NO,
                                "Satoshis this participant contributes"},
                            {"destination_index", RPCArg::Type::NUM, RPCArg::Optional::NO,
                                "Index into outputs[] for this participant's destination"},
                        },
                    },
                },
            },
            {"outputs_conditions_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte conditions root that the spend tx must use as tx.conditions_root. "
                "Pins every destination scriptPubKey structurally — see QABIBlock docs."},
            {"output_values", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Per-output amounts. The destination scriptPubKey is implicit "
                "(0xDF + outputs_conditions_root for every output).",
                {
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO,
                        "Output value (BTC)"},
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "qabi_block", "Serialised QABIBlock bytes (hex)"},
            {RPCResult::Type::STR_HEX, "qabi_root", "SHA256(serialised block) — 32 bytes hex"},
            {RPCResult::Type::NUM, "size", "Serialised block size in bytes"},
        }},
        RPCExamples{HelpExampleCli("qabi_buildblock", "...")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        rung::QABIBlock block;
        block.version = rung::QABI_BLOCK_VERSION_CURRENT;

        auto pk = ParseHex(self.Arg<std::string>("coordinator_pubkey"));
        if (pk.size() != rung::QABI_COORDINATOR_PUBKEY_SIZE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("coordinator_pubkey must be exactly %d bytes", rung::QABI_COORDINATOR_PUBKEY_SIZE));
        }
        block.coordinator_pubkey = pk;

        block.prime_expiry_height = self.Arg<uint64_t>("prime_expiry_height");

        auto bid = ParseHex(self.Arg<std::string>("batch_id"));
        if (bid.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "batch_id must be 32 bytes");
        }
        std::memcpy(block.batch_id.data(), bid.data(), 32);

        const UniValue& entries = request.params[3].get_array();
        for (size_t i = 0; i < entries.size(); ++i) {
            const UniValue& e = entries[i];
            rung::QABIEntry entry;
            auto pid = ParseHex(e["participant_id"].get_str());
            if (pid.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "participant_id must be 32 bytes at index " + std::to_string(i));
            }
            std::memcpy(entry.participant_id.data(), pid.data(), 32);
            entry.contribution = AmountFromValue(e["contribution"]);
            entry.destination_index = e["destination_index"].getInt<uint32_t>();
            block.entries.push_back(entry);
        }

        auto ocr_bytes = ParseHex(request.params[4].get_str());
        if (ocr_bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs_conditions_root must be 32 bytes");
        }
        std::memcpy(block.outputs_conditions_root.data(), ocr_bytes.data(), 32);

        const UniValue& outs = request.params[5].get_array();
        for (size_t i = 0; i < outs.size(); ++i) {
            block.output_values.push_back(AmountFromValue(outs[i]));
        }

        // Validate destination_index bounds.
        for (size_t i = 0; i < block.entries.size(); ++i) {
            if (block.entries[i].destination_index >= block.output_values.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "destination_index out of range at entry " + std::to_string(i));
            }
        }

        auto bytes = rung::SerializeQABIBlock(block);
        if (bytes.size() > rung::QABI_BLOCK_MAX_HARD) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "serialised qabi_block exceeds hard cap");
        }
        uint256 root = rung::ComputeQABIRoot(bytes);

        UniValue result(UniValue::VOBJ);
        result.pushKV("qabi_block", HexStr(bytes));
        result.pushKV("qabi_root", root.GetHex());
        result.pushKV("size", static_cast<uint64_t>(bytes.size()));
        return result;
    },
    };
}

static RPCHelpMan qabi_blockinfo()
{
    return RPCHelpMan{
        "qabi_blockinfo",
        "Decode serialised qabi_block bytes into a JSON representation for\n"
        "inspection and debugging. Useful for wallets reviewing a batch before\n"
        "priming, and for validators investigating a rejected QABIO tx.\n",
        {
            {"qabi_block", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Serialised QABIBlock bytes (hex)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "version", "Block format version"},
            {RPCResult::Type::STR_HEX, "batch_id", ""},
            {RPCResult::Type::STR_HEX, "coordinator_pubkey", ""},
            {RPCResult::Type::NUM, "prime_expiry_height", ""},
            {RPCResult::Type::STR_HEX, "outputs_conditions_root", "32-byte conditions root the spend tx must use"},
            {RPCResult::Type::NUM, "n_entries", ""},
            {RPCResult::Type::NUM, "n_outputs", ""},
            {RPCResult::Type::STR_HEX, "qabi_root", "SHA256 of the serialised bytes"},
            {RPCResult::Type::ARR, "entries", "Participant list", {
                {RPCResult::Type::OBJ, "", "Entry", {
                    {RPCResult::Type::STR_HEX, "participant_id", ""},
                    {RPCResult::Type::STR_AMOUNT, "contribution", ""},
                    {RPCResult::Type::NUM, "destination_index", ""},
                }},
            }},
            {RPCResult::Type::ARR, "output_values", "Per-output amounts. Destination scriptPubKey is implicit (0xDF + outputs_conditions_root).", {
                {RPCResult::Type::STR_AMOUNT, "", "Output value (BTC)"},
            }},
        }},
        RPCExamples{HelpExampleCli("qabi_blockinfo", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto bytes = ParseHex(self.Arg<std::string>("qabi_block"));

        std::string err;
        auto parsed = rung::ParseQABIBlock(bytes, err);
        if (!parsed) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "parse failed: " + err);
        }

        uint256 root = rung::ComputeQABIRoot(bytes);

        UniValue result(UniValue::VOBJ);
        result.pushKV("version", static_cast<int>(parsed->version));
        result.pushKV("batch_id", parsed->batch_id.GetHex());
        result.pushKV("coordinator_pubkey", HexStr(parsed->coordinator_pubkey));
        result.pushKV("prime_expiry_height", static_cast<uint64_t>(parsed->prime_expiry_height));
        result.pushKV("outputs_conditions_root", parsed->outputs_conditions_root.GetHex());
        result.pushKV("n_entries", static_cast<uint64_t>(parsed->entries.size()));
        result.pushKV("n_outputs", static_cast<uint64_t>(parsed->output_values.size()));
        result.pushKV("qabi_root", root.GetHex());

        UniValue entries(UniValue::VARR);
        for (const auto& e : parsed->entries) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("participant_id", e.participant_id.GetHex());
            entry.pushKV("contribution", ValueFromAmount(e.contribution));
            entry.pushKV("destination_index", static_cast<uint64_t>(e.destination_index));
            entries.push_back(entry);
        }
        result.pushKV("entries", entries);

        UniValue output_values(UniValue::VARR);
        for (int64_t v : parsed->output_values) {
            output_values.push_back(ValueFromAmount(v));
        }
        result.pushKV("output_values", output_values);

        return result;
    },
    };
}

static RPCHelpMan qabi_authchain()
{
    return RPCHelpMan{
        "qabi_authchain",
        "Compute the auth_tip and the preimage at a given depth for a QABI\n"
        "hash chain. Used by wallets to derive the committed state for a new\n"
        "QABI-enabled UTXO and to reveal preimages at priming/spend time.\n",
        {
            {"auth_seed", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "32-byte wallet secret (hex)"},
            {"chain_length", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "Chain length N. auth_tip = H^N(auth_seed)"},
            {"depth", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
             "If specified, also return the preimage at this depth (0 = tip, N = seed)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "auth_tip", "H^chain_length(auth_seed)"},
            {RPCResult::Type::STR_HEX, "preimage", /*optional=*/true, "Preimage at depth (present if depth was specified)"},
        }},
        RPCExamples{HelpExampleCli("qabi_authchain", "\"<seed>\" 20000 10")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto seed = ParseHex(self.Arg<std::string>("auth_seed"));
        if (seed.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "auth_seed must be exactly 32 bytes");
        }
        uint32_t chain_length = self.Arg<uint64_t>("chain_length");

        uint256 tip = rung::ComputeAuthChainTip(std::span<const uint8_t>(seed), chain_length);

        UniValue result(UniValue::VOBJ);
        result.pushKV("auth_tip", tip.GetHex());

        if (!request.params[2].isNull()) {
            uint32_t depth = request.params[2].getInt<uint32_t>();
            uint256 preimage;
            if (!rung::ComputeAuthChainPreimageAt(
                    std::span<const uint8_t>(seed), chain_length, depth, preimage)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid depth (must be <= chain_length)");
            }
            result.pushKV("preimage", preimage.GetHex());
        }

        return result;
    },
    };
}

static RPCHelpMan qabi_signqabo()
{
    return RPCHelpMan{
        "qabi_signqabo",
        "Coordinator-side signing operation for a QABIO batch tx. Takes an\n"
        "unsigned TX_MLSC v4 tx (with tx.qabi_block populated but\n"
        "tx.aggregated_sig empty or placeholder) and the coordinator's FALCON-512\n"
        "private key, computes SIGHASH_QABO over the tx, signs the hash, and\n"
        "returns a new tx hex with tx.aggregated_sig set to the resulting\n"
        "FALCON-512 signature.\n"
        "\n"
        "Inputs:\n"
        "  - hex_tx: unsigned (or partially signed) TX_MLSC v4 tx hex\n"
        "  - privkey: coordinator's FALCON-512 private key (hex)\n"
        "\n"
        "Output: signed tx hex with aggregated_sig = FALCON(privkey, SIGHASH_QABO(tx))\n"
        "\n"
        "Requires liboqs support for FALCON-512 signing.\n",
        {
            {"hex_tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The unsigned TX_MLSC v4 transaction hex"},
            {"privkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Coordinator's FALCON-512 private key (hex)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "Signed tx hex (aggregated_sig populated)"},
            {RPCResult::Type::STR_HEX, "sighash", "The SIGHASH_QABO that was signed"},
            {RPCResult::Type::NUM, "sig_size", "Size of the FALCON signature in bytes"},
        }},
        RPCExamples{HelpExampleCli("qabi_signqabo", "\"<tx hex>\" \"<falcon privkey hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        if (!rung::HasPQSupport()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                "qabi_signqabo requires liboqs support (not compiled in)");
        }

        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, self.Arg<std::string>("hex_tx"), true)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx decode failed");
        }
        if (mtx.qabi_block.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "tx.qabi_block is empty — not a QABIO batch tx");
        }

        auto privkey = ParseHex(self.Arg<std::string>("privkey"));
        if (privkey.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "empty privkey");
        }

        // Zero out aggregated_sig before computing the sighash — SIGHASH_QABO
        // deliberately excludes it (chicken-and-egg) so the hash is the same
        // regardless of what's currently in that field.
        mtx.aggregated_sig.clear();

        uint256 sighash = rung::ComputeSighashQABO(CTransaction(mtx));

        std::vector<uint8_t> sig;
        if (!rung::SignPQ(rung::RungScheme::FALCON512,
                           std::span<const uint8_t>(privkey),
                           std::span<const uint8_t>(sighash.begin(), 32),
                           sig)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "FALCON-512 signing failed");
        }

        // Pad to exactly 666 bytes (consensus cap) — liboqs FALCON signatures
        // are variable-length ≤666 bytes. Zero-pad any shorter result.
        if (sig.size() > rung::QABI_AGGREGATED_SIG_MAX) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                "FALCON signature exceeds consensus cap");
        }
        sig.resize(rung::QABI_AGGREGATED_SIG_MAX, 0x00);
        mtx.aggregated_sig = sig;

        // Re-serialise the signed tx.
        DataStream ss;
        ss << TX_WITH_WITNESS(CTransaction(mtx));

        UniValue result(UniValue::VOBJ);
        result.pushKV("hex", HexStr(ss));
        result.pushKV("sighash", sighash.GetHex());
        result.pushKV("sig_size", static_cast<uint64_t>(sig.size()));
        return result;
    },
    };
}

static RPCHelpMan qabi_sighash()
{
    return RPCHelpMan{
        "qabi_sighash",
        "Compute SIGHASH_QABO for a QABIO tx. Used by coordinators to\n"
        "determine what bytes their FALCON signature must cover before signing.\n"
        "The sighash covers tx.version, vin, vout, conditions_root, qabi_block,\n"
        "per-input scriptWitness stacks, and nLockTime. It deliberately excludes\n"
        "tx.aggregated_sig (chicken-and-egg).\n",
        {
            {"hex_tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Hex-encoded CTransaction (RUNG_TX_VERSION with tx-level fields)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "sighash", "SIGHASH_QABO — 32 bytes hex"},
        }},
        RPCExamples{HelpExampleCli("qabi_sighash", "\"<tx hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, self.Arg<std::string>("hex_tx"), true)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx decode failed");
        }
        CTransaction tx(mtx);
        uint256 sighash = rung::ComputeSighashQABO(tx);

        UniValue result(UniValue::VOBJ);
        result.pushKV("sighash", sighash.GetHex());
        return result;
    },
    };
}

#endif // ENABLE_QABIO

// ============================================================================

void RegisterRungRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rung", &decoderung},
        {"rung", &createrung},
        {"rung", &serialiseconditions},
        {"rung", &validateladder},
        {"rung", &createrungtx},
        {"rung", &signrungtx},
        {"rung", &signladder},
        {"rung", &computemutation},
        {"rung", &computectvhash},
        {"rung", &generatepqkeypair},
        {"rung", &pqpubkeycommit},
        {"rung", &extractadaptorsecret},
        {"rung", &verifyadaptorpresig},
        {"rung", &parseladder},
        {"rung", &formatladder},
#ifdef ENABLE_QABIO
        // QABI family (BIP-YYYY). Only registered when the extension is
        // compiled in. Callers on a node built without QABIO get
        // "method not found" for any of these RPCs.
        {"rung", &qabi_buildblock},
        {"rung", &qabi_blockinfo},
        {"rung", &qabi_authchain},
        {"rung", &qabi_sighash},
        {"rung", &qabi_signqabo},
#endif // ENABLE_QABIO
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
