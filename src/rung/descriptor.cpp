// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/descriptor.h>

#include <rung/conditions.h>
#include <rung/serialize.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <sstream>

namespace rung {

// ============================================================================
// Parser internals
// ============================================================================

namespace {

/** Parser resource limits — prevents DoS via malicious descriptors. */
static constexpr int MAX_PARSE_DEPTH = 32;
static constexpr size_t MAX_PARSE_ITEMS = 1000;
static constexpr size_t MAX_OUTPUT_INDEX = 4096;

struct ParseContext {
    const std::string& desc;
    const std::map<std::string, std::vector<uint8_t>>& keys;
    size_t pos{0};
    std::string error;
    int depth{0};           //!< Current nesting depth (and/or wrappers)
    size_t item_count{0};   //!< Total items parsed (blocks + rungs + outputs)
};

void SkipWhitespace(ParseContext& ctx)
{
    while (ctx.pos < ctx.desc.size() && std::isspace(ctx.desc[ctx.pos])) {
        ++ctx.pos;
    }
}

bool Expect(ParseContext& ctx, char c)
{
    SkipWhitespace(ctx);
    if (ctx.pos >= ctx.desc.size() || ctx.desc[ctx.pos] != c) {
        ctx.error = std::string("expected '") + c + "' at position " + std::to_string(ctx.pos);
        return false;
    }
    ++ctx.pos;
    return true;
}

bool Match(ParseContext& ctx, const std::string& keyword)
{
    SkipWhitespace(ctx);
    if (ctx.pos + keyword.size() > ctx.desc.size()) return false;
    if (ctx.desc.substr(ctx.pos, keyword.size()) != keyword) return false;
    // Ensure not a prefix of a longer identifier
    size_t end = ctx.pos + keyword.size();
    if (end < ctx.desc.size() && (std::isalnum(ctx.desc[end]) || ctx.desc[end] == '_')) return false;
    ctx.pos += keyword.size();
    return true;
}

bool Peek(ParseContext& ctx, const std::string& keyword)
{
    SkipWhitespace(ctx);
    if (ctx.pos + keyword.size() > ctx.desc.size()) return false;
    if (ctx.desc.substr(ctx.pos, keyword.size()) != keyword) return false;
    size_t end = ctx.pos + keyword.size();
    if (end < ctx.desc.size() && (std::isalnum(ctx.desc[end]) || ctx.desc[end] == '_')) return false;
    return true;
}

std::string ReadIdentifier(ParseContext& ctx)
{
    SkipWhitespace(ctx);
    size_t start = ctx.pos;
    while (ctx.pos < ctx.desc.size() &&
           (std::isalnum(ctx.desc[ctx.pos]) || ctx.desc[ctx.pos] == '_')) {
        ++ctx.pos;
    }
    return ctx.desc.substr(start, ctx.pos - start);
}

std::string ReadAlias(ParseContext& ctx)
{
    SkipWhitespace(ctx);
    if (ctx.pos >= ctx.desc.size() || ctx.desc[ctx.pos] != '@') {
        ctx.error = "expected '@' alias at position " + std::to_string(ctx.pos);
        return "";
    }
    ++ctx.pos;
    return ReadIdentifier(ctx);
}

bool ReadUint32(ParseContext& ctx, uint32_t& out)
{
    SkipWhitespace(ctx);
    size_t start = ctx.pos;
    while (ctx.pos < ctx.desc.size() && std::isdigit(ctx.desc[ctx.pos])) {
        ++ctx.pos;
    }
    if (ctx.pos == start) {
        ctx.error = "expected number at position " + std::to_string(ctx.pos);
        return false;
    }
    try {
        unsigned long val = std::stoul(ctx.desc.substr(start, ctx.pos - start));
        if (val > 0xFFFFFFFF) {
            ctx.error = "number too large at position " + std::to_string(start);
            return false;
        }
        out = static_cast<uint32_t>(val);
    } catch (...) {
        ctx.error = "invalid number at position " + std::to_string(start);
        return false;
    }
    return true;
}

std::string ReadHex(ParseContext& ctx)
{
    SkipWhitespace(ctx);
    size_t start = ctx.pos;
    while (ctx.pos < ctx.desc.size() && HexDigit(ctx.desc[ctx.pos]) != -1) {
        ++ctx.pos;
    }
    return ctx.desc.substr(start, ctx.pos - start);
}

std::vector<uint8_t> MakeNumericField(uint32_t val)
{
    std::vector<uint8_t> data(4);
    data[0] = val & 0xFF;
    data[1] = (val >> 8) & 0xFF;
    data[2] = (val >> 16) & 0xFF;
    data[3] = (val >> 24) & 0xFF;
    return data;
}

RungScheme ParseScheme(const std::string& name)
{
    if (name == "schnorr") return RungScheme::SCHNORR;
    if (name == "ecdsa") return RungScheme::ECDSA;
    if (name == "falcon512") return RungScheme::FALCON512;
    if (name == "falcon1024") return RungScheme::FALCON1024;
    if (name == "dilithium3") return RungScheme::DILITHIUM3;
    if (name == "sphincs_sha") return RungScheme::SPHINCS_SHA;
    return RungScheme::SCHNORR; // default
}

std::string SchemeToString(RungScheme s)
{
    switch (s) {
    case RungScheme::SCHNORR: return "schnorr";
    case RungScheme::ECDSA: return "ecdsa";
    case RungScheme::FALCON512: return "falcon512";
    case RungScheme::FALCON1024: return "falcon1024";
    case RungScheme::DILITHIUM3: return "dilithium3";
    case RungScheme::SPHINCS_SHA: return "sphincs_sha";
    }
    return "schnorr";
}

bool LookupKey(ParseContext& ctx, const std::string& alias, std::vector<uint8_t>& out)
{
    auto it = ctx.keys.find(alias);
    if (it == ctx.keys.end()) {
        ctx.error = "unknown key alias: @" + alias;
        return false;
    }
    out = it->second;
    return true;
}

bool ParseBlock(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks);

bool ParseSig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // sig(@alias) or sig(@alias, scheme)
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;

    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);

    block.type = RungBlockType::SIG;
    RungScheme scheme = RungScheme::SCHNORR;

    SkipWhitespace(ctx);
    if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ',') {
        ++ctx.pos;
        std::string scheme_name = ReadIdentifier(ctx);
        scheme = ParseScheme(scheme_name);
    }

    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(scheme)}});
    return Expect(ctx, ')');
}

bool ParseCsv(ParseContext& ctx, RungBlock& block, RungBlockType type)
{
    if (!Expect(ctx, '(')) return false;
    uint32_t val;
    if (!ReadUint32(ctx, val)) return false;
    block.type = type;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(val)});
    return Expect(ctx, ')');
}

bool ParseMultisig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // multisig(K, @pk1, @pk2, ...) or multisig(K, @pk1, @pk2, ..., scheme)
    // v2 emits MULTISIG_CONDITIONS = [NUMERIC(K), SCHEME, HASH256(pubkey_root)]
    // and folds the N pubkeys into the inner pubkey-Merkle root.
    if (!Expect(ctx, '(')) return false;
    uint32_t threshold;
    if (!ReadUint32(ctx, threshold)) return false;

    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(threshold)});

    std::vector<std::vector<uint8_t>> ms_pubkeys;
    while (true) {
        if (++ctx.item_count > MAX_PARSE_ITEMS) {
            ctx.error = "descriptor exceeds maximum item count";
            return false;
        }
        SkipWhitespace(ctx);
        if (ctx.pos >= ctx.desc.size()) break;
        if (ctx.desc[ctx.pos] == ')') break;
        if (!Expect(ctx, ',')) return false;
        SkipWhitespace(ctx);
        if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == '@') {
            std::string alias = ReadAlias(ctx);
            if (alias.empty()) return false;
            std::vector<uint8_t> pk;
            if (!LookupKey(ctx, alias, pk)) return false;
            // Normalize x-only (32 B) → compressed (33 B, even-Y) for canonical
            // pubkey-tree leaf hashing. Mirrors ParseBlockSpec.
            if (pk.size() == 32) pk.insert(pk.begin(), 0x02);
            ms_pubkeys.push_back(pk);
            rung_pks.push_back(pk);
        } else {
            // Must be a scheme name at the end
            break;
        }
    }

    if (ms_pubkeys.empty()) {
        ctx.error = "multisig requires at least one pubkey";
        return false;
    }
    if (ms_pubkeys.size() > MAX_PUBKEYS_PER_MULTISIG) {
        ctx.error = "multisig has " + std::to_string(ms_pubkeys.size()) +
                    " pubkeys, max " + std::to_string(MAX_PUBKEYS_PER_MULTISIG);
        return false;
    }
    if (threshold == 0 || threshold > ms_pubkeys.size()) {
        ctx.error = "multisig threshold K out of range [1, N]";
        return false;
    }

    // SCHEME (default: SCHNORR — all keys share the same scheme).
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});

    // HASH256(pubkey_root) — inner Merkle commitment.
    uint256 pubkey_root = BuildPubkeyMerkleRoot(ms_pubkeys);
    block.fields.push_back({RungDataType::HASH256,
        std::vector<uint8_t>(pubkey_root.begin(), pubkey_root.end())});

    // Pop MULTISIG pubkeys back off rung_pks — the outer leaf hash must NOT
    // fold them in (PubkeyCountForBlock = 0). The descriptor parser/printer
    // and wallet auto-derive read them from block.merkle_pubkeys instead.
    rung_pks.resize(rung_pks.size() - ms_pubkeys.size());
    block.merkle_pubkeys = std::move(ms_pubkeys);

    return Expect(ctx, ')');
}

bool ParseHashGuarded(ParseContext& ctx, RungBlock& block)
{
    if (!Expect(ctx, '(')) return false;
    std::string hex = ReadHex(ctx);
    auto bytes = ParseHex(hex);
    if (bytes.size() != 32) {
        ctx.error = "hash_guarded requires 32-byte hash";
        return false;
    }
    block.type = RungBlockType::HASH_GUARDED;
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

bool ParseCtv(ParseContext& ctx, RungBlock& block)
{
    if (!Expect(ctx, '(')) return false;
    std::string hex = ReadHex(ctx);
    auto bytes = ParseHex(hex);
    if (bytes.size() != 32) {
        ctx.error = "ctv requires 32-byte template hash";
        return false;
    }
    block.type = RungBlockType::CTV;
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

// QABI family
bool ParseQABIPrime(ParseContext& ctx, RungBlock& block)
{
    // qabi_prime() — no committed fields in conditions context.
    if (!Expect(ctx, '(')) return false;
    block.type = RungBlockType::QABI_PRIME;
    return Expect(ctx, ')');
}

bool ParseQABISpend(ParseContext& ctx, RungBlock& block)
{
    // qabi_spend(auth_tip_hex, committed_root_hex, committed_depth,
    //             committed_expiry, owner_id_hex)
    if (!Expect(ctx, '(')) return false;

    auto auth_tip = ParseHex(ReadHex(ctx));
    if (auth_tip.size() != 32) {
        ctx.error = "qabi_spend auth_tip must be 32 bytes";
        return false;
    }
    if (!Expect(ctx, ',')) return false;

    auto committed_root = ParseHex(ReadHex(ctx));
    if (committed_root.size() != 32) {
        ctx.error = "qabi_spend committed_root must be 32 bytes";
        return false;
    }
    if (!Expect(ctx, ',')) return false;

    uint32_t committed_depth;
    if (!ReadUint32(ctx, committed_depth)) return false;
    if (!Expect(ctx, ',')) return false;

    uint32_t committed_expiry;
    if (!ReadUint32(ctx, committed_expiry)) return false;
    if (!Expect(ctx, ',')) return false;

    auto owner_id = ParseHex(ReadHex(ctx));
    if (owner_id.size() != 32) {
        ctx.error = "qabi_spend owner_id must be 32 bytes";
        return false;
    }

    block.type = RungBlockType::QABI_SPEND;
    block.fields.push_back({RungDataType::HASH256, auth_tip});
    block.fields.push_back({RungDataType::HASH256, committed_root});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(committed_depth)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(committed_expiry)});
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, owner_id});
    return Expect(ctx, ')');
}

bool ParsePqBatch(ParseContext& ctx, RungBlock& block)
{
    // pq_batch(pubkey_hash_hex) — commits SHA256(falcon_pubkey).
    // The pubkey + signature are revealed in the witness of one
    // anchor input per tx; other inputs gated by the same hash
    // validate via the cross-input cache.
    if (!Expect(ctx, '(')) return false;
    auto bytes = ParseHex(ReadHex(ctx));
    if (bytes.size() != 32) {
        ctx.error = "pq_batch requires 32-byte pubkey hash";
        return false;
    }
    block.type = RungBlockType::PQ_BATCH;
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

bool ParseAmountLock(ParseContext& ctx, RungBlock& block)
{
    if (!Expect(ctx, '(')) return false;
    uint32_t min_val, max_val;
    if (!ReadUint32(ctx, min_val)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, max_val)) return false;
    block.type = RungBlockType::AMOUNT_LOCK;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(min_val)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(max_val)});
    return Expect(ctx, ')');
}

bool ParseTimelockedSig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;
    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);

    if (!Expect(ctx, ',')) return false;
    uint32_t csv_val;
    if (!ReadUint32(ctx, csv_val)) return false;

    block.type = RungBlockType::TIMELOCKED_SIG;
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(csv_val)});
    return Expect(ctx, ')');
}

bool ParseOutputCheck(ParseContext& ctx, RungBlock& block)
{
    if (!Expect(ctx, '(')) return false;
    uint32_t idx, min_sats, max_sats;
    if (!ReadUint32(ctx, idx)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, min_sats)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, max_sats)) return false;
    if (!Expect(ctx, ',')) return false;

    std::string hex = ReadHex(ctx);
    auto bytes = ParseHex(hex);
    if (bytes.size() != 32) {
        ctx.error = "output_check requires 32-byte script_hash";
        return false;
    }

    block.type = RungBlockType::OUTPUT_CHECK;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(idx)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(min_sats)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(max_sats)});
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

// ── Signature family (new) ──────────────────────────────────────────────

bool ParseAdaptorSig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // adaptor_sig(@signer) or adaptor_sig(@signer, scheme)
    // v0.7: dropped the v0.6 @adaptor_point arg (T = t·G is off-chain only).
    if (!Expect(ctx, '(')) return false;
    std::string alias1 = ReadAlias(ctx);
    if (alias1.empty()) return false;
    std::vector<uint8_t> pk1;
    if (!LookupKey(ctx, alias1, pk1)) return false;
    rung_pks.push_back(pk1);

    block.type = RungBlockType::ADAPTOR_SIG;
    // ADAPTOR_SIG has nullptr conditions layout — no fields in conditions.
    // Optional scheme argument is accepted but not stored in conditions.
    SkipWhitespace(ctx);
    if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ',') {
        ++ctx.pos;
        ReadIdentifier(ctx);
    }
    return Expect(ctx, ')');
}

bool ParseMusigThreshold(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // musig_threshold(M, @pk1, @pk2, ...)
    // Conditions: [NUMERIC(M), NUMERIC(N)]
    // Merkle leaf: 1 aggregate pubkey (pubkey_count=1 in descriptor table)
    // For simplicity, we pass individual pubkeys and let the signing path handle aggregation.
    if (!Expect(ctx, '(')) return false;
    uint32_t threshold;
    if (!ReadUint32(ctx, threshold)) return false;
    block.type = RungBlockType::MUSIG_THRESHOLD;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(threshold)});
    uint32_t n_keys = 0;
    while (true) {
        SkipWhitespace(ctx);
        if (ctx.pos >= ctx.desc.size() || ctx.desc[ctx.pos] == ')') break;
        if (!Expect(ctx, ',')) return false;
        SkipWhitespace(ctx);
        if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == '@') {
            std::string alias = ReadAlias(ctx);
            if (alias.empty()) return false;
            std::vector<uint8_t> pk;
            if (!LookupKey(ctx, alias, pk)) return false;
            rung_pks.push_back(pk);
            ++n_keys;
        } else break;
    }
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(n_keys)});
    return Expect(ctx, ')');
}

bool ParseKeyRefSig(ParseContext& ctx, RungBlock& block)
{
    // key_ref_sig(relay_idx, block_idx)
    if (!Expect(ctx, '(')) return false;
    uint32_t relay_idx, block_idx;
    if (!ReadUint32(ctx, relay_idx)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, block_idx)) return false;
    block.type = RungBlockType::KEY_REF_SIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(relay_idx)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(block_idx)});
    return Expect(ctx, ')');
}

// ── Hash family (new) ──────────────────────────────────────────────────

bool ParseTaggedHash(ParseContext& ctx, RungBlock& block)
{
    // tagged_hash(tag_hex, expected_hex)
    if (!Expect(ctx, '(')) return false;
    auto tag = ParseHex(ReadHex(ctx));
    if (tag.size() != 32) { ctx.error = "tagged_hash tag must be 32 bytes"; return false; }
    if (!Expect(ctx, ',')) return false;
    auto expected = ParseHex(ReadHex(ctx));
    if (expected.size() != 32) { ctx.error = "tagged_hash expected must be 32 bytes"; return false; }
    block.type = RungBlockType::TAGGED_HASH;
    block.fields.push_back({RungDataType::HASH256, tag});
    block.fields.push_back({RungDataType::HASH256, expected});
    return Expect(ctx, ')');
}

// ── Covenant family (new) ──────────────────────────────────────────────

bool ParseVaultLock(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // vault_lock(@recovery, @hot, delay)
    if (!Expect(ctx, '(')) return false;
    std::string r_alias = ReadAlias(ctx);
    if (r_alias.empty()) return false;
    std::vector<uint8_t> r_pk;
    if (!LookupKey(ctx, r_alias, r_pk)) return false;
    rung_pks.push_back(r_pk);

    if (!Expect(ctx, ',')) return false;
    std::string h_alias = ReadAlias(ctx);
    if (h_alias.empty()) return false;
    std::vector<uint8_t> h_pk;
    if (!LookupKey(ctx, h_alias, h_pk)) return false;
    rung_pks.push_back(h_pk);

    if (!Expect(ctx, ',')) return false;
    uint32_t delay;
    if (!ReadUint32(ctx, delay)) return false;
    block.type = RungBlockType::VAULT_LOCK;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(delay)});
    return Expect(ctx, ')');
}

// ── Recursion family ───────────────────────────────────────────────────

bool ParseRecurseSame(ParseContext& ctx, RungBlock& block)
{
    // recurse_same(max_depth)
    if (!Expect(ctx, '(')) return false;
    uint32_t depth;
    if (!ReadUint32(ctx, depth)) return false;
    block.type = RungBlockType::RECURSE_SAME;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(depth)});
    return Expect(ctx, ')');
}

bool ParseRecurseModified(ParseContext& ctx, RungBlock& block)
{
    // recurse_modified(max_depth, block_idx, param_idx, delta)
    if (!Expect(ctx, '(')) return false;
    uint32_t depth, blk, param, delta;
    if (!ReadUint32(ctx, depth)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, blk)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, param)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, delta)) return false;
    block.type = RungBlockType::RECURSE_MODIFIED;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(depth)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(blk)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(param)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(delta)});
    return Expect(ctx, ')');
}

bool ParseRecurseUntil(ParseContext& ctx, RungBlock& block)
{
    // recurse_until(height)
    if (!Expect(ctx, '(')) return false;
    uint32_t height;
    if (!ReadUint32(ctx, height)) return false;
    block.type = RungBlockType::RECURSE_UNTIL;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(height)});
    return Expect(ctx, ')');
}

bool ParseRecurseCount(ParseContext& ctx, RungBlock& block)
{
    // recurse_count(count)
    if (!Expect(ctx, '(')) return false;
    uint32_t count;
    if (!ReadUint32(ctx, count)) return false;
    block.type = RungBlockType::RECURSE_COUNT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(count)});
    return Expect(ctx, ')');
}

bool ParseRecurseSplit(ParseContext& ctx, RungBlock& block)
{
    // recurse_split(max_splits, min_sats)
    if (!Expect(ctx, '(')) return false;
    uint32_t splits, min_sats;
    if (!ReadUint32(ctx, splits)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, min_sats)) return false;
    block.type = RungBlockType::RECURSE_SPLIT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(splits)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(min_sats)});
    return Expect(ctx, ')');
}

bool ParseRecurseDecay(ParseContext& ctx, RungBlock& block)
{
    // recurse_decay(max_depth, block_idx, param_idx, decay_per_step)
    if (!Expect(ctx, '(')) return false;
    uint32_t depth, blk, param, decay;
    if (!ReadUint32(ctx, depth)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, blk)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, param)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, decay)) return false;
    block.type = RungBlockType::RECURSE_DECAY;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(depth)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(blk)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(param)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(decay)});
    return Expect(ctx, ')');
}

// ── Anchor family ──────────────────────────────────────────────────────

bool ParseDataReturn(ParseContext& ctx, RungBlock& block)
{
    // data_return(hex)
    if (!Expect(ctx, '(')) return false;
    auto bytes = ParseHex(ReadHex(ctx));
    if (bytes.empty() || bytes.size() > 40) {
        ctx.error = "data_return requires 1-40 byte payload";
        return false;
    }
    block.type = RungBlockType::DATA_RETURN;
    block.fields.push_back({RungDataType::DATA, bytes});
    return Expect(ctx, ')');
}

// ── PLC family ─────────────────────────────────────────────────────────

bool ParseTwoNumericBlock(ParseContext& ctx, RungBlock& block, RungBlockType type)
{
    // Generic: type(N, N) — hysteresis_fee, hysteresis_value, input_count, output_count, etc.
    if (!Expect(ctx, '(')) return false;
    uint32_t a, b;
    if (!ReadUint32(ctx, a)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, b)) return false;
    block.type = type;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(a)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(b)});
    return Expect(ctx, ')');
}

bool ParseOneNumericBlock(ParseContext& ctx, RungBlock& block, RungBlockType type)
{
    // Generic: type(N) — weight_limit, timer_continuous, etc.
    if (!Expect(ctx, '(')) return false;
    uint32_t val;
    if (!ReadUint32(ctx, val)) return false;
    block.type = type;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(val)});
    return Expect(ctx, ')');
}

bool ParsePubkeyNumericBlock(ParseContext& ctx, RungBlock& block, RungBlockType type,
                              std::vector<std::vector<uint8_t>>& rung_pks)
{
    // type(@pk, N) — latch_set, counter_down
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;
    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);
    if (!Expect(ctx, ',')) return false;
    uint32_t val;
    if (!ReadUint32(ctx, val)) return false;
    block.type = type;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(val)});
    return Expect(ctx, ')');
}

bool ParsePubkeyTwoNumericBlock(ParseContext& ctx, RungBlock& block, RungBlockType type,
                                 std::vector<std::vector<uint8_t>>& rung_pks)
{
    // type(@pk, N, N) — latch_reset, counter_preset, counter_up
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;
    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);
    if (!Expect(ctx, ',')) return false;
    uint32_t a, b;
    if (!ReadUint32(ctx, a)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, b)) return false;
    block.type = type;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(a)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(b)});
    return Expect(ctx, ')');
}

bool ParsePubkeyNumericHashBlock(ParseContext& ctx, RungBlock& block, RungBlockType type,
                                  std::vector<std::vector<uint8_t>>& rung_pks)
{
    // type(@pk, N, hex) — one_shot
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;
    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);
    if (!Expect(ctx, ',')) return false;
    uint32_t val;
    if (!ReadUint32(ctx, val)) return false;
    if (!Expect(ctx, ',')) return false;
    auto h = ParseHex(ReadHex(ctx));
    if (h.size() != 32) { ctx.error = "requires 32-byte hash"; return false; }
    block.type = type;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(val)});
    block.fields.push_back({RungDataType::HASH256, h});
    return Expect(ctx, ')');
}

bool ParseCompare(ParseContext& ctx, RungBlock& block)
{
    // compare(op, value_b) or compare(op, value_b, value_c)
    if (!Expect(ctx, '(')) return false;
    uint32_t op, vb;
    if (!ReadUint32(ctx, op)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, vb)) return false;
    block.type = RungBlockType::COMPARE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(op)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(vb)});
    SkipWhitespace(ctx);
    if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ',') {
        ++ctx.pos;
        uint32_t vc;
        if (!ReadUint32(ctx, vc)) return false;
        block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(vc)});
    }
    return Expect(ctx, ')');
}

bool ParseRateLimit(ParseContext& ctx, RungBlock& block)
{
    // rate_limit(max_per_block, accumulation_cap, refill_blocks)
    if (!Expect(ctx, '(')) return false;
    uint32_t a, b, c;
    if (!ReadUint32(ctx, a)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, b)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, c)) return false;
    block.type = RungBlockType::RATE_LIMIT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(a)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(b)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(c)});
    return Expect(ctx, ')');
}

bool ParseCosign(ParseContext& ctx, RungBlock& block)
{
    // cosign(conditions_hash_hex)
    if (!Expect(ctx, '(')) return false;
    auto bytes = ParseHex(ReadHex(ctx));
    if (bytes.size() != 32) { ctx.error = "cosign requires 32-byte conditions hash"; return false; }
    block.type = RungBlockType::COSIGN;
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

// ── Compound family (new) ──────────────────────────────────────────────

bool ParseCltvSig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // cltv_sig(@pk, height)
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;
    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);
    if (!Expect(ctx, ',')) return false;
    uint32_t height;
    if (!ReadUint32(ctx, height)) return false;
    block.type = RungBlockType::CLTV_SIG;
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(height)});
    return Expect(ctx, ')');
}

bool ParseHtlc(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // htlc(@receiver, @sender, preimage_hex, csv_blocks)
    // v0.7: receiver is pubkeys[0] (path=0, preimage spend); sender is pubkeys[1] (path=1, refund).
    if (!Expect(ctx, '(')) return false;
    std::string a1 = ReadAlias(ctx);
    if (a1.empty()) return false;
    std::vector<uint8_t> pk1;
    if (!LookupKey(ctx, a1, pk1)) return false;
    rung_pks.push_back(pk1);

    if (!Expect(ctx, ',')) return false;
    std::string a2 = ReadAlias(ctx);
    if (a2.empty()) return false;
    std::vector<uint8_t> pk2;
    if (!LookupKey(ctx, a2, pk2)) return false;
    rung_pks.push_back(pk2);

    if (!Expect(ctx, ',')) return false;
    auto preimage = ParseHex(ReadHex(ctx));
    if (preimage.empty()) { ctx.error = "htlc requires preimage hex"; return false; }

    if (!Expect(ctx, ',')) return false;
    uint32_t csv_val;
    if (!ReadUint32(ctx, csv_val)) return false;

    block.type = RungBlockType::HTLC;
    // Conditions: HASH256(sha256(preimage)), NUMERIC(csv), SCHEME
    CSHA256 hasher;
    std::vector<uint8_t> hash(CSHA256::OUTPUT_SIZE);
    hasher.Write(preimage.data(), preimage.size()).Finalize(hash.data());
    block.fields.push_back({RungDataType::HASH256, hash});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(csv_val)});
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
    return Expect(ctx, ')');
}

bool ParseHashSig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // hash_sig(@pk, preimage_hex)
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;
    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);

    if (!Expect(ctx, ',')) return false;
    auto preimage = ParseHex(ReadHex(ctx));
    if (preimage.empty()) { ctx.error = "hash_sig requires preimage hex"; return false; }

    block.type = RungBlockType::HASH_SIG;
    CSHA256 hasher;
    std::vector<uint8_t> hash(CSHA256::OUTPUT_SIZE);
    hasher.Write(preimage.data(), preimage.size()).Finalize(hash.data());
    block.fields.push_back({RungDataType::HASH256, hash});
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
    return Expect(ctx, ')');
}

bool ParsePtlc(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // ptlc(@pk, csv_blocks)
    // v0.7: dropped the v0.6 @adaptor_point arg (T = t·G is off-chain only).
    if (!Expect(ctx, '(')) return false;
    std::string a1 = ReadAlias(ctx);
    if (a1.empty()) return false;
    std::vector<uint8_t> pk1;
    if (!LookupKey(ctx, a1, pk1)) return false;
    rung_pks.push_back(pk1);

    if (!Expect(ctx, ',')) return false;
    uint32_t csv_val;
    if (!ReadUint32(ctx, csv_val)) return false;

    block.type = RungBlockType::PTLC;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(csv_val)});
    return Expect(ctx, ')');
}

bool ParseTimelockedMultisig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // timelocked_multisig(K, @pk1, @pk2, ..., csv_blocks)
    // v2 emits TIMELOCKED_MULTISIG_CONDITIONS =
    //   [NUMERIC(K), NUMERIC(CSV), SCHEME, HASH256(pubkey_root)].
    if (!Expect(ctx, '(')) return false;
    uint32_t threshold;
    if (!ReadUint32(ctx, threshold)) return false;

    block.type = RungBlockType::TIMELOCKED_MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(threshold)});

    std::vector<std::vector<uint8_t>> ms_pubkeys;
    uint32_t csv_val = 0;
    while (true) {
        SkipWhitespace(ctx);
        if (ctx.pos >= ctx.desc.size() || ctx.desc[ctx.pos] == ')') break;
        if (!Expect(ctx, ',')) return false;
        SkipWhitespace(ctx);
        if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == '@') {
            std::string alias = ReadAlias(ctx);
            if (alias.empty()) return false;
            std::vector<uint8_t> pk;
            if (!LookupKey(ctx, alias, pk)) return false;
            if (pk.size() == 32) pk.insert(pk.begin(), 0x02);
            ms_pubkeys.push_back(pk);
            rung_pks.push_back(pk);
        } else {
            // Must be csv_blocks (last numeric argument)
            if (!ReadUint32(ctx, csv_val)) return false;
            break;
        }
    }

    if (ms_pubkeys.empty()) {
        ctx.error = "timelocked_multisig requires at least one pubkey";
        return false;
    }
    if (ms_pubkeys.size() > MAX_PUBKEYS_PER_MULTISIG) {
        ctx.error = "timelocked_multisig has " + std::to_string(ms_pubkeys.size()) +
                    " pubkeys, max " + std::to_string(MAX_PUBKEYS_PER_MULTISIG);
        return false;
    }
    if (threshold == 0 || threshold > ms_pubkeys.size()) {
        ctx.error = "timelocked_multisig threshold K out of range [1, N]";
        return false;
    }

    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(csv_val)});
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});

    uint256 pubkey_root = BuildPubkeyMerkleRoot(ms_pubkeys);
    block.fields.push_back({RungDataType::HASH256,
        std::vector<uint8_t>(pubkey_root.begin(), pubkey_root.end())});

    // Same side-channel handoff as ParseMultisig — see comment there.
    rung_pks.resize(rung_pks.size() - ms_pubkeys.size());
    block.merkle_pubkeys = std::move(ms_pubkeys);

    return Expect(ctx, ')');
}

bool ParseAnchorFee(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // anchor_fee(@pk1, @pk2, min_fee, max_fee, max_weight, commitment)
    if (!Expect(ctx, '(')) return false;

    // Two pubkeys
    std::string a1 = ReadAlias(ctx);
    if (a1.empty()) return false;
    std::vector<uint8_t> pk1;
    if (!LookupKey(ctx, a1, pk1)) return false;
    rung_pks.push_back(pk1);

    if (!Expect(ctx, ',')) return false;
    std::string a2 = ReadAlias(ctx);
    if (a2.empty()) return false;
    std::vector<uint8_t> pk2;
    if (!LookupKey(ctx, a2, pk2)) return false;
    rung_pks.push_back(pk2);

    // Four numerics: min_fee, max_fee, max_weight, commitment
    uint32_t min_fee, max_fee, max_weight, commitment;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, min_fee)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, max_fee)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, max_weight)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, commitment)) return false;

    block.type = RungBlockType::ANCHOR_FEE;
    // Conditions layout: [SCHEME(1), NUMERIC, NUMERIC, NUMERIC, NUMERIC]
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(min_fee)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(max_fee)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(max_weight)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(commitment)});
    return Expect(ctx, ')');
}

// ── Governance family (new) ────────────────────────────────────────────

bool ParseAccumulator(ParseContext& ctx, RungBlock& block)
{
    // accumulator(root_hex)
    if (!Expect(ctx, '(')) return false;
    auto bytes = ParseHex(ReadHex(ctx));
    if (bytes.size() != 32) { ctx.error = "accumulator requires 32-byte root"; return false; }
    block.type = RungBlockType::ACCUMULATOR;
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

bool ParseRelativeValue(ParseContext& ctx, RungBlock& block)
{
    // relative_value(numerator, denominator)
    if (!Expect(ctx, '(')) return false;
    uint32_t num, den;
    if (!ReadUint32(ctx, num)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, den)) return false;
    block.type = RungBlockType::RELATIVE_VALUE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(num)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(den)});
    return Expect(ctx, ')');
}

// ── Legacy family ──────────────────────────────────────────────────────

bool ParseLegacySingleKey(ParseContext& ctx, RungBlock& block, RungBlockType type,
                           std::vector<std::vector<uint8_t>>& rung_pks)
{
    // p2pk(@pk) | p2pkh(@pk) | p2wpkh(@pk) | p2tr(@pk)
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;
    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;

    block.type = type;

    // P2PKH/P2WPKH: PUBKEY → HASH160(pubkey) in conditions
    // (pubkey_count=0, NOT added to Merkle leaf)
    // P2PK/P2TR: PUBKEY goes to rung_pubkeys (Merkle leaf) + SCHEME in conditions
    if (type == RungBlockType::P2PKH_LEGACY || type == RungBlockType::P2WPKH_LEGACY) {
        // Compute RIPEMD160(SHA256(pubkey)) for conditions
        RungField h160_field;
        h160_field.type = RungDataType::HASH160;
        h160_field.data.resize(CHash160::OUTPUT_SIZE);
        CHash160().Write(pk).Finalize(h160_field.data);
        block.fields.push_back(std::move(h160_field));
    } else {
        // P2PK, P2TR: pubkey in Merkle leaf + SCHEME
        rung_pks.push_back(pk);
        block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
    }
    return Expect(ctx, ')');
}

bool ParseLegacyScript(ParseContext& ctx, RungBlock& block, RungBlockType type)
{
    // p2sh(inner_hex) | p2wsh(inner_hex) | p2tr_script(inner_hex)
    // Use PREIMAGE — the node auto-converts to HASH160 (P2SH) or HASH256 (P2WSH/P2TR_SCRIPT)
    if (!Expect(ctx, '(')) return false;
    auto bytes = ParseHex(ReadHex(ctx));
    if (bytes.empty()) { ctx.error = "legacy script block requires inner conditions hex"; return false; }
    block.type = type;
    block.fields.push_back({RungDataType::PREIMAGE, bytes});
    return Expect(ctx, ')');
}

// ── Block dispatcher ───────────────────────────────────────────────────

bool ParseBlock(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    if (++ctx.item_count > MAX_PARSE_ITEMS) {
        ctx.error = "descriptor exceeds maximum item count (" + std::to_string(MAX_PARSE_ITEMS) + ")";
        return false;
    }

    SkipWhitespace(ctx);

    // Check for inversion prefix
    bool inverted = false;
    if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == '!') {
        inverted = true;
        ++ctx.pos;
    }

    SkipWhitespace(ctx);
    std::string name = ReadIdentifier(ctx);

    bool ok = false;
    // Signature family
    if (name == "sig") ok = ParseSig(ctx, block, rung_pks);
    else if (name == "multisig") ok = ParseMultisig(ctx, block, rung_pks);
    else if (name == "adaptor_sig") ok = ParseAdaptorSig(ctx, block, rung_pks);
    else if (name == "musig_threshold") ok = ParseMusigThreshold(ctx, block, rung_pks);
    else if (name == "key_ref_sig") ok = ParseKeyRefSig(ctx, block);
    // Timelock family
    else if (name == "csv") ok = ParseCsv(ctx, block, RungBlockType::CSV);
    else if (name == "csv_time") ok = ParseCsv(ctx, block, RungBlockType::CSV_TIME);
    else if (name == "cltv") ok = ParseCsv(ctx, block, RungBlockType::CLTV);
    else if (name == "cltv_time") ok = ParseCsv(ctx, block, RungBlockType::CLTV_TIME);
    // Hash family
    else if (name == "tagged_hash") ok = ParseTaggedHash(ctx, block);
    else if (name == "hash_guarded") ok = ParseHashGuarded(ctx, block);
    // QABI family
    else if (name == "qabi_prime") ok = ParseQABIPrime(ctx, block);
    else if (name == "qabi_spend") ok = ParseQABISpend(ctx, block);
    else if (name == "pq_batch") ok = ParsePqBatch(ctx, block);
    // Covenant family
    else if (name == "ctv") ok = ParseCtv(ctx, block);
    else if (name == "vault_lock") ok = ParseVaultLock(ctx, block, rung_pks);
    else if (name == "amount_lock") ok = ParseAmountLock(ctx, block);
    // Recursion family
    else if (name == "recurse_same") ok = ParseRecurseSame(ctx, block);
    else if (name == "recurse_modified") ok = ParseRecurseModified(ctx, block);
    else if (name == "recurse_until") ok = ParseRecurseUntil(ctx, block);
    else if (name == "recurse_count") ok = ParseRecurseCount(ctx, block);
    else if (name == "recurse_split") ok = ParseRecurseSplit(ctx, block);
    else if (name == "recurse_decay") ok = ParseRecurseDecay(ctx, block);
    // Anchor family: each has specific conditions fields
    else if (name == "anchor") ok = ParseOneNumericBlock(ctx, block, RungBlockType::ANCHOR);
    else if (name == "anchor_channel") ok = ParseOneNumericBlock(ctx, block, RungBlockType::ANCHOR_CHANNEL);
    else if (name == "anchor_pool") { // HASH256 + NUMERIC
        if (!Expect(ctx, '(')) { ok = false; } else {
            auto h = ParseHex(ReadHex(ctx));
            if (h.size() != 32) { ctx.error = "anchor_pool requires 32-byte hash"; ok = false; }
            else if (!Expect(ctx, ',')) { ok = false; }
            else { uint32_t n; if (!ReadUint32(ctx, n)) { ok = false; }
            else { block.type = RungBlockType::ANCHOR_POOL;
                block.fields.push_back({RungDataType::HASH256, h});
                block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(n)});
                ok = Expect(ctx, ')'); }}}}
    else if (name == "anchor_reserve") { // NUMERIC + NUMERIC + HASH256
        if (!Expect(ctx, '(')) { ok = false; } else {
            uint32_t n1, n2;
            if (!ReadUint32(ctx, n1) || !Expect(ctx, ',') || !ReadUint32(ctx, n2) || !Expect(ctx, ',')) { ok = false; }
            else { auto h = ParseHex(ReadHex(ctx));
                if (h.size() != 32) { ctx.error = "anchor_reserve requires 32-byte hash"; ok = false; }
                else { block.type = RungBlockType::ANCHOR_RESERVE;
                    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(n1)});
                    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(n2)});
                    block.fields.push_back({RungDataType::HASH256, h});
                    ok = Expect(ctx, ')'); }}}}
    else if (name == "anchor_seal") { // HASH256 + HASH256
        if (!Expect(ctx, '(')) { ok = false; } else {
            auto h1 = ParseHex(ReadHex(ctx));
            if (h1.size() != 32 || !Expect(ctx, ',')) { ctx.error = "anchor_seal requires two 32-byte hashes"; ok = false; }
            else { auto h2 = ParseHex(ReadHex(ctx));
                if (h2.size() != 32) { ctx.error = "anchor_seal requires two 32-byte hashes"; ok = false; }
                else { block.type = RungBlockType::ANCHOR_SEAL;
                    block.fields.push_back({RungDataType::HASH256, h1});
                    block.fields.push_back({RungDataType::HASH256, h2});
                    ok = Expect(ctx, ')'); }}}}
    else if (name == "anchor_oracle") ok = ParsePubkeyNumericBlock(ctx, block, RungBlockType::ANCHOR_ORACLE, rung_pks);
    else if (name == "data_return") ok = ParseDataReturn(ctx, block);
    // PLC family
    else if (name == "hysteresis_fee") ok = ParseTwoNumericBlock(ctx, block, RungBlockType::HYSTERESIS_FEE);
    else if (name == "hysteresis_value") ok = ParseTwoNumericBlock(ctx, block, RungBlockType::HYSTERESIS_VALUE);
    else if (name == "timer_continuous") ok = ParseTwoNumericBlock(ctx, block, RungBlockType::TIMER_CONTINUOUS);
    else if (name == "timer_off_delay") ok = ParseOneNumericBlock(ctx, block, RungBlockType::TIMER_OFF_DELAY);
    else if (name == "latch_set") ok = ParsePubkeyNumericBlock(ctx, block, RungBlockType::LATCH_SET, rung_pks);
    else if (name == "latch_reset") ok = ParsePubkeyTwoNumericBlock(ctx, block, RungBlockType::LATCH_RESET, rung_pks);
    else if (name == "counter_down") ok = ParsePubkeyNumericBlock(ctx, block, RungBlockType::COUNTER_DOWN, rung_pks);
    else if (name == "counter_preset") ok = ParsePubkeyTwoNumericBlock(ctx, block, RungBlockType::COUNTER_PRESET, rung_pks);
    else if (name == "counter_up") ok = ParsePubkeyTwoNumericBlock(ctx, block, RungBlockType::COUNTER_UP, rung_pks);
    else if (name == "compare") ok = ParseCompare(ctx, block);
    else if (name == "sequencer") ok = ParseTwoNumericBlock(ctx, block, RungBlockType::SEQUENCER);
    else if (name == "one_shot") ok = ParsePubkeyNumericHashBlock(ctx, block, RungBlockType::ONE_SHOT, rung_pks);
    else if (name == "rate_limit") ok = ParseRateLimit(ctx, block);
    else if (name == "cosign") ok = ParseCosign(ctx, block);
    // Compound family
    else if (name == "timelocked_sig") ok = ParseTimelockedSig(ctx, block, rung_pks);
    else if (name == "cltv_sig") ok = ParseCltvSig(ctx, block, rung_pks);
    else if (name == "htlc") ok = ParseHtlc(ctx, block, rung_pks);
    else if (name == "hash_sig") ok = ParseHashSig(ctx, block, rung_pks);
    else if (name == "ptlc") ok = ParsePtlc(ctx, block, rung_pks);
    else if (name == "timelocked_multisig") ok = ParseTimelockedMultisig(ctx, block, rung_pks);
    else if (name == "anchor_fee") ok = ParseAnchorFee(ctx, block, rung_pks);
    // Governance family
    else if (name == "epoch_gate") ok = ParseTwoNumericBlock(ctx, block, RungBlockType::EPOCH_GATE);
    else if (name == "weight_limit") ok = ParseOneNumericBlock(ctx, block, RungBlockType::WEIGHT_LIMIT);
    else if (name == "input_count") ok = ParseTwoNumericBlock(ctx, block, RungBlockType::INPUT_COUNT);
    else if (name == "output_count") ok = ParseTwoNumericBlock(ctx, block, RungBlockType::OUTPUT_COUNT);
    else if (name == "relative_value") ok = ParseRelativeValue(ctx, block);
    else if (name == "accumulator") ok = ParseAccumulator(ctx, block);
    else if (name == "output_check") ok = ParseOutputCheck(ctx, block);
    // Legacy family
    else if (name == "p2pk") ok = ParseLegacySingleKey(ctx, block, RungBlockType::P2PK_LEGACY, rung_pks);
    else if (name == "p2pkh") ok = ParseLegacySingleKey(ctx, block, RungBlockType::P2PKH_LEGACY, rung_pks);
    else if (name == "p2sh") ok = ParseLegacyScript(ctx, block, RungBlockType::P2SH_LEGACY);
    else if (name == "p2wpkh") ok = ParseLegacySingleKey(ctx, block, RungBlockType::P2WPKH_LEGACY, rung_pks);
    else if (name == "p2wsh") ok = ParseLegacyScript(ctx, block, RungBlockType::P2WSH_LEGACY);
    else if (name == "p2tr") ok = ParseLegacySingleKey(ctx, block, RungBlockType::P2TR_LEGACY, rung_pks);
    else if (name == "p2tr_script") ok = ParseLegacyScript(ctx, block, RungBlockType::P2TR_SCRIPT_LEGACY);
    else {
        ctx.error = "unknown block type: " + name;
        return false;
    }

    if (ok && inverted) {
        if (!IsInvertibleBlockType(block.type)) {
            ctx.error = "block type " + name + " cannot be inverted";
            return false;
        }
        block.inverted = true;
    }

    return ok;
}

bool ParseRung(ParseContext& ctx, Rung& rung, std::vector<std::vector<uint8_t>>& rung_pks)
{
    if (++ctx.depth > MAX_PARSE_DEPTH) {
        ctx.error = "descriptor nesting exceeds maximum depth (" + std::to_string(MAX_PARSE_DEPTH) + ")";
        return false;
    }
    if (++ctx.item_count > MAX_PARSE_ITEMS) {
        ctx.error = "descriptor exceeds maximum item count (" + std::to_string(MAX_PARSE_ITEMS) + ")";
        return false;
    }

    SkipWhitespace(ctx);

    if (Peek(ctx, "and")) {
        Match(ctx, "and");
        if (!Expect(ctx, '(')) { --ctx.depth; return false; }

        RungBlock block;
        if (!ParseBlock(ctx, block, rung_pks)) return false;
        rung.blocks.push_back(std::move(block));

        while (true) {
            SkipWhitespace(ctx);
            if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ')') {
                ++ctx.pos;
                break;
            }
            if (!Expect(ctx, ',')) return false;
            RungBlock next_block;
            if (!ParseBlock(ctx, next_block, rung_pks)) return false;
            rung.blocks.push_back(std::move(next_block));
        }
    } else {
        // Single block rung
        RungBlock block;
        if (!ParseBlock(ctx, block, rung_pks)) return false;
        rung.blocks.push_back(std::move(block));
    }

    --ctx.depth;
    return true;
}

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

bool ParseDescriptor(const std::string& desc,
                     const std::map<std::string, std::vector<uint8_t>>& keys,
                     RungConditions& out,
                     std::vector<std::vector<std::vector<uint8_t>>>& pubkeys,
                     std::string& error)
{
    // Audit 2026-05-03 second pass F10: cap descriptor length to bound
    // memory pressure from hostile input. The existing MAX_PARSE_ITEMS
    // (1000) and MAX_PARSE_DEPTH (32) caps bound the AST size, but a
    // single very long descriptor string (e.g. 1 MB of nested aliases)
    // could still cause allocator pressure during tokenisation. 65 KB is
    // well above any realistic ladder descriptor (typical: ~200 B; the
    // largest playground preset is under 4 KB) while staying small enough
    // to keep the parser's worst-case allocations bounded.
    static constexpr size_t MAX_DESCRIPTOR_LEN = 65536;
    if (desc.size() > MAX_DESCRIPTOR_LEN) {
        error = "descriptor too long: " + std::to_string(desc.size()) +
                " bytes exceeds maximum (" + std::to_string(MAX_DESCRIPTOR_LEN) + ")";
        return false;
    }
    ParseContext ctx{desc, keys, 0, {}};

    SkipWhitespace(ctx);
    if (!Match(ctx, "ladder")) {
        ctx.error = "descriptor must start with 'ladder('";
        error = ctx.error;
        return false;
    }
    if (!Expect(ctx, '(')) { error = ctx.error; return false; }

    if (!Match(ctx, "or")) {
        // Single rung (no or() wrapper)
        Rung rung;
        std::vector<std::vector<uint8_t>> rung_pks;
        if (!ParseRung(ctx, rung, rung_pks)) { error = ctx.error; return false; }
        out.rungs.push_back(std::move(rung));
        pubkeys.push_back(std::move(rung_pks));
    } else {
        if (!Expect(ctx, '(')) { error = ctx.error; return false; }

        // Parse first rung
        Rung first_rung;
        std::vector<std::vector<uint8_t>> first_pks;
        if (!ParseRung(ctx, first_rung, first_pks)) { error = ctx.error; return false; }
        out.rungs.push_back(std::move(first_rung));
        pubkeys.push_back(std::move(first_pks));

        // Parse remaining rungs
        while (true) {
            SkipWhitespace(ctx);
            if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ')') {
                ++ctx.pos;
                break;
            }
            if (!Expect(ctx, ',')) { error = ctx.error; return false; }

            Rung rung;
            std::vector<std::vector<uint8_t>> rung_pks;
            if (!ParseRung(ctx, rung, rung_pks)) { error = ctx.error; return false; }
            out.rungs.push_back(std::move(rung));
            pubkeys.push_back(std::move(rung_pks));
        }
    }

    if (!Expect(ctx, ')')) { error = ctx.error; return false; }

    SkipWhitespace(ctx);
    if (ctx.pos != ctx.desc.size()) {
        error = "unexpected trailing characters at position " + std::to_string(ctx.pos);
        return false;
    }

    return true;
}

std::string FormatDescriptor(const RungConditions& conditions,
                             const std::vector<std::vector<std::vector<uint8_t>>>& pubkeys,
                             const std::map<std::string, std::string>& aliases)
{
    auto format_block = [&](const RungBlock& block, size_t rung_idx, size_t& pk_cursor) -> std::string {
        std::string result;
        if (block.inverted) result += "!";

        auto get_alias = [&](size_t ri) -> std::string {
            if (ri < pubkeys.size() && pk_cursor < pubkeys[ri].size()) {
                std::string hex = HexStr(pubkeys[ri][pk_cursor]);
                pk_cursor++;
                auto it = aliases.find(hex);
                if (it != aliases.end()) return "@" + it->second;
                return "@" + hex.substr(0, 8);
            }
            pk_cursor++;
            return "@?";
        };

        switch (block.type) {
        case RungBlockType::SIG: {
            result += "sig(" + get_alias(rung_idx);
            if (!block.fields.empty() && block.fields[0].type == RungDataType::SCHEME &&
                !block.fields[0].data.empty()) {
                auto s = static_cast<RungScheme>(block.fields[0].data[0]);
                if (s != RungScheme::SCHNORR) {
                    result += ", " + SchemeToString(s);
                }
            }
            result += ")";
            return result;
        }
        case RungBlockType::CSV:
        case RungBlockType::CSV_TIME:
        case RungBlockType::CLTV:
        case RungBlockType::CLTV_TIME: {
            std::string name;
            switch (block.type) {
            case RungBlockType::CSV: name = "csv"; break;
            case RungBlockType::CSV_TIME: name = "csv_time"; break;
            case RungBlockType::CLTV: name = "cltv"; break;
            case RungBlockType::CLTV_TIME: name = "cltv_time"; break;
            default: break;
            }
            if (!block.fields.empty()) {
                uint32_t val = 0;
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    val |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
                result += name + "(" + std::to_string(val) + ")";
            }
            return result;
        }
        case RungBlockType::MULTISIG: {
            uint32_t threshold = 0;
            if (!block.fields.empty()) {
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    threshold |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
            }
            result += "multisig(" + std::to_string(threshold);
            // v2: pubkeys live in block.merkle_pubkeys (side hint), not in the
            // outer positional rung_pks list (consensus skips them via
            // PubkeyCountForBlock=0). Use the hint for alias resolution.
            for (const auto& pk : block.merkle_pubkeys) {
                std::string hex = HexStr(pk);
                auto it = aliases.find(hex);
                result += ", " + (it != aliases.end() ? "@" + it->second
                                                      : "@" + hex.substr(0, 8));
            }
            result += ")";
            return result;
        }
        case RungBlockType::ADAPTOR_SIG: {
            result += "adaptor_sig(" + get_alias(rung_idx) + ", " + get_alias(rung_idx);
            // Audit 2026-05-03 second pass F10: also check
            // !fields[0].data.empty() — a manually-constructed RungBlock
            // with fields[0].type == SCHEME but empty data would otherwise
            // out-of-bounds-read data[0]. Normal flow doesn't produce this
            // shape (deserialiser enforces SCHEME = 1 byte), but the
            // formatter is defensive against caller-supplied corruption.
            if (!block.fields.empty() &&
                block.fields[0].type == RungDataType::SCHEME &&
                !block.fields[0].data.empty()) {
                auto s = static_cast<RungScheme>(block.fields[0].data[0]);
                if (s != RungScheme::SCHNORR) result += ", " + SchemeToString(s);
            }
            result += ")";
            return result;
        }
        case RungBlockType::MUSIG_THRESHOLD: {
            uint32_t threshold = 0;
            if (!block.fields.empty())
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    threshold |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
            result += "musig_threshold(" + std::to_string(threshold);
            size_t n = PubkeyCountForBlock(block.type, block);
            for (size_t i = 0; i < n; ++i) result += ", " + get_alias(rung_idx);
            result += ")";
            return result;
        }
        case RungBlockType::KEY_REF_SIG: {
            result += "key_ref_sig(";
            for (size_t i = 0; i < block.fields.size(); ++i) {
                if (i > 0) result += ", ";
                uint32_t val = 0;
                for (size_t j = 0; j < block.fields[i].data.size() && j < 4; ++j)
                    val |= static_cast<uint32_t>(block.fields[i].data[j]) << (8 * j);
                result += std::to_string(val);
            }
            result += ")";
            return result;
        }
        case RungBlockType::TAGGED_HASH: {
            result += "tagged_hash(";
            for (size_t i = 0; i < block.fields.size(); ++i) {
                if (i > 0) result += ", ";
                result += HexStr(block.fields[i].data);
            }
            result += ")";
            return result;
        }
        case RungBlockType::HASH_GUARDED: {
            result += "hash_guarded(";
            if (!block.fields.empty()) result += HexStr(block.fields[0].data);
            result += ")";
            return result;
        }
        case RungBlockType::QABI_PRIME: {
            result += "qabi_prime()";
            return result;
        }
        case RungBlockType::QABI_SPEND: {
            // Fields: HASH256 auth_tip, HASH256 committed_root,
            //          NUMERIC committed_depth, NUMERIC committed_expiry,
            //          PUBKEY_COMMIT owner_id
            result += "qabi_spend(";
            if (block.fields.size() == 5) {
                result += HexStr(block.fields[0].data) + ", ";
                result += HexStr(block.fields[1].data) + ", ";
                uint32_t depth = 0, expiry = 0;
                for (size_t i = 0; i < block.fields[2].data.size() && i < 4; ++i)
                    depth |= static_cast<uint32_t>(block.fields[2].data[i]) << (8 * i);
                for (size_t i = 0; i < block.fields[3].data.size() && i < 4; ++i)
                    expiry |= static_cast<uint32_t>(block.fields[3].data[i]) << (8 * i);
                result += std::to_string(depth) + ", ";
                result += std::to_string(expiry) + ", ";
                result += HexStr(block.fields[4].data);
            }
            result += ")";
            return result;
        }
        case RungBlockType::CTV: {
            result += "ctv(";
            if (!block.fields.empty()) result += HexStr(block.fields[0].data);
            result += ")";
            return result;
        }
        case RungBlockType::PQ_BATCH: {
            // Field: HASH256 SHA256(falcon_pubkey).
            result += "pq_batch(";
            if (!block.fields.empty()) result += HexStr(block.fields[0].data);
            result += ")";
            return result;
        }
        case RungBlockType::VAULT_LOCK: {
            result += "vault_lock(" + get_alias(rung_idx) + ", " + get_alias(rung_idx) + ", ";
            if (!block.fields.empty()) {
                uint32_t val = 0;
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    val |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
                result += std::to_string(val);
            }
            result += ")";
            return result;
        }
        case RungBlockType::AMOUNT_LOCK:
        case RungBlockType::HYSTERESIS_FEE:
        case RungBlockType::HYSTERESIS_VALUE:
        case RungBlockType::TIMER_OFF_DELAY:
        case RungBlockType::INPUT_COUNT:
        case RungBlockType::OUTPUT_COUNT:
        case RungBlockType::EPOCH_GATE:
        case RungBlockType::RELATIVE_VALUE:
        case RungBlockType::RECURSE_SPLIT: {
            std::string name = BlockTypeName(block.type);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            result += name + "(";
            for (size_t i = 0; i < block.fields.size(); ++i) {
                if (i > 0) result += ", ";
                uint32_t val = 0;
                for (size_t j = 0; j < block.fields[i].data.size() && j < 4; ++j)
                    val |= static_cast<uint32_t>(block.fields[i].data[j]) << (8 * j);
                result += std::to_string(val);
            }
            result += ")";
            return result;
        }
        case RungBlockType::RECURSE_SAME:
        case RungBlockType::RECURSE_UNTIL:
        case RungBlockType::RECURSE_COUNT:
        case RungBlockType::WEIGHT_LIMIT:
        case RungBlockType::TIMER_CONTINUOUS:
        case RungBlockType::SEQUENCER: {
            std::string name = BlockTypeName(block.type);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            result += name + "(";
            if (!block.fields.empty()) {
                uint32_t val = 0;
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    val |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
                result += std::to_string(val);
            }
            result += ")";
            return result;
        }
        case RungBlockType::RECURSE_MODIFIED:
        case RungBlockType::RECURSE_DECAY: {
            std::string name = BlockTypeName(block.type);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            result += name + "(";
            for (size_t i = 0; i < block.fields.size(); ++i) {
                if (i > 0) result += ", ";
                uint32_t val = 0;
                for (size_t j = 0; j < block.fields[i].data.size() && j < 4; ++j)
                    val |= static_cast<uint32_t>(block.fields[i].data[j]) << (8 * j);
                result += std::to_string(val);
            }
            result += ")";
            return result;
        }
        case RungBlockType::TIMELOCKED_SIG:
        case RungBlockType::CLTV_SIG: {
            std::string name = BlockTypeName(block.type);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            result += name + "(" + get_alias(rung_idx) + ", ";
            // Skip SCHEME field, find NUMERIC
            for (const auto& f : block.fields) {
                if (f.type == RungDataType::NUMERIC) {
                    uint32_t val = 0;
                    for (size_t i = 0; i < f.data.size() && i < 4; ++i)
                        val |= static_cast<uint32_t>(f.data[i]) << (8 * i);
                    result += std::to_string(val);
                    break;
                }
            }
            result += ")";
            return result;
        }
        case RungBlockType::HTLC: {
            result += "htlc(" + get_alias(rung_idx) + ", " + get_alias(rung_idx) + ", ";
            for (const auto& f : block.fields) {
                if (f.type == RungDataType::HASH256) { result += HexStr(f.data) + ", "; break; }
            }
            for (const auto& f : block.fields) {
                if (f.type == RungDataType::NUMERIC) {
                    uint32_t val = 0;
                    for (size_t i = 0; i < f.data.size() && i < 4; ++i)
                        val |= static_cast<uint32_t>(f.data[i]) << (8 * i);
                    result += std::to_string(val);
                    break;
                }
            }
            result += ")";
            return result;
        }
        case RungBlockType::HASH_SIG: {
            result += "hash_sig(" + get_alias(rung_idx) + ", ";
            for (const auto& f : block.fields) {
                if (f.type == RungDataType::HASH256) { result += HexStr(f.data); break; }
            }
            result += ")";
            return result;
        }
        case RungBlockType::PTLC: {
            result += "ptlc(" + get_alias(rung_idx) + ", " + get_alias(rung_idx) + ", ";
            for (const auto& f : block.fields) {
                if (f.type == RungDataType::NUMERIC) {
                    uint32_t val = 0;
                    for (size_t i = 0; i < f.data.size() && i < 4; ++i)
                        val |= static_cast<uint32_t>(f.data[i]) << (8 * i);
                    result += std::to_string(val);
                    break;
                }
            }
            result += ")";
            return result;
        }
        case RungBlockType::TIMELOCKED_MULTISIG: {
            uint32_t threshold = 0;
            if (!block.fields.empty())
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    threshold |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
            result += "timelocked_multisig(" + std::to_string(threshold);
            // v2: pubkeys via inner Merkle root, surfaced through merkle_pubkeys.
            for (const auto& pk : block.merkle_pubkeys) {
                std::string hex = HexStr(pk);
                auto it = aliases.find(hex);
                result += ", " + (it != aliases.end() ? "@" + it->second
                                                      : "@" + hex.substr(0, 8));
            }
            for (const auto& f : block.fields) {
                if (f.type == RungDataType::NUMERIC && &f != &block.fields[0]) {
                    uint32_t val = 0;
                    for (size_t i = 0; i < f.data.size() && i < 4; ++i)
                        val |= static_cast<uint32_t>(f.data[i]) << (8 * i);
                    result += ", " + std::to_string(val);
                    break;
                }
            }
            result += ")";
            return result;
        }
        case RungBlockType::COMPARE: {
            result += "compare(";
            for (size_t i = 0; i < block.fields.size(); ++i) {
                if (i > 0) result += ", ";
                uint32_t val = 0;
                for (size_t j = 0; j < block.fields[i].data.size() && j < 4; ++j)
                    val |= static_cast<uint32_t>(block.fields[i].data[j]) << (8 * j);
                result += std::to_string(val);
            }
            result += ")";
            return result;
        }
        case RungBlockType::RATE_LIMIT: {
            result += "rate_limit(";
            for (size_t i = 0; i < block.fields.size(); ++i) {
                if (i > 0) result += ", ";
                uint32_t val = 0;
                for (size_t j = 0; j < block.fields[i].data.size() && j < 4; ++j)
                    val |= static_cast<uint32_t>(block.fields[i].data[j]) << (8 * j);
                result += std::to_string(val);
            }
            result += ")";
            return result;
        }
        case RungBlockType::COSIGN: {
            result += "cosign(";
            if (!block.fields.empty()) result += HexStr(block.fields[0].data);
            result += ")";
            return result;
        }
        case RungBlockType::ACCUMULATOR: {
            result += "accumulator(";
            if (!block.fields.empty()) result += HexStr(block.fields[0].data);
            result += ")";
            return result;
        }
        case RungBlockType::OUTPUT_CHECK: {
            result += "output_check(";
            for (size_t i = 0; i < block.fields.size(); ++i) {
                if (i > 0) result += ", ";
                if (block.fields[i].type == RungDataType::HASH256) {
                    result += HexStr(block.fields[i].data);
                } else {
                    uint32_t val = 0;
                    for (size_t j = 0; j < block.fields[i].data.size() && j < 4; ++j)
                        val |= static_cast<uint32_t>(block.fields[i].data[j]) << (8 * j);
                    result += std::to_string(val);
                }
            }
            result += ")";
            return result;
        }
        case RungBlockType::LATCH_SET:
        case RungBlockType::LATCH_RESET:
        case RungBlockType::COUNTER_DOWN:
        case RungBlockType::COUNTER_PRESET:
        case RungBlockType::COUNTER_UP:
        case RungBlockType::ONE_SHOT: {
            std::string name = BlockTypeName(block.type);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            result += name + "(" + get_alias(rung_idx) + ", ";
            if (!block.fields.empty()) {
                uint32_t val = 0;
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    val |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
                result += std::to_string(val);
            }
            result += ")";
            return result;
        }
        case RungBlockType::ANCHOR:
        case RungBlockType::ANCHOR_CHANNEL:
        case RungBlockType::ANCHOR_POOL:
        case RungBlockType::ANCHOR_RESERVE:
        case RungBlockType::ANCHOR_SEAL:
        case RungBlockType::ANCHOR_ORACLE: {
            std::string name = BlockTypeName(block.type);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            result += name + "()";
            return result;
        }
        case RungBlockType::DATA_RETURN: {
            result += "data_return(";
            if (!block.fields.empty()) result += HexStr(block.fields[0].data);
            result += ")";
            return result;
        }
        case RungBlockType::P2PK_LEGACY:
        case RungBlockType::P2PKH_LEGACY:
        case RungBlockType::P2WPKH_LEGACY:
        case RungBlockType::P2TR_LEGACY: {
            std::string name;
            switch (block.type) {
            case RungBlockType::P2PK_LEGACY: name = "p2pk"; break;
            case RungBlockType::P2PKH_LEGACY: name = "p2pkh"; break;
            case RungBlockType::P2WPKH_LEGACY: name = "p2wpkh"; break;
            case RungBlockType::P2TR_LEGACY: name = "p2tr"; break;
            default: break;
            }
            result += name + "(" + get_alias(rung_idx) + ")";
            return result;
        }
        case RungBlockType::P2SH_LEGACY:
        case RungBlockType::P2WSH_LEGACY:
        case RungBlockType::P2TR_SCRIPT_LEGACY: {
            std::string name;
            switch (block.type) {
            case RungBlockType::P2SH_LEGACY: name = "p2sh"; break;
            case RungBlockType::P2WSH_LEGACY: name = "p2wsh"; break;
            case RungBlockType::P2TR_SCRIPT_LEGACY: name = "p2tr_script"; break;
            default: break;
            }
            result += name + "(";
            if (!block.fields.empty()) result += HexStr(block.fields[0].data);
            result += ")";
            return result;
        }
        default: {
            result += BlockTypeName(block.type) + "(...)";
            return result;
        }
        }
    };

    std::string result = "ladder(";
    if (conditions.rungs.size() > 1) result += "or(";

    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
        if (r > 0) result += ", ";
        const auto& rung = conditions.rungs[r];
        size_t pk_cursor = 0;

        if (rung.blocks.size() > 1) {
            result += "and(";
            for (size_t b = 0; b < rung.blocks.size(); ++b) {
                if (b > 0) result += ", ";
                result += format_block(rung.blocks[b], r, pk_cursor);
            }
            result += ")";
        } else if (rung.blocks.size() == 1) {
            result += format_block(rung.blocks[0], r, pk_cursor);
        }
    }

    if (conditions.rungs.size() > 1) result += ")";
    result += ")";
    return result;
}

// ============================================================================
// TX_MLSC descriptors
// ============================================================================

bool ParseTxMLSCDescriptor(const std::string& desc,
                            const std::map<std::string, std::vector<uint8_t>>& keys,
                            TxMLSCDescriptor& out,
                            std::string& error)
{
    ParseContext ctx{desc, keys, 0, {}};

    SkipWhitespace(ctx);
    if (!Match(ctx, "ladder")) {
        error = "descriptor must start with 'ladder('";
        return false;
    }
    if (!Expect(ctx, '(')) { error = ctx.error; return false; }

    // Parse output() wrappers
    bool first = true;
    while (true) {
        SkipWhitespace(ctx);
        if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ')') {
            ++ctx.pos;
            break;
        }
        if (!first) {
            if (!Expect(ctx, ',')) { error = ctx.error; return false; }
            SkipWhitespace(ctx);
        }
        first = false;

        if (!Match(ctx, "output")) {
            error = "expected 'output(' at position " + std::to_string(ctx.pos);
            return false;
        }
        if (!Expect(ctx, '(')) { error = ctx.error; return false; }

        // Parse output index
        SkipWhitespace(ctx);
        size_t idx_start = ctx.pos;
        while (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] >= '0' && ctx.desc[ctx.pos] <= '9') {
            ++ctx.pos;
        }
        if (ctx.pos == idx_start) {
            error = "expected output index at position " + std::to_string(ctx.pos);
            return false;
        }
        // Audit 2026-05-03 second pass F10: pre-validate length before
        // std::stoul. A 30+-digit decimal exceeds ULONG_MAX and stoul
        // throws std::out_of_range. The exception is normally caught by
        // the JSONRPC framework but produces a generic 500-class error;
        // pre-checking gives a clean RPC_INVALID_PARAMETER instead.
        const size_t idx_str_len = ctx.pos - idx_start;
        if (idx_str_len > 10) { // uint32 max = 10 digits, MAX_OUTPUT_INDEX much smaller
            error = "output index too large (more than 10 digits) at position " + std::to_string(idx_start);
            return false;
        }
        size_t output_index;
        try {
            output_index = std::stoul(ctx.desc.substr(idx_start, idx_str_len));
        } catch (const std::exception&) {
            error = "invalid output index at position " + std::to_string(idx_start);
            return false;
        }
        if (output_index > MAX_OUTPUT_INDEX) {
            error = "output index " + std::to_string(output_index) + " exceeds maximum (" + std::to_string(MAX_OUTPUT_INDEX) + ")";
            return false;
        }

        if (!Expect(ctx, ',')) { error = ctx.error; return false; }

        // Ensure outputs vector is large enough
        while (out.outputs.size() <= output_index) {
            out.outputs.push_back({});
        }

        // Parse rungs for this output: or(rung1, rung2, ...) or single rung
        SkipWhitespace(ctx);
        if (Match(ctx, "or")) {
            if (!Expect(ctx, '(')) { error = ctx.error; return false; }
            // Multiple rungs
            bool first_rung = true;
            while (true) {
                SkipWhitespace(ctx);
                if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ')') {
                    ++ctx.pos;
                    break;
                }
                if (!first_rung) {
                    if (!Expect(ctx, ',')) { error = ctx.error; return false; }
                }
                first_rung = false;
                Rung rung;
                std::vector<std::vector<uint8_t>> rung_pks;
                if (!ParseRung(ctx, rung, rung_pks)) { error = ctx.error; return false; }
                out.outputs[output_index].rungs.push_back(std::move(rung));
                out.outputs[output_index].rung_pubkeys.push_back(std::move(rung_pks));
            }
        } else {
            // Single rung
            Rung rung;
            std::vector<std::vector<uint8_t>> rung_pks;
            if (!ParseRung(ctx, rung, rung_pks)) { error = ctx.error; return false; }
            out.outputs[output_index].rungs.push_back(std::move(rung));
            out.outputs[output_index].rung_pubkeys.push_back(std::move(rung_pks));
        }

        if (!Expect(ctx, ')')) { error = ctx.error; return false; } // close output()
    }

    SkipWhitespace(ctx);
    if (ctx.pos != ctx.desc.size()) {
        error = "unexpected trailing characters at position " + std::to_string(ctx.pos);
        return false;
    }

    // Validate: every output has at least one rung
    for (size_t i = 0; i < out.outputs.size(); ++i) {
        if (out.outputs[i].rungs.empty()) {
            error = "output " + std::to_string(i) + " has no rungs";
            return false;
        }
    }

    return true;
}

std::string FormatTxMLSCDescriptor(const std::vector<CreationProofRung>& rungs)
{
    // Group rungs by output_index
    std::map<uint8_t, std::vector<size_t>> output_rungs;
    for (size_t i = 0; i < rungs.size(); ++i) {
        output_rungs[rungs[i].coil.output_index].push_back(i);
    }

    std::string result = "ladder(";
    bool first_output = true;
    for (const auto& [idx, rung_indices] : output_rungs) {
        if (!first_output) result += ", ";
        first_output = false;
        result += "output(" + std::to_string(idx) + ", ";
        if (rung_indices.size() > 1) result += "or(";
        for (size_t r = 0; r < rung_indices.size(); ++r) {
            if (r > 0) result += ", ";
            const auto& cp_rung = rungs[rung_indices[r]];
            // Format blocks as type names
            if (cp_rung.blocks.size() > 1) result += "and(";
            for (size_t b = 0; b < cp_rung.blocks.size(); ++b) {
                if (b > 0) result += ", ";
                auto bt = static_cast<RungBlockType>(cp_rung.blocks[b].first);
                if (cp_rung.blocks[b].second) result += "!";
                result += BlockTypeName(bt);
            }
            if (cp_rung.blocks.size() > 1) result += ")";
        }
        if (rung_indices.size() > 1) result += ")";
        result += ")";
    }
    result += ")";
    return result;
}

} // namespace rung
