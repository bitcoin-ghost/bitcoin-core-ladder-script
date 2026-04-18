// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/MIT.

#ifndef BITCOIN_RUNG_SHIMS_H
#define BITCOIN_RUNG_SHIMS_H

// ============================================================================
// Bitcoin Core → libladder shim layer
// ============================================================================
//
// libladder (under src/rung/) is written to accept byte spans, LadderScript,
// LadderTxView, and other adapter types from src/rung/api.h. The library
// knows nothing about Core's CScript, CTransaction, CTxOut, CAmount, or
// BaseSignatureChecker.
//
// This header provides thin inline overloads that accept the Core types
// and forward to the library's adapter-typed entry points. It is the ONLY
// file that spans the boundary — any Bitcoin Core code that calls into
// rung includes this header, never reaches into src/rung/ with Core types.
//
// Every function here is inline and header-only so there is no object file
// to link against (nothing goes into bitcoin_rung — bitcoin_rung's link
// deps stay limited to crypto / util / secp256k1 / oqs).

#include <rung/conditions.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rung {

// --- Conversions -----------------------------------------------------------

/** View a CScript as a read-only byte span for the library. */
inline std::span<const uint8_t> ToLadderScript(const CScript& s)
{
    return std::span<const uint8_t>{s.data(), s.size()};
}

/** Copy a library-returned byte vector back into a CScript. */
inline CScript ToCScript(const std::vector<uint8_t>& bytes)
{
    return CScript(bytes.begin(), bytes.end());
}

// --- Conditions / MLSC script predicates ----------------------------------
//
// Overloads that accept CScript and forward to the span-based library API.

inline bool IsMLSCScript(const CScript& s)          { return rung::api::IsMLSCScript(ToLadderScript(s)); }
inline bool IsLadderScript(const CScript& s)        { return rung::api::IsLadderScript(ToLadderScript(s)); }
inline bool IsCompactMLSC(const CScript& s)         { return rung::api::IsCompactMLSC(ToLadderScript(s)); }
inline bool GetMLSCRoot(const CScript& s, uint256& out)
                                                    { return rung::api::GetMLSCRoot(ToLadderScript(s), out); }
inline std::vector<uint8_t> GetMLSCData(const CScript& s)
                                                    { return rung::api::GetMLSCData(ToLadderScript(s)); }
inline bool HasMLSCData(const CScript& s)           { return rung::api::HasMLSCData(ToLadderScript(s)); }

// Builders: library returns byte vectors, shim wraps back into CScript.
inline CScript CreateMLSCScript(const uint256& root)
{
    return ToCScript(rung::api::CreateMLSCScript(root));
}
inline CScript CreateMLSCScript(const uint256& root, const std::vector<uint8_t>& data)
{
    return ToCScript(rung::api::CreateMLSCScript(root, data));
}

// Deserialise / serialise inline conditions (0xC1 — always rejected).
inline bool IsRungConditionsScript(const CScript& s)
{
    return rung::api::IsRungConditionsScript(ToLadderScript(s));
}
inline bool DeserializeRungConditions(const CScript& s, rung::RungConditions& out, std::string& error)
{
    return rung::api::DeserializeRungConditions(ToLadderScript(s), out, error);
}
inline CScript SerializeRungConditions(const rung::RungConditions& c)
{
    return ToCScript(rung::api::SerializeRungConditions(c));
}

}  // namespace rung

#endif  // BITCOIN_RUNG_SHIMS_H
