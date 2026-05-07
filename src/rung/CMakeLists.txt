# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Ladder Script: typed transaction conditions for Bitcoin (v4 RUNG_TX).
# Replaces raw Bitcoin Script opcodes with 61 typed function blocks.
# Every witness byte must conform to a typed field — no arbitrary data possible.

# liboqs is a HARD dependency for Ladder Script. The base SIG block
# supports FALCON-512, FALCON-1024, Dilithium3, and SPHINCS+ as valid
# signature schemes — these are consensus-critical, not optional
# extensions. A node built without liboqs would silently disagree with
# liboqs-enabled nodes on whether a PQ-signed spend is valid, which is
# a consensus split. Always require liboqs, always link it, and always
# define HAVE_LIBOQS.
#
# AUD-04: pin to a specific liboqs version. Different liboqs versions
# can produce divergent verify results for marginal/malformed FALCON
# signatures (the variable-length sig framing is the historic upstream
# patch hot spot). Without an EXACT pin every operator's distro picks
# whatever liboqs is on hand, fragmenting the network across version
# boundaries — a chain-split vector. The pinned version MUST match
# what the BIP specifies as the consensus crypto. The runtime
# `static_assert` in pq_verify.cpp guards against the rare case where
# CMake finds an EXACT-matching install but compiles against a
# different OQS_VERSION_TEXT header (system-dir leak, multi-install).
set(LADDER_LIBOQS_VERSION "0.10.1" CACHE STRING
    "Pinned liboqs version. Changing this constitutes a hard fork.")
find_package(liboqs ${LADDER_LIBOQS_VERSION} EXACT REQUIRED)
message(STATUS "liboqs ${LADDER_LIBOQS_VERSION} found (EXACT pin) — "
               "post-quantum signature verification enabled")

# QABIO extension — N-party post-quantum batch I/O, specified in BIP-YYYY
# as a separable soft-fork extension on top of Ladder Script.
#
# ENABLE_QABIO=ON  (default): full QABIO consensus rules, the FALCON-512
#                              coordinator signature path, QABI_PRIME and
#                              QABI_SPEND evaluators, and the qabi_* RPC
#                              family are all compiled in.
# ENABLE_QABIO=OFF           : Base Ladder Script only. QABI_PRIME and
#                              QABI_SPEND block types still deserialise
#                              (for wire-format forward compatibility)
#                              but return UNSATISFIED on evaluation.
#                              liboqs is still required (the base SIG
#                              block's PQ schemes need it) — the flag
#                              only separates the QABIO-specific
#                              consensus surface from the base layer
#                              for BIP review purposes, it does not
#                              remove any consensus-critical crypto.
option(ENABLE_QABIO "Enable QABIO extension (N-party PQ batch I/O, BIP-YYYY)" ON)

set(_rung_sources
  adaptor.cpp
  types.cpp
  serialize.cpp
  conditions.cpp
  sighash.cpp
  evaluator.cpp
  block_helpers.cpp
  blocks/sig.cpp
  blocks/timelock.cpp
  blocks/hash.cpp
  blocks/covenant.cpp
  blocks/anchor.cpp
  blocks/recursion.cpp
  blocks/plc.cpp
  blocks/compound.cpp
  blocks/governance.cpp
  blocks/legacy.cpp
  policy.cpp
  rpc.cpp
  pq_verify.cpp
  descriptor.cpp
)
if(ENABLE_QABIO)
  list(APPEND _rung_sources qabi.cpp blocks/qabi.cpp)
endif()

add_library(bitcoin_rung STATIC EXCLUDE_FROM_ALL ${_rung_sources})

target_include_directories(bitcoin_rung
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(bitcoin_rung
  PRIVATE
    core_interface
    bitcoin_consensus
    bitcoin_util
    secp256k1
    univalue
    Boost::headers
    OQS::oqs
)

# HAVE_LIBOQS and ENABLE_QABIO are both PUBLIC: they change the
# definitions of types exposed in rung/*.h (QABOSigCache, RungEvalContext
# members, VerifyRungTx parameters), so every translation unit that
# includes those headers — validation.cpp in bitcoin_node, rung_tests.cpp
# in the test target, etc. — must see the same flag state as bitcoin_rung
# itself. PRIVATE would let dependents see a different type and produce
# an ODR/mangled-name split at link time.
target_compile_definitions(bitcoin_rung PUBLIC HAVE_LIBOQS)

if(ENABLE_QABIO)
  target_compile_definitions(bitcoin_rung PUBLIC ENABLE_QABIO)
  message(STATUS "QABIO extension enabled (BIP-YYYY consensus rules active)")
else()
  message(STATUS "QABIO extension disabled (base Ladder Script only — QABI_SPEND returns UNSATISFIED)")
endif()
