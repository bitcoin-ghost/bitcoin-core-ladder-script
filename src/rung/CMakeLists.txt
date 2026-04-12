# Copyright (c) 2026 The Ladder Script developers
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
find_package(liboqs REQUIRED)
message(STATUS "liboqs found — post-quantum signature verification enabled")

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
  policy.cpp
  rpc.cpp
  pq_verify.cpp
  descriptor.cpp
)
if(ENABLE_QABIO)
  list(APPEND _rung_sources qabi.cpp)
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
    OQS::oqs
)

target_compile_definitions(bitcoin_rung PRIVATE HAVE_LIBOQS)

# QABIO compile-time gate. Propagated to every translation unit in
# bitcoin_rung so evaluator.cpp, rpc.cpp, policy.cpp, etc. can
# conditionally compile their QABIO-specific code.
if(ENABLE_QABIO)
  target_compile_definitions(bitcoin_rung PRIVATE ENABLE_QABIO)
  message(STATUS "QABIO extension enabled (BIP-YYYY consensus rules active)")
else()
  message(STATUS "QABIO extension disabled (base Ladder Script only — QABI_SPEND returns UNSATISFIED)")
endif()
