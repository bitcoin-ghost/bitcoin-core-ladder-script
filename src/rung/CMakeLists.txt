# Copyright (c) 2026 The Ladder Script developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Ladder Script: typed transaction conditions for Bitcoin (v4 RUNG_TX).
# Replaces raw Bitcoin Script opcodes with 61 typed function blocks.
# Every witness byte must conform to a typed field — no arbitrary data possible.

add_library(bitcoin_rung STATIC EXCLUDE_FROM_ALL
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
  qabi.cpp
)

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
)

# Optional post-quantum signature support via liboqs
find_package(liboqs QUIET)
if(liboqs_FOUND)
  message(STATUS "liboqs found — post-quantum signature verification enabled")
  target_compile_definitions(bitcoin_rung PRIVATE HAVE_LIBOQS)
  target_link_libraries(bitcoin_rung PRIVATE OQS::oqs)
else()
  message(STATUS "liboqs not found — post-quantum signature verification disabled (PQ schemes will return UNSATISFIED)")
endif()
