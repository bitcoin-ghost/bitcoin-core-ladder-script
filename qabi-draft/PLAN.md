# QABI Block Type Implementation Plan

## Context

QABI (Quantum Atomic Batch Input) is a new block type that enables multi-party quantum signature aggregation through systematic/script-level enforcement. Multiple independent UTXOs can be bonded under a single FALCON witness via a coordinator, with each participant's spending conditions enforcing trustless consent. This achieves O(1) quantum signature overhead for N-party transactions without new cryptography.

QABI is functionally like SIG but **rejects classical schemes** (Schnorr/ECDSA). Only PQ schemes (FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA) are accepted. Participants set their own conditions using existing blocks (OUTPUT_CHECK, INPUT_COUNT, etc.). QABI is just the anchor.

## Block Specification

- **Type**: `0x0006` (signature family, after KEY_REF_SIG)
- **Micro-header slot**: `0x3F` (next free)
- **Conditions layout**: `[SCHEME(1)]` — alias of SIG_CONDITIONS
- **Witness layout**: `[PUBKEY(var), SIGNATURE(var)]` — alias of SIG_WITNESS
- **pubkey_count**: 1
- **key_consuming**: true
- **invertible**: false
- **conditions_only**: false
- **Descriptor**: `qabi(@key)` or `qabi(@key, falcon512)`

## Evaluation Logic

1. Extract PUBKEY, SIGNATURE, SCHEME from merged block
2. Check SCHEME is PQ via `IsPQScheme()` — return UNSATISFIED if classical
3. Verify PQ signature via `EvalPQSig()` (reuses existing PQ verifier)

## Files to Modify

### 1. `src/rung/types.h` (8 locations)
- Add `QABI = 0x0006` to RungBlockType enum (after KEY_REF_SIG)
- Add to IsKnownBlockType switch
- Add to BlockTypeName: `"QABI"`
- Add to IsKeyConsumingBlockType (single pubkey)
- Add to PubkeyCountForBlock → return 1
- Define `QABI_CONDITIONS = SIG_CONDITIONS` (alias)
- Define `QABI_WITNESS = SIG_WITNESS` (alias)
- Add to GetImplicitLayout for both CONDITIONS and WITNESS contexts
- Add `0x0006` to MICRO_HEADER_TABLE at slot 0x3F
- Add BlockDescriptor entry

### 2. `src/rung/rpc.cpp` (2 locations)
- Add `"QABI"` to ParseBlockType
- Add `case RungBlockType::QABI` to BuildWitnessBlock:
  - Enforce PQ scheme: if `block_spec` has `"privkey"` (classical) without `"scheme"`, reject
  - If `"scheme"` provided, validate `IsPQScheme()` before calling `SignSingleKey`
  - Otherwise route to PQ signing path (pq_privkey + pq_pubkey)

### 3. `src/rung/evaluator.cpp` (2 locations)
- Add `EvalQabiBlock()` function:
  - Find PUBKEY, SIGNATURE, SCHEME fields
  - Check `IsPQScheme(scheme)` — UNSATISFIED if classical
  - Call `EvalPQSig(scheme, sig, pubkey, checker)`
- Add `case RungBlockType::QABI` to EvalBlock switch

### 4. `src/rung/descriptor.cpp` (3 locations)
- Add `ParseQabi()` function:
  - Syntax: `qabi(@alias)` or `qabi(@alias, scheme_name)`
  - Default scheme: FALCON512
  - Validate scheme is PQ via `IsPQScheme()` — error if classical
  - Push SCHEME field, push pubkey to rung_pks
- Add `"qabi"` to ParseBlock dispatcher
- Add `case RungBlockType::QABI` to formatladder (always print scheme name)

### 5. `test/functional/feature_rung_tx.py` (1 test method)
- Add `test_qabi_block()` method with skip-if-no-PQ guard
- Test: create QABI output → fund → sign with FALCON → spend → verify

## Known Non-Issues
- **SIGHASH**: SIGHASH_ALL already covers all inputs/outputs — no change needed
- **Multiple QABI**: Multiple QABI blocks in one tx are redundant but harmless — consensus doesn't enforce uniqueness (document as convention)
- **Auto-tweak**: createtxmlsc checks `type == SIG` — QABI naturally excluded
- **signladder auto-upgrade**: checks `type == SIG` — QABI naturally excluded
- **Variable-size encoding**: PQ keys (up to 1952B) and sigs (up to 49216B) fit within FieldMaxSize limits
- **Serialization**: No special handling — standard micro-header + implicit fields

## Headaches Addressed
1. **BuildWitnessBlock PQ enforcement**: QABI case must reject classical signing (no bare `privkey` without PQ scheme). Enforce at RPC level.
2. **Descriptor PQ validation**: `ParseQabi` must reject non-PQ schemes at parse time.
3. **Test portability**: QABI tests need liboqs. Add skip guard for builds without PQ support.

## Verification
1. Build with `-j2` (OOM-safe for WSL2)
2. Run functional test: `python3 test/functional/feature_rung_tx.py`
3. Deploy to signet VPS and test:
   - `generatepqkeypair FALCON512` → get PQ keypair
   - `createtxmlsc` with QABI block + FALCON pubkey → fund → mine
   - `signrungtx` with PQ signing params → broadcast → mine
   - Verify: QABI with Schnorr scheme → must fail (UNSATISFIED)
   - Verify: multi-input QABI batch → one FALCON sig covers all inputs
