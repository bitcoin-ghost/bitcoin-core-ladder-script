# TLA+ Formal Specifications

Formal models of Ladder Script (TX_MLSC / RUNG_TX v4) consensus rules. These
specifications verify safety properties of every feature in the bitcoin-core-ladder
fork of Bitcoin Core v30.0.

> **See `spec/RESULTS.md` for the latest run report** — exhaustive
> model-check stats, the simulation-mode coverage for the
> multi-dimensional specs, and the honest framing on what this evidence
> is and is not.

## Specifications (21 total)

### Core features (4 — model-checked)

| Spec | Properties | Status |
|------|-----------|--------|
| AutoKeyPath | Tweak detection, routing correctness, domain separation | PASS (78K states) |
| UTXODedup | Synthetic entry lifecycle, inflation, reorg cleanup | PASS (98 states) |
| AnchorFee | Fee rate pinning resistance, weight limit, fail-closed | PASS (8.5M states) |
| HybridCreationProof | 3+ output proof requirement, root binding, rejection cases | Not yet (WSL2 OOM) |

### General evaluation (7)

| Spec | Properties |
|------|-----------|
| LadderEval | AND/OR logic, inversion, relay DAG, first-wins, empty rung/ladder |
| LadderMerkle | Tree construction, sorted interior nodes, path verification, all 3 proof modes |
| LadderSighash | Commitment completeness, ANYPREVOUT, ANYPREVOUTANYSCRIPT, domain separation |
| LadderAntiSpam | Field type restrictions, preimage limits, DATA restriction, embeddable bounds |
| LadderWireFormat | Micro-header encoding/decoding, compact coil, flag bytes, creation proof bounds |
| SharedProof | Thread-safe cache, leaf membership, cross-source rejection, same-source acceptance |
| RecursiveCovenant | RECURSE_SAME/SPLIT/MODIFIED/COUNT/UNTIL/DECAY termination, value conservation |

### Per-family block type specs (10)

| Spec | Block types |
|------|------------|
| BlockSignature | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG |
| BlockTimelock | CSV, CSV_TIME, CLTV, CLTV_TIME |
| BlockHash | TAGGED_HASH, HASH_GUARDED |
| BlockCovenant | CTV, VAULT_LOCK, AMOUNT_LOCK |
| BlockRecursion | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| BlockAnchor | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN |
| BlockPLC | HYSTERESIS_FEE, COMPARE, LATCH_SET, COUNTER_DOWN, SEQUENCER, COSIGN (representative subset) |
| BlockCompound | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG, ANCHOR_FEE |
| BlockGovernance | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK |
| BlockLegacy | P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT legacy wrappers |

## Running

Requires TLA+ tools (tla2tools.jar) and Java 17+. The tools are available in the
ghost-labs-ladder-script repo at `spec/jdk-17.0.18+8-jre/bin/java` and `spec/tla2tools.jar`.

**WARNING:** Do NOT run on WSL2 with limited RAM. Use a VPS with 16GB+ RAM.
Use `-workers 2` (not `-workers auto`) on memory-constrained systems.

### Quick start (small constants — for testing)

```bash
# Set up paths (adjust if running from a different location)
JAVA=~/dev/projects/ghost-labs-ladder-script/spec/jdk-17.0.18+8-jre/bin/java
TLA2TOOLS=~/dev/projects/ghost-labs-ladder-script/spec/tla2tools.jar
SPEC_DIR=~/dev/projects/bitcoin-core-ladder/spec

# Core features
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/AutoKeyPath.cfg $SPEC_DIR/AutoKeyPath.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/UTXODedup.cfg $SPEC_DIR/UTXODedup.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/AnchorFee.cfg $SPEC_DIR/AnchorFee.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/HybridCreationProof.cfg $SPEC_DIR/HybridCreationProof.tla -workers 2

# General evaluation
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/LadderEval.cfg $SPEC_DIR/LadderEval.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/LadderMerkle.cfg $SPEC_DIR/LadderMerkle.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/LadderSighash.cfg $SPEC_DIR/LadderSighash.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/LadderAntiSpam.cfg $SPEC_DIR/LadderAntiSpam.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/LadderWireFormat.cfg $SPEC_DIR/LadderWireFormat.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/SharedProof.cfg $SPEC_DIR/SharedProof.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/RecursiveCovenant.cfg $SPEC_DIR/RecursiveCovenant.tla -workers 2

# Per-family block types
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockSignature.cfg $SPEC_DIR/BlockSignature.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockTimelock.cfg $SPEC_DIR/BlockTimelock.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockHash.cfg $SPEC_DIR/BlockHash.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockCovenant.cfg $SPEC_DIR/BlockCovenant.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockRecursion.cfg $SPEC_DIR/BlockRecursion.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockAnchor.cfg $SPEC_DIR/BlockAnchor.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockPLC.cfg $SPEC_DIR/BlockPLC.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockCompound.cfg $SPEC_DIR/BlockCompound.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockGovernance.cfg $SPEC_DIR/BlockGovernance.tla -workers 2
$JAVA -jar $TLA2TOOLS -config $SPEC_DIR/BlockLegacy.cfg $SPEC_DIR/BlockLegacy.tla -workers 2
```

### VPS constants

Each `.cfg` file ships with small constants for fast testing. The `.tla` files
contain commented-out VPS constants (typically 10-100x larger) for thorough
verification on a 16GB+ RAM machine. To use them, edit the `.cfg` file and
replace the default constants with the VPS values noted in the `.tla` header.

### Run all specs (bash one-liner)

```bash
for cfg in $SPEC_DIR/*.cfg; do
  tla="${cfg%.cfg}.tla"
  echo "=== $(basename $tla) ==="
  $JAVA -jar $TLA2TOOLS -config "$cfg" "$tla" -workers 2
done
```

## Source file reference

| Source file | What it covers |
|------------|---------------|
| `src/rung/types.h` | 62 block types, field types, implicit layouts, invertibility, key-consuming |
| `src/rung/evaluator.cpp` | EvalBlock dispatch, all Eval*Block functions, VerifyRungTx, BatchVerifier |
| `src/rung/serialize.cpp` | Wire format, micro-headers, compact coil, field validation |
| `src/rung/conditions.cpp` | Merkle tree, leaf computation, proof verification, creation proofs |
| `src/rung/sighash.cpp` | SignatureHashLadder, SignatureHashLadderKeyPath, hash types |
| `src/primitives/transaction.h` | Wire format, flag bytes, creation proof bounds |
| `src/coins.cpp` | Synthetic root entry, MLSC_ROOT_VOUT |
| `src/validation.cpp` | CScriptCheck routing, UTXO inflation, block_height passing |
| `src/compressor.cpp` | Type 0x06 MLSC compression |
