# TLA+ Formal Specifications

Formal models of Ladder Script consensus rules. These specifications verify
safety properties of the new features added in the bitcoin-core-ladder fork.

## Specifications

| Spec | Properties | State space (est.) |
|------|-----------|-------------------|
| HybridCreationProof | 3+ output proof requirement, root binding, rejection cases | ~500K states |
| UTXODedup | Synthetic entry lifecycle, inflation, reorg cleanup | ~100K states |
| AnchorFee | Fee rate pinning resistance, weight limit, fail-closed | ~5M states |
| AutoKeyPath | Tweak detection, routing correctness, domain separation | ~50K states |

## Running

Requires TLA+ tools (tla2tools.jar) and Java 17+.

```bash
java -jar tla2tools.jar -config HybridCreationProof.cfg HybridCreationProof.tla -workers 2
java -jar tla2tools.jar -config UTXODedup.cfg UTXODedup.tla -workers 2
java -jar tla2tools.jar -config AnchorFee.cfg AnchorFee.tla -workers 2
java -jar tla2tools.jar -config AutoKeyPath.cfg AutoKeyPath.tla -workers 2
```

**WARNING:** The AnchorFee spec with large constants can use significant memory.
Use `-workers 2` and keep MaxFeeRate/MaxWeight small. Do NOT use `-workers auto`
on memory-constrained systems (WSL2 with <8GB RAM).

## Verification status

These specs have NOT been model-checked yet. They are written to be checked
on a machine with adequate resources (16GB+ RAM recommended for AnchorFee).
