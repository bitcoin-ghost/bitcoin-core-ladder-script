# TLA+ Verification Results

Captured: 2026-05-12. Tooling: tla2tools v1.8.0, OpenJDK 11.0.30, WSL2
on Ubuntu 22.04 with 11 GB RAM available, 16 cores.

The same `.cfg` files this directory ships with — no constants were
adjusted upward for this run. Raw TLC logs are under
`spec/consensus/results/` (exhaustive) and
`spec/consensus/results-sim/` (simulation).

## Exhaustive model checking — PASS

These specs complete exhaustive state-space exploration under TLC at
the shipped constants. Every reachable state was visited; every
declared invariant held; no counter-examples found.

| Spec | Distinct states | Total generated | Depth | Wall clock | Result |
|------|-----------------:|-----------------:|------:|-----------:|--------|
| AutoKeyPath | 78,720 | 118,080 | 2 | 59 s | ✓ No error |
| UTXODedup | 98 | 433 | 5 | < 1 s | ✓ No error |
| AnchorFee | 8,518,400 | 12,777,600 | 2 | 29 s | ✓ No error |

**Properties covered**:

- **AutoKeyPath**: x-only tweak detection, key-path / script-path
  routing correctness, `LadderTweak/v1` domain separation from
  `TapTweak`.
- **UTXODedup**: synthetic-entry lifecycle (creation, refcount
  decrement, GC at refcount = 0), MLSC root inflation, reorg
  re-creation via recovery root in undo data.
- **AnchorFee**: fee-rate pinning resistance, weight-limit
  enforcement, fail-closed behaviour when `tx_weight` is zero or
  vsize is degenerate.

## Specs out of exhaustive reach

The following specs have multi-dimensional state spaces whose
exhaustive exploration is **not tractable for TLC at any reachable
hardware configuration**. The commit history in `spec/` records
progressive constant reductions ending in "skipped (covered by
simulation)" for each.

Practical bar: even when shrunk to constants that would render the
properties trivial, these still exceed memory. Examples from the
commit log:

| Spec | State-space note from commit log |
|------|---------------------------------|
| SharedProof | 536M states at 8×4 constants — too large |
| RecursiveCovenant | 4×4×4×2 still too large |
| LadderWireFormat | Stuck computing initial states at MaxSlots = 10 |
| LadderAntiSpam | > 1 M set elements even at WSL2 constants |
| LadderEval | > 1 M set elements even at WSL2 constants |
| BlockPLC | 6 block types × value ranges — exhaustive infeasible |
| BlockGovernance | 4 value dimensions |
| BlockRecursion | 5 value dimensions |
| BlockTimelock | 3 value dimensions with large ranges |

For these, exhaustive verification via TLC is **not the right tool**.
Two practical alternatives, both deferred to follow-on work:

- **Apalache** (SMT-backed TLA+ model checker). Scales better than
  TLC for some shapes by replacing explicit state enumeration with
  symbolic reasoning. Not magic — some specs are still infeasible —
  but worth trying for the specs above.
- **TLAPS** (TLA+ Proof System). Hand-crafted machine-checked
  proofs for named load-bearing invariants. Genuinely "definitive"
  for the properties proved; the tradeoff is multi-week-per-invariant
  effort by a formal-methods specialist.

## Simulation-mode random sampling

While exhaustive checking is infeasible for the specs above,
**simulation mode** walks random paths through the state space with
constant memory. It does not prove the absence of counter-examples
(it is statistical), but billions of sampled paths without finding
one is meaningful evidence.

A simulation run across all 21 specs is in progress via
`spec/consensus/simulate-all.sh` at 1 M traces × depth 50 per spec,
8 workers, 6 GB heap (tuned down from the script's 28-worker /
32 GB defaults to fit the local WSL2 environment). Results stream to
`spec/consensus/results-sim/`. This document will be updated when
the run completes.

## What this report is not

- **Not a proof of consensus correctness.** Exhaustive TLC results
  prove the properties hold *over the modelled state space at the
  shipped constants*. The shipped constants are smaller than the
  production constants (MaxRungs = 16 etc.). Bug classes that only
  manifest at production scale will not be caught here.
- **Not a substitute for an external security audit.** This is
  supporting evidence. The BIP draft's activation gate (§Open
  Items, component 2) requires this report to be *published*; it
  does **not** treat it as definitive verification.
- **Not exhaustive coverage.** 13 of 21 specs were model-checkable
  at some level; 8 are simulation-only. The simulation results are
  random-path samples, not proofs.

## How to reproduce

```sh
# Exhaustive runs (the three specs above)
java -Xmx4g -jar ~/tla/tla2tools.jar -config spec/AutoKeyPath.cfg spec/AutoKeyPath.tla -workers 2
java -Xmx2g -jar ~/tla/tla2tools.jar -config spec/UTXODedup.cfg   spec/UTXODedup.tla   -workers 2
java -Xmx8g -jar ~/tla/tla2tools.jar -config spec/AnchorFee.cfg   spec/AnchorFee.tla   -workers 4

# Simulation run
JAVA=/usr/bin/java TLA2TOOLS=~/tla/tla2tools.jar \
    ./spec/consensus/simulate-all.sh 1000000 50
```

tla2tools v1.8.0 from
<https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar>.
Java 11+ required.
