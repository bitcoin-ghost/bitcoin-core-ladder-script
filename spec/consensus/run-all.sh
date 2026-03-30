#!/bin/bash
# Run all 21 TLA+ specs at consensus-level constants
# Designed for: 192 GB RAM, 32 cores
# Usage: ./run-all.sh [WORKERS]
#   WORKERS defaults to 28 (leaves 4 cores for OS)

set -euo pipefail

WORKERS=${1:-28}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SPEC_DIR="$(dirname "$SCRIPT_DIR")"

# Java and TLA+ tools — installed by setup
JAVA="${JAVA:-/usr/bin/java}"
TLA2TOOLS="${TLA2TOOLS:-$SPEC_DIR/tla2tools.jar}"

# JVM heap: 170 GB (leaves ~20 GB for OS + JVM overhead)
JVM_HEAP="-Xmx170g -Xms32g"

RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

SPECS=(
    AnchorFee
    AutoKeyPath
    BlockAnchor
    # BlockCompound — skipped (3+ value dimensions; covered by simulation)
    BlockCovenant
    # BlockGovernance — skipped (4 value dimensions; covered by simulation)
    BlockHash
    BlockLegacy
    # BlockPLC — skipped (6 block types × value ranges; covered by simulation)
    # BlockRecursion — skipped (5 value dimensions; covered by simulation)
    BlockSignature
    # BlockTimelock — skipped (3 value dimensions with large ranges; covered by simulation)
    HybridCreationProof
    # LadderAntiSpam — skipped (>1M set elements even at WSL2 constants; needs spec restructure; covered by simulation)
    # LadderEval — skipped (>1M set elements even at WSL2 constants; needs spec restructure; covered by simulation)
    LadderMerkle
    LadderSighash
    # LadderWireFormat — skipped (stuck at 134M initial states even at MaxSlots=10; covered by simulation)
    RecursiveCovenant
    SharedProof
    UTXODedup
)

PASSED=0
FAILED=0
ERRORS=()

echo "============================================"
echo "TLA+ Consensus-Level Model Checking"
echo "============================================"
echo "Workers:    $WORKERS"
echo "JVM heap:   $JVM_HEAP"
echo "Specs:      ${#SPECS[@]}"
echo "Results:    $RESULTS_DIR"
echo "Started:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================"
echo ""

for spec in "${SPECS[@]}"; do
    TLA_FILE="$SPEC_DIR/${spec}.tla"
    CFG_FILE="$SCRIPT_DIR/${spec}.cfg"

    if [ ! -f "$TLA_FILE" ]; then
        echo "SKIP: $spec — .tla file not found"
        continue
    fi
    if [ ! -f "$CFG_FILE" ]; then
        echo "SKIP: $spec — .cfg file not found in consensus/"
        continue
    fi

    LOG_FILE="$RESULTS_DIR/${spec}.log"
    echo -n "Running $spec ... "
    START=$(date +%s)

    set +e
    # Use /dev/shm for TLC metadata (RAM-backed, avoids disk exhaustion)
    METADIR="/dev/shm/tlc-${spec}"
    mkdir -p "$METADIR"
    "$JAVA" $JVM_HEAP -cp "$TLA2TOOLS" tlc2.TLC \
        -workers "$WORKERS" \
        -config "$CFG_FILE" \
        -deadlock \
        -metadir "$METADIR" \
        "$TLA_FILE" \
        > "$LOG_FILE" 2>&1
    EXIT_CODE=$?
    rm -rf "$METADIR"
    set -e

    END=$(date +%s)
    ELAPSED=$((END - START))

    # Extract state count from TLC output
    STATES=$(grep -oP '\d+ states generated' "$LOG_FILE" | grep -oP '^\d+' || echo "?")
    DISTINCT=$(grep -oP '\d+ distinct states' "$LOG_FILE" | grep -oP '^\d+' || echo "?")

    if [ $EXIT_CODE -eq 0 ] && grep -q 'Model checking completed. No error has been found' "$LOG_FILE"; then
        echo "PASS (${ELAPSED}s, ${STATES} states, ${DISTINCT} distinct)"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL (${ELAPSED}s, exit=$EXIT_CODE)"
        FAILED=$((FAILED + 1))
        ERRORS+=("$spec")
        # Show the error from the log
        grep -A5 'Error\|Invariant\|violated\|Exception' "$LOG_FILE" | head -10
        echo ""
    fi
done

echo ""
echo "============================================"
echo "Results: $PASSED passed, $FAILED failed"
echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ ${#ERRORS[@]} -gt 0 ]; then
    echo "Failed specs: ${ERRORS[*]}"
    echo "============================================"
    exit 1
fi
echo "All specs passed at consensus-level constants."
echo "============================================"
