#!/bin/bash
# Run all 21 TLA+ specs in SIMULATION mode at consensus-level constants
# Simulation: random walks through state space — no exhaustive enumeration
# Can run at ANY constant size without memory explosion
#
# Usage: ./simulate-all.sh [TRACES] [DEPTH]
#   TRACES defaults to 10000000 (10M random traces per spec)
#   DEPTH defaults to 100 (max steps per trace)

set -euo pipefail

TRACES=${1:-10000000}
DEPTH=${2:-100}
WORKERS=${WORKERS:-28}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SPEC_DIR="$(dirname "$SCRIPT_DIR")"

JAVA="${JAVA:-/usr/bin/java}"
TLA2TOOLS="${TLA2TOOLS:-$SPEC_DIR/tla2tools.jar}"

# Simulation uses much less memory than model checking
JVM_HEAP="${JVM_HEAP:--Xmx32g -Xms4g}"

RESULTS_DIR="$SCRIPT_DIR/results-sim"
mkdir -p "$RESULTS_DIR"

# Consensus-level constants for simulation (full limits)
# These are written to temporary cfg files per spec
write_sim_cfg() {
    local spec=$1
    local cfg="$RESULTS_DIR/${spec}.cfg"
    case "$spec" in
        AnchorFee)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxFeeRate = 200
    MaxWeight = 4000000
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        AutoKeyPath)
            cat > "$cfg" << 'EOF'
CONSTANTS
    NumKeys = 16
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockAnchor)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxFields = 16
    MaxCommitment = 1000
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockCompound)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxKeys = 16
    MaxDelay = 144
    MaxHeight = 1000
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockCovenant)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxAmount = 100000
    MaxDelay = 144
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockGovernance)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxWeight = 4000000
    MaxCount = 100
    MaxHeight = 1000
    MaxAmount = 100000
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockHash)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxHashValues = 16
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockLegacy)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxHashValues = 16
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockPLC)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxValue = 100000
    MaxSteps = 16
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockRecursion)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxCount = 20
    MaxHeight = 1000
    MaxSplits = 16
    MaxAmount = 100000
    DustLimit = 546
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockSignature)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxKeys = 16
    MaxThreshold = 16
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        BlockTimelock)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxHeight = 1000
    MaxTime = 1000
    MaxSequence = 65535
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        HybridCreationProof)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxOutputs = 252
    MaxLeaves = 252
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        LadderAntiSpam)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxFields = 16
    MaxPreimagePerTx = 50
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        LadderEval)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxRungs = 16
    MaxBlocksPerRung = 8
    MaxRelays = 8
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        LadderMerkle)
            cat > "$cfg" << 'EOF'
CONSTANTS
    NumLeaves = 32
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        LadderSighash)
            cat > "$cfg" << 'EOF'
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        LadderWireFormat)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxSlots = 128
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        RecursiveCovenant)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxDepth = 16
    MaxCount = 16
    MaxSplits = 16
    MinSats = 546
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        SharedProof)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxInputs = 16
    MaxSources = 8
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
        UTXODedup)
            cat > "$cfg" << 'EOF'
CONSTANTS
    MaxOutputs = 252
SPECIFICATION Spec
INVARIANT SafetyInvariant
EOF
            ;;
    esac
    echo "$cfg"
}

SPECS=(
    AnchorFee AutoKeyPath BlockAnchor BlockCompound BlockCovenant
    BlockGovernance BlockHash BlockLegacy BlockPLC BlockRecursion
    BlockSignature BlockTimelock HybridCreationProof LadderAntiSpam
    LadderEval LadderMerkle LadderSighash LadderWireFormat
    RecursiveCovenant SharedProof UTXODedup
)

PASSED=0
FAILED=0
ERRORS=()

echo "============================================"
echo "TLA+ Simulation Mode — Consensus Limits"
echo "============================================"
echo "Traces:     $TRACES per spec"
echo "Depth:      $DEPTH steps per trace"
echo "Workers:    $WORKERS"
echo "Specs:      ${#SPECS[@]}"
echo "Results:    $RESULTS_DIR"
echo "Started:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================"
echo ""

for spec in "${SPECS[@]}"; do
    TLA_FILE="$SPEC_DIR/${spec}.tla"
    if [ ! -f "$TLA_FILE" ]; then
        echo "SKIP: $spec — .tla file not found"
        continue
    fi

    CFG_FILE=$(write_sim_cfg "$spec")
    LOG_FILE="$RESULTS_DIR/${spec}.log"
    echo -n "Simulating $spec ... "
    START=$(date +%s)

    set +e
    "$JAVA" $JVM_HEAP -cp "$TLA2TOOLS" tlc2.TLC \
        -simulate num="$TRACES",depth="$DEPTH" \
        -workers "$WORKERS" \
        -config "$CFG_FILE" \
        -deadlock \
        "$TLA_FILE" \
        > "$LOG_FILE" 2>&1
    EXIT_CODE=$?
    set -e

    END=$(date +%s)
    ELAPSED=$((END - START))

    TRACES_RUN=$(grep -oP '\d+ traces' "$LOG_FILE" | grep -oP '^\d+' || echo "?")

    if [ $EXIT_CODE -eq 0 ] && grep -q 'Simulation using seed' "$LOG_FILE"; then
        if grep -q 'Error' "$LOG_FILE" && ! grep -q 'No error' "$LOG_FILE"; then
            echo "FAIL (${ELAPSED}s, exit=$EXIT_CODE)"
            FAILED=$((FAILED + 1))
            ERRORS+=("$spec")
            grep -A3 'Error\|Invariant\|violated' "$LOG_FILE" | head -5
        else
            echo "PASS (${ELAPSED}s, ${TRACES_RUN} traces)"
            PASSED=$((PASSED + 1))
        fi
    elif grep -q 'Simulation completed' "$LOG_FILE" || grep -q 'No error has been found' "$LOG_FILE"; then
        echo "PASS (${ELAPSED}s, ${TRACES_RUN} traces)"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL (${ELAPSED}s, exit=$EXIT_CODE)"
        FAILED=$((FAILED + 1))
        ERRORS+=("$spec")
        grep -A3 'Error\|Invariant\|violated\|Exception' "$LOG_FILE" | head -5
        echo ""
    fi
done

echo ""
echo "============================================"
echo "Simulation Results: $PASSED passed, $FAILED failed"
echo "Traces per spec: $TRACES  Depth: $DEPTH"
echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ ${#ERRORS[@]} -gt 0 ]; then
    echo "Failed specs: ${ERRORS[*]}"
    echo "============================================"
    exit 1
fi
echo "All specs passed simulation at consensus-level constants."
echo "============================================"
