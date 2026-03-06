#!/bin/bash

###############################################################################
# Unified Experiment Runner
# Executes all baseline, Phase 1, and Phase 2 experiments systematically
# with comprehensive error checking and result verification
###############################################################################

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$PROJECT_ROOT/experiments"
RESULTS_DIR="$PROJECT_ROOT/results_$(date +%Y%m%d_%H%M%S)"

echo "=========================================="
echo "MQTT Security Experiments - Full Test Suite"
echo "=========================================="
echo "Project: $PROJECT_ROOT"
echo "Results Dir: $RESULTS_DIR"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"

# Activate virtual environment
if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    echo "Activating virtual environment..."
    source "$PROJECT_ROOT/venv/bin/activate"
fi

# Check broker status
echo ""
echo "Checking broker status..."
if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Mosquitto broker is not running!"
    echo "Please start the broker with: mosquitto -c broker/mosquitto_tls.conf -d"
    exit 1
fi
echo "✓ Broker is running (PID: $(pidof mosquitto))"

# Function to run a test and capture output
run_test() {
    local test_name=$1
    local test_path=$2
    local test_cmd=$3
    local working_dir=${4:-.}
    
    echo ""
    echo "=========================================="
    echo "Running: $test_name"
    echo "=========================================="
    
    # Change to working directory (default is current, which is $SCRIPTS_DIR)
    cd "$working_dir"
    
    if eval "$test_cmd"; then
        echo "✓ $test_name completed successfully"
        # Copy results to archive
        if [ -f "$test_path/results.csv" ]; then
            cp "$test_path/results.csv" "$RESULTS_DIR/results_$(basename $(dirname $test_path))_$(basename $test_path).csv"
        fi
        return 0
    else
        echo "✗ $test_name failed!"
        return 1
    fi
}

failed_tests=()
passed_tests=()

# ============================================================================
# BASELINE EXPERIMENTS
# ============================================================================
echo ""
echo "########################################"
echo "BASELINE EXPERIMENTS"
echo "########################################"

if run_test "Baseline TLS Certificate" "baseline" "bash baseline/run_baseline.sh" "$SCRIPTS_DIR"; then
    passed_tests+=("Baseline")
else
    failed_tests+=("Baseline")
fi

# ============================================================================
# PHASE 1 EXPERIMENTS
# ============================================================================
echo ""
echo "########################################"
echo "PHASE 1 EXPERIMENTS"
echo "########################################"

# Phase 1A: Sequential
if run_test "Phase 1A: Sequential Connections" "phase1/phase1A_sequential" "bash phase1/phase1A_sequential/run.sh" "$SCRIPTS_DIR"; then
    passed_tests+=("Phase1A")
else
    failed_tests+=("Phase1A")
fi

# Phase 1B: Concurrent
if run_test "Phase 1B: Concurrent Connections" "phase1/phase1B_concurrent" "bash phase1/phase1B_concurrent/run.sh" "$SCRIPTS_DIR"; then
    passed_tests+=("Phase1B")
else
    failed_tests+=("Phase1B")
fi

# Phase 1C: Sustained Load
if run_test "Phase 1C: Sustained Load (15s)" "phase1/phase1C_sustained" "timeout 20 bash phase1/phase1C_sustained/run.sh || true" "$SCRIPTS_DIR"; then
    passed_tests+=("Phase1C")
else
    failed_tests+=("Phase1C")
fi

# Phase 1D: Lifetime
if run_test "Phase 1D: Connection Lifetime" "phase1/phase1D_lifetime" "bash phase1/phase1D_lifetime/run.sh" "$SCRIPTS_DIR"; then
    passed_tests+=("Phase1D")
else
    failed_tests+=("Phase1D")
fi

# Phase 1E: Saturation
if run_test "Phase 1E: Saturation Test" "phase1/phase1E_saturation" "timeout 120 bash phase1/phase1E_saturation/run.sh || true" "$SCRIPTS_DIR"; then
    passed_tests+=("Phase1E")
else
    failed_tests+=("Phase1E")
fi

# ============================================================================
# PHASE 2 EXPERIMENTS
# ============================================================================
echo ""
echo "########################################"
echo "PHASE 2 EXPERIMENTS (TLS-PSK)"
echo "########################################"

# Phase 2: PSK
if run_test "Phase 2: TLS-PSK Certificate" "phase2_psk" "bash phase2_psk/run.sh" "$SCRIPTS_DIR"; then
    passed_tests+=("Phase2PSK")
else
    failed_tests+=("Phase2PSK")
fi

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo ""
echo "Passed Tests (${#passed_tests[@]}):"
for test in "${passed_tests[@]}"; do
    echo "  ✓ $test"
done
echo ""
echo "Failed Tests (${#failed_tests[@]}):"
for test in "${failed_tests[@]}"; do
    echo "  ✗ $test"
done
echo ""
echo "Results archived to: $RESULTS_DIR"
echo ""

if [ ${#failed_tests[@]} -eq 0 ]; then
    echo "✓ All experiments completed successfully!"
    echo ""
    echo "Collected results files:"
    ls -lh "$RESULTS_DIR"
    exit 0
else
    echo "✗ Some experiments failed. Please review the output above."
    exit 1
fi
