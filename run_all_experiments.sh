#!/bin/bash

###############################################################################
# Unified Experiment Runner
# Runs all MQTT 5.0 security experiments:
#   Baseline, Phase 1 (A-E), Phase 2 (PSK), Session Resumption,
#   PSK Optimization, User Property Attack, AUTH Flood Attack
###############################################################################

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$PROJECT_ROOT/experiments"

echo "=========================================="
echo "MQTT 5.0 Security — Full Experiment Suite"
echo "=========================================="
echo "Project: $PROJECT_ROOT"
echo ""

# Activate virtual environment
if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

failed_tests=()
passed_tests=()

run_test() {
    local test_name=$1
    local test_cmd=$2

    echo ""
    echo "=========================================="
    echo "Running: $test_name"
    echo "=========================================="

    if eval "$test_cmd"; then
        echo "  [PASS] $test_name"
        passed_tests+=("$test_name")
    else
        echo "  [FAIL] $test_name"
        failed_tests+=("$test_name")
    fi
}

# ── Baseline & Phase 1 (Certificate TLS) ────────────────────────────────
run_test "Baseline TLS Certificate"     "bash $SCRIPTS_DIR/baseline/run_baseline.sh"
run_test "Phase 1A: Sequential"         "bash $SCRIPTS_DIR/phase1/phase1A_sequential/run.sh"
run_test "Phase 1B: Concurrent"         "bash $SCRIPTS_DIR/phase1/phase1B_concurrent/run.sh"
run_test "Phase 1C: Sustained Load"     "timeout 120 bash $SCRIPTS_DIR/phase1/phase1C_sustained/run.sh || true"
run_test "Phase 1D: Connection Lifetime" "bash $SCRIPTS_DIR/phase1/phase1D_lifetime/run.sh"
run_test "Phase 1E: Saturation"         "timeout 120 bash $SCRIPTS_DIR/phase1/phase1E_saturation/run.sh || true"

# ── Phase 2 (TLS-PSK) ───────────────────────────────────────────────────
run_test "Phase 2: TLS-PSK"             "bash $SCRIPTS_DIR/phase2_psk/run.sh"

# ── Session Resumption ──────────────────────────────────────────────────
run_test "Session Resumption"           "bash $SCRIPTS_DIR/session_resumption/run.sh"

# ── PSK Optimization ────────────────────────────────────────────────────
run_test "PSK Optimization"             "bash $SCRIPTS_DIR/psk_optimized/run.sh"

# ── User Property Attack (Broker-Side Proxy) ────────────────────────────
run_test "User Property Attack"         "bash $SCRIPTS_DIR/user_property_attack/run.sh"

# ── AUTH Flood Attack (Broker-Side Proxy) ────────────────────────────────
run_test "AUTH Flood Attack"            "bash $SCRIPTS_DIR/auth_flood/run.sh"

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo ""
echo "Passed (${#passed_tests[@]}):"
for t in "${passed_tests[@]}"; do echo "  [PASS] $t"; done
echo ""
if [ ${#failed_tests[@]} -gt 0 ]; then
    echo "Failed (${#failed_tests[@]}):"
    for t in "${failed_tests[@]}"; do echo "  [FAIL] $t"; done
    echo ""
fi

# Run comprehensive analysis
echo "=========================================="
echo "Running comprehensive analysis..."
echo "=========================================="
python "$PROJECT_ROOT/analyze_all.py"

if [ ${#failed_tests[@]} -eq 0 ]; then
    echo "All experiments completed successfully."
    exit 0
else
    echo "Some experiments failed. Check output above."
    exit 1
fi
