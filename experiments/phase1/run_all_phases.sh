#!/bin/bash

# Master script to run all Phase 1 experiments
# Results will be saved in each respective phase folder

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "Starting Phase 1 Experiments"
echo "=========================================="
echo ""

# Check if mosquitto is running
if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Mosquitto broker is not running!"
    echo "Please start the broker before running experiments."
    exit 1
fi

# Activate virtual environment if it exists
if [ -f "$SCRIPT_DIR/../../venv/bin/activate" ]; then
    echo "Activating virtual environment..."
    source "$SCRIPT_DIR/../../venv/bin/activate"
fi

# Phase 1A: Sequential Connections
echo "=========================================="
echo "Phase 1A: Sequential TLS Handshake Test"
echo "=========================================="
echo "Testing 200 sequential connections..."
cd "$SCRIPT_DIR/phase1A_sequential"
bash run.sh
if [ $? -eq 0 ]; then
    echo "✓ Phase 1A completed successfully"
    echo "  Results saved to: phase1A_sequential/results.csv"
else
    echo "✗ Phase 1A failed!"
fi
echo ""

# Phase 1B: Concurrent Connections
echo "=========================================="
echo "Phase 1B: Concurrent Connection Test"
echo "=========================================="
echo "Testing concurrent connections (10, 50, 100, 200, 400)..."
cd "$SCRIPT_DIR/phase1B_concurrent"
bash run.sh
if [ $? -eq 0 ]; then
    echo "✓ Phase 1B completed successfully"
    echo "  Results saved to: phase1B_concurrent/results.csv"
else
    echo "✗ Phase 1B failed!"
fi
echo ""

# Phase 1C: Sustained Load
echo "=========================================="
echo "Phase 1C: Sustained Load Test"
echo "=========================================="
echo "Running sustained load test (300 seconds)..."
cd "$SCRIPT_DIR/phase1C_sustained"
bash run.sh
if [ $? -eq 0 ]; then
    echo "✓ Phase 1C completed successfully"
    echo "  Results saved to: phase1C_sustained/results.csv"
else
    echo "✗ Phase 1C failed!"
fi
echo ""

# Phase 1D: Connection Lifetime
echo "=========================================="
echo "Phase 1D: Connection Lifetime Test"
echo "=========================================="
echo "Testing connection lifetimes (1s, 10s, 60s)..."
cd "$SCRIPT_DIR/phase1D_lifetime"
bash run.sh
if [ $? -eq 0 ]; then
    echo "✓ Phase 1D completed successfully"
    echo "  Results saved to: phase1D_lifetime/results.csv"
else
    echo "✗ Phase 1D failed!"
fi
echo ""

# Phase 1E: Saturation Test
echo "=========================================="
echo "Phase 1E: Broker Saturation Test"
echo "=========================================="
echo "Testing saturation with increasing concurrent clients..."
cd "$SCRIPT_DIR/phase1E_saturation"
bash run.sh
if [ $? -eq 0 ]; then
    echo "✓ Phase 1E completed successfully"
    echo "  Results saved to: phase1E_saturation/results.csv"
else
    echo "✗ Phase 1E failed!"
fi
echo ""

# Summary
echo "=========================================="
echo "Phase 1 Experiments Complete!"
echo "=========================================="
echo ""
echo "Results Summary:"
echo "  Phase 1A: $SCRIPT_DIR/phase1A_sequential/results.csv"
echo "  Phase 1B: $SCRIPT_DIR/phase1B_concurrent/results.csv"
echo "  Phase 1C: $SCRIPT_DIR/phase1C_sustained/results.csv"
echo "  Phase 1D: $SCRIPT_DIR/phase1D_lifetime/results.csv"
echo "  Phase 1E: $SCRIPT_DIR/phase1E_saturation/results.csv"
echo ""
