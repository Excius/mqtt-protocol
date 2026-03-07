#!/bin/bash

# Master script to run all Phase 1 experiments (TLS Certificate based)
# Phase 1 uses MQTT 5.0 + TLS cert as the base configuration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/../.."
BROKER_CONF="$PROJECT_ROOT/broker/mosquitto_tls.conf"

echo "=========================================="
echo "Phase 1: TLS Certificate experiments"
echo "=========================================="
echo ""

# Activate virtual environment
if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

# Start broker with TLS cert config
killall mosquitto 2>/dev/null
sleep 1
echo "Starting broker with TLS cert config..."
mosquitto -c "$BROKER_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start Mosquitto broker"
    exit 1
fi
echo "Broker running (PID: $(pidof mosquitto))"
echo ""

# Phase 1A: Sequential Connections
echo "=========================================="
echo "Phase 1A: Sequential TLS Handshake Test"
echo "=========================================="
bash "$SCRIPT_DIR/phase1A_sequential/run.sh"
echo "✓ Phase 1A done"
echo ""

# Phase 1B: Concurrent Connections
echo "=========================================="
echo "Phase 1B: Concurrent Connection Test"
echo "=========================================="
bash "$SCRIPT_DIR/phase1B_concurrent/run.sh"
echo "✓ Phase 1B done"
echo ""

# Phase 1C: Sustained Load
echo "=========================================="
echo "Phase 1C: Sustained Load Test (60s)"
echo "=========================================="
bash "$SCRIPT_DIR/phase1C_sustained/run.sh"
echo "✓ Phase 1C done"
echo ""

# Phase 1D: Connection Lifetime
echo "=========================================="
echo "Phase 1D: Connection Lifetime Test"
echo "=========================================="
bash "$SCRIPT_DIR/phase1D_lifetime/run.sh"
echo "✓ Phase 1D done"
echo ""

# Phase 1E: Saturation Test
echo "=========================================="
echo "Phase 1E: Broker Saturation Test"
echo "=========================================="
bash "$SCRIPT_DIR/phase1E_saturation/run.sh"
echo "✓ Phase 1E done"
echo ""

# Summary
echo "=========================================="
echo "Phase 1 Complete!"
echo "=========================================="
echo ""
echo "Results:"
echo "  1A Sequential: $SCRIPT_DIR/phase1A_sequential/results.csv"
echo "  1B Concurrent: $SCRIPT_DIR/phase1B_concurrent/results.csv"
echo "  1C Sustained:  $SCRIPT_DIR/phase1C_sustained/results.csv"
echo "  1D Lifetime:   $SCRIPT_DIR/phase1D_lifetime/results.csv"
echo "  1E Saturation: $SCRIPT_DIR/phase1E_saturation/results.csv"
echo ""
