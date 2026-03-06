#!/bin/bash
###############################################################################
# QUICK START GUIDE - MQTT Security Experiments
###############################################################################

echo "=========================================="
echo "MQTT Security Experiments - Quick Start"
echo "=========================================="
echo ""

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Step 1: Verify Broker is Running${NC}"
if pidof mosquitto > /dev/null; then
    echo -e "${GREEN}✓ Mosquitto broker is running${NC}"
else
    echo "✗ Mosquitto broker is not running"
    echo "  Starting broker..."
    cd "$PROJECT_ROOT"
    mosquitto -c broker/mosquitto_tls.conf -d
    sleep 2
    if pidof mosquitto > /dev/null; then
        echo -e "${GREEN}✓ Broker started successfully${NC}"
    else
        echo "✗ Failed to start broker"
        exit 1
    fi
fi
echo ""

echo -e "${YELLOW}Step 2: Activate Virtual Environment${NC}"
if [ -d "$PROJECT_ROOT/venv" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
    echo -e "${GREEN}✓ Virtual environment activated${NC}"
else
    echo "✗ Virtual environment not found"
    echo "  Create it with: python3 -m venv venv"
    exit 1
fi
echo ""

echo -e "${YELLOW}Step 3: Choose What to Run${NC}"
echo ""
echo "Options:"
echo "  1 - Run ALL experiments (Baseline + Phase 1 A-E + Phase 2)"
echo "  2 - Baseline only (50 iterations)"
echo "  3 - Phase 1A only (Sequential connections)"
echo "  4 - Phase 1B only (Concurrent scaling)"
echo "  5 - Phase 1C only (Sustained load)"
echo "  6 - Phase 1D only (Connection lifetime)"
echo "  7 - Phase 1E only (Saturation test)"
echo "  8 - Phase 2 only (TLS-PSK)"
echo ""

read -p "Enter choice (1-8): " choice

cd "$PROJECT_ROOT"

case $choice in
    1)
        echo -e "${YELLOW}Running ALL experiments...${NC}"
        bash run_all_experiments.sh
        ;;
    2)
        echo -e "${YELLOW}Running Baseline...${NC}"
        bash experiments/baseline/run_baseline.sh
        echo -e "${GREEN}✓ Results saved to experiments/baseline/results.csv${NC}"
        ;;
    3)
        echo -e "${YELLOW}Running Phase 1A (Sequential)...${NC}"
        bash experiments/phase1/phase1A_sequential/run.sh
        echo -e "${GREEN}✓ Results saved to experiments/phase1/phase1A_sequential/results.csv${NC}"
        ;;
    4)
        echo -e "${YELLOW}Running Phase 1B (Concurrent)...${NC}"
        bash experiments/phase1/phase1B_concurrent/run.sh
        echo -e "${GREEN}✓ Results saved to experiments/phase1/phase1B_concurrent/results.csv${NC}"
        ;;
    5)
        echo -e "${YELLOW}Running Phase 1C (Sustained Load - will run for 300 seconds)...${NC}"
        bash experiments/phase1/phase1C_sustained/run.sh
        echo -e "${GREEN}✓ Results saved to experiments/phase1/phase1C_sustained/results.csv${NC}"
        ;;
    6)
        echo -e "${YELLOW}Running Phase 1D (Connection Lifetime)...${NC}"
        bash experiments/phase1/phase1D_lifetime/run.sh
        echo -e "${GREEN}✓ Results saved to experiments/phase1/phase1D_lifetime/results.csv${NC}"
        ;;
    7)
        echo -e "${YELLOW}Running Phase 1E (Saturation Test - will test up to 1000 clients)...${NC}"
        bash experiments/phase1/phase1E_saturation/run.sh
        echo -e "${GREEN}✓ Results saved to experiments/phase1/phase1E_saturation/results.csv${NC}"
        ;;
    8)
        echo -e "${YELLOW}Running Phase 2 (TLS-PSK)...${NC}"
        bash experiments/phase2_psk/run.sh
        echo -e "${GREEN}✓ Results saved to experiments/phase2_psk/results.csv${NC}"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}=========================================="
echo "Experiment Complete!"
echo "==========================================${NC}"
