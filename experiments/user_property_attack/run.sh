#!/bin/bash

# User Property Injection Attack Test
# ====================================
# Runs VULNERABLE and PROTECTED tests on SEPARATE broker instances
# so results are independently comparable.
#
# Vulnerable: attack_client.py sends 30 attack packets/iter with
#             50 user properties × 1KB each (NO validation)
#             → Broker memory grows as retained messages accumulate
#
# Protected:  safe_client.py validates before sending, rejects
#             oversized packets, only sends 5 normal packets/iter
#             → Broker memory stays flat

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../.."
OUT_VULNERABLE="$DIR/results_vulnerable.csv"
OUT_PROTECTED="$DIR/results_protected.csv"
BROKER_CONF="$PROJECT_ROOT/broker/mosquitto_psk.conf"
ITERATIONS=20

echo "=========================================="
echo "User Property Injection Attack Tests"
echo "=========================================="
echo ""
echo "Attack: 30 packets × 50 properties × 1KB = ~1.5MB/iteration"
echo "Iterations: $ITERATIONS"
echo "Expected vulnerable memory growth: ~30MB"
echo ""

# Initialize CSV files
echo "iteration,packets_sent,packets_rejected,cpu_before,cpu_after,mem_kb" > "$OUT_VULNERABLE"
echo "iteration,packets_sent,packets_rejected,cpu_before,cpu_after,mem_kb" > "$OUT_PROTECTED"

# ==========================================
# TEST 1: VULNERABLE BROKER (No validation)
# ==========================================
echo "--- Phase 1: VULNERABLE MQTT (No Validation) ---"
echo ""

# Kill any existing mosquitto and start fresh
killall mosquitto 2>/dev/null
sleep 2

echo "Starting fresh broker for VULNERABLE test..."
mosquitto -c "$BROKER_CONF" -d
sleep 1

# Verify broker is running
if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start broker"
    exit 1
fi

INITIAL_MEM_VULN=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo "Broker started. Initial memory: ${INITIAL_MEM_VULN} KB"
echo ""

for i in $(seq 1 $ITERATIONS); do
    echo -n "  Iteration $i/$ITERATIONS... "

    # Get broker stats before
    STATS_BEFORE=$("$DIR/broker_stats.sh")
    CPU_BEFORE=$(echo "$STATS_BEFORE" | cut -d',' -f1)

    # Run attack client (NO validation - all packets sent including attack)
    PACKETS=$(timeout 30 python "$DIR/attack_client.py" "$i" 2>/dev/null)
    # attack_client.py prints just the sent count
    PACKETS=$(echo "$PACKETS" | tail -1 | tr -d '[:space:]')
    [ -z "$PACKETS" ] && PACKETS=0

    sleep 0.5

    # Get broker stats after
    STATS_AFTER=$("$DIR/broker_stats.sh")
    CPU_AFTER=$(echo "$STATS_AFTER" | cut -d',' -f2)
    MEM_AFTER=$(echo "$STATS_AFTER" | cut -d',' -f3)

    # Vulnerable: 0 rejected (everything sent)
    REJECTED=0

    echo "$i,$PACKETS,$REJECTED,$CPU_BEFORE,$CPU_AFTER,$MEM_AFTER" >> "$OUT_VULNERABLE"
    echo "sent=$PACKETS, mem=${MEM_AFTER}KB"

    sleep 0.5
done

FINAL_MEM_VULN=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo ""
echo "Vulnerable test complete."
echo "  Initial memory: ${INITIAL_MEM_VULN} KB"
echo "  Final memory:   ${FINAL_MEM_VULN} KB"
echo "  Memory growth:  $((FINAL_MEM_VULN - INITIAL_MEM_VULN)) KB"

# ==========================================
# TEST 2: PROTECTED BROKER (With validation)
# ==========================================
echo ""
echo "--- Phase 2: PROTECTED MQTT (With Validation) ---"
echo ""

# Kill vulnerable broker and restart fresh
killall mosquitto 2>/dev/null
sleep 2

echo "Starting fresh broker for PROTECTED test..."
mosquitto -c "$BROKER_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start broker"
    exit 1
fi

INITIAL_MEM_PROT=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo "Broker started. Initial memory: ${INITIAL_MEM_PROT} KB"
echo ""

for i in $(seq 1 $ITERATIONS); do
    echo -n "  Iteration $i/$ITERATIONS... "

    STATS_BEFORE=$("$DIR/broker_stats.sh")
    CPU_BEFORE=$(echo "$STATS_BEFORE" | cut -d',' -f1)

    # Run safe client (with validation - attack packets rejected before sending)
    OUTPUT=$(timeout 30 python "$DIR/safe_client.py" "$i" 2>/dev/null)
    # safe_client.py prints "sent_count,rejected_count"
    OUTPUT=$(echo "$OUTPUT" | tail -1 | tr -d '[:space:]')
    PACKETS=$(echo "$OUTPUT" | cut -d',' -f1)
    REJECTED=$(echo "$OUTPUT" | cut -d',' -f2)
    [ -z "$PACKETS" ] && PACKETS=0
    [ -z "$REJECTED" ] && REJECTED=0

    sleep 0.5

    STATS_AFTER=$("$DIR/broker_stats.sh")
    CPU_AFTER=$(echo "$STATS_AFTER" | cut -d',' -f2)
    MEM_AFTER=$(echo "$STATS_AFTER" | cut -d',' -f3)

    echo "$i,$PACKETS,$REJECTED,$CPU_BEFORE,$CPU_AFTER,$MEM_AFTER" >> "$OUT_PROTECTED"
    echo "sent=$PACKETS, rejected=$REJECTED, mem=${MEM_AFTER}KB"

    sleep 0.5
done

FINAL_MEM_PROT=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo ""
echo "Protected test complete."
echo "  Initial memory: ${INITIAL_MEM_PROT} KB"
echo "  Final memory:   ${FINAL_MEM_PROT} KB"
echo "  Memory growth:  $((FINAL_MEM_PROT - INITIAL_MEM_PROT)) KB"

# ==========================================
# SUMMARY
# ==========================================
echo ""
echo "=========================================="
echo "Test Complete - Results Summary"
echo "=========================================="
echo ""
echo "  VULNERABLE: memory grew from ${INITIAL_MEM_VULN}KB to ${FINAL_MEM_VULN}KB (+$((FINAL_MEM_VULN - INITIAL_MEM_VULN))KB)"
echo "  PROTECTED:  memory grew from ${INITIAL_MEM_PROT}KB to ${FINAL_MEM_PROT}KB (+$((FINAL_MEM_PROT - INITIAL_MEM_PROT))KB)"
echo ""
echo "  Results:"
echo "    Vulnerable: $OUT_VULNERABLE"
echo "    Protected:  $OUT_PROTECTED"
echo ""
echo "  Analysis: cd $(basename $DIR) && python analyze.py"
echo ""

# Restart broker for normal use
killall mosquitto 2>/dev/null
sleep 1
mosquitto -c "$BROKER_CONF" -d
echo "Broker restarted for normal use."
