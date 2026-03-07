#!/bin/bash

# MQTT 5.0 AUTH Flood Attack Test
# =================================
# Runs VULNERABLE and PROTECTED tests on SEPARATE broker instances.
#
# Vulnerable: attack_client.py floods with rapid TLS connection cycling +
#             AUTH Re-authenticate packets (10 threads × 5 s/iteration)
#             → Broker CPU spikes, legitimate client latency degrades
#
# Protected:  safe_client.py passes through AuthRateLimiter middleware
#             (2 conns/sec, 0 AUTH packets, max 20 conns) → broker
#             CPU stays normal, legitimate client latency stays low

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../.."
OUT_VULNERABLE="$DIR/results_vulnerable.csv"
OUT_PROTECTED="$DIR/results_protected.csv"
BROKER_CONF="$PROJECT_ROOT/broker/mosquitto_psk.conf"
ITERATIONS=10

echo "=========================================="
echo "MQTT 5.0 AUTH Flood Attack Tests"
echo "=========================================="
echo ""
echo "Attack: 10 threads × rapid reconnect + AUTH flood × ${ATTACK_DURATION:-5}s/iteration"
echo "Iterations: $ITERATIONS"
echo ""

# Initialize CSVs
echo "iteration,flood_conns,auth_packets_sent,legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb" > "$OUT_VULNERABLE"
echo "iteration,flood_conns,auth_packets_sent,legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb" > "$OUT_PROTECTED"

# ==========================================
# TEST 1: VULNERABLE (Auth Flood, No Protection)
# ==========================================
echo "--- Phase 1: VULNERABLE MQTT (Auth Flood, No Protection) ---"
echo ""

# Kill any existing broker and start fresh
killall mosquitto 2>/dev/null
sleep 2

echo "Starting fresh broker for VULNERABLE test..."
mosquitto -c "$BROKER_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start broker"
    exit 1
fi

INITIAL_MEM_VULN=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo "Broker started. Initial memory: ${INITIAL_MEM_VULN} KB"
echo ""

for i in $(seq 1 $ITERATIONS); do
    echo -n "  Iteration $i/$ITERATIONS... "

    STATS_BEFORE=$("$DIR/broker_stats.sh")
    CPU_BEFORE=$(echo "$STATS_BEFORE" | cut -d',' -f1)

    OUTPUT=$(timeout 30 python "$DIR/attack_client.py" "$i" 2>/dev/null)
    OUTPUT=$(echo "$OUTPUT" | tail -1 | tr -d '[:space:]')

    FLOOD_CONNS=$(echo "$OUTPUT" | cut -d',' -f1)
    AUTH_PKTS=$(echo "$OUTPUT" | cut -d',' -f2)
    LEGIT_LAT=$(echo "$OUTPUT" | cut -d',' -f3)
    LEGIT_OK=$(echo "$OUTPUT" | cut -d',' -f4)

    [ -z "$FLOOD_CONNS" ] && FLOOD_CONNS=0
    [ -z "$AUTH_PKTS" ] && AUTH_PKTS=0
    [ -z "$LEGIT_LAT" ] && LEGIT_LAT=-1
    [ -z "$LEGIT_OK" ] && LEGIT_OK=0

    sleep 0.5

    STATS_AFTER=$("$DIR/broker_stats.sh")
    CPU_AFTER=$(echo "$STATS_AFTER" | cut -d',' -f2)
    MEM_AFTER=$(echo "$STATS_AFTER" | cut -d',' -f3)

    echo "$i,$FLOOD_CONNS,$AUTH_PKTS,$LEGIT_LAT,$LEGIT_OK,$CPU_BEFORE,$CPU_AFTER,$MEM_AFTER" >> "$OUT_VULNERABLE"
    echo "conns=$FLOOD_CONNS auth=$AUTH_PKTS legit=${LEGIT_LAT}ms ok=$LEGIT_OK mem=${MEM_AFTER}KB"

    sleep 1
done

FINAL_MEM_VULN=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo ""
echo "Vulnerable test complete."
echo "  Initial memory: ${INITIAL_MEM_VULN} KB"
echo "  Final memory:   ${FINAL_MEM_VULN} KB"
echo "  Memory growth:  $((FINAL_MEM_VULN - INITIAL_MEM_VULN)) KB"

# ==========================================
# TEST 2: PROTECTED (Rate Limited + AUTH Blocked)
# ==========================================
echo ""
echo "--- Phase 2: PROTECTED MQTT (Rate Limited, AUTH Blocked) ---"
echo ""

# Kill old broker and start fresh
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

    OUTPUT=$(timeout 30 python "$DIR/safe_client.py" "$i" 2>/dev/null)
    OUTPUT=$(echo "$OUTPUT" | tail -1 | tr -d '[:space:]')

    CONNS=$(echo "$OUTPUT" | cut -d',' -f1)
    AUTH_PKTS=$(echo "$OUTPUT" | cut -d',' -f2)
    LEGIT_LAT=$(echo "$OUTPUT" | cut -d',' -f3)
    LEGIT_OK=$(echo "$OUTPUT" | cut -d',' -f4)

    [ -z "$CONNS" ] && CONNS=0
    [ -z "$AUTH_PKTS" ] && AUTH_PKTS=0
    [ -z "$LEGIT_LAT" ] && LEGIT_LAT=-1
    [ -z "$LEGIT_OK" ] && LEGIT_OK=0

    sleep 0.5

    STATS_AFTER=$("$DIR/broker_stats.sh")
    CPU_AFTER=$(echo "$STATS_AFTER" | cut -d',' -f2)
    MEM_AFTER=$(echo "$STATS_AFTER" | cut -d',' -f3)

    echo "$i,$CONNS,$AUTH_PKTS,$LEGIT_LAT,$LEGIT_OK,$CPU_BEFORE,$CPU_AFTER,$MEM_AFTER" >> "$OUT_PROTECTED"
    echo "conns=$CONNS auth=$AUTH_PKTS legit=${LEGIT_LAT}ms ok=$LEGIT_OK mem=${MEM_AFTER}KB"

    sleep 1
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
echo "  VULNERABLE: memory ${INITIAL_MEM_VULN}KB → ${FINAL_MEM_VULN}KB (+$((FINAL_MEM_VULN - INITIAL_MEM_VULN))KB)"
echo "  PROTECTED:  memory ${INITIAL_MEM_PROT}KB → ${FINAL_MEM_PROT}KB (+$((FINAL_MEM_PROT - INITIAL_MEM_PROT))KB)"
echo ""
echo "  Results:"
echo "    Vulnerable: $OUT_VULNERABLE"
echo "    Protected:  $OUT_PROTECTED"
echo ""
echo "  Analysis: python $DIR/analyze.py"
echo ""

# Restart broker for normal use
killall mosquitto 2>/dev/null
sleep 1
mosquitto -c "$BROKER_CONF" -d
echo "Broker restarted for normal use."
