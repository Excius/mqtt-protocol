#!/usr/bin/env bash
set -euo pipefail

# ==========================================================================
# User Property Injection — BROKER-SIDE Protection via Security Proxy
# ==========================================================================
#
# Phase 1 (Vulnerable):
#   attack_client.py → Mosquitto:8883 (direct, no proxy, no protection)
#   All attack packets (50 props × 1KB) reach the broker unfiltered.
#
# Phase 2 (Protected — Broker-Side Proxy):
#   attack_client.py → Proxy:8883 → Mosquitto:1884
#   Proxy inspects PUBLISH packets and drops oversized user properties.
#   Same attack code — protection is entirely broker-side.
#
# The attacker CANNOT bypass broker-side protection because the proxy
# sits between the attacker and the broker.
# ==========================================================================

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PROXY="$ROOT/proxy/proxy_broker.py"
BROKER_PSK_CONF="$ROOT/broker/mosquitto_psk.conf"
BROKER_INT_CONF="$ROOT/broker/mosquitto_internal.conf"
PSK_FILE="$ROOT/certs/psk.txt"
STATS_FILE="/tmp/mqtt_proxy_stats.json"

OUT_VULN="$DIR/results_vulnerable.csv"
OUT_PROT="$DIR/results_protected.csv"
ITERATIONS=20

echo "=========================================================="
echo "User Property Injection — Broker-Side Proxy Protection"
echo "=========================================================="
echo ""
echo "Attack: 30 packets × 50 properties × 1KB = ~1.5MB/iteration"
echo "Iterations: $ITERATIONS"
echo "Vulnerable: attack_client → Mosquitto:8883 (direct)"
echo "Protected:  attack_client → Proxy:8883 → Mosquitto:1884"
echo ""

# Activate venv
source "$ROOT/venv/bin/activate" 2>/dev/null || true

PROXY_PID=""
cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    killall mosquitto 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# CSV headers
echo "iteration,packets_sent,packets_rejected,cpu_before,cpu_after,mem_kb" > "$OUT_VULN"
echo "iteration,packets_forwarded,packets_dropped,cpu_before,cpu_after,mem_kb" > "$OUT_PROT"

# ======================================================================
# PHASE 1: VULNERABLE — No proxy, direct to Mosquitto
# ======================================================================
echo "--- Phase 1: VULNERABLE (Direct to Mosquitto, No Protection) ---"
echo ""

killall mosquitto 2>/dev/null || true
sleep 2

echo "Starting Mosquitto on :8883 (PSK, direct)..."
mosquitto -c "$BROKER_PSK_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start broker"
    exit 1
fi

INIT_MEM=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo "Broker started. Initial memory: ${INIT_MEM} KB"
echo ""

for i in $(seq 1 $ITERATIONS); do
    echo -n "  Iteration $i/$ITERATIONS... "

    # CPU/memory before
    STATS_B=$("$DIR/broker_stats.sh")
    CPU_B=$(echo "$STATS_B" | cut -d',' -f1)

    # Run attack (attack_client.py outputs packet count on last line)
    PKTS=$(timeout 30 python "$DIR/attack_client.py" "$i" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ -z "$PKTS" ] && PKTS=0

    sleep 0.5

    STATS_A=$("$DIR/broker_stats.sh")
    CPU_A=$(echo "$STATS_A" | cut -d',' -f2)
    MEM=$(echo "$STATS_A" | cut -d',' -f3)

    echo "$i,$PKTS,0,$CPU_B,$CPU_A,$MEM" >> "$OUT_VULN"
    echo "sent=$PKTS, mem=${MEM}KB"
    sleep 0.5
done

FINAL_MEM_V=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo ""
echo "Vulnerable phase complete."
echo "  Memory: ${INIT_MEM}KB → ${FINAL_MEM_V}KB (+$((FINAL_MEM_V - INIT_MEM))KB)"

# ======================================================================
# PHASE 2: PROTECTED — Proxy in front of Mosquitto
# ======================================================================
echo ""
echo "--- Phase 2: PROTECTED (Proxy → Mosquitto, Broker-Side) ---"
echo ""

# Stop old broker
killall mosquitto 2>/dev/null || true
sleep 2

# Start internal Mosquitto on 1884 (no TLS — behind proxy)
echo "Starting internal Mosquitto on :1884 (plain TCP, localhost)..."
mosquitto -c "$BROKER_INT_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start internal broker"
    exit 1
fi

# Start security proxy on 8883
echo "Starting security proxy on :8883 (mode=user_property)..."
python "$PROXY" \
    --mode user_property \
    --listen-port 8883 \
    --backend-port 1884 \
    --psk-file "$PSK_FILE" \
    --stats-file "$STATS_FILE" \
    --conn-timeout 30 &
PROXY_PID=$!
sleep 2

# Verify proxy is running
if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "ERROR: Proxy failed to start"
    exit 1
fi
echo "Proxy started (PID: $PROXY_PID)"

INIT_MEM_P=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
echo "Internal broker memory: ${INIT_MEM_P} KB"
echo ""

for i in $(seq 1 $ITERATIONS); do
    echo -n "  Iteration $i/$ITERATIONS... "

    # Reset proxy stats for this iteration
    kill -USR1 "$PROXY_PID" 2>/dev/null || true
    sleep 0.2

    # CPU/memory before
    CPU_B=$(ps -p "$(pidof mosquitto)" -o %cpu= 2>/dev/null | tr -d ' ')
    [ -z "$CPU_B" ] && CPU_B="0.0"

    # Run the SAME attack client against proxy:8883
    timeout 30 python "$DIR/attack_client.py" "$i" 2>/dev/null > /dev/null || true

    sleep 1

    # Dump proxy stats
    kill -USR1 "$PROXY_PID" 2>/dev/null || true
    sleep 0.3

    # Read proxy stats
    FORWARDED=0
    DROPPED=0
    if [ -f "$STATS_FILE" ]; then
        FORWARDED=$(python3 -c "import json; d=json.load(open('$STATS_FILE')); print(d.get('packets_forwarded',0))" 2>/dev/null || echo 0)
        DROPPED=$(python3 -c "import json; d=json.load(open('$STATS_FILE')); print(d.get('packets_dropped',0))" 2>/dev/null || echo 0)
    fi
    [ -z "$FORWARDED" ] && FORWARDED=0
    [ -z "$DROPPED" ] && DROPPED=0

    # CPU/memory after
    CPU_A=$(ps -p "$(pidof mosquitto)" -o %cpu= 2>/dev/null | tr -d ' ')
    MEM=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
    [ -z "$CPU_A" ] && CPU_A="0.0"
    [ -z "$MEM" ] && MEM=0

    echo "$i,$FORWARDED,$DROPPED,$CPU_B,$CPU_A,$MEM" >> "$OUT_PROT"
    echo "forwarded=$FORWARDED, dropped=$DROPPED, mem=${MEM}KB"
    sleep 0.5
done

FINAL_MEM_P=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')

# Stop proxy
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""

echo ""
echo "Protected phase complete."
echo "  Memory: ${INIT_MEM_P}KB → ${FINAL_MEM_P}KB (+$((FINAL_MEM_P - INIT_MEM_P))KB)"

# ======================================================================
# SUMMARY
# ======================================================================
echo ""
echo "=========================================================="
echo "Results Summary — Broker-Side User Property Protection"
echo "=========================================================="
echo ""
echo "  VULNERABLE (no proxy):"
echo "    Memory: ${INIT_MEM}KB → ${FINAL_MEM_V}KB  (+$((FINAL_MEM_V - INIT_MEM))KB)"
echo ""
echo "  PROTECTED (proxy):"
echo "    Memory: ${INIT_MEM_P}KB → ${FINAL_MEM_P}KB  (+$((FINAL_MEM_P - INIT_MEM_P))KB)"
echo ""
echo "  CSV files:"
echo "    Vulnerable: $OUT_VULN"
echo "    Protected:  $OUT_PROT"
echo ""

# Restart broker for normal use
killall mosquitto 2>/dev/null || true
sleep 1
mosquitto -c "$BROKER_PSK_CONF" -d 2>/dev/null || true
echo "Broker restarted for normal use."
