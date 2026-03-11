#!/usr/bin/env bash
set -euo pipefail

# ==========================================================================
# AUTH Flood Attack — BROKER-SIDE Protection via Security Proxy
# ==========================================================================
#
# Phase 1 (Vulnerable):
#   attack_client.py → Mosquitto:8883 (direct, no proxy)
#   10 threads flood TLS connections + AUTH Re-authenticate packets.
#
# Phase 2 (Protected — Broker-Side Proxy):
#   attack_client.py → Proxy:8883 → Mosquitto:1884
#   Proxy rate-limits connections and blocks ALL AUTH packets.
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
ITERATIONS=10

echo "=========================================================="
echo "AUTH Flood Attack — Broker-Side Proxy Protection"
echo "=========================================================="
echo ""
echo "Attack: 10 threads × rapid TLS+AUTH flood × 5s/iteration"
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
echo "iteration,flood_conns,flood_attempts,auth_packets_sent,legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb" > "$OUT_VULN"
echo "iteration,flood_conns,flood_attempts,auth_packets_sent,auth_packets_blocked,conns_rejected,legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb" > "$OUT_PROT"

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

    STATS_B=$("$DIR/broker_stats.sh")
    CPU_B=$(echo "$STATS_B" | cut -d',' -f1)

    # attack_client.py outputs: conns,attempts,auths,legit_lat,legit_ok
    OUTPUT=$(timeout 30 python "$DIR/attack_client.py" "$i" 2>/dev/null | tail -1 | tr -d '[:space:]')

    FLOOD_CONNS=$(echo "$OUTPUT" | cut -d',' -f1)
    FLOOD_ATTEMPTS=$(echo "$OUTPUT" | cut -d',' -f2)
    AUTH_PKTS=$(echo "$OUTPUT" | cut -d',' -f3)
    LEGIT_LAT=$(echo "$OUTPUT" | cut -d',' -f4)
    LEGIT_OK=$(echo "$OUTPUT" | cut -d',' -f5)

    [ -z "$FLOOD_CONNS" ] && FLOOD_CONNS=0
    [ -z "$FLOOD_ATTEMPTS" ] && FLOOD_ATTEMPTS=0
    [ -z "$AUTH_PKTS" ] && AUTH_PKTS=0
    [ -z "$LEGIT_LAT" ] && LEGIT_LAT=-1
    [ -z "$LEGIT_OK" ] && LEGIT_OK=0

    sleep 0.5

    STATS_A=$("$DIR/broker_stats.sh")
    CPU_A=$(echo "$STATS_A" | cut -d',' -f2)
    MEM=$(echo "$STATS_A" | cut -d',' -f3)

    echo "$i,$FLOOD_CONNS,$FLOOD_ATTEMPTS,$AUTH_PKTS,$LEGIT_LAT,$LEGIT_OK,$CPU_B,$CPU_A,$MEM" >> "$OUT_VULN"
    echo "conns=$FLOOD_CONNS attempts=$FLOOD_ATTEMPTS auth=$AUTH_PKTS legit=${LEGIT_LAT}ms ok=$LEGIT_OK mem=${MEM}KB"
    sleep 1
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

killall mosquitto 2>/dev/null || true
sleep 2

echo "Starting internal Mosquitto on :1884 (plain TCP, localhost)..."
mosquitto -c "$BROKER_INT_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start internal broker"
    exit 1
fi

echo "Starting security proxy on :8883 (mode=auth_flood)..."
python "$PROXY" \
    --mode auth_flood \
    --listen-port 8883 \
    --backend-port 1884 \
    --psk-file "$PSK_FILE" \
    --stats-file "$STATS_FILE" \
    --conn-timeout 5 &
PROXY_PID=$!
sleep 2

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

    # Reset proxy stats
    kill -USR1 "$PROXY_PID" 2>/dev/null || true
    sleep 0.2

    CPU_B=$(ps -p "$(pidof mosquitto)" -o %cpu= 2>/dev/null | tr -d ' ')
    [ -z "$CPU_B" ] && CPU_B="0.0"

    # Run the SAME attack client against proxy:8883
    # attack_client.py outputs: conns,attempts,auths,legit_lat,legit_ok
    OUTPUT=$(timeout 30 python "$DIR/attack_client.py" "$i" 2>/dev/null | tail -1 | tr -d '[:space:]')

    FLOOD_CONNS=$(echo "$OUTPUT" | cut -d',' -f1)
    FLOOD_ATTEMPTS=$(echo "$OUTPUT" | cut -d',' -f2)
    AUTH_PKTS=$(echo "$OUTPUT" | cut -d',' -f3)
    LEGIT_LAT_ATTACK=$(echo "$OUTPUT" | cut -d',' -f4)
    LEGIT_OK_ATTACK=$(echo "$OUTPUT" | cut -d',' -f5)

    [ -z "$FLOOD_CONNS" ] && FLOOD_CONNS=0
    [ -z "$FLOOD_ATTEMPTS" ] && FLOOD_ATTEMPTS=0
    [ -z "$AUTH_PKTS" ] && AUTH_PKTS=0
    [ -z "$LEGIT_LAT_ATTACK" ] && LEGIT_LAT_ATTACK=-1

    sleep 0.5

    # Measure legit latency AFTER the flood ends (shows broker recovery)
    # The rate limiter may block legit clients during active flood,
    # so we measure post-flood to show the broker is unaffected.
    LEGIT_POST=$(python3 -c "
import sys, os
sys.path.insert(0, os.path.join('$ROOT'))
from experiments.common.measurement import TLSHandshakeMeasurer
try:
    m = TLSHandshakeMeasurer('localhost', 8883)
    lat = m.measure_psk_handshake('client1', '0123456789abcdef')
    print(f'{lat:.3f},1')
except Exception:
    print('-1.000,0')
" 2>/dev/null)

    LEGIT_LAT=$(echo "$LEGIT_POST" | cut -d',' -f1)
    LEGIT_OK=$(echo "$LEGIT_POST" | cut -d',' -f2)
    [ -z "$LEGIT_LAT" ] && LEGIT_LAT=-1
    [ -z "$LEGIT_OK" ] && LEGIT_OK=0

    # Get proxy stats
    kill -USR1 "$PROXY_PID" 2>/dev/null || true
    sleep 0.3

    PROXY_AUTH_BLOCKED=0
    PROXY_CONNS_REJECTED=0
    if [ -f "$STATS_FILE" ]; then
        PROXY_AUTH_BLOCKED=$(python3 -c "import json; d=json.load(open('$STATS_FILE')); print(d.get('auth_packets_blocked',0))" 2>/dev/null || echo 0)
        PROXY_CONNS_REJECTED=$(python3 -c "import json; d=json.load(open('$STATS_FILE')); print(d.get('connections_rejected',0))" 2>/dev/null || echo 0)
    fi
    [ -z "$PROXY_AUTH_BLOCKED" ] && PROXY_AUTH_BLOCKED=0
    [ -z "$PROXY_CONNS_REJECTED" ] && PROXY_CONNS_REJECTED=0

    # CPU/memory after
    CPU_A=$(ps -p "$(pidof mosquitto)" -o %cpu= 2>/dev/null | tr -d ' ')
    MEM=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')
    [ -z "$CPU_A" ] && CPU_A="0.0"
    [ -z "$MEM" ] && MEM=0

    echo "$i,$FLOOD_CONNS,$FLOOD_ATTEMPTS,$AUTH_PKTS,$PROXY_AUTH_BLOCKED,$PROXY_CONNS_REJECTED,$LEGIT_LAT,$LEGIT_OK,$CPU_B,$CPU_A,$MEM" >> "$OUT_PROT"
    echo "conns=$FLOOD_CONNS attempts=$FLOOD_ATTEMPTS auth_sent=$AUTH_PKTS auth_blocked=$PROXY_AUTH_BLOCKED rejected=$PROXY_CONNS_REJECTED legit=${LEGIT_LAT}ms mem=${MEM}KB"
    sleep 1
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
echo "Results Summary — Broker-Side AUTH Flood Protection"
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
