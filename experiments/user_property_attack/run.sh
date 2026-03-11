#!/usr/bin/env bash
set -euo pipefail

# ==========================================================================
# User Property Injection — Multi-Vector Attack + Broker-Side Proxy
# ==========================================================================
#
# Five distinct attack vectors are exercised in every iteration:
#
#   VT-1 (count overflow)   — >10 properties per packet     → Rule 1
#   VT-2 (key overflow)     — key > 256 bytes                → Rule 2
#   VT-3 (value overflow)   — value > 256 bytes              → Rule 3
#   VT-4 (payload overflow) — per-packet total > 4096 bytes  → Rule 4
#   VT-5 (budget exhaust)   — cumulative per-client > 32 KB  → Rule 5
#
# Packet counts are randomised per iteration → genuinely dynamic CSV rows.
#
# Phase 1 (Vulnerable):
#   attack_client.py → Mosquitto:8883 (TLS-PSK direct, no proxy)
#   All attack packets reach the broker unfiltered.
#
# Phase 2 (Protected — Broker-Side Proxy):
#   attack_client.py → Proxy:8883 → Mosquitto:1884
#   Proxy inspects every PUBLISH and drops rule-violating packets.
#   Same attack code — protection is entirely broker-side.
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

echo "=================================================================="
echo "User Property Injection — Multi-Vector Attack (5 rule vectors)"
echo "=================================================================="
echo ""
echo "Attack vectors: count overflow | key size | value size | payload | budget"
echo "Packet counts:  randomised every iteration"
echo "Iterations:     $ITERATIONS"
echo "Vulnerable:     attack_client → Mosquitto:8883 (direct, no proxy)"
echo "Protected:      attack_client → Proxy:8883 → Mosquitto:1884"
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

# ---------------------------------------------------------------------------
# CSV headers
# Vulnerable: one column per attack vector + total
# Protected:  per-drop-type breakdown mirrors the 5 proxy rules
# ---------------------------------------------------------------------------
echo "iteration,normal_sent,vt1_sent,vt2_sent,vt3_sent,vt4_sent,vt5_sent,total_sent,cpu_before,cpu_after,mem_kb" \
    > "$OUT_VULN"
echo "iteration,packets_forwarded,packets_dropped,prop_count_drops,key_size_drops,val_size_drops,payload_drops,budget_drops,cpu_before,cpu_after,mem_kb" \
    > "$OUT_PROT"

# ======================================================================
# PHASE 1: VULNERABLE — No proxy, direct to Mosquitto
# ======================================================================
echo "--- Phase 1: VULNERABLE (Direct to Mosquitto, No Proxy) ---"
echo ""

killall mosquitto 2>/dev/null || true
sleep 2

echo "Starting Mosquitto on :8883 (TLS-PSK, direct)..."
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

    CPU_B=$("$DIR/broker_stats.sh" | cut -d',' -f1)

    # attack_client.py prints: normal_sent,vt1_sent,vt2_sent,vt3_sent,vt4_sent,vt5_sent
    COUNTS=$(timeout 60 python "$DIR/attack_client.py" \
        --host localhost --port 8883 --tls-psk \
        --iteration $i \
        2>/dev/null | tail -1 | tr -d '[:space:]')
    [ -z "$COUNTS" ] && COUNTS="0,0,0,0,0,0"

    N=$(  echo "$COUNTS" | cut -d',' -f1)
    VT1=$(echo "$COUNTS" | cut -d',' -f2)
    VT2=$(echo "$COUNTS" | cut -d',' -f3)
    VT3=$(echo "$COUNTS" | cut -d',' -f4)
    VT4=$(echo "$COUNTS" | cut -d',' -f5)
    VT5=$(echo "$COUNTS" | cut -d',' -f6)
    TOTAL=$(( N + VT1 + VT2 + VT3 + VT4 + VT5 ))

    sleep 0.5

    STATS_A=$("$DIR/broker_stats.sh")
    CPU_A=$(echo "$STATS_A" | cut -d',' -f2)
    MEM=$(  echo "$STATS_A" | cut -d',' -f3)

    echo "$i,$N,$VT1,$VT2,$VT3,$VT4,$VT5,$TOTAL,$CPU_B,$CPU_A,$MEM" >> "$OUT_VULN"
    echo "total=$TOTAL (n=$N vt1=$VT1 vt2=$VT2 vt3=$VT3 vt4=$VT4 vt5=$VT5), mem=${MEM}KB"
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

killall mosquitto 2>/dev/null || true
sleep 2

echo "Starting internal Mosquitto on :1884 (plain TCP, localhost only)..."
mosquitto -c "$BROKER_INT_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start internal broker"
    exit 1
fi

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

    # Flush proxy stats at start of window
    kill -USR1 "$PROXY_PID" 2>/dev/null || true
    sleep 0.2

    CPU_B=$(ps -p "$(pidof mosquitto)" -o %cpu= 2>/dev/null | tr -d ' ')
    [ -z "$CPU_B" ] && CPU_B="0.0"

    # Run the SAME attack client through the proxy
    timeout 60 python "$DIR/attack_client.py" \
        --host localhost --port 8883 --tls-psk \
        --iteration $i \
        2>/dev/null > /dev/null || true

    sleep 1

    # Dump proxy stats for this iteration window
    kill -USR1 "$PROXY_PID" 2>/dev/null || true
    sleep 0.3

    FORWARDED=0; DROPPED=0
    PROP_COUNT=0; KEY_SIZE=0; VAL_SIZE=0; PAYLOAD=0; BUDGET=0
    if [ -f "$STATS_FILE" ]; then
        read -r FORWARDED DROPPED PROP_COUNT KEY_SIZE VAL_SIZE PAYLOAD BUDGET < <(
            python3 - "$STATS_FILE" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
print(
    d.get('packets_forwarded', 0),
    d.get('packets_dropped', 0),
    d.get('prop_count_drops', 0),
    d.get('key_size_drops', 0),
    d.get('val_size_drops', 0),
    d.get('payload_drops', 0),
    d.get('budget_drops', 0),
)
PYEOF
        ) 2>/dev/null || true
    fi
    FORWARDED="${FORWARDED:-0}"
    DROPPED="${DROPPED:-0}"
    PROP_COUNT="${PROP_COUNT:-0}"
    KEY_SIZE="${KEY_SIZE:-0}"
    VAL_SIZE="${VAL_SIZE:-0}"
    PAYLOAD="${PAYLOAD:-0}"
    BUDGET="${BUDGET:-0}"

    CPU_A=$(ps -p "$(pidof mosquitto)" -o %cpu= 2>/dev/null | tr -d ' ')
    MEM=$(  ps -p "$(pidof mosquitto)" -o rss=  2>/dev/null | tr -d ' ')
    [ -z "$CPU_A" ] && CPU_A="0.0"
    [ -z "$MEM"   ] && MEM=0

    echo "$i,$FORWARDED,$DROPPED,$PROP_COUNT,$KEY_SIZE,$VAL_SIZE,$PAYLOAD,$BUDGET,$CPU_B,$CPU_A,$MEM" \
        >> "$OUT_PROT"
    echo "fwd=$FORWARDED drp=$DROPPED (cnt=$PROP_COUNT key=$KEY_SIZE val=$VAL_SIZE pay=$PAYLOAD bgt=$BUDGET) mem=${MEM}KB"
    sleep 0.5
done

FINAL_MEM_P=$(ps -p "$(pidof mosquitto)" -o rss= 2>/dev/null | tr -d ' ')

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
echo "=================================================================="
echo "Results Summary — Multi-Vector User Property Protection"
echo "=================================================================="
echo ""
echo "  VULNERABLE (no proxy):"
echo "    Memory: ${INIT_MEM}KB → ${FINAL_MEM_V}KB  (+$((FINAL_MEM_V - INIT_MEM))KB)"
echo ""
echo "  PROTECTED (proxy, 5 rule types tracked):"
echo "    Memory: ${INIT_MEM_P}KB → ${FINAL_MEM_P}KB  (+$((FINAL_MEM_P - INIT_MEM_P))KB)"
echo ""
echo "  CSV files:"
echo "    Vulnerable: $OUT_VULN"
echo "    Protected:  $OUT_PROT"
echo ""

killall mosquitto 2>/dev/null || true
sleep 1
mosquitto -c "$BROKER_PSK_CONF" -d 2>/dev/null || true
echo "Broker restarted for normal use."
