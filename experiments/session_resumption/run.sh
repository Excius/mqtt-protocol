#!/bin/bash

# Session Resumption Test
# Compares full PSK handshake vs resumed session performance

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../.."
BROKER_CONF="$PROJECT_ROOT/broker/mosquitto_psk.conf"
OUT_NEW="$DIR/results_new_handshake.csv"
OUT_RESUMED="$DIR/results_session_resumed.csv"
ITERATIONS=50

echo "=========================================="
echo "Session Resumption Test"
echo "=========================================="
echo "Iterations: $ITERATIONS"
echo ""

# Restart broker with PSK config
killall mosquitto 2>/dev/null
sleep 1
mosquitto -c "$BROKER_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null 2>&1; then
    echo "ERROR: Failed to start broker"
    exit 1
fi

echo "iteration,handshake_ms,cpu_before,cpu_after,mem_kb" > "$OUT_NEW"
echo "iteration,handshake_ms,cpu_before,cpu_after,mem_kb" > "$OUT_RESUMED"

for i in $(seq 1 $ITERATIONS); do
  # Test 1: Full new handshake (no session reuse)
  HANDSHAKE_NEW=$(python "$DIR/client_connect.py" new 2>/dev/null)
  STATS_NEW=$("$DIR/broker_stats.sh")
  CPU_BEFORE=$(echo "$STATS_NEW" | cut -d',' -f1)
  CPU_AFTER=$(echo "$STATS_NEW" | cut -d',' -f2)
  MEM=$(echo "$STATS_NEW" | cut -d',' -f3)

  echo "$i,$HANDSHAKE_NEW,$CPU_BEFORE,$CPU_AFTER,$MEM" >> "$OUT_NEW"

  sleep 0.5

  # Test 2: Session resumption (should be faster)
  HANDSHAKE_RESUMED=$(python "$DIR/client_connect.py" resumed 2>/dev/null)
  STATS_RESUMED=$("$DIR/broker_stats.sh")
  CPU_BEFORE=$(echo "$STATS_RESUMED" | cut -d',' -f1)
  CPU_AFTER=$(echo "$STATS_RESUMED" | cut -d',' -f2)
  MEM=$(echo "$STATS_RESUMED" | cut -d',' -f3)

  echo "$i,$HANDSHAKE_RESUMED,$CPU_BEFORE,$CPU_AFTER,$MEM" >> "$OUT_RESUMED"

  echo "  $i/$ITERATIONS: new=${HANDSHAKE_NEW}ms, resumed=${HANDSHAKE_RESUMED}ms"
  sleep 0.5
done

echo ""
echo "Session Resumption experiment completed"
echo "Results:"
echo "  New handshake: $OUT_NEW"
echo "  Session resumed: $OUT_RESUMED"
