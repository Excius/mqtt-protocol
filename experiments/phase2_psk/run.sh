#!/bin/bash

# Phase 2: TLS-PSK Handshake Measurement
# Measures 50 PSK handshakes to compare against cert-based baseline

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../.."
BROKER_CONF="$PROJECT_ROOT/broker/mosquitto_psk.conf"
OUT="$DIR/results.csv"
ITERATIONS=50

echo "=========================================="
echo "Phase 2: TLS-PSK Handshake Test"
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

echo "iteration,handshake_ms,cpu_before,cpu_after,mem_kb" > "$OUT"

for i in $(seq 1 $ITERATIONS); do
  HANDSHAKE=$(python "$DIR/client_connect.py" 2>/dev/null)
  if [ -z "$HANDSHAKE" ]; then
    echo "  Iteration $i/$ITERATIONS: connection failed"
    continue
  fi

  STATS=$("$DIR/broker_stats.sh")
  CPU_BEFORE=$(echo "$STATS" | cut -d',' -f1)
  CPU_AFTER=$(echo "$STATS" | cut -d',' -f2)
  MEM=$(echo "$STATS" | cut -d',' -f3)

  echo "$i,$HANDSHAKE,$CPU_BEFORE,$CPU_AFTER,$MEM" >> "$OUT"
  echo "  Iteration $i/$ITERATIONS: ${HANDSHAKE}ms"
  sleep 0.5
done

echo ""
echo "Phase 2 (TLS-PSK) experiment completed"
echo "Results: $OUT"
