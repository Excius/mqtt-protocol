#!/bin/bash

# Baseline TLS Certificate Handshake Measurement
# Measures 50 sequential cert-based handshakes as the reference benchmark

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../.."
BROKER_CONF="$PROJECT_ROOT/broker/mosquitto_tls.conf"
OUT="$DIR/results.csv"
ITERATIONS=50

echo "=========================================="
echo "Baseline TLS Certificate Handshake Test"
echo "=========================================="
echo "Iterations: $ITERATIONS"
echo ""

# Restart broker with TLS cert config
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
echo "Baseline experiment completed"
echo "Results: $OUT"

