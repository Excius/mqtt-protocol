#!/bin/bash

# Phase 1A: Sequential TLS Certificate Handshake Test
# Measures 50 sequential cert-based handshakes

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../../.."
OUT="$DIR/results.csv"
ITERATIONS=50

echo "[Phase 1A] Sequential TLS Certificate Handshake Test"
echo "Iterations: $ITERATIONS"

if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

echo "iteration,handshake_ms,cpu_before,cpu_after,mem_kb" > "$OUT"

get_broker_stats() {
  PID=$(pidof mosquitto 2>/dev/null)
  if [ -z "$PID" ]; then echo "0,0,0"; return; fi
  CPU_BEFORE=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ')
  sleep 0.05
  CPU_AFTER=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ')
  MEM=$(ps -p "$PID" -o rss= 2>/dev/null | tr -d ' ')
  echo "$CPU_BEFORE,$CPU_AFTER,$MEM"
}

for i in $(seq 1 $ITERATIONS); do
  HANDSHAKE=$(python "$DIR/client.py" 2>/dev/null)
  if [ -z "$HANDSHAKE" ]; then continue; fi

  STATS=$(get_broker_stats)
  CPU_BEFORE=$(echo "$STATS" | cut -d',' -f1)
  CPU_AFTER=$(echo "$STATS" | cut -d',' -f2)
  MEM=$(echo "$STATS" | cut -d',' -f3)

  echo "$i,$HANDSHAKE,$CPU_BEFORE,$CPU_AFTER,$MEM" >> "$OUT"
  echo "  $i/$ITERATIONS: ${HANDSHAKE}ms"
  sleep 0.5
done

echo "[Phase 1A] Completed. Results: $OUT"
