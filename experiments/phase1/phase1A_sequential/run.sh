#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/results.csv"
echo "iteration,handshake_ms,cpu_before,cpu_after,mem_kb" > "$OUT"

cd "$DIR/../.."

# Common broker stats function
get_broker_stats() {
  PID=$(pidof mosquitto 2>/dev/null)
  if [ -z "$PID" ]; then
    echo "0,0,0"
    return 0
  fi
  
  CPU_BEFORE=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ')
  sleep 0.05
  CPU_AFTER=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ')
  MEM=$(ps -p "$PID" -o rss= 2>/dev/null | tr -d ' ')
  
  echo "$CPU_BEFORE,$CPU_AFTER,$MEM"
}

for i in {1..50}; do
  HANDSHAKE=$(python -m phase1.phase1A_sequential.client)
  STATS=$(get_broker_stats)

  CPU_BEFORE=$(echo "$STATS" | cut -d',' -f1)
  CPU_AFTER=$(echo "$STATS" | cut -d',' -f2)
  MEM=$(echo "$STATS" | cut -d',' -f3)

  echo "$i,$HANDSHAKE,$CPU_BEFORE,$CPU_AFTER,$MEM" >> "$OUT"
  sleep 1
done

echo "Phase 1A (Sequential) experiment completed"
