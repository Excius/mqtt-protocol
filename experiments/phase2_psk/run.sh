#!/bin/bash

# Get script directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/results.csv"

echo "iteration,handshake_ms,cpu_before,cpu_after,mem_kb" > $OUT

for i in {1..50}; do
  HANDSHAKE=$(python "$DIR/client_connect.py")
  STATS=$("$DIR/broker_stats.sh")
  CPU_AFTER=$(echo "$STATS" | cut -d',' -f2)
  MEM=$(echo "$STATS" | cut -d',' -f3)

  echo "$i,$HANDSHAKE,$CPU_BEFORE,$CPU_AFTER,$MEM" >> $OUT
  sleep 1
done

echo "Phase 2 (TLS-PSK) experiment completed"
