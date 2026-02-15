#!/bin/bash

OUT="experiments/phase2_psk/results.csv"
echo "run,handshake_ms,cpu_percent,mem_kb" > $OUT

for i in {1..50}; do
  HANDSHAKE=$(experiments/phase2_psk/client_connect.sh)
  STATS=$(experiments/phase2_psk/broker_stats.sh)

  CPU=$(echo "$STATS" | cut -d',' -f1)
  MEM=$(echo "$STATS" | cut -d',' -f2)

  echo "$i,$HANDSHAKE,$CPU,$MEM" >> $OUT
  sleep 1
done

echo "Phase 2 (TLS-PSK) experiment completed"