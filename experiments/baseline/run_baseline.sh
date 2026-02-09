#!/bin/bash

OUT="experiments/baseline/results.csv"

echo "run,handshake_ms,cpu_percent,mem_kb" >$OUT

for i in {1..50}; do
  HANDSHAKE=$(python experiments/baseline/client_connect.py)
  STATS=$(experiments/baseline/broker_stats.sh)

  CPU=$(echo "$STATS" | cut -d',' -f1)
  MEM=$(echo "$STATS" | cut -d',' -f2)

  echo "$i,$HANDSHAKE,$CPU,$MEM" >>$OUT
  sleep 1
done

echo "Baseline experiment completed"
