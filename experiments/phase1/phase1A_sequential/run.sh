#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/results.csv"
echo "iteration,handshake_ms,cpu_avg,mem_kb" >"$OUT"

cd "$DIR/.."

for i in {1..200}; do
  HANDSHAKE=$(python -m phase1A_sequential.client)
  CPU=$(python -c "from common.cpu_sampler import sample_cpu; print(sample_cpu())")
  MEM=$(python -c "from common.broker_stats import get_broker_stats; print(get_broker_stats()[1])")
  echo "$i,$HANDSHAKE,$CPU,$MEM" >>"$OUT"
done
