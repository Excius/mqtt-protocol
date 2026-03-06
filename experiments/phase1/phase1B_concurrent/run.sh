#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/results.csv"
echo "clients,avg_latency,cpu_avg" >"$OUT"

cd "$DIR/.."

for N in 10 50 100 200 400; do
  sed -i "s/^N =.*/N = $N/" phase1B_concurrent/launcher.py
  RES=$(python phase1B_concurrent/launcher.py)
  echo "$N,$RES" >>"$OUT"
done

