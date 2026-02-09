#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DURATION=300 # total experiment time in seconds
INTERVAL=1   # one connection per second
OUT="$DIR/results.csv"

echo "time_s,cpu_percent,mem_kb" >"$OUT"

echo "[Phase-1C] Sustained load test started"
echo "Duration: $DURATION seconds"
echo "Interval: $INTERVAL second"

if [ -f "$DIR/../../../venv/bin/activate" ]; then
  source "$DIR/../../../venv/bin/activate"
fi

cd "$DIR"
python sustained_load.py \
  --duration $DURATION \
  --interval $INTERVAL \
  --output "$OUT"

echo "[Phase-1C] Experiment completed"
