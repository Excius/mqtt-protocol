#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/results.csv"
START=50
END=1000
STEP=50

echo "clients,success,failed" >"$OUT"

if [ -f "$DIR/../../../venv/bin/activate" ]; then
  source "$DIR/../../../venv/bin/activate"
fi

echo "[Phase-1E] Saturation test started"

cd "$DIR"
for N in $(seq $START $STEP $END); do
  echo "Testing $N concurrent clients..."
  RESULT=$(python launcher.py --clients $N)

  SUCCESS=$(echo $RESULT | cut -d',' -f1)
  FAILED=$(echo $RESULT | cut -d',' -f2)

  echo "$N,$SUCCESS,$FAILED" >>"$OUT"
  sleep 2
done

echo "[Phase-1E] Experiment completed"
