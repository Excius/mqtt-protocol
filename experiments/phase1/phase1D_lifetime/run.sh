#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/results.csv"
echo "duration_s,cpu,mem" >"$OUT"

cd "$DIR/.."

for D in 1 10 60; do
  python "$DIR/client.py" $D
  python -c "import sys; sys.path.insert(0, '$DIR/..'); from common.broker_stats import get_broker_stats; print('$D,' + ','.join(map(str, get_broker_stats())))" >>"$OUT"
done
