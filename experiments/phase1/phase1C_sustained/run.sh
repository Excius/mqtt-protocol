#!/bin/bash

# Phase 1C: Sustained TLS Certificate Load Test
# Measures handshake latency and broker stats under continuous load

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../../.."
DURATION=60    # total experiment time in seconds
INTERVAL=1     # one connection per second
OUT="$DIR/results.csv"

echo "[Phase 1C] Sustained TLS Certificate Load Test"
echo "Duration: ${DURATION}s, Interval: ${INTERVAL}s"

if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

# Clear old results 
> "$OUT"

python "$DIR/sustained_load.py" \
    --duration $DURATION \
    --interval $INTERVAL \
    --output "$OUT"

echo "[Phase 1C] Completed. Results: $OUT"
