#!/bin/bash

# Phase 1E: Broker Saturation Test
# Tests how many concurrent TLS cert connections the broker can handle

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../../.."
OUT="$DIR/results.csv"

echo "[Phase 1E] Broker Saturation Test"

if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

echo "clients,success,failed,cpu,mem_kb" > "$OUT"

for N in 50 100 150 200 250 300 400 500; do
    echo "  Testing $N concurrent clients..."
    RESULT=$(python "$DIR/launcher.py" --clients $N 2>/dev/null)
    if [ -n "$RESULT" ]; then
        echo "$N,$RESULT" >> "$OUT"
        echo "    Result: $RESULT"
    fi
    sleep 2
done

echo "[Phase 1E] Completed. Results: $OUT"
