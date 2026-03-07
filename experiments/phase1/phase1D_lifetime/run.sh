#!/bin/bash

# Phase 1D: Connection Lifetime Test
# Measures broker impact of holding TLS cert connections for various durations

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../../.."
OUT="$DIR/results.csv"

echo "[Phase 1D] Connection Lifetime Test"

if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

echo "duration_s,handshake_ms,cpu,mem_kb" > "$OUT"

for D in 1 5 10 30 60; do
    echo "  Testing ${D}s connection lifetime..."
    RES=$(python "$DIR/client.py" $D 2>/dev/null)
    if [ -n "$RES" ]; then
        echo "$D,$RES" >> "$OUT"
        echo "    Result: $RES"
    fi
    sleep 1
done

echo "[Phase 1D] Completed. Results: $OUT"
