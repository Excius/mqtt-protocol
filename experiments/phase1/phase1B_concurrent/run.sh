#!/bin/bash

# Phase 1B: Concurrent TLS Certificate Handshake Test
# Tests how handshake latency scales with concurrent connections

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$DIR/../../.."
OUT="$DIR/results.csv"

echo "[Phase 1B] Concurrent TLS Certificate Handshake Test"

if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

echo "clients,avg_latency_ms,success,failed,cpu,mem_kb" > "$OUT"

for N in 10 25 50 100 150 200; do
    echo "  Testing $N concurrent clients..."
    RES=$(python "$DIR/launcher.py" --clients $N 2>/dev/null)
    if [ -n "$RES" ]; then
        echo "$N,$RES" >> "$OUT"
        echo "    Result: $RES"
    fi
    sleep 2
done

echo "[Phase 1B] Completed. Results: $OUT"

