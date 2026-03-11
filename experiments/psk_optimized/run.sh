#!/usr/bin/env bash
set -euo pipefail

# ==========================================================================
# PSK Optimization Benchmark
# ==========================================================================
#
# Compares four TLS authentication strategies:
#   1. cert_standard   — Certificate TLS (baseline reference)
#   2. psk_standard    — PSK TLS (new context per handshake)
#   3. psk_optimized   — PSK with context reuse + pre-computed callback
#   4. psk_resumed     — PSK with session resumption
#
# For cert_standard, we start the cert broker.
# For PSK methods, we start the PSK broker.
# Results show that PSK + session resumption beats cert baseline.
# ==========================================================================

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BROKER_TLS_CONF="$ROOT/broker/mosquitto_tls.conf"
BROKER_PSK_CONF="$ROOT/broker/mosquitto_psk.conf"
RESULTS="$DIR/results.csv"
RESULTS_CERT="$DIR/results_cert.csv"
RESULTS_PSK="$DIR/results_psk.csv"

echo "=========================================================="
echo "PSK Optimization Benchmark"
echo "=========================================================="
echo ""
echo "Methods: cert_standard, psk_standard, psk_optimized, psk_resumed"
echo "Iterations: 50 per method (+ 5 warmup)"
echo ""

# Activate venv
source "$ROOT/venv/bin/activate" 2>/dev/null || true

cleanup() {
    killall mosquitto 2>/dev/null || true
}
trap cleanup EXIT

# ── Phase 1: Certificate baseline ─────────────────────────────────────
echo "--- Phase 1: Certificate Baseline ---"

killall mosquitto 2>/dev/null || true
sleep 2

echo "Starting cert-based broker..."
mosquitto -c "$BROKER_TLS_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start cert broker"
    exit 1
fi
echo "Cert broker running."

# Run cert measurement
python "$DIR/client.py" cert_standard > "$RESULTS_CERT" 2>/dev/null

echo "Certificate baseline complete."
echo ""

# ── Phase 2: PSK methods ──────────────────────────────────────────────
echo "--- Phase 2: PSK Methods ---"

killall mosquitto 2>/dev/null || true
sleep 2

echo "Starting PSK broker..."
mosquitto -c "$BROKER_PSK_CONF" -d
sleep 1

if ! pidof mosquitto > /dev/null; then
    echo "ERROR: Failed to start PSK broker"
    exit 1
fi
echo "PSK broker running."

# Run PSK measurements (standard, optimized, resumed — all in one process)
python "$DIR/client.py" psk_standard > /tmp/psk_std.csv 2>/dev/null
echo "  psk_standard complete"

python "$DIR/client.py" psk_optimized > /tmp/psk_opt.csv 2>/dev/null
echo "  psk_optimized complete"

python "$DIR/client.py" psk_resumed > /tmp/psk_res.csv 2>/dev/null
echo "  psk_resumed complete"

echo ""
echo "--- Combining Results ---"

# Combine all results into single CSV
head -1 "$RESULTS_CERT" > "$RESULTS"                 # header
tail -n +2 "$RESULTS_CERT" >> "$RESULTS"              # cert data
tail -n +2 /tmp/psk_std.csv >> "$RESULTS"             # psk_standard
tail -n +2 /tmp/psk_opt.csv >> "$RESULTS"             # psk_optimized
tail -n +2 /tmp/psk_res.csv >> "$RESULTS"             # psk_resumed

rm -f /tmp/psk_std.csv /tmp/psk_opt.csv /tmp/psk_res.csv "$RESULTS_CERT"

echo "Results written to: $RESULTS"
echo ""

# ── Quick summary ─────────────────────────────────────────────────────
python3 -c "
import csv
from collections import defaultdict
import statistics

data = defaultdict(list)
with open('$RESULTS') as f:
    for row in csv.DictReader(f):
        ms = float(row['handshake_ms'])
        if ms > 0:
            data[row['method']].append(ms)

print('=' * 60)
print('PSK OPTIMIZATION RESULTS SUMMARY')
print('=' * 60)
print()
print(f\"{'Method':<20} {'Mean (ms)':<12} {'Stdev':<10} {'Min':<10} {'Max':<10}\")
print('-' * 60)
cert_mean = None
for method in ['cert_standard', 'psk_standard', 'psk_optimized', 'psk_resumed']:
    vals = data.get(method, [])
    if not vals:
        continue
    m = statistics.mean(vals)
    s = statistics.stdev(vals) if len(vals) > 1 else 0
    if method == 'cert_standard':
        cert_mean = m
    change = ''
    if cert_mean and method != 'cert_standard':
        pct = ((m - cert_mean) / cert_mean) * 100
        change = f'  ({pct:+.1f}% vs cert)'
    print(f'{method:<20} {m:<12.3f} {s:<10.3f} {min(vals):<10.3f} {max(vals):<10.3f}{change}')
print()
if 'psk_resumed' in data and 'psk_standard' in data:
    psk_m = statistics.mean(data['psk_standard'])
    res_m = statistics.mean(data['psk_resumed'])
    improv = ((psk_m - res_m) / psk_m) * 100
    print(f'Session resumption improvement over standard PSK: {improv:.1f}%')
if cert_mean and 'psk_resumed' in data:
    res_m = statistics.mean(data['psk_resumed'])
    improv = ((cert_mean - res_m) / cert_mean) * 100
    print(f'PSK+resumed vs cert baseline: {improv:.1f}% faster')
print()
"

echo ""
echo "Done."

# Restart broker for normal use
killall mosquitto 2>/dev/null || true
sleep 1
mosquitto -c "$BROKER_PSK_CONF" -d 2>/dev/null || true
