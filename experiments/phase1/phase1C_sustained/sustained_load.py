"""
Sustained load testfor Phase 1C.
Measures TLS handshake latency and broker stats over time.
"""
import argparse
import csv
import time
import sys
import os
from pathlib import Path

# Add parent directory to path for imports BEFORE any other imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.measurement import TLSHandshakeMeasurer, CPUMonitor

parser = argparse.ArgumentParser()
parser.add_argument("--duration", type=int, required=True)
parser.add_argument("--interval", type=float, required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

# Resolve paths relative to project root
# sustained_load.py is at experiments/phase1/phase1C_sustained/sustained_load.py
# so we need to go up to mqtt-security which is 4 levels up
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")

measurer = TLSHandshakeMeasurer("localhost", 8883)
start = time.time()

with open(args.output, "a", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["elapsed_sec", "handshake_ms", "cpu_percent", "mem_kb"])

    while time.time() - start < args.duration:
        try:
            handshake_ms = measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)
            cpu, mem = CPUMonitor.get_broker_stats()
            elapsed = int(time.time() - start)
            
            writer.writerow([elapsed, f"{handshake_ms:.3f}", f"{cpu:.1f}", mem])
            f.flush()
        except Exception as e:
            print(f"Error during sustained load: {e}")

        time.sleep(args.interval)

