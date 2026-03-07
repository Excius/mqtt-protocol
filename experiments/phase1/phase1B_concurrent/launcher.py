"""
Phase 1B: Concurrent TLS certificate handshake launcher.
Spawns N concurrent processes, each doing one cert-based TLS handshake.
Measures average latency and broker CPU/memory.
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import multiprocessing as mp
import time
from common.measurement import TLSHandshakeMeasurer, CPUMonitor

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def worker(results, idx):
    """Worker: measure one cert-based TLS handshake."""
    try:
        measurer = TLSHandshakeMeasurer("localhost", 8883)
        results[idx] = measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)
    except Exception:
        results[idx] = -1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", type=int, default=10)
    args = parser.parse_args()

    manager = mp.Manager()
    results = manager.dict()
    jobs = []

    for i in range(args.clients):
        p = mp.Process(target=worker, args=(results, i))
        jobs.append(p)
        p.start()

    for j in jobs:
        j.join()

    latencies = [v for v in results.values() if v > 0]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    success = len(latencies)
    failed = args.clients - success

    time.sleep(0.1)
    cpu, mem = CPUMonitor.get_broker_stats()

    print(f"{avg_latency:.3f},{success},{failed},{cpu:.1f},{mem}")


