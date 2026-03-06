"""
Concurrent TLS handshake launcher for Phase 1B.
"""
import sys
from pathlib import Path

# Add experiments directory to path BEFORE importing anything else
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import multiprocessing as mp
import time
import client_worker
from common.measurement import CPUMonitor

N = 400

# Resolve paths relative to project root
# launcher is at experiments/phase1/phase1B_concurrent/launcher.py
# so we need to go up to mqtt-security which is 4 levels up
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


if __name__ == "__main__":
    manager = mp.Manager()
    results = manager.dict()
    jobs = []

    for i in range(N):
        p = mp.Process(target=client_worker.worker, 
                      args=(results, i, CAFILE, CERTFILE, KEYFILE))
        jobs.append(p)
        p.start()

    for j in jobs:
        j.join()

    latencies = [v for v in results.values() if v != -1]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    time.sleep(0.1)
    cpu, mem = CPUMonitor.get_broker_stats()
    
    print(f"{avg_latency:.3f},{cpu:.1f},{mem}")


