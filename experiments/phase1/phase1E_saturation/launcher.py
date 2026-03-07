"""
Phase 1E: Saturation test.
Attempts to open many concurrent TLS cert connections to find capacity limits.
"""
import argparse
import multiprocessing as mp
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.measurement import TLSHandshakeMeasurer, CPUMonitor

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def try_connect(_):
    """Attempt one TLS cert handshake."""
    try:
        measurer = TLSHandshakeMeasurer("localhost", 8883)
        measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)
        return 1
    except Exception:
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", type=int, required=True)
    args = parser.parse_args()

    pool = mp.Pool(min(args.clients, mp.cpu_count() * 4))
    results = pool.map(try_connect, range(args.clients))
    pool.close()
    pool.join()

    success = sum(results)
    failed = args.clients - success
    cpu, mem = CPUMonitor.get_broker_stats()

    print(f"{success},{failed},{cpu:.1f},{mem}")

