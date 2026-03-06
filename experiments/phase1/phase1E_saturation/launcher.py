"""
Saturation test for Phase 1E.
Attempts to open many concurrent TLS connections.
"""
import argparse
import multiprocessing as mp
import sys
import os

from pathlib import Path

# Add path for imports BEFORE other imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.measurement import TLSHandshakeMeasurer

parser = argparse.ArgumentParser()
parser.add_argument("--clients", type=int, required=True)
args = parser.parse_args()

# Resolve paths relative to project root
# launcher.py is at experiments/phase1/phase1E_saturation/launcher.py
# so we need to go up to mqtt-security which is 4 levels up
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def try_connect(_):
    """Attempt one TLS handshake."""
    try:
        measurer = TLSHandshakeMeasurer("localhost", 8883)
        measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)
        return 1
    except Exception as e:
        print(f"Connection failed: {e}")
        return 0


if __name__ == "__main__":
    pool = mp.Pool(args.clients)
    results = pool.map(try_connect, range(args.clients))
    pool.close()
    pool.join()

    success = sum(results)
    failed = args.clients - success

    print(f"{success},{failed}")

