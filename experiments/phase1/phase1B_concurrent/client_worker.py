"""
Clean TLS handshake measurement worker for concurrent phase.
"""
import sys
from pathlib import Path

# Add experiments directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.measurement import TLSHandshakeMeasurer


def worker(results, idx, cafile, certfile, keyfile):
    """Worker function for concurrent measurements."""
    try:
        measurer = TLSHandshakeMeasurer("localhost", 8883)
        results[idx] = measurer.measure_cert_handshake(cafile, certfile, keyfile)
    except Exception as e:
        print(f"Worker {idx} error: {e}")
        results[idx] = -1

