"""
Baseline TLS certificate handshake measurement.
Measures individual cert-based handshake latency as the reference
benchmark for all other experiments.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.measurement import TLSHandshakeMeasurer

PROJECT_ROOT = Path(__file__).parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

BROKER = "localhost"
PORT = 8883
CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def measure_handshake():
    """Measure one certificate-based TLS handshake."""
    measurer = TLSHandshakeMeasurer(BROKER, PORT)
    return measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)


if __name__ == "__main__":
    print(f"{measure_handshake():.3f}")
