"""
Phase 1A: Sequential TLS certificate handshake measurement.
Measures latency of sequential cert-based handshakes one at a time.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.measurement import TLSHandshakeMeasurer

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

BROKER = "localhost"
PORT = 8883
CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def connect_once():
    """Measure one certificate-based TLS handshake."""
    measurer = TLSHandshakeMeasurer(BROKER, PORT)
    return measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)


if __name__ == "__main__":
    print(f"{connect_once():.3f}")
