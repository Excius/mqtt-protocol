"""
Clean baseline TLS handshake measurement (certificate-based).
Uses ssl module directly for accurate TLS-only measurement.
"""
import sys
from pathlib import Path

# Add experiments directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.measurement import TLSHandshakeMeasurer

BROKER = "localhost"
PORT = 8883

# Resolve paths relative to project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def measure_handshake():
    """Measure certificate-based TLS handshake."""
    measurer = TLSHandshakeMeasurer(BROKER, PORT)
    return measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)


if __name__ == "__main__":
    print(f"{measure_handshake():.3f}")
