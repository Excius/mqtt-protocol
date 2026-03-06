"""
Clean baseline TLS handshake measurement (certificate-based) for Phase 1A Sequential.
Uses ssl module directly for accurate TLS-only measurement.
"""
import sys
import os
from pathlib import Path

# Add experiments directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.measurement import TLSHandshakeMeasurer

# Resolve paths relative to project root (parent of experiments)
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

BROKER = "localhost"
PORT = 8883
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")
CAFILE = str(CERTS_DIR / "ca.crt")


def connect_once():
    """Measure one certificate-based TLS handshake."""
    measurer = TLSHandshakeMeasurer(BROKER, PORT)
    return measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)


if __name__ == "__main__":
    print(f"{connect_once():.3f}")
