"""
Clean PSK TLS handshake measurement.
Uses ssl module directly for accurate TLS-only measurement.
"""
import sys
from pathlib import Path

# Add experiments directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.measurement import TLSHandshakeMeasurer

# Resolve paths relative to project root
# client_connect.py is at experiments/phase2_psk/client_connect.py
# so we need to go up to mqtt-security which is 3 levels up
PROJECT_ROOT = Path(__file__).parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"
PSK_FILE = CERTS_DIR / "psk.txt"

BROKER = "localhost"
PORT = 8883
PSK_ID = "client1"
PSK_KEY = None

# Read PSK key from certs/psk.txt
with open(PSK_FILE) as f:
    for line in f:
        if line.startswith(PSK_ID + ":"):
            PSK_KEY = line.split(":", 1)[1].strip()
            break

if PSK_KEY is None:
    raise RuntimeError(f"PSK key for identity {PSK_ID} not found in {PSK_FILE}")


def measure_handshake():
    """Measure PSK-based TLS handshake."""
    measurer = TLSHandshakeMeasurer(BROKER, PORT)
    return measurer.measure_psk_handshake(PSK_ID, PSK_KEY)


if __name__ == "__main__":
    print(f"{measure_handshake():.3f}")
