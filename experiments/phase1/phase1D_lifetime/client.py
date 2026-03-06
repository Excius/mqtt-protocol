"""
Connection lifetime test for Phase 1D.
Establishes TLS connection and measures broker resources over time.
"""
import time
import sys
import os
import ssl
import socket
from pathlib import Path

# Add path for imports BEFORE other imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Resolve paths relative to project root
# client.py is at experiments/phase1/phase1D_lifetime/client.py
# so we need to go up to mqtt-security which is 4 levels up
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def run(duration):
    """Keep a TLS connection open for specified duration."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    s = socket.create_connection(("localhost", 8883))
    ss = ctx.wrap_socket(s, server_hostname="localhost",
                        do_handshake_on_connect=False)
    
    # Perform handshake
    ss.do_handshake()
    
    # Keep connection alive for specified duration
    time.sleep(duration)
    
    # Clean close
    try:
        ss.close()
    except:
        pass


if __name__ == "__main__":
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
        run(duration)

