"""
Session resumption measurement - tests both full handshake and resumed session.
Uses ssl module directly with session caching enabled.
"""
import sys
import socket
import ssl
import time
from pathlib import Path

# Add experiments directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Resolve paths relative to project root
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


def measure_new_handshake():
    """Measure a full TLS handshake with PSK (no session reuse)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    def psk_callback(hint):
        return PSK_ID.encode(), bytes.fromhex(PSK_KEY)
    
    context.set_psk_client_callback(psk_callback)
    
    # Create a socket and perform TLS handshake
    sock = socket.create_connection((BROKER, PORT), timeout=5)
    
    t0 = time.perf_counter()
    tls = context.wrap_socket(sock, server_hostname=BROKER)
    t1 = time.perf_counter()
    
    elapsed_ms = (t1 - t0) * 1000
    
    try:
        tls.shutdown()
    except:
        pass
    try:
        tls.close()
    except:
        pass
    
    return elapsed_ms


def measure_session_resumption():
    """
    Measure session resumption.
    First creates a session, then reuses it on second connection.
    Returns the time for the resumed connection (should be much faster).
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Enable session caching
    context.session_stats()
    
    def psk_callback(hint):
        return PSK_ID.encode(), bytes.fromhex(PSK_KEY)
    
    context.set_psk_client_callback(psk_callback)
    
    # First connection - establish session
    sock1 = socket.create_connection((BROKER, PORT), timeout=5)
    tls1 = context.wrap_socket(sock1, server_hostname=BROKER, 
                               do_handshake_on_connect=False)
    tls1.do_handshake()
    session = tls1.session
    
    try:
        tls1.shutdown()
    except:
        pass
    try:
        tls1.close()
    except:
        pass
    
    # Small delay before reusing session
    time.sleep(0.01)
    
    # Second connection - reuse session (should be much faster)
    sock2 = socket.create_connection((BROKER, PORT), timeout=5)
    tls2 = context.wrap_socket(sock2, server_hostname=BROKER,
                               do_handshake_on_connect=False,
                               session=session)
    
    t0 = time.perf_counter()
    tls2.do_handshake()
    t1 = time.perf_counter()
    
    elapsed_ms = (t1 - t0) * 1000
    
    try:
        tls2.shutdown()
    except:
        pass
    try:
        tls2.close()
    except:
        pass
    
    return elapsed_ms


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "new":
        # Measure full handshake
        print(f"{measure_new_handshake():.3f}")
    else:
        # Measure session resumption (default)
        print(f"{measure_session_resumption():.3f}")
