"""
Phase 1D: Connection lifetime test.
Establishes a TLS cert connection and holds it open for specified duration.
Outputs handshake time and broker stats.
"""
import time
import sys
import ssl
import socket
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.measurement import CPUMonitor

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def run(duration):
    """Hold a TLS cert connection open for specified duration, print stats."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    s = socket.create_connection(("localhost", 8883), timeout=5)
    ss = ctx.wrap_socket(s, server_hostname="localhost",
                         do_handshake_on_connect=False)

    t0 = time.perf_counter()
    ss.do_handshake()
    t1 = time.perf_counter()
    handshake_ms = (t1 - t0) * 1000

    # Hold connection open
    time.sleep(duration)

    # Get broker stats while connected
    cpu, mem = CPUMonitor.get_broker_stats()

    try:
        ss.close()
    except Exception:
        pass

    # Output: handshake_ms,cpu,mem_kb
    print(f"{handshake_ms:.3f},{cpu:.1f},{mem}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(int(sys.argv[1]))

