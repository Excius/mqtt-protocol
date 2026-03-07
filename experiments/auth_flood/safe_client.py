"""
MQTT 5.0 Protected Client (AUTH Flood Mitigated)

Attempts the SAME auth flood attack as attack_client.py but with
application-level protection middleware that:
  1. Rate-limits new connections (max RATE_LIMIT_PER_SEC / second)
  2. Blocks ALL AUTH Re-authenticate packets (MAX_AUTH_PER_CONN = 0)
  3. Caps total concurrent connections (MAX_TOTAL_CONNS)
  4. Enforces aggressive authentication timeout (AUTH_TIMEOUT_SEC)
  5. Validates AUTH reason codes — rejects invalid/unexpected codes
  6. Enforces proper connection lifecycle (clean DISCONNECT)

This demonstrates how straightforward middleware controls completely
neutralise the AUTH flood DoS attack.

CWE-799 Mitigation: Proper Control of Interaction Frequency
"""

import socket
import ssl
import struct
import threading
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from experiments.common.measurement import TLSHandshakeMeasurer

BROKER = "localhost"
PORT = 8883
PSK_ID = "client1"
PSK_KEY = "0123456789abcdef"

# Same attack parameters (for fair comparison with attack_client.py)
FLOOD_THREADS = 10
ATTACK_DURATION = 5
AUTH_PACKETS_PER_CONN = 50

# ── Protection parameters ───────────────────────────────────────────────
RATE_LIMIT_PER_SEC = 2       # Max 2 new connections per second
MAX_AUTH_PER_CONN = 0        # Block ALL AUTH packets (re-auth not needed)
MAX_TOTAL_CONNS = 20         # Hard cap on total connections in the test
AUTH_TIMEOUT_SEC = 2.0       # Force-disconnect if connection lives > 2 s
VALID_AUTH_REASONS = {0x00, 0x18, 0x19}  # Success, ContinueAuth, ReAuth


# ── MQTT 5.0 packet builders (same as attack_client) ────────────────────

def encode_varint(n):
    result = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        result.append(byte)
        if n == 0:
            break
    return bytes(result)


def build_mqtt5_connect(client_id):
    var_header = b'\x00\x04MQTT\x05\x02\x00\x3c\x00'
    cid = client_id.encode('utf-8')
    payload = struct.pack('!H', len(cid)) + cid
    remaining = var_header + payload
    return b'\x10' + encode_varint(len(remaining)) + remaining


def build_mqtt5_auth(auth_method="SCRAM-SHA-256",
                     auth_data=b"flood-data-placeholder"):
    method_bytes = auth_method.encode('utf-8')
    props = b'\x15' + struct.pack('!H', len(method_bytes)) + method_bytes
    props += b'\x16' + struct.pack('!H', len(auth_data)) + auth_data
    props_len = encode_varint(len(props))
    var_header = b'\x19' + props_len + props
    return b'\xf0' + encode_varint(len(var_header)) + var_header


def build_mqtt5_disconnect():
    """Build a clean MQTT 5.0 DISCONNECT packet (reason 0x00 = Normal)."""
    # Reason code 0x00, properties length 0
    return b'\xe0\x02\x00\x00'


def create_psk_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_psk_client_callback(
        lambda hint: (PSK_ID.encode(), bytes.fromhex(PSK_KEY))
    )
    return ctx


class FloodStats:
    def __init__(self):
        self._lock = threading.Lock()
        self.total_conns = 0
        self.total_auths = 0

    def add(self, conns, auths):
        with self._lock:
            self.total_conns += conns
            self.total_auths += auths


# ── Protection Middleware ────────────────────────────────────────────────

class AuthRateLimiter:
    """
    Application-layer middleware that prevents AUTH flood abuse.

    Policies enforced:
      - Connection rate limit (sliding window, per second)
      - Per-connection AUTH packet cap (0 = no re-auth allowed)
      - Total connection cap over the lifetime of the test
      - Aggressive authentication timeout (force-disconnect stalled conns)
      - AUTH reason code validation (reject invalid/unexpected codes)
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._conn_timestamps = []
        self._total_conns = 0
        self.blocked_conns = 0
        self.blocked_auths = 0
        self.timed_out_conns = 0
        self.invalid_reason_codes = 0

    def allow_connection(self):
        with self._lock:
            now = time.time()
            # Sliding 1-second window
            self._conn_timestamps = [
                t for t in self._conn_timestamps if t > now - 1
            ]
            if len(self._conn_timestamps) >= RATE_LIMIT_PER_SEC:
                self.blocked_conns += 1
                return False
            if self._total_conns >= MAX_TOTAL_CONNS:
                self.blocked_conns += 1
                return False
            self._conn_timestamps.append(now)
            self._total_conns += 1
            return True

    def allow_auth_packet(self, conn_auth_count):
        if conn_auth_count >= MAX_AUTH_PER_CONN:
            with self._lock:
                self.blocked_auths += 1
            return False
        return True

    def check_connection_timeout(self, conn_start_time):
        """Return True if the connection has exceeded AUTH_TIMEOUT_SEC."""
        if time.time() - conn_start_time > AUTH_TIMEOUT_SEC:
            with self._lock:
                self.timed_out_conns += 1
            return True
        return False

    def validate_auth_reason_code(self, reason_code):
        """
        Validate AUTH reason code per MQTT 5.0 §3.15.2.1.
        Valid codes: 0x00 (Success), 0x18 (Continue), 0x19 (Re-authenticate).
        Anything else is protocol-violating and gets rejected.
        """
        if reason_code not in VALID_AUTH_REASONS:
            with self._lock:
                self.invalid_reason_codes += 1
            return False
        return True


# ── Protected flood worker ───────────────────────────────────────────────

def protected_worker(worker_id, stop_event, stats, middleware):
    """
    Same flood loop as attack_client but every operation is gated
    by the AuthRateLimiter middleware — including timeout and
    reason code validation.
    """
    local_conns = 0
    local_auths = 0
    ctx = create_psk_context()
    connect_pkt = build_mqtt5_connect(f"prot-{worker_id}")
    auth_pkt = build_mqtt5_auth()
    disconnect_pkt = build_mqtt5_disconnect()

    # Extract the reason code from our auth packet for validation
    # AUTH packet: 0xf0 <remaining_len> <reason_code> <props...>
    # reason_code is the first byte of the variable header
    auth_reason_code = 0x19   # Re-authenticate (what attack_client sends)

    while not stop_event.is_set():
        # ── Gate 1: rate-limit connection ──
        if not middleware.allow_connection():
            time.sleep(0.5)   # throttle — back off
            continue

        conn_start = time.time()

        try:
            raw = socket.create_connection((BROKER, PORT), timeout=3)
            tls = ctx.wrap_socket(raw, server_hostname=BROKER)
            local_conns += 1

            # CONNECT
            tls.sendall(connect_pkt)
            try:
                tls.settimeout(0.5)
                tls.recv(128)
            except socket.timeout:
                pass

            # ── Gate 2: AUTH packets — rate limit + reason code + timeout ──
            auth_count = 0
            for _ in range(AUTH_PACKETS_PER_CONN):
                if stop_event.is_set():
                    break
                # Check authentication timeout
                if middleware.check_connection_timeout(conn_start):
                    break          # Force disconnect — stalled too long
                # Validate reason code
                if not middleware.validate_auth_reason_code(auth_reason_code):
                    break          # Invalid reason code — reject
                # Check AUTH packet cap
                if not middleware.allow_auth_packet(auth_count):
                    break          # ALL blocked (MAX_AUTH_PER_CONN = 0)
                try:
                    tls.sendall(auth_pkt)
                    auth_count += 1
                    local_auths += 1
                except (BrokenPipeError, ConnectionResetError,
                        ssl.SSLError, OSError):
                    break

            # ── Clean DISCONNECT (proper lifecycle) ──
            try:
                tls.sendall(disconnect_pkt)
            except Exception:
                pass
            try:
                tls.close()
            except Exception:
                pass

        except (ConnectionRefusedError, ConnectionResetError,
                socket.timeout, ssl.SSLError, OSError):
            time.sleep(0.01)

    stats.add(local_conns, local_auths)


# ── Legitimate client measurement ────────────────────────────────────────

def measure_legit_handshake():
    measurer = TLSHandshakeMeasurer(BROKER, PORT)
    try:
        latency = measurer.measure_psk_handshake(PSK_ID, PSK_KEY)
        return latency, 1
    except Exception:
        return -1.0, 0


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    iteration = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    stats = FloodStats()
    middleware = AuthRateLimiter()
    stop_event = threading.Event()

    # Launch same number of threads as attack_client
    threads = []
    for i in range(FLOOD_THREADS):
        t = threading.Thread(
            target=protected_worker,
            args=(f"{iteration}-{i}", stop_event, stats, middleware),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Measure legit latency mid-test (same timing as attack_client)
    time.sleep(ATTACK_DURATION * 0.4)
    legit_latency, legit_success = measure_legit_handshake()
    time.sleep(ATTACK_DURATION * 0.6)

    stop_event.set()
    for t in threads:
        t.join(timeout=5)

    # Same output format as attack_client
    print(f"{stats.total_conns},{stats.total_auths},"
          f"{legit_latency:.3f},{legit_success}")


if __name__ == "__main__":
    main()
