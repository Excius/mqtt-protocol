#!/usr/bin/env python3
"""
MQTT 5.0 Security Proxy — Broker-Side Protection

A TLS-terminating TCP proxy that sits between MQTT clients and Mosquitto,
providing real-time packet inspection and security enforcement.

Architecture:
    [Client] --TLS-PSK:8883--> [Proxy] --TCP:1884--> [Mosquitto]
                                  |
                          (inspects & filters)

Modes:
    --mode user_property   Enforce user-property limits on PUBLISH packets
    --mode auth_flood      Rate-limit connections, block AUTH packets
    --mode all             Enable all protections (default)

Stats:
    The proxy writes stats to --stats-file (default: /tmp/mqtt_proxy_stats.json)
    Send SIGUSR1 to dump-and-reset per-iteration stats.

Usage:
    python proxy_broker.py --mode user_property --psk-file certs/psk.txt
    python proxy_broker.py --mode auth_flood --psk-file certs/psk.txt
    python proxy_broker.py --mode all --psk-file certs/psk.txt
"""

import socket
import ssl
import struct
import threading
import time
import sys
import os
import json
import signal
import argparse
import logging
from collections import defaultdict
from pathlib import Path

# ── Logging ──────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('mqtt-proxy')


# ── MQTT 5.0 Constants ──────────────────────────────────────────────────

CONNECT     = 1
CONNACK     = 2
PUBLISH     = 3
PUBACK      = 4
PUBREC      = 5
PUBREL      = 6
PUBCOMP     = 7
SUBSCRIBE   = 8
SUBACK      = 9
UNSUBSCRIBE = 10
UNSUBACK    = 11
PINGREQ     = 12
PINGRESP    = 13
DISCONNECT  = 14
AUTH        = 15

PTYPE_NAMES = {
    1: 'CONNECT', 2: 'CONNACK', 3: 'PUBLISH', 4: 'PUBACK',
    5: 'PUBREC', 6: 'PUBREL', 7: 'PUBCOMP',
    8: 'SUBSCRIBE', 9: 'SUBACK', 10: 'UNSUBSCRIBE', 11: 'UNSUBACK',
    12: 'PINGREQ', 13: 'PINGRESP', 14: 'DISCONNECT', 15: 'AUTH',
}

PROP_USER_PROPERTY = 0x26   # Property ID 38

# MQTT 5.0 property data-type mapping (for skipping unknown properties)
BYTE_PROPS      = {0x01, 0x17, 0x19, 0x24, 0x25, 0x28, 0x29, 0x2A}
TWO_BYTE_PROPS  = {0x13, 0x21, 0x23}
FOUR_BYTE_PROPS = {0x02, 0x11, 0x18, 0x22, 0x27}
VARINT_PROPS    = {0x0B}
UTF8_PROPS      = {0x03, 0x08, 0x12, 0x15, 0x1A, 0x1C, 0x1F}
BINARY_PROPS    = {0x09, 0x16}


# ── Low-level helpers ────────────────────────────────────────────────────

def recv_exact(sock, n):
    """Receive exactly *n* bytes from socket.  Returns bytes or None."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        except (socket.timeout, ConnectionError, ssl.SSLError, OSError):
            return None if not buf else bytes(buf)
    return bytes(buf)


def decode_varint(data, offset):
    """Decode MQTT variable-length integer.  Returns (value, bytes_consumed)."""
    multiplier = 1
    value = 0
    consumed = 0
    while offset + consumed < len(data):
        byte = data[offset + consumed]
        value += (byte & 0x7F) * multiplier
        consumed += 1
        if byte & 0x80 == 0:
            return value, consumed
        multiplier *= 128
        if multiplier > 128 ** 3:
            break
    return 0, 1  # malformed — return safe defaults


def encode_varint(n):
    """Encode an integer as MQTT variable-length bytes."""
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out.append(byte)
        if n == 0:
            break
    return bytes(out)


def skip_property(data, offset, prop_id):
    """Skip past one MQTT 5.0 property value.  Returns new offset or None."""
    if prop_id in BYTE_PROPS:
        return offset + 1
    if prop_id in TWO_BYTE_PROPS:
        return offset + 2
    if prop_id in FOUR_BYTE_PROPS:
        return offset + 4
    if prop_id in VARINT_PROPS:
        _, consumed = decode_varint(data, offset)
        return offset + consumed
    if prop_id in UTF8_PROPS:
        if offset + 2 > len(data):
            return None
        slen = struct.unpack('!H', data[offset:offset + 2])[0]
        return offset + 2 + slen
    if prop_id in BINARY_PROPS:
        if offset + 2 > len(data):
            return None
        blen = struct.unpack('!H', data[offset:offset + 2])[0]
        return offset + 2 + blen
    if prop_id == PROP_USER_PROPERTY:
        # string pair — key then value
        if offset + 2 > len(data):
            return None
        klen = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2 + klen
        if offset + 2 > len(data):
            return None
        vlen = struct.unpack('!H', data[offset:offset + 2])[0]
        return offset + 2 + vlen
    return None  # unknown — cannot skip safely


# ── MQTT Packet reader / parser ─────────────────────────────────────────

def read_packet(sock, timeout=30):
    """
    Read one complete MQTT packet from *sock*.
    Returns the raw bytes or None on EOF / error.
    """
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        header = recv_exact(sock, 1)
        if not header:
            return None

        # remaining-length (1–4 bytes)
        remaining = 0
        multiplier = 1
        rl_bytes = bytearray()
        for _ in range(4):
            b = recv_exact(sock, 1)
            if not b:
                return None
            rl_bytes.append(b[0])
            remaining += (b[0] & 0x7F) * multiplier
            if b[0] & 0x80 == 0:
                break
            multiplier *= 128

        body = recv_exact(sock, remaining) if remaining > 0 else b''
        if body is None:
            return None
        return header + bytes(rl_bytes) + body
    except Exception:
        return None
    finally:
        try:
            sock.settimeout(old_timeout)
        except Exception:
            pass


def get_packet_type(packet):
    return (packet[0] >> 4) & 0x0F


def parse_publish_user_properties(packet):
    """
    Extract User Property list from an MQTT 5.0 PUBLISH packet.
    Returns list of (key, value) tuples, or empty list on error.
    """
    if get_packet_type(packet) != PUBLISH:
        return []

    # skip fixed header
    offset = 1
    _, rl_size = decode_varint(packet, offset)
    offset += rl_size

    qos = (packet[0] >> 1) & 0x03

    # Topic Name
    if offset + 2 > len(packet):
        return []
    topic_len = struct.unpack('!H', packet[offset:offset + 2])[0]
    offset += 2 + topic_len

    # Packet Identifier (QoS 1/2)
    if qos > 0:
        offset += 2

    # Properties length
    if offset >= len(packet):
        return []
    props_len, ps = decode_varint(packet, offset)
    offset += ps
    props_end = offset + props_len

    user_props = []
    while offset < props_end and offset < len(packet):
        prop_id = packet[offset]
        offset += 1
        if prop_id == PROP_USER_PROPERTY:
            if offset + 2 > len(packet):
                break
            klen = struct.unpack('!H', packet[offset:offset + 2])[0]
            offset += 2
            key = packet[offset:offset + klen].decode('utf-8', errors='replace')
            offset += klen
            if offset + 2 > len(packet):
                break
            vlen = struct.unpack('!H', packet[offset:offset + 2])[0]
            offset += 2
            val = packet[offset:offset + vlen].decode('utf-8', errors='replace')
            offset += vlen
            user_props.append((key, val))
        else:
            new_off = skip_property(packet, offset, prop_id)
            if new_off is None:
                break
            offset = new_off
    return user_props


# ── Thread-safe statistics ───────────────────────────────────────────────

class ProxyStats:
    """Atomic counters for proxy operations."""

    def __init__(self, stats_file):
        self._lock = threading.Lock()
        self._stats_file = stats_file
        self.reset()

    def reset(self):
        with self._lock:
            self.packets_forwarded = 0
            self.packets_dropped = 0
            self.connections_accepted = 0
            self.connections_rejected = 0
            self.auth_packets_blocked = 0

    def forward(self):
        with self._lock:
            self.packets_forwarded += 1

    def drop(self):
        with self._lock:
            self.packets_dropped += 1

    def accept_conn(self):
        with self._lock:
            self.connections_accepted += 1

    def reject_conn(self):
        with self._lock:
            self.connections_rejected += 1

    def block_auth(self):
        with self._lock:
            self.auth_packets_blocked += 1

    def snapshot(self):
        with self._lock:
            return {
                'packets_forwarded':    self.packets_forwarded,
                'packets_dropped':      self.packets_dropped,
                'connections_accepted':  self.connections_accepted,
                'connections_rejected':  self.connections_rejected,
                'auth_packets_blocked':  self.auth_packets_blocked,
            }

    def dump_and_reset(self):
        """Write current stats to file, then reset counters."""
        snap = self.snapshot()
        try:
            with open(self._stats_file, 'w') as f:
                json.dump(snap, f)
        except Exception as e:
            log.error(f"Failed to write stats: {e}")
        self.reset()
        return snap


# ── Connection rate limiter ──────────────────────────────────────────────

class ConnectionRateLimiter:
    """Sliding-window rate limiter for new connections."""

    def __init__(self, max_per_sec=2, max_total=20):
        self.max_per_sec = max_per_sec
        self.max_total = max_total
        self._lock = threading.Lock()
        self._timestamps = []
        self._total = 0
        self._active = 0

    def allow(self):
        with self._lock:
            now = time.time()
            self._timestamps = [t for t in self._timestamps if t > now - 1]
            if len(self._timestamps) >= self.max_per_sec:
                return False
            if self._total >= self.max_total:
                return False
            self._timestamps.append(now)
            self._total += 1
            self._active += 1
            return True

    def release(self):
        with self._lock:
            self._active = max(0, self._active - 1)


# ── Security rule sets ───────────────────────────────────────────────────

class UserPropertyRules:
    """
    Validates PUBLISH packets against user-property size limits.

    Rules enforced:
      1. Max 10 user properties per packet
      2. Max 256 bytes per property key
      3. Max 256 bytes per property value
      4. Max 4096 bytes total property payload per packet
      5. Per-client cumulative budget of 32 KB
    """
    MAX_PROPERTIES      = 10
    MAX_KEY_SIZE        = 256
    MAX_VALUE_SIZE      = 256
    MAX_TOTAL_PAYLOAD   = 4096
    MAX_CLIENT_BUDGET   = 32768

    def __init__(self):
        self._budgets = defaultdict(int)
        self._lock = threading.Lock()

    def inspect(self, packet, client_id="default"):
        """Return 'forward' or 'drop'."""
        if get_packet_type(packet) != PUBLISH:
            return 'forward'

        props = parse_publish_user_properties(packet)

        # Rule 1 – property count
        if len(props) > self.MAX_PROPERTIES:
            return 'drop'

        total_payload = 0
        for key, val in props:
            kb = len(key.encode('utf-8'))
            vb = len(val.encode('utf-8'))
            # Rule 2/3 – key / value sizes
            if kb > self.MAX_KEY_SIZE or vb > self.MAX_VALUE_SIZE:
                return 'drop'
            total_payload += kb + vb

        # Rule 4 – per-packet payload
        if total_payload > self.MAX_TOTAL_PAYLOAD:
            return 'drop'

        # Rule 5 – per-client cumulative budget
        with self._lock:
            if self._budgets[client_id] + total_payload > self.MAX_CLIENT_BUDGET:
                return 'drop'
            self._budgets[client_id] += total_payload

        return 'forward'


class AuthFloodRules:
    """
    Blocks AUTH packets and enforces connection-level policies.

    Rules enforced:
      1. Connection rate limiting (handled by ConnectionRateLimiter separately)
      2. 0 AUTH packets allowed per connection
      3. AUTH reason code validation (only 0x00, 0x18, 0x19 would be valid)
      4. Connection timeout enforcement (handled by session timeout)
    """
    MAX_AUTH_PER_CONN = 0
    VALID_REASONS = {0x00, 0x18, 0x19}

    def inspect(self, packet, client_id="default"):
        """Return 'forward' or 'drop'."""
        if get_packet_type(packet) == AUTH:
            return 'drop'
        return 'forward'


class CombinedRules:
    """Apply both user-property AND auth-flood rules."""

    def __init__(self):
        self.user_prop = UserPropertyRules()
        self.auth_flood = AuthFloodRules()

    def inspect(self, packet, client_id="default"):
        r = self.user_prop.inspect(packet, client_id)
        if r != 'forward':
            return r
        return self.auth_flood.inspect(packet, client_id)


# ── Per-client handler ───────────────────────────────────────────────────

class ClientHandler(threading.Thread):
    """Bidirectional relay for a single client through the proxy."""

    def __init__(self, client_sock, backend_host, backend_port,
                 rules, stats, conn_timeout=30, client_id="anon"):
        super().__init__(daemon=True)
        self.client = client_sock
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.rules = rules
        self.stats = stats
        self.conn_timeout = conn_timeout
        self.client_id = client_id
        self._stop = threading.Event()

    def run(self):
        backend = None
        try:
            backend = socket.create_connection(
                (self.backend_host, self.backend_port), timeout=10
            )
            # Start relay threads
            t1 = threading.Thread(target=self._client_to_backend,
                                  args=(backend,), daemon=True)
            t2 = threading.Thread(target=self._backend_to_client,
                                  args=(backend,), daemon=True)
            t1.start()
            t2.start()
            # Wait with timeout
            t1.join(timeout=self.conn_timeout)
            t2.join(timeout=max(1, self.conn_timeout - 5))
        except Exception as e:
            log.debug(f"Handler {self.client_id}: {e}")
        finally:
            self._stop.set()
            for s in (self.client, backend):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _client_to_backend(self, backend):
        """Read packets from client, inspect, and forward valid ones."""
        while not self._stop.is_set():
            pkt = read_packet(self.client, timeout=10)
            if pkt is None:
                break
            action = self.rules.inspect(pkt, self.client_id)
            if action == 'forward':
                try:
                    backend.sendall(pkt)
                    self.stats.forward()
                except Exception:
                    break
            else:
                ptype = get_packet_type(pkt)
                if ptype == AUTH:
                    self.stats.block_auth()
                self.stats.drop()
                log.debug(
                    f"DROPPED {PTYPE_NAMES.get(ptype, '?')} from {self.client_id}"
                )
        self._stop.set()

    def _backend_to_client(self, backend):
        """Forward responses from backend to client (transparent)."""
        while not self._stop.is_set():
            pkt = read_packet(backend, timeout=10)
            if pkt is None:
                break
            try:
                self.client.sendall(pkt)
            except Exception:
                break
        self._stop.set()


# ── Main proxy server ───────────────────────────────────────────────────

class MQTTSecurityProxy:
    """
    TLS-PSK terminating proxy with MQTT packet inspection.

    Listens for client TLS connections on *listen_port*, inspects MQTT
    traffic, and forwards validated packets to a backend Mosquitto
    broker on *backend_port* (plain TCP, localhost only).
    """

    def __init__(self, listen_port=8883, backend_host='127.0.0.1',
                 backend_port=1884, psk_file='certs/psk.txt',
                 psk_hint='mypsk', mode='all',
                 stats_file='/tmp/mqtt_proxy_stats.json',
                 conn_timeout=30):
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.psk_hint = psk_hint
        self.conn_timeout = conn_timeout
        self.stats = ProxyStats(stats_file)
        self._running = False
        self._conn_counter = 0

        # Load PSK identities
        self._psk_db = {}
        self._load_psk_file(psk_file)

        # Select rules
        if mode == 'user_property':
            self.rules = UserPropertyRules()
            self.rate_limiter = None
        elif mode == 'auth_flood':
            self.rules = AuthFloodRules()
            self.rate_limiter = ConnectionRateLimiter(
                max_per_sec=2, max_total=200
            )
        elif mode == 'all':
            self.rules = CombinedRules()
            self.rate_limiter = ConnectionRateLimiter(
                max_per_sec=2, max_total=200
            )
        else:
            raise ValueError(f"Unknown mode: {mode}")

        log.info(f"Proxy mode: {mode}")

    def _load_psk_file(self, path):
        p = Path(path)
        if not p.exists():
            log.error(f"PSK file not found: {path}")
            sys.exit(1)
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                identity, key_hex = line.split(':', 1)
                self._psk_db[identity] = bytes.fromhex(key_hex.strip())
        log.info(f"Loaded {len(self._psk_db)} PSK identities from {path}")

    def _psk_server_callback(self, identity):
        """Return PSK bytes for a given identity, or None to reject."""
        key = self._psk_db.get(identity)
        if key is None:
            log.warning(f"Unknown PSK identity: {identity}")
        return key

    def _build_ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_psk_server_callback(self._psk_server_callback,
                                    identity_hint=self.psk_hint)
        # No certificates needed — PSK only
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def serve_forever(self):
        """Start accepting connections."""
        self._running = True
        ssl_ctx = self._build_ssl_context()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', self.listen_port))
        srv.listen(128)
        srv.settimeout(1)

        log.info(f"Proxy listening on :{self.listen_port} → "
                 f"{self.backend_host}:{self.backend_port}")

        while self._running:
            try:
                raw, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            # Rate limiter gate (before TLS handshake to save CPU)
            if self.rate_limiter and not self.rate_limiter.allow():
                raw.close()
                self.stats.reject_conn()
                continue

            # TLS handshake
            try:
                tls_sock = ssl_ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError) as e:
                log.debug(f"TLS handshake failed from {addr}: {e}")
                try:
                    raw.close()
                except Exception:
                    pass
                continue

            self._conn_counter += 1
            cid = f"client-{self._conn_counter}"
            self.stats.accept_conn()

            handler = ClientHandler(
                tls_sock, self.backend_host, self.backend_port,
                self.rules, self.stats,
                conn_timeout=self.conn_timeout,
                client_id=cid,
            )
            handler.start()

        srv.close()
        log.info("Proxy stopped.")

    def stop(self):
        self._running = False


# ── Signal handling ──────────────────────────────────────────────────────

_proxy_instance = None


def _handle_sigusr1(signum, frame):
    """Dump and reset stats on SIGUSR1."""
    if _proxy_instance:
        snap = _proxy_instance.stats.dump_and_reset()
        log.info(f"Stats dumped (SIGUSR1): {snap}")


def _handle_sigterm(signum, frame):
    if _proxy_instance:
        _proxy_instance.stop()
    sys.exit(0)


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    global _proxy_instance

    parser = argparse.ArgumentParser(description='MQTT 5.0 Security Proxy')
    parser.add_argument('--listen-port', type=int, default=8883,
                        help='Port to listen on (default: 8883)')
    parser.add_argument('--backend-host', default='127.0.0.1')
    parser.add_argument('--backend-port', type=int, default=1884,
                        help='Backend Mosquitto port (default: 1884)')
    parser.add_argument('--psk-file', default='certs/psk.txt',
                        help='Path to PSK identity file')
    parser.add_argument('--psk-hint', default='mypsk')
    parser.add_argument('--mode', choices=['user_property', 'auth_flood', 'all'],
                        default='all', help='Protection mode')
    parser.add_argument('--stats-file', default='/tmp/mqtt_proxy_stats.json',
                        help='Path for stats output')
    parser.add_argument('--conn-timeout', type=int, default=30,
                        help='Per-connection timeout in seconds')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    proxy = MQTTSecurityProxy(
        listen_port=args.listen_port,
        backend_host=args.backend_host,
        backend_port=args.backend_port,
        psk_file=args.psk_file,
        psk_hint=args.psk_hint,
        mode=args.mode,
        stats_file=args.stats_file,
        conn_timeout=args.conn_timeout,
    )
    _proxy_instance = proxy

    signal.signal(signal.SIGUSR1, _handle_sigusr1)
    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)

    proxy.serve_forever()


if __name__ == '__main__':
    main()
