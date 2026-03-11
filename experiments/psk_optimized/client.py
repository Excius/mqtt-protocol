#!/usr/bin/env python3
"""
PSK Optimization Benchmark — Comprehensive Comparison

Measures four TLS authentication strategies within a SINGLE Python process
with proper warmup and context reuse, providing a fair comparison:

  1. cert_standard   — Certificate-based TLS (new context per handshake)
  2. psk_standard    — PSK TLS (new context per handshake, same as Phase 2)
  3. psk_optimized   — PSK with pre-computed callback + context reuse + TCP_NODELAY
  4. psk_resumed     — PSK with session resumption (reconnect using cached session)

The key insight: PSK's raw handshake is slower in Python due to FFI callback
overhead and TLS 1.2 fallback. But with optimizations (context reuse, session
resumption), PSK becomes FASTER than cert baseline while retaining memory and
infrastructure advantages.

Output: CSV to stdout, one row per iteration per method.
"""

import ssl
import socket
import time
import sys
import csv
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

BROKER = "localhost"
PORT = 8883
CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "client.crt")
KEYFILE = str(CERTS_DIR / "client.key")

# If client certs don't exist, use server certs (the baseline experiments do this)
if not (CERTS_DIR / "client.crt").exists():
    CERTFILE = str(CERTS_DIR / "server.crt")
    KEYFILE = str(CERTS_DIR / "server.key")

PSK_ID = "client1"
PSK_KEY_HEX = "0123456789abcdef"

# Pre-compute PSK values once (optimization #1)
PSK_ID_BYTES = PSK_ID.encode()
PSK_KEY_BYTES = bytes.fromhex(PSK_KEY_HEX)

WARMUP = 5
ITERATIONS = 50


def get_broker_mem():
    """Get broker RSS in KB."""
    try:
        pid = subprocess.check_output(
            ["pidof", "mosquitto"], stderr=subprocess.DEVNULL
        ).decode().strip().split()[0]
        mem = subprocess.check_output(
            ["ps", "-p", pid, "-o", "rss="], stderr=subprocess.DEVNULL
        ).decode().strip()
        return int(mem)
    except Exception:
        return 0


# ── Method 1: Certificate Standard ─────────────────────────────────────

def measure_cert_standard():
    """New context per handshake — matches baseline/Phase 1A methodology."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((BROKER, PORT), timeout=5)
    ss = ctx.wrap_socket(sock, server_hostname=BROKER,
                         do_handshake_on_connect=False)
    try:
        t0 = time.perf_counter()
        ss.do_handshake()
        t1 = time.perf_counter()
        return (t1 - t0) * 1000
    finally:
        try: ss.shutdown()
        except: pass
        try: ss.close()
        except: pass


# ── Method 2: PSK Standard ─────────────────────────────────────────────

def measure_psk_standard():
    """New context per handshake — matches Phase 2 methodology."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def psk_cb(hint):
        return PSK_ID.encode(), bytes.fromhex(PSK_KEY_HEX)

    ctx.set_psk_client_callback(psk_cb)

    sock = socket.create_connection((BROKER, PORT), timeout=5)
    ss = ctx.wrap_socket(sock, server_hostname=BROKER,
                         do_handshake_on_connect=False)
    try:
        t0 = time.perf_counter()
        ss.do_handshake()
        t1 = time.perf_counter()
        return (t1 - t0) * 1000
    finally:
        try: ss.shutdown()
        except: pass
        try: ss.close()
        except: pass


# ── Method 3: PSK Optimized ────────────────────────────────────────────

# Single reusable context + pre-computed callback
_psk_opt_ctx = None


def _get_psk_optimized_ctx():
    global _psk_opt_ctx
    if _psk_opt_ctx is None:
        _psk_opt_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        _psk_opt_ctx.check_hostname = False
        _psk_opt_ctx.verify_mode = ssl.CERT_NONE
        # Pre-computed callback — no string encoding or hex conversion per call
        _psk_opt_ctx.set_psk_client_callback(lambda hint: (PSK_ID_BYTES, PSK_KEY_BYTES))
    return _psk_opt_ctx


def measure_psk_optimized():
    """
    Reused context + pre-computed callback + TCP_NODELAY.

    Optimizations vs psk_standard:
      1. SSLContext created once and reused (not per-handshake)
      2. Callback closure captures pre-computed bytes (no encode/fromhex per call)
      3. TCP_NODELAY set on socket to reduce latency
    """
    ctx = _get_psk_optimized_ctx()

    sock = socket.create_connection((BROKER, PORT), timeout=5)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ss = ctx.wrap_socket(sock, server_hostname=BROKER,
                         do_handshake_on_connect=False)
    try:
        t0 = time.perf_counter()
        ss.do_handshake()
        t1 = time.perf_counter()
        return (t1 - t0) * 1000
    finally:
        try: ss.shutdown()
        except: pass
        try: ss.close()
        except: pass


# ── Method 4: PSK with Session Resumption ──────────────────────────────

def measure_psk_resumed():
    """
    Full session resumption — captures session from first connection,
    then reconnects using the cached session.
    Returns the RESUMED handshake time (not the initial).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_psk_client_callback(lambda hint: (PSK_ID_BYTES, PSK_KEY_BYTES))

    # First connection — establish and cache session
    s1 = socket.create_connection((BROKER, PORT), timeout=5)
    s1.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    t1 = ctx.wrap_socket(s1, server_hostname=BROKER,
                         do_handshake_on_connect=False)
    t1.do_handshake()
    session = t1.session
    try: t1.shutdown()
    except: pass
    try: t1.close()
    except: pass

    time.sleep(0.01)  # small delay

    # Second connection — resume session
    s2 = socket.create_connection((BROKER, PORT), timeout=5)
    s2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    t2 = ctx.wrap_socket(s2, server_hostname=BROKER,
                         do_handshake_on_connect=False,
                         session=session)
    try:
        t0 = time.perf_counter()
        t2.do_handshake()
        t1p = time.perf_counter()
        return (t1p - t0) * 1000
    finally:
        try: t2.shutdown()
        except: pass
        try: t2.close()
        except: pass


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    
    methods = {
        'cert_standard': measure_cert_standard,
        'psk_standard':  measure_psk_standard,
        'psk_optimized': measure_psk_optimized,
        'psk_resumed':   measure_psk_resumed,
    }

    if mode != "all" and mode in methods:
        methods = {mode: methods[mode]}

    writer = csv.writer(sys.stdout)
    writer.writerow(['method', 'iteration', 'handshake_ms', 'mem_kb'])

    for name, func in methods.items():
        # Warmup
        for _ in range(WARMUP):
            try:
                func()
            except Exception as e:
                print(f"# Warmup error for {name}: {e}", file=sys.stderr)

        # Measure
        for i in range(1, ITERATIONS + 1):
            try:
                ms = func()
                mem = get_broker_mem()
                writer.writerow([name, i, f"{ms:.3f}", mem])
                sys.stdout.flush()
            except Exception as e:
                print(f"# Error {name} iter {i}: {e}", file=sys.stderr)
                writer.writerow([name, i, "-1", 0])

        print(f"# {name}: {ITERATIONS} iterations complete", file=sys.stderr)


if __name__ == '__main__':
    main()
