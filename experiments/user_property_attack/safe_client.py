"""
MQTT 5.0 Protected Client (WITH Validation)

Validates all user properties BEFORE sending. Rejects packets that exceed
defined security limits. Only well-formed, bounded packets reach the broker.

Uses the SAME attack parameters as attack_client.py, but applies validation
that blocks oversized packets while allowing normal ones through.

Limits enforced:
  - Max 10 user properties per packet  (normal has 2 → PASS)
  - Max 256 bytes per property key      (normal ~11B → PASS)
  - Max 256 bytes per property value    (normal ~11B → PASS)
  - Max 4096 bytes total payload per packet (normal ~44B → PASS)
  - Per-client cumulative budget of 32 KB (normal ~44B × 5 = ~220B → PASS)

Attack packets: 50 properties × 1KB values → BLOCKED by first check (50 > 10)
Normal packets: 2 properties × ~11B values → ALLOWED through all checks

CWE-770 Mitigation: Enforce resource allocation limits
"""

import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
import ssl
import sys
import time
import threading

BROKER = "localhost"
PORT = 8883
PSK_ID = "client1"
PSK_KEY = "0123456789abcdef"

# Same attack parameters as attack_client.py (for fair comparison)
NORMAL_PACKETS = 5
ATTACK_PACKETS = 30
NUM_PROPERTIES = 50
PROP_VALUE_SIZE = 1024

# Protection limits
MAX_PROPERTIES = 10          # Max allowed user properties per packet
MAX_KEY_SIZE = 256           # Max bytes per property key
MAX_VALUE_SIZE = 256         # Max bytes per property value
MAX_TOTAL_PAYLOAD = 4096     # Max total payload bytes per packet (4 KB)
MAX_CLIENT_BUDGET = 32768    # Per-client cumulative budget (32 KB)


def create_psk_context():
    """Create TLS context with PSK authentication."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_psk_client_callback(
        lambda hint: (PSK_ID.encode(), bytes.fromhex(PSK_KEY))
    )
    return ctx


# Track per-client cumulative payload
_client_payload_used = 0


def validate_properties(user_properties):
    """
    Validate user properties against security limits.
    Checks: count, key size, value size, total payload, and client budget.
    Returns (is_valid, reason) tuple.
    """
    global _client_payload_used

    if len(user_properties) > MAX_PROPERTIES:
        return False, f"Too many properties: {len(user_properties)} > {MAX_PROPERTIES}"

    total_payload = 0
    for key, value in user_properties:
        key_bytes = len(key.encode())
        val_bytes = len(value.encode())
        if key_bytes > MAX_KEY_SIZE:
            return False, f"Key too large: {key_bytes}B > {MAX_KEY_SIZE}B"
        if val_bytes > MAX_VALUE_SIZE:
            return False, f"Value too large: {val_bytes}B > {MAX_VALUE_SIZE}B"
        total_payload += key_bytes + val_bytes

    if total_payload > MAX_TOTAL_PAYLOAD:
        return False, f"Total payload too large: {total_payload}B > {MAX_TOTAL_PAYLOAD}B"

    if _client_payload_used + total_payload > MAX_CLIENT_BUDGET:
        return False, (f"Client budget exceeded: {_client_payload_used}B used + "
                       f"{total_payload}B new > {MAX_CLIENT_BUDGET}B budget")

    # Deduct from budget on success
    _client_payload_used += total_payload
    return True, "OK"


def main():
    iteration = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    connected = threading.Event()
    sent_count = 0
    rejected_count = 0

    def on_connect(client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            connected.set()
        else:
            print(f"  Connection failed: {reason_code}", file=sys.stderr)

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        protocol=mqtt.MQTTv5,
        client_id=f"safe-{iteration}"
    )
    client.on_connect = on_connect
    client.tls_set_context(create_psk_context())

    try:
        client.connect(BROKER, PORT)
    except Exception as e:
        print(f"  Connect error: {e}", file=sys.stderr)
        print("0")
        return

    client.loop_start()

    if not connected.wait(timeout=5):
        print("  Connection timeout", file=sys.stderr)
        print("0")
        client.loop_stop()
        return

    # Phase 1: Normal packets (small properties → pass validation)
    for i in range(NORMAL_PACKETS):
        user_props = [("sensor", "temperature"), ("unit", "celsius")]

        valid, reason = validate_properties(user_props)
        if valid:
            props = Properties(PacketTypes.PUBLISH)
            props.UserProperty = user_props
            result = client.publish(
                f"normal/iter{iteration}/{i}",
                f"temp={20 + i}",
                retain=True,
                properties=props,
                qos=0
            )
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                sent_count += 1
        else:
            rejected_count += 1
        time.sleep(0.01)

    print(f"  [SAFE] Normal packets sent: {sent_count}/{NORMAL_PACKETS}", file=sys.stderr)

    # Phase 2: Attempt attack packets → VALIDATE and REJECT before sending
    for i in range(ATTACK_PACKETS):
        user_props = []
        for j in range(NUM_PROPERTIES):
            user_props.append((f"atk-{j:04d}", "X" * PROP_VALUE_SIZE))

        valid, reason = validate_properties(user_props)
        if valid:
            # Would send if validation passed (but it won't for attack packets)
            props = Properties(PacketTypes.PUBLISH)
            props.UserProperty = user_props
            result = client.publish(
                f"attack/iter{iteration}/{i}",
                "malicious-data",
                retain=True,
                properties=props,
                qos=0
            )
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                sent_count += 1
        else:
            rejected_count += 1
        time.sleep(0.005)

    print(f"  [SAFE] Attack packets REJECTED: {rejected_count}/{ATTACK_PACKETS}", file=sys.stderr)

    time.sleep(1)

    client.loop_stop()
    try:
        client.disconnect()
    except Exception:
        pass

    # Output: sent_count,rejected_count (parsed by run.sh)
    print(f"{sent_count},{rejected_count}")


if __name__ == "__main__":
    main()
