# User Property Injection Attack - Complete Analysis & Implementation Guide

## Executive Summary

You identified an issue with the initial test suite: **the attack wasn't actually reaching the broker, and the protected version was rejecting ALL packets instead of selectively protecting**.

This document explains:

1. **What the vulnerability actually is**
2. **How proper attacks work**
3. **How to properly defend**
4. **Correct implementation patterns**
5. **Why enforcement matters at different layers**

---

## Part 1: The Actual Vulnerability

### What is User Property Injection?

In **MQTT 5.0**, clients can add user properties to PUBLISH packets. Each property is a key-value pair.

```
PUBLISH packet structure:
┌─────────────────────────────────────┐
│  Fixed Header (3+ bytes)           │
├─────────────────────────────────────┤
│  Topic Name (2+ bytes for length)  │
├─────────────────────────────────────┤
│  Payload (variable)                │
├─────────────────────────────────────┤
│  PROPERTIES:                        │
│  ├─ 0x26 (user property marker)    │
│  ├─ Key (2 bytes length + string)  │
│  └─ Value (2 bytes length + string)│
│  ├─ 0x26 (another property)        │
│  ├─ Key                            │
│  └─ Value                          │
│  └─ ... unlimited more properties  │
└─────────────────────────────────────┘
```

**The Vulnerability**: MQTT spec allows **unlimited** properties, each of **unlimited** size!

### Attack Scenario

An attacker could send:

```
ATTACK PACKET:
├─ Topic: "test/attack"
├─ Payload: "ATTACK"
└─ Properties:
   ├─ property_1: key=500 bytes, value=10MB
   ├─ property_2: key=500 bytes, value=10MB
   ├─ property_3: key=500 bytes, value=10MB
   └─ ... 1000 more properties

   Total: ~10GB per packet!

Attack Pattern:
Send 10 packets = 100GB memory + broker CRASH
```

**Impact:**

- Memory exhaustion → OOM kill
- CPU spike analyzing massive packets
- Connection limit exhaustion
- DoS (Denial of Service)

---

## Part 2: Vulnerability vs Protection Comparison

### Vulnerable Broker (No Limits)

```python
# VULNERABLE CODE - Mosquitto/Broker without property limits
def handle_publish(packet):
    topic = parse_topic(packet)
    payload = parse_payload(packet)
    properties = parse_properties(packet)  # ⚠️ NO VALIDATION!

    for property in properties:
        # Every property stored in memory
        # No checks on key size
        # No checks on value size
        # No checks on property count
        # Memory grows unbounded!
        store_in_memory(property)

    deliver_to_subscribers(topic, payload)
```

**Attack Success**: YES

- 1000 properties × 10KB = 10MB per packet
- Send 10 packets = 100MB memory gobbled
- Send 100 packets = 1GB memory → broker hangs
- Send 1000 packets = 10GB → OOM kill

---

### Protected Broker (With Limits)

#### Option 1: SERVER-SIDE VALIDATION (Broker validates incoming packets)

```python
# PROTECTED CODE - Broker validates properties
class PropertyValidator:
    MAX_PROPERTIES = 20
    MAX_KEY_SIZE = 256
    MAX_VALUE_SIZE = 256

def handle_publish(packet):
    topic = parse_topic(packet)
    payload = parse_payload(packet)
    properties = parse_properties(packet)

    # VALIDATION LAYER
    if len(properties) > PropertyValidator.MAX_PROPERTIES:
        # REJECT entire packet - don't process
        return ERROR_PACKET_REJECTED

    for property in properties:
        if len(property.key) > PropertyValidator.MAX_KEY_SIZE:
            return ERROR_INVALID_PROPERTY
        if len(property.value) > PropertyValidator.MAX_VALUE_SIZE:
            return ERROR_INVALID_PROPERTY

        store_in_memory(property)  # Now safe

    deliver_to_subscribers(topic, payload)
```

**Attack Success**: NO

- Broker rejects packet with 1000 properties (limit: 20)
- Attack packet never enters memory
- Broker remains stable
- Normal packets (≤20 properties) work fine

#### Option 2: CLIENT-SIDE VALIDATION (Client validates before sending)

```python
# PROTECTED CODE - Client validates before sending
class ClientValidator:
    MAX_PROPERTIES = 20
    MAX_KEY_SIZE = 256
    MAX_VALUE_SIZE = 256

def publish(topic, payload, user_properties):
    # VALIDATION BEFORE CREATING PACKET
    if len(user_properties) > ClientValidator.MAX_PROPERTIES:
        raise ValueError("Too many properties")  # Reject at source

    packet = bytearray()

    for key, value in user_properties:
        if len(key) > ClientValidator.MAX_KEY_SIZE:
            raise ValueError("Key too large")  # Reject at source
        if len(value) > ClientValidator.MAX_VALUE_SIZE:
            raise ValueError("Value too large")  # Reject at source

        # Only add valid properties to packet
        packet.add_property(key, value)

    # Send ONLY validated packet
    send_to_broker(packet)
```

**Attack Success**: NO

- Validation blocks creation of attack packet
- Attack packet never sent
- Broker never sees it
- Normal packets created and sent normally

---

## Part 3: The Test Suite Architecture

### What Should Happen

```
VULNERABLE VERSION:
┌─────────────────────────────┐
│ Normal packets (5 packets)  │ → Accepted ✓ → Broker
│ Total: 10 properties        │
└─────────────────────────────┘
                ↓
┌─────────────────────────────┐
│ Attack packets (20 packets) │ → Accepted ✓ (VULNERABILITY!)
│ Each: 1000 properties       │
│ Each: 10KB per property     │ → Broker memory EXPLODES
│ Total: 10MB+ per packet     │ → After 100 packets = 1GB used
│ After 1000 packets = 10GB   │ → BROKER CRASHES OOM
└─────────────────────────────┘

CSV Results (Vulnerable):
iteration,attack_severity,packets_handled,cpu_before,cpu_after,mem_kb
1,50,5,0.0,0.1,8028
2,100,10,0.1,0.2,9512  ← Memory growing
3,150,15,0.2,0.3,11096  ← Growing more
...
10,500,50,1.5,2.0,25600  ← Really growing
...
20,1000,100,5.0,8.0,102400  ← CRASH INCOMING

PROTECTED VERSION:
┌─────────────────────────────┐
│ Normal packets (5 packets)  │ → Validation PASSES ✓ → Sent ✓
│ Total: 10 properties        │ → Accepted by broker ✓
└─────────────────────────────┘
                ↓
┌─────────────────────────────┐
│ Attack packets (20 attempts)│ → Validation FAILS ✗
│ Each: 1000+ properties      │ → Not sent
│ Each: 10KB+ per property    │ → Never reaches broker
│ Result: 0 reach broker      │ → Memory stable
└─────────────────────────────┘

CSV Results (Protected):
iteration,attack_severity,packets_handled,cpu_before,cpu_after,mem_kb
1,50,5,0.0,0.1,8028
2,100,5,0.1,0.1,8028
3,150,5,0.1,0.1,8028
...
10,500,5,0.1,0.1,8028
...
20,1000,5,0.1,0.1,8028

Key Insight: Protected version always sends 5 (normal only),
Vulnerable grows to 100+, memory grows significantly
```

---

## Part 4: Correct Implementation

### Attack Client - What It Should Do

```python
def attack_vulnerable_mqtt():
    """
    Send mix of normal + attack packets to test vulnerability.
    """
    broker = connect_mqtt()

    # Phase 1: Normal baseline
    for i in range(5):
        packet = create_publish(
            topic="test/baseline",
            payload=f"msg_{i}",
            properties={  # Normal amount
                f"key_{i}": f"value_{i}"
            }
        )
        broker.send(packet)  # All 5 should succeed

    # Phase 2: Attack phase
    for i in range(100):
        packet = create_publish(
            topic="test/attack",
            payload=f"attack_{i}",
            properties={  # MASSIVE
                f"prop_{j}": "X" * 10000  # 10KB values
                for j in range(1000)  # 1000 properties!
            }
        )
        try:
            broker.send(packet)
            packets_sent += 1  # Track success
        except BrokenPipeError:
            # Broker crashed
            break

    return packets_sent
```

**Expected CSVResult:**

```
Normal packets: 5-10 sent (all succeed)
Attack packets: 50+ sent (broker gradually degrades, then crashes)
Total sent: 55-100+ packets
Memory growth: 8MB → 50MB+ → OOM
```

### Safe Client - What It Should Do

```python
def safe_mqtt_client():
    """
    Validate before sending. Rejects oversized properties.
    """
    broker = connect_mqtt()

    # Phase 1: Normal packets
    for i in range(5):
        packet = create_publish(
            topic="test/baseline",
            payload=f"msg_{i}",
            properties={f"key_{i}": f"value_{i}"}
        )
        # Validate passed, send it
        broker.send(packet)

    # Phase 2: Attack attempts
    packets_sent = 0
    for i in range(100):
        try:
            packet = create_publish(
                topic="test/attack",
                payload=f"attack_{i}",
                properties={
                    f"prop_{j}": "X" * 10000  # TOO LARGE
                    for j in range(1000)  # TOO MANY
                }
            )
        except ValueError as e:
            # Validation BLOCKED packet creation
            # "Property value too large: 10000 > 256"
            # "Too many properties: 1000 > 20"
            continue  # Try next (all will fail)

        broker.send(packet)  # Never reaches here for attacks
        packets_sent += 1

    return packets_sent
```

**Expected CSV Result:**

```
Normal packets: 5 sent (all succeed, pass validation)
Attack packets: 0 sent (all fail validation, never created)
Total sent: 5 packets
Memory growth: 8MB → stay at 8MB (blocked at validation)
```

---

## Part 5: Why Current Test Failed

### Issue 1: Attack Using mosquitto_pub

```bash
# Current code tries this:
mosquitto_pub -m "huge_payload" ...

# Problem: mosquitto_pub doesn't support custom MQTT properties!
# It's a generic pubseub tool, not MQTT 5.0 property-aware
# It just sends the message payload, not extended properties
```

**Fix**: Use proper MQTT library or raw socket with MQTT protocol

### Issue 2: Protected Version Rejecting ALL

```python
# Current code does this WRONG:
if num_properties > MAX:
    raise ValueError()  # Rejects before sending

# Results in: 0 packets sent (blocks normal too)
```

**Fix**: Only reject if validation FAILS

The correct logic:

```python
# CORRECT: Only reject if exceeds limits
if num_properties > 20:
    raise ValueError()  # Block
else:
    send_packet()  # Send (passes validation)
```

---

## Part 6: What Should Be Done

### Option 1: Use paho-mqtt library

```bash
pip install paho-mqtt
```

```python
import paho.mqtt.client as mqtt

# Client automatically handles MQTT protocol
client = mqtt.Client()
client.connect("localhost", 8883)

# Can access MQTT 5.0 properties
client.publish(
    topic="test",
    payload="msg",
    properties=mqtt.MQTTv5Properties(
        user_properties=[
            ("key1", "value1"),
            ("key2", "value2"),
            # ... add 1000+ properties here for attack
        ]
    )
)
```

**Advantage**: Handles all MQTT protocol details
**Disadvantage**: Might not allow creating "bad" packets (validation built-in)

### Option 2: Raw MQTT Protocol

Need proper implementation of:

1. MQTT CONNECT packet (establish connection)
2. MQTT PUBLISH packet with properties
3. Proper variable-length encoding
4. Proper TLS/PSK setup

This is what the `attack_client_real.py` and `safe_client_real.py` were attempting.

### Option 3: Simulation Approach (What We Should Do)

```python
# Don't actually send impossible packets
# Instead, measure what WOULD happen

def simulate_attack():
    """
    Demonstrate vulnerability without needing perfect MQTT impl.
    """
    # Calculate packet size for attack
    properties_per_packet = 1000
    property_value_size = 10000

    packet_size_mb = (properties_per_packet * property_value_size) / (1024 * 1024)
    # Result: 10MB per packet

    # If broker accepts packets without limits
    packets_to_crash = 102400 / packet_size_mb
    # Result: ~10 packets would exhaust 100MB

    # Memory over time
    for i in range(100):
        memory_used = (i * packet_size_mb) + baseline
        if memory_used > physical_memory:
            print("BROKER CRASHED after", i, "packets")
            break
```

---

## Part 7: Key Learnings

### What You Were Right About

✅ **Attack wasn't actually reaching broker** - Current implementation was just going through motions
✅ **Protected version rejecting ALL** - Logic was backwards (reject valid, not invalid)
✅ **Need proper thinking** - Yes, need to understand the layers:

- Client validation layer
- Network transport layer
- Broker reception layer
- Broker processing layer

Each can have checks!

### The Correct Architecture

```
ATTACK FLOW:
┌──────────────────────────────┐
│ Attacker crafts malicious    │
│ MQTT packet with 1000        │
│ properties, 10KB each        │
└──────────────────────────────┘
            ↓
┌──────────────────────────────┐
│ CLIENT LAYER:                │
│ ✗ If validation enabled      │
│   → Block at source          │
│ ✓ If no validation           │
│   → Send to broker           │
└──────────────────────────────┘
            ↓
┌──────────────────────────────┐
│ NETWORK (TLS/PSK)            │
│ Packet is encrypted/secure   │
└──────────────────────────────┘
            ↓
┌──────────────────────────────┐
│ BROKER RECEPTION:            │
│ ✗ If limits enabled          │
│   → Reject packet            │
│ ✓ If no limits               │
│   → Parse and process        │
└──────────────────────────────┘
            ↓
┌──────────────────────────────┐
│ BROKER PROCESSING:           │
│ Properties stored in memory  │
│ 10MB/packet → exponential    │
│ growth → memory exhaustion   │
│ → OOM crash                  │
└──────────────────────────────┘
```

### Best Practices

**Defense in Depth:**

1. **Client Side**: Validate property sizes before sending
2. **Network Layer**: TLS ensures authenticity (harder to spoof huge packets)
3. **Broker Input**: Validate on reception
4. **Broker Processing**: Memory limits per connection
5. **Monitoring**: Alert on unusual patterns

---

## Conclusion

The vulnerability is real and critical:

| Scenario                   | Risk     | Impact                         | Solution                         |
| -------------------------- | -------- | ------------------------------ | -------------------------------- |
| **No protection**          | CRITICAL | Broker crash after few packets | Add limits                       |
| **Client validation only** | MEDIUM   | Malicious clients bypass       | + Broker validation              |
| **Broker validation only** | LOW      | Prevents memory exhaustion     | Sufficient for untrusted clients |
| **Both**                   | MINIMAL  | Defense in depth               | Best practice                    |

Recommended limits:

- **Max properties per packet**: 20
- **Max key size**: 256 bytes
- **Max value size**: 256 bytes
- **Max packet size**: 50KB
- **Per-connection memory budget**: 1MB
