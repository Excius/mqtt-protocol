# User Property Injection Attack - Implementation Patterns

## Attack Pattern vs Protection Pattern

### Pattern 1: Vulnerable MQTT Broker

**Code:**

```python
# VULNERABLE - No property validation
class VulnerableMQTTBroker:
    def handle_publish_packet(self, publisher_id, packet):
        """Process PUBLISH packet with NO property limits."""

        # Parse packet
        topic = packet.extract_topic()
        payload = packet.extract_payload()
        properties = packet.extract_properties()

        # Store ALL properties - no validation!
        for prop in properties:
            key = prop.key      # No size check!
            value = prop.value  # No size check!

            # Direct storage - memory grows unbounded
            self.message_store[publisher_id].append({
                'key': key,      # Can be 100MB
                'value': value   # Can be 100MB
            })

        # Deliver message
        self.deliver_to_subscribers(topic, payload)

        return SUCCESS
```

**Attack Packet:**

```
MQTT PUBLISH Packet:
├─ Topic: "test/attack"
├─ Payload: "BOO"
└─ User Properties:
   ├─ property_0: key="k0", value="V" * 10000000  (10MB)
   ├─ property_1: key="k1", value="V" * 10000000  (10MB)
   ├─ property_2: key="k2", value="V" * 10000000  (10MB)
   ├─ ... (1000 properties × 10MB = 10GB!)
```

**Memory Impact:**

```
Baseline: 8 MB
After packet 1: 8 + 10GB = 10GB
After packet 2: 10GB + 10GB = 20GB  ← OOM Kill
```

**Result:** 🔴 BROKER CRASHES (OOM)

---

### Pattern 2: Protected MQTT Broker (Server-Side Limits)

**Code:**

```python
# PROTECTED - Server enforces limits
class ProtectedMQTTBroker:
    # Configuration
    MAX_USER_PROPERTIES = 20
    MAX_KEY_SIZE = 256  # bytes
    MAX_VALUE_SIZE = 256  # bytes
    MAX_PACKET_SIZE = 65536  # 64KB

    def handle_publish_packet(self, publisher_id, packet):
        """Process PUBLISH packet WITH validation."""

        # Parse packet
        topic = packet.extract_topic()
        payload = packet.extract_payload()
        properties = packet.extract_properties()

        # === VALIDATION LAYER ===

        # Check 1: Total property count
        if len(properties) > self.MAX_USER_PROPERTIES:
            return REJECT(
                reason="Too many properties",
                detail=f"{len(properties)} > {self.MAX_USER_PROPERTIES}"
            )

        # Check 2: Total packet size
        if len(packet.raw_bytes) > self.MAX_PACKET_SIZE:
            return REJECT(
                reason="Packet too large",
                detail=f"{len(packet.raw_bytes)} > {self.MAX_PACKET_SIZE}"
            )

        # Check 3: Each property's size
        for i, prop in enumerate(properties):
            key_size = len(prop.key.encode('utf-8'))
            value_size = len(prop.value.encode('utf-8'))

            if key_size > self.MAX_KEY_SIZE:
                return REJECT(
                    reason=f"Property {i} key too large",
                    detail=f"{key_size} > {self.MAX_KEY_SIZE}"
                )

            if value_size > self.MAX_VALUE_SIZE:
                return REJECT(
                    reason=f"Property {i} value too large",
                    detail=f"{value_size} > {self.MAX_VALUE_SIZE}"
                )

            # All checks passed - store it
            self.message_store[publisher_id].append({
                'key': key_size,    # Max 256 bytes
                'value': value_size # Max 256 bytes
            })

        # Deliver message
        self.deliver_to_subscribers(topic, payload)

        return SUCCESS
```

**Attack Packet (Same as Above):**

```
MQTT PUBLISH Packet:
├─ Topic: "test/attack"
├─ Payload: "BOO"
└─ User Properties: (1000 properties)
```

**Validation Result:**

```
Check 1: len(properties) = 1000 > MAX_USER_PROPERTIES (20)
         → REJECT with reason "Too many properties"
         → Packet discarded
         → Zero memory impact
```

**Memory Impact:**

```
Baseline: 8 MB
After rejection: 8 MB (no change!)  ← Still safe
After 1000 attack packets: 8 MB     ← Completely unaffected
```

**Result:** 🟢 ATTACK BLOCKED, BROKER SAFE

---

### Pattern 3: Protected MQTT Client (Client-Side Validation)

**Code:**

```python
# PROTECTED - Client validates before creating packet
class SafeMQTTPublisher:
    # Configuration
    MAX_USER_PROPERTIES = 20
    MAX_KEY_SIZE = 256  # bytes
    MAX_VALUE_SIZE = 256  # bytes

    def publish(self, topic, payload, user_properties):
        """
        Publish to broker with validation.
        Raises ValueError if properties exceed limits.
        """

        # === CLIENT-SIDE VALIDATION ===

        # Validate property count
        if len(user_properties) > self.MAX_USER_PROPERTIES:
            raise ValueError(
                f"Too many properties: {len(user_properties)} > {self.MAX_USER_PROPERTIES}"
            )

        # Validate each property
        validated_properties = []
        for key, value in user_properties.items():
            # Check key size
            key_bytes = key.encode('utf-8')
            if len(key_bytes) > self.MAX_KEY_SIZE:
                raise ValueError(
                    f"Property key too large: {len(key_bytes)} > {self.MAX_KEY_SIZE}"
                )

            # Check value size
            value_bytes = value.encode('utf-8')
            if len(value_bytes) > self.MAX_VALUE_SIZE:
                raise ValueError(
                    f"Property value too large: {len(value_bytes)} > {self.MAX_VALUE_SIZE}"
                )

            # Validation passed - add to packet
            validated_properties.append((key, value))

        # === PACKET CREATION (only after validation) ===
        packet = self.create_mqtt_publish_packet(
            topic=topic,
            payload=payload,
            properties=validated_properties  # Only validated ones
        )

        # Send packet
        self.broker_connection.send(packet)

        return True
```

**When Attacker Tries to Use:**

```python
# Attacker tries:
publisher.publish(
    topic="test/attack",
    payload="BOO",
    user_properties={
        f"prop_{i}": "V" * 10000000  # 10MB value
        for i in range(1000)  # 1000 properties
    }
)

# Validation catches it immediately:
# ValueError: Too many properties: 1000 > 20
# (Packet never created, never sent!)
```

**Result:** 🟢 ATTACK BLOCKED AT SOURCE

---

## Side-by-Side Comparison

### Normal Packet (Valid in All Modes)

```
Packet:
├─ Topic: "sensor/temperature"
├─ Payload: "23.5"
└─ Properties (5 total):
   ├─ "location": "room-1"
   ├─ "timestamp": "2026-03-07T21:42:00Z"
   ├─ "unit": "celsius"
   ├─ "accuracy": "±0.5"
   └─ "sensor_id": "DHT22-001"

Vulnerable Broker:
├─ Receives: ✓ (no validation)
├─ Stores: ✓ ALL 5 properties
└─ Result: SUCCESS

Protected Broker:
├─ Check count: 5 ≤ 20? ✓
├─ Check sizes: All ≤ 256? ✓
├─ Result: SUCCESS ✓

Safe Client:
├─ Count: 5 ≤ 20? ✓
├─ Sizes: All ≤ 256? ✓
├─ Creates packet: ✓
└─ Sends: ✓
```

### Attack Packet (Large Properties)

```
Packet:
├─ Topic: "test/attack"
├─ Payload: "BOO"
└─ Properties (1000 total):
   ├─ "prop_0": "V" * 1000000  (1MB)
   ├─ "prop_1": "V" * 1000000  (1MB)
   ├─ ... 1000 more
   └─ Total: ~1GB

Vulnerable Broker:
├─ Receives: ✓ (no validation!)
├─ Tries to store: ALL 1GB
├─ Memory impact: +1GB
├─ After 10 packets: 10GB used
☑→ Result: CRASH (OOM)

Protected Broker:
├─ Check count: 1000 ≤ 20? ✗ FAIL
├─ Validation rejects: ✓
├─ Memory impact: 0KB
└─ Result: REJECTED ✓

Safe Client:
├─ Count: 1000 ≤ 20? ✗ FAIL
├─ Raises ValueError: ✓
├─ Packet never created: ✓
├─ Never sent to broker: ✓
└─ Result: BLOCKED AT SOURCE ✓
```

---

## Implementation Requirements

### To Simulate Real Attack (What Code Should Do)

```python
# ACTUAL attack that would work against vulnerable broker
def real_mqtt_property_attack():
    # Use real MQTT library that supports MQTT 5.0
    import paho.mqtt.client as mqtt

    client = mqtt.Client(protocol=mqtt.MQTTv311)  # Need 5.0!
    client.connect("vulnerable-broker.example.com", 8883)

    # Create attack properties
    attack_props = mqtt.MQTTv5Properties()

    # Add 1000 huge properties
    for i in range(1000):
        attack_props.add_user_property(
            key=f"prop_{i}",
            value="X" * 10000000  # 10MB each
        )

    # Send attack packet
    # Each send: 10GB packet
    # Broker attempts to process → memory explosion

    info = client.publish(
        topic="test/attack",
        payload="ATTACK",
        properties=attack_props
    )

    # Expected: Broker disconnects/crashes after few packets
```

### To Defend (What Broker Should Do)

```python
# In Mosquitto config or equivalent:
[mqtt_5_0_limits]
max_user_properties = 20        # Limit properties per packet
max_property_key_bytes = 256    # Limit key size
max_property_value_bytes = 256  # Limit value size
max_packet_bytes = 65536        # Total packet size limit

# In broker code:
if number_of_properties > max_user_properties:
    reject_packet()
if any_key_size > max_property_key_bytes:
    reject_packet()
if any_value_size > max_property_value_bytes:
    reject_packet()
if total_packet_size > max_packet_bytes:
    reject_packet()
```

---

## Why This Matters

### Memory Growth Graph (Vulnerable vs Protected)

```
Memory Usage Over Time:

VULNERABLE MQTT (No Limits):
┌─────────────────────────────────
│                          X (CRASH)
│                        /
│                      /
│                    /
│                  /
│                /
│              /
│            /
│          /
│    ______/
└─────────────────────────────────
  0  10  20  30  40  50  60  70  80
           Packets Sent

Memory used: 8MB → 100MB → 1GB → OOM

PROTECTED MQTT (With Limits):
┌─────────────────────────────────
│ ────────────────────────────────
│ (Flat line - stays at baseline)
│
│ ────────────────────────────────
│
└─────────────────────────────────
  0  10  20  30  40  50  60  70  80
           Packets Sent

Memory used: 8MB → 8.1MB → 8.1MB → stable
```

### CPU Impact

```
Validation overhead:
- Count check: O(1)   - instantaneous
- Size checks: O(n)   - linear in property count
- For 1000 properties: ~1ms validation time

But: Prevents crash that would waste hours of debugging
Trade-off: 1ms validation cost vs. 100% stability = EXCELLENT

Normal operation (20 properties):
- Normal validation: <0.1ms
- No performance impact
```

---

## Testing Strategy

### What Each CSV Should Show

**results_vulnerable.csv:**

```
iteration,attack_severity,packets_handled,cpu_before,cpu_after,mem_kb
1,50,5,0.0,0.1,8028      ← Normal packets + few attacks
2,100,10,0.1,0.2,9512    ← Memory growing
3,150,15,0.2,0.3,11096   ← Growing faster
...
10,500,50,1.5,2.0,25600  ← Significant growth
...
15,750,75,3.0,4.0,51200  ← Even more
...
20,1000,100,5.0,8.0,102400 ← Too much!
         ↑ Memory exhausted
```

Interpretation:

- Early iterations: Accepts 5-10 packets (baseline)
- Middle iterations: Growing to 30-50 packets
- Late iterations: Might start rejecting or hanging
- Memory growth: Clear exponential growth

**results_protected.csv:**

```
iteration,attack_severity,packets_handled,cpu_before,cpu_after,mem_kb
1,50,5,0.0,0.1,8028    ← Only normal packets
2,100,5,0.1,0.1,8028   ← Still 5 (attacks rejected)
3,150,5,0.1,0.1,8028   ← Still 5
...
10,500,5,0.1,0.1,8028  ← Always 5
...
15,750,5,0.1,0.1,8028  ← Always 5
...
20,1000,5,0.1,0.1,8028 ← Still 5!
       ↑ Consistent, safe
```

Interpretation:

- All iterations: Consistently 5 packets (only valid ones)
- Attack packets: Rejected by validation
- Memory: Flat line (no impact)
- CPU: Slightly higher (validation overhead) but still minimal

---

## Key Takeaways

1. **Vulnerability is real**: Unlimited properties = unlimited memory consumption
2. **Attack is simple**: Send large properties, broker crashes
3. **Protection is straightforward**: Enforce limits in 4 places (count, key, value, total)
4. **Defense in depth works**: Client + Broker validation = most robust
5. **Testing shows the difference**: Exponential growth vs. flat line (obvious in graphs)

Remember: **A properly implemented attack clearly shows unbounded growth, while properly protected broker stays flat regardless of attack severity.**
