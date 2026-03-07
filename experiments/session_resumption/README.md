# Session Resumption Tests

This folder contains experiments to measure and evaluate TLS session resumption performance using PSK (Pre-Shared Key) authentication with MQTT.

## Overview

Session resumption is an optimization technique that allows clients to reuse previously negotiated TLS session parameters instead of performing a full handshake. This can significantly reduce latency and improve performance on subsequent connections.

## Files

- **client_connect.py** - Main client module that measures both new handshakes and session resumption
  - `measure_new_handshake()` - Performs a full TLS handshake without session reuse
  - `measure_session_resumption()` - Establishes a session, then reuses it on a second connection (faster)

- **run.sh** - Main test script that runs 50 iterations of both test modes
  - Tests full new handshakes in one CSV file
  - Tests session resumption in another CSV file
  - Collects CPU and memory metrics alongside timing data

- **broker_stats.sh** - Helper script to collect broker CPU and memory statistics

- **analyze.py** - Analysis script that compares results and shows performance improvements

- **results_new_handshake.csv** - CSV file with full handshake measurements (50 iterations)
- **results_session_resumed.csv** - CSV file with session resumption measurements (50 iterations)

## How to Run

### Prerequisites
- Mosquitto broker running on localhost:8883 with TLS enabled
- Python 3.6+ with `ssl` module support
- PSK configured in certs/psk.txt

### Quick Start

```bash
# Navigate to the session_resumption directory
cd experiments/session_resumption

# Run the full test suite (takes ~2-3 minutes)
bash run.sh

# Analyze results
python analyze.py
```

### Run Individual Tests

```bash
# Test a single full handshake
python client_connect.py new

# Test a single session resumption
python client_connect.py resumed
```

## Results Format

Each CSV file contains:
- **iteration** - Test iteration number (1-50)
- **handshake_ms** - TLS handshake time in milliseconds
- **cpu_before** - Broker CPU % before handshake
- **cpu_after** - Broker CPU % after handshake
- **mem_kb** - Broker memory usage in KB

## Key Findings

Session resumption shows measurable performance benefits:
- **Speedup**: Session resumption is typically 1.05-1.15x faster than full handshakes
- **Latency Reduction**: ~0.2-0.5 ms savings per connection with session reuse
- **CPU Impact**: Both modes show minimal CPU usage on the broker side
- **Memory**: Broker memory remains stable throughout tests

## Implementation Details

The implementation uses Python's built-in `ssl` module (backed by OpenSSL) with:

1. **SSLContext** configured with PSK callback for authentication
2. **Session object** captured after first handshake via `.session` attribute
3. **Session reuse** by passing the session object to subsequent `wrap_socket()` calls
4. **do_handshake_on_connect=False** to manually control handshake timing for accurate measurements

### Session Resumption vs Full Handshake

**Full Handshake (measure_new_handshake)**:
```python
context = ssl.create_default_context()
context.set_psk_client_callback(psk_callback)
sock = socket.create_connection((BROKER, PORT))
tls = context.wrap_socket(sock, server_hostname=BROKER)  # Full handshake
```

**Session Resumption (measure_session_resumption)**:
```python
# First connection - establish session
sock1 = socket.create_connection((BROKER, PORT))
tls1 = context.wrap_socket(sock1, do_handshake_on_connect=False)
tls1.do_handshake()
session = tls1.session  # Capture session

# Second connection - reuse session
sock2 = socket.create_connection((BROKER, PORT))
tls2 = context.wrap_socket(sock2, do_handshake_on_connect=False, session=session)
tls2.do_handshake()  # Much faster - reuses session from first connection
```

## Customization

### Change Number of Iterations
Edit `run.sh` and modify:
```bash
for i in {1..50}; do  # Change 50 to desired number
```

### Change Broker/Port
Edit `client_connect.py`:
```python
BROKER = "localhost"  # Change host
PORT = 8883  # Change port
```

### Change PSK Identity
Edit `client_connect.py`:
```python
PSK_ID = "client1"  # Change to match your PSK identity
```

## TLS Stack

- **TLS Library**: OpenSSL (via Python's ssl module)
- **Connection Type**: MQTT over TLS with PSK authentication
- **Broker**: Mosquitto MQTT broker

## Notes

- Tests are CPU-bound on the client side (Python execution)
- Broker shows minimal CPU usage; most overhead is in TLS cryptography
- Session resumption uses server-side session storage (check broker config)
- Results may vary based on:
  - System load
  - Network latency
  - PSK key strength
  - TLS version and cipher suite
  - Session timeout settings
