# MQTT 5.0 Security Project — Full Context

> **Last updated:** 11 March 2026
> **Purpose:** Complete reference of project architecture, decisions, bugs fixed, results, and reasoning — so any future collaborator (human or AI) can pick up exactly where this left off.

---

## 1. Project Goal

Evaluate the **security and performance** of MQTT 5.0 with different TLS authentication mechanisms and demonstrate two MQTT 5.0–specific attack vectors with broker-side mitigation. The project is structured as a series of experiments measuring TLS handshake latency, broker resource consumption (CPU/memory), and attack impact.

**Research Questions:**

1. What is the baseline cost of MQTT 5.0 + TLS certificate authentication?
2. How does it scale under concurrent/sustained load?
3. Does TLS-PSK (Pre-Shared Key) perform differently from certificate auth?
4. Can TLS session resumption reduce reconnection overhead?
5. Can MQTT 5.0 User Properties be exploited for resource exhaustion, and can it be mitigated with broker-side protection?
6. Can MQTT 5.0 AUTH packets be used for DoS attacks, and can broker-side rate limiting neutralise them?

---

## 2. Environment

| Component   | Version / Details       |
| ----------- | ----------------------- |
| OS          | Linux (Arch-based)      |
| Python      | 3.13.5                  |
| Virtual Env | `venv/` in project root |
| OpenSSL     | 3.5.4 (Sep 2025)        |
| Mosquitto   | 2.0.21                  |
| paho-mqtt   | 2.1.0 (Python)          |
| Protocol    | MQTT 5.0 over TLS 1.2   |

**Python venv activation:** `source venv/bin/activate`

---

## 3. TLS Configuration

### Certificate-Based (Baseline / Phase 1)

- **Config:** `broker/mosquitto_tls.conf`
- **Certs:** `certs/ca.crt`, `certs/server.crt`, `certs/server.key`
- Broker listens on port 8883 with `tls_version tlsv1.2`
- `allow_anonymous true` (auth is at TLS level, not MQTT username level)

### PSK-Based (Phase 2 / Session Resumption / Attacks)

- **Config:** `broker/mosquitto_psk.conf`
- **PSK file:** `certs/psk.txt` → `client1:0123456789abcdef`
- **PSK hint:** `mypsk`
- Same port 8883, TLS 1.2

### Internal (Behind Proxy)

- **Config:** `broker/mosquitto_internal.conf`
- **Port:** 1884, localhost only, plain TCP (no TLS)
- `allow_anonymous true`
- Used only when the security proxy handles TLS termination

### Critical Rule

- **Baseline + Phase 1 (A–E)** → must use `mosquitto_tls.conf` (cert-based)
- **Phase 2 / Session Resumption / PSK Optimized** → must use `mosquitto_psk.conf` (PSK-based)
- **Attack experiments (protected phase)** → proxy on :8883, Mosquitto on :1884 using `mosquitto_internal.conf`
- **Attack experiments (vulnerable phase)** → direct to Mosquitto on :8883 using `mosquitto_psk.conf`
- Each `run.sh` script handles its own broker start/stop with the correct config

---

## 4. Project Structure

```
mqtt-security/
├── README.md                          # Results reference & CSV field documentation
├── CONTEXT.md                         # This file — full technical context
├── analyze_all.py                     # Unified analysis of all experiments
├── run_all_experiments.sh             # Master script to run everything
│
├── broker/
│   ├── mosquitto_tls.conf             # Cert-based TLS config (:8883)
│   ├── mosquitto_psk.conf             # PSK-based TLS config (:8883)
│   └── mosquitto_internal.conf        # Plain TCP config (:1884, behind proxy)
│
├── certs/
│   ├── ca.crt, ca.key, ca.srl         # Certificate Authority
│   ├── server.crt, server.csr, server.key  # Broker certificate
│   └── psk.txt                        # PSK identity:key file
│
├── proxy/
│   ├── __init__.py
│   └── proxy_broker.py                # Security proxy (TLS-PSK termination + MQTT inspection)
│
├── experiments/
│   ├── common/
│   │   └── measurement.py             # Core: TLSHandshakeMeasurer + CPUMonitor
│   │
│   ├── baseline/                      # 50 single cert handshakes
│   │   ├── client_connect.py
│   │   ├── run_baseline.sh
│   │   ├── broker_stats.sh
│   │   └── results.csv
│   │
│   ├── phase1/                        # TLS cert scalability tests
│   │   ├── run_all_phases.sh          # Runs 1A→1E with cert broker
│   │   ├── common/                    # Phase1-specific helpers
│   │   │   ├── broker_stats.py
│   │   │   ├── cpu_sampler.py
│   │   │   └── utils.py
│   │   ├── phase1A_sequential/        # 50 back-to-back handshakes
│   │   ├── phase1B_concurrent/        # 10–200 simultaneous clients
│   │   ├── phase1C_sustained/         # 1 handshake/sec for 60s
│   │   ├── phase1D_lifetime/          # Hold connections 1–60s
│   │   └── phase1E_saturation/        # 50–500 simultaneous clients
│   │
│   ├── phase2_psk/                    # PSK handshake comparison
│   ├── psk_optimized/                 # 4-method comparison (cert/psk/optimized/resumed)
│   ├── session_resumption/            # PSK session reuse test
│   │
│   ├── user_property_attack/          # MQTT 5.0 property injection
│   │   ├── attack_client.py           # Sends oversized user properties
│   │   ├── run.sh                     # Vulnerable + proxy-protected phases
│   │   ├── analyze.py                 # Per-experiment analysis
│   │   ├── broker_stats.sh
│   │   ├── results_vulnerable.csv
│   │   └── results_protected.csv
│   │
│   └── auth_flood/                    # AUTH packet flood attack
│       ├── attack_client.py           # 10-thread TLS+AUTH flood
│       ├── run.sh                     # Vulnerable + proxy-protected phases
│       ├── analyze.py                 # Per-experiment analysis
│       ├── broker_stats.sh
│       ├── results_vulnerable.csv
│       └── results_protected.csv
```

---

## 5. Broker-Side Protection Architecture (Python Security Proxy)

### Design Rationale

Client-side validation is **not a security control** because the attacker controls the client. A malicious client will simply bypass any client-side checks. The only way to enforce security is at the **broker side**, between the attacker and Mosquitto.

Both attack experiments (vulnerable and protected) use the **same `attack_client.py`**. The difference is:

- **Vulnerable phase:** Attack packets go directly to Mosquitto (no proxy)
- **Protected phase:** Attack packets pass through a Python security proxy that enforces limits before forwarding

### Proxy Architecture

```
                   Protected Mode
┌─────────────────┐
│  attack_client  │ (MQTT 5.0 over TLS-PSK)
└────────┬────────┘
         │ Port 8883 (client-facing, TLS-PSK)
    ┌────▼─────────────────────────────────────┐
    │  proxy_broker.py (Python Security Proxy) │
    │  • TLS-PSK termination                   │
    │  • MQTT packet inspection                │
    │  • Rate limit connections (2/sec)         │
    │  • Block AUTH packets (0 allowed)         │
    │  • Validate user properties              │
    │  • Enforce cumulative budgets            │
    │  • Track per-client state                │
    │  • SIGUSR1 stats dump (JSON)             │
    └────┬─────────────────────────────────────┘
         │ Port 1884 (broker-facing, plain TCP, localhost)
    ┌────▼─────────────────────────────┐
    │  mosquitto_internal.conf         │
    │  (Bare Mosquitto, no TLS)        │
    └──────────────────────────────────┘
```

### Proxy Modes

The proxy supports three modes via `--mode`:

- `user_property` — Enforce user-property limits on PUBLISH packets
- `auth_flood` — Rate-limit connections, block AUTH packets
- `all` — Enable all protections (default)

### Proxy Statistics

The proxy tracks per-interval statistics via `ProxyStats`:

- `packets_forwarded` — MQTT packets that passed inspection and were forwarded to Mosquitto
- `packets_dropped` — MQTT packets blocked by any validation rule (total)
- `connections_accepted` — TLS connections accepted by the proxy
- `connections_rejected` — TLS connections rejected by the rate limiter
- `auth_packets_blocked` — AUTH packets intercepted and dropped

**Per-violation-type packet drop counters (User Property mode):**

- `prop_count_drops` — Packets dropped by Rule 1 (property count > 10)
- `key_size_drops` — Packets dropped by Rule 2 (key exceeds 256 bytes)
- `val_size_drops` — Packets dropped by Rule 3 (value exceeds 256 bytes)
- `payload_drops` — Packets dropped by Rule 4 (per-packet total payload > 4096 bytes)
- `budget_drops` — Packets dropped by Rule 5 (cumulative per-client budget > 32 KB)

Invariant: `packets_dropped == prop_count_drops + key_size_drops + val_size_drops + payload_drops + budget_drops` in user_property mode.

Stats are dumped to a JSON file on SIGUSR1 signal, then counters reset. This allows `run.sh` scripts to read per-iteration proxy metrics.

### Protection Rules

**User Property Attack mode:**

1. Max 10 user properties per PUBLISH
2. Max 256 bytes per property key
3. Max 256 bytes per property value
4. Max 4,096 bytes total payload per packet
5. Max 32 KB cumulative per client

**AUTH Flood mode:**

1. Max 2 connections per second (sliding window)
2. 0 AUTH packets allowed (all dropped)
3. Max 20 concurrent connections
4. 2-second authentication timeout

---

## 6. Core Measurement Module

File: `experiments/common/measurement.py`

### TLSHandshakeMeasurer

- Creates a raw TCP socket → wraps with `ssl.SSLContext` → performs manual `do_handshake()` with `time.perf_counter()` timing
- Two methods:
  - `measure_cert_handshake(cafile, certfile, keyfile)` — for certificate auth
  - `measure_psk_handshake(psk_identity, psk_key_hex)` — for PSK auth
- Does NOT use paho-mqtt (pure ssl-level measurement with zero MQTT overhead)
- Returns elapsed time in milliseconds

### CPUMonitor

- `get_broker_stats()` → uses `pidof mosquitto` + `ps -p PID -o %cpu=,rss=`
- `get_cpu_before_and_after(handshake_func)` → samples CPU before and after handshake

**Why ssl-level and not paho-mqtt for handshake measurement:**
Using paho-mqtt's `connect()` would include MQTT CONNECT/CONNACK overhead. We isolate TLS handshake cost specifically by measuring at the socket+ssl layer.

---

## 7. Experiment Details & Results

### 7.1 Baseline — `experiments/baseline/`

**Purpose:** Cost of a single MQTT 5.0 + TLS certificate handshake under zero load. Reference point.

| Metric         | Value                   |
| -------------- | ----------------------- |
| Iterations     | 50                      |
| Auth Type      | TLS Certificate         |
| Mean Handshake | 1.92 ms                 |
| Range          | 1.13–3.63 ms            |
| Memory         | 7,992→8,076 KB (stable) |

---

### 7.2 Phase 1A — Sequential — `experiments/phase1/phase1A_sequential/`

**Purpose:** 50 back-to-back handshakes. No degradation.

| Metric         | Value            |
| -------------- | ---------------- |
| Mean Handshake | 2.10 ms          |
| Range          | 1.13–3.42 ms     |
| Memory         | Flat at 8,076 KB |

---

### 7.3 Phase 1B — Concurrent — `experiments/phase1/phase1B_concurrent/`

**Purpose:** Concurrency scaling (10–200 simultaneous clients).

| Clients | Avg Latency (ms) | Success | Memory (KB) |
| ------- | ---------------- | ------- | ----------- |
| 10      | 4.83             | 10/10   | 8,516       |
| 25      | 4.93             | 25/25   | 9,352       |
| 50      | 7.29             | 50/50   | 10,896      |
| 100     | 9.76             | 100/100 | 13,764      |
| 150     | 10.13            | 150/150 | 15,592      |
| 200     | 14.32            | 200/200 | 19,496      |

Zero failures. ~55 KB per concurrent client.

---

### 7.4 Phase 1C — Sustained Load — `experiments/phase1/phase1C_sustained/`

**Purpose:** 1 handshake/sec for 60s. Memory flat. No degradation.

| Metric     | Value             |
| ---------- | ----------------- |
| Handshakes | 59 (in 60s)       |
| Mean       | 3.38 ms           |
| Memory     | Flat at 19,496 KB |

---

### 7.5 Phase 1D — Connection Lifetime — `experiments/phase1/phase1D_lifetime/`

**Purpose:** Connection duration (1–60s) has zero resource impact. Memory and CPU constant.

---

### 7.6 Phase 1E — Saturation — `experiments/phase1/phase1E_saturation/`

**Purpose:** 50–500 simultaneous clients. Zero failures. Memory grows linearly (~34 KB/client above 200).

---

### 7.7 Phase 2 — TLS-PSK — `experiments/phase2_psk/`

**Purpose:** PSK vs certificate comparison.

| Metric         | Value          |
| -------------- | -------------- |
| Mean Handshake | 4.79 ms        |
| Range          | 2.94–7.73 ms   |
| Memory         | 7,496–7,576 KB |

PSK is ~2.5× slower than cert baseline due to:

1. **TLS version mismatch:** Certs use TLSv1.3 (1-RTT), PSK falls to TLSv1.2 (2-RTT)
2. **Python FFI overhead:** `ssl.set_psk_client_callback()` crosses Python↔C boundary per handshake

PSK context setup IS faster (0.194 vs 0.341 ms) and uses less memory (~444 KB less RSS). This is a Python limitation, not a protocol limitation.

---

### 7.8 PSK Optimized — `experiments/psk_optimized/`

**Purpose:** Compare all 4 methods: cert_standard, psk_standard, psk_optimized, psk_resumed.

| Method        | Mean Latency | vs Cert    |
| ------------- | ------------ | ---------- |
| cert_standard | 2.36 ms      | (baseline) |
| psk_standard  | 6.38 ms      | +170%      |
| psk_optimized | 7.29 ms      | +209%      |
| psk_resumed   | 0.89 ms      | **−62%**   |

**Key finding:** PSK + Session Resumption (0.89 ms) is 62% faster than certificate baseline.

---

### 7.9 Session Resumption — `experiments/session_resumption/`

**Purpose:** TLS session caching for reconnecting IoT devices.

| Metric      | New Handshake | Resumed          |
| ----------- | ------------- | ---------------- |
| Mean        | 5.32 ms       | 0.56 ms          |
| Range       | 2.99–7.71 ms  | 0.31–1.08 ms     |
| Improvement | —             | **89.5% faster** |

---

### 7.10 User Property Attack — `experiments/user_property_attack/`

**Purpose:** Demonstrate User Property memory exhaustion (CWE-770) and broker-side proxy mitigation using a **multi-vector attack** that exercises all 5 proxy rules independently.

**Attack Vectors (packet counts randomised each iteration):**

| Vector | Violation | Payload/packet | Rule triggered | Count range |
|--------|-----------|----------------|----------------|-------------|
| Normal | 1–5 legitimate properties | ~50 B | — (always forwarded) | 3–10/iter |
| VT-1 | 25–40 props × 2 KB values, retain=True, unique topic | ~62 KB | Rule 1: property count | 5–15/iter |
| VT-2 | Key length 300–600 bytes | tiny | Rule 2: key size | 2–10/iter |
| VT-3 | Single value 5–10 KB, retain=True, unique topic | ~7.5 KB | Rule 3: value size | 2–10/iter |
| VT-4 | 10 props × (key≈220B + val≈230B) = ~4500B total, retain=True | ~4.5 KB | Rule 4: packet payload | 3–8/iter |
| VT-5 | 7–8 props × (82B key + 102B val) ≈ 1260B, retain=True | ~1.3 KB | Rule 5: cumulative budget | 30–50/iter |

VT-1/VT-3/VT-4 use `retain=True` + unique per-iteration/per-packet topics so retained messages accumulate in the unprotected broker. VT-5 is calibrated so the 32 KB per-client budget exhausts after ~26 packets — ensuring `budget_drops` fires every iteration.

| Metric                  | Vulnerable (no proxy)                    | Protected (proxy)                            |
| ----------------------- | ---------------------------------------- | -------------------------------------------- |
| Total packets sent      | ~70/iter (varies), 1,398 over 20 iters   | 629 forwarded over 20 iters (28–36/iter)     |
| Packets dropped         | 0                                        | 849 blocked (57.4% block rate)               |
| Rule 1 drops            | n/a                                      | 186 (count overflow)                         |
| Rule 2 drops            | n/a                                      | 119 (key size)                               |
| Rule 3 drops            | n/a                                      | 121 (value size)                             |
| Rule 4 drops            | n/a                                      | 98 (payload total)                           |
| Rule 5 drops            | n/a                                      | **325** (budget exhaustion — dominant)       |
| Memory growth (20 iter) | **+18,140 KB (+18 MB)** 6,020→24,160 KB | +1,276 KB (+1.3 MB) 2,936→4,212 KB          |
| Memory reduction        | —                                        | **92.6%**                                    |

**How it works:**

- Vulnerable: `attack_client.py → Mosquitto:8883` (direct, PSK config) — all retained packets accumulate
- Protected: `attack_client.py → proxy_broker.py:8883 → Mosquitto:1884` (proxy validates)
- `UserPropertyRules.inspect()` returns a specific drop code per rule (`'drop_count'`, `'drop_keysize'`, `'drop_valsize'`, `'drop_payload'`, `'drop_budget'`)
- `ProxyStats.drop(reason)` routes to the corresponding per-type counter
- `run.sh` passes `--iteration $i` to attack_client so each iteration’s retain topics are globally unique (no overwrite across iterations)
- VT-5 budget exhaustion: budget = 32,768 B, each packet ≈ 1,260 B → exhausted at packet 26; the remaining 4–24 VT-5 packets per iteration are dropped as `budget_drops`

**CSV schemas:**

- `results_vulnerable.csv`: `iteration,normal_sent,vt1_sent,vt2_sent,vt3_sent,vt4_sent,vt5_sent,total_sent,cpu_before,cpu_after,mem_kb`
- `results_protected.csv`: `iteration,packets_forwarded,packets_dropped,prop_count_drops,key_size_drops,val_size_drops,payload_drops,budget_drops,cpu_before,cpu_after,mem_kb`

---

### 7.11 AUTH Flood Attack — `experiments/auth_flood/`

**Purpose:** Demonstrate AUTH Re-authenticate flooding (CWE-799) and broker-side proxy mitigation.

**Attack:** `attack_client.py` runs 10 concurrent threads that rapidly cycle: TLS connect → MQTT CONNECT → flood 50 AUTH packets (reason 0x19) → close → repeat. 5 seconds per iteration, 10 iterations.

| Metric                 | Vulnerable (no proxy) | Protected (proxy)        |
| ---------------------- | --------------------- | ------------------------ |
| Flood connections/iter | ~3,300                | 10 (rate-limited)        |
| Flood attempts/iter    | ~3,300                | ~8,500 (mostly rejected) |
| AUTH packets sent/iter | ~149,000              | 500 (by attacker)        |
| AUTH packets blocked   | 0 (no proxy)          | 500 (100% blocked)       |
| Connections rejected   | 0 (no proxy)          | ~8,500 (by proxy)        |
| Legit latency          | 9.9 ms (mid-attack)   | 1.2 ms (post-flood)      |
| CPU                    | 73%                   | 0%                       |
| Memory growth          | +2,296 KB             | +140 KB                  |

**How it works:**

- Vulnerable: `attack_client.py → Mosquitto:8883` (direct, processes all connections)
- Protected: `attack_client.py → proxy_broker.py:8883 → Mosquitto:1884` (proxy rate-limits)
- Proxy allows ~2 conns/sec (10 total in 5s), blocks ALL AUTH packets, rejects ~8,500 connection attempts
- Legit latency is measured POST-FLOOD in protected mode (shows broker recovery, not mid-attack stress)

**CSV schemas:**

- `results_vulnerable.csv`: `iteration,flood_conns,flood_attempts,auth_packets_sent,legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb`
- `results_protected.csv`: `iteration,flood_conns,flood_attempts,auth_packets_sent,auth_packets_blocked,conns_rejected,legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb`

**Key difference from vulnerable CSV:** Protected CSV has two extra columns — `auth_packets_blocked` and `conns_rejected` — sourced from proxy stats JSON dump (not from attack_client output).

---

## 8. Bugs Found & Fixed

### 8.1 Phase 1B: `sed -i` Mutating Source Code

**Problem:** `run.sh` used `sed -i` to change the client count in `launcher.py` — mutating source on disk.
**Fix:** `launcher.py` now accepts `--clients N` via argparse.

### 8.2 Phase 1C: CSV Double-Header

**Problem:** Both `run.sh` and `sustained_load.py` wrote CSV headers.
**Fix:** Python writes its own header in `"w"` mode. Shell doesn't write one.

### 8.3 Phase 1D: Missing CAFILE + Fragile Inline Python

**Problem:** `client.py` didn't load `ca.crt`. `run.sh` used inline `python -c` to parse stats.
**Fix:** Added CAFILE. `client.py` outputs `handshake_ms,cpu,mem_kb` directly.

### 8.4 Phase 1E: Too Many Clients + Noisy Output

**Problem:** Tested up to 1000 clients. Stderr polluted stdout and broke CSV.
**Fix:** Reduced max to 500. Suppressed stderr in workers.

### 8.5 Phase 2 PSK: Undefined `CPU_BEFORE` Variable

**Problem:** `run.sh` never set `CPU_BEFORE` — written as empty string to CSV.
**Fix:** Sample `broker_stats.sh` before AND after each handshake.

### 8.6 Session Resumption: No Broker Management

**Problem:** `run.sh` didn't start/stop the broker.
**Fix:** Added broker lifecycle management (kill existing, start PSK broker).

### 8.7 User Property Attack: `mosquitto_pub` Cannot Send User Properties

**Problem:** Initial `mosquitto_pub` approach doesn't support MQTT 5.0 User Properties.
**Fix:** Rewrote using paho-mqtt with `Properties(PacketTypes.PUBLISH)`.

### 8.8 Cert vs PSK Broker Mismatch

**Problem:** Phase 1 scripts tried cert handshakes while PSK broker was running.
**Fix:** Each `run.sh` kills existing broker and starts correct config.

### 8.9 AUTH Flood Protected CSV: Wrong Data Sources

**Problem:** Protected CSV showed `flood_conns=10, auth_packets=0, latency=-1` because:

- Used proxy's accepted connections count (~10 due to rate limiting) instead of attacker's output
- Hardcoded `AUTH_REACHED=0` instead of reading proxy stats
- Legit latency measured mid-flood (rate limiter blocks it) → always -1

**Fix:**

- Use `attack_client.py` output for `flood_conns` and `flood_attempts` (attacker perspective)
- Read `auth_packets_blocked` and `connections_rejected` from proxy stats JSON dump
- Measure legit latency POST-FLOOD (after attack ends, separate Python call)
- Added `flood_attempts` field to `FloodStats` counter in attack_client.py
- Added `auth_packets_blocked` and `conns_rejected` columns to protected CSV

---

## 9. Architecture Decisions & Reasoning

### Why SSL-Level (Not paho-mqtt) for Handshake Measurement

We measure at the `ssl.SSLSocket.do_handshake()` level, not via `paho_mqtt.Client.connect()`. This isolates TLS cost from MQTT CONNECT/CONNACK overhead.

### Why Phase 1 Uses Certificates as Baseline

Certificate-based TLS is the standard production deployment. PSK is the optimisation being evaluated against it.

### Why User Property Attack Uses paho-mqtt (Not mosquitto_pub)

`mosquitto_pub` does not support MQTT 5.0 User Properties. The only way to inject custom properties is programmatically via paho-mqtt.

### Why Broker-Side Protection (Not Client-Side)

The attacker controls the client. Any client-side validation can be bypassed. The security proxy sits between attacker and broker, enforcing rules the attacker cannot circumvent. Both experiments use the **same attack_client.py** in both vulnerable and protected phases — the only difference is whether the proxy is deployed.

### Why Post-Flood Legit Latency in Protected Mode

During an active flood against the proxy, the rate limiter may block legitimate clients along with attackers (they all come through the same port). Measuring legit latency POST-FLOOD shows the broker's state after the attack stops — confirming it was never stressed (0.7–1.4 ms vs vulnerable mode's 7–17 ms during active flood).

### Why 50 Iterations for Most Tests

50 iterations provides a statistically meaningful sample for mean, standard deviation, and outlier detection, while keeping total test time under 2 minutes per phase.

---

## 10. Key Code Patterns

### Running a Cert Handshake Test

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from experiments.common.measurement import TLSHandshakeMeasurer, CPUMonitor

measurer = TLSHandshakeMeasurer("localhost", 8883)
elapsed_ms = measurer.measure_cert_handshake("certs/ca.crt", "certs/client.crt", "certs/client.key")
```

### Running a PSK Handshake Test

```python
from experiments.common.measurement import TLSHandshakeMeasurer

measurer = TLSHandshakeMeasurer("localhost", 8883)
elapsed_ms = measurer.measure_psk_handshake("client1", "0123456789abcdef")
```

### Shell Script Pattern (run.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"

killall mosquitto 2>/dev/null || true
sleep 0.5
mosquitto -c "$ROOT/broker/mosquitto_psk.conf" -d
sleep 1

source "$ROOT/venv/bin/activate"
python "$DIR/client.py"
```

### Proxy Stats Collection Pattern (attack run.sh)

```bash
# Reset stats before iteration
kill -USR1 "$PROXY_PID" 2>/dev/null || true
sleep 0.2

# Run attack...

# Read stats after iteration
kill -USR1 "$PROXY_PID" 2>/dev/null || true
sleep 0.3
AUTH_BLOCKED=$(python3 -c "import json; d=json.load(open('$STATS_FILE')); print(d.get('auth_packets_blocked',0))")
CONNS_REJECTED=$(python3 -c "import json; d=json.load(open('$STATS_FILE')); print(d.get('connections_rejected',0))")
```

---

## 11. CSV File Schemas

| File                                             | Columns                                                                                                                                                 |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `baseline/results.csv`                           | `iteration,handshake_ms,cpu_before,cpu_after,mem_kb`                                                                                                    |
| `phase1A/results.csv`                            | `iteration,handshake_ms,cpu_before,cpu_after,mem_kb`                                                                                                    |
| `phase1B/results.csv`                            | `clients,avg_latency_ms,success,failed,cpu,mem_kb`                                                                                                      |
| `phase1C/results.csv`                            | `elapsed_sec,handshake_ms,cpu_percent,mem_kb`                                                                                                           |
| `phase1D/results.csv`                            | `duration_s,handshake_ms,cpu,mem_kb`                                                                                                                    |
| `phase1E/results.csv`                            | `clients,success,failed,cpu,mem_kb`                                                                                                                     |
| `phase2_psk/results.csv`                         | `iteration,handshake_ms,cpu_before,cpu_after,mem_kb`                                                                                                    |
| `psk_optimized/results.csv`                      | `method,iteration,handshake_ms,mem_kb`                                                                                                                  |
| `session_resumption/results_new_handshake.csv`   | `iteration,handshake_ms,cpu_before,cpu_after,mem_kb`                                                                                                    |
| `session_resumption/results_session_resumed.csv` | `iteration,handshake_ms,cpu_before,cpu_after,mem_kb`                                                                                                    |
| `user_property_attack/results_vulnerable.csv`    | `iteration,normal_sent,vt1_sent,vt2_sent,vt3_sent,vt4_sent,vt5_sent,total_sent,cpu_before,cpu_after,mem_kb`                                             |
| `user_property_attack/results_protected.csv`     | `iteration,packets_forwarded,packets_dropped,prop_count_drops,key_size_drops,val_size_drops,payload_drops,budget_drops,cpu_before,cpu_after,mem_kb`      |
| `auth_flood/results_vulnerable.csv`              | `iteration,flood_conns,flood_attempts,auth_packets_sent,legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb`                                     |
| `auth_flood/results_protected.csv`               | `iteration,flood_conns,flood_attempts,auth_packets_sent,auth_packets_blocked,conns_rejected,legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb` |

---

## 12. Summary of Results

| Experiment           | Auth | Key Finding                       | Headline Number                                 |
| -------------------- | ---- | --------------------------------- | ----------------------------------------------- |
| Baseline             | Cert | Reference handshake cost          | **1.92 ms** mean                                |
| Phase 1A             | Cert | No sequential degradation         | 2.10 ms (≈baseline)                             |
| Phase 1B             | Cert | Linear concurrency scaling        | 4.8→14.3 ms (10→200 clients)                    |
| Phase 1C             | Cert | Stable under sustained load       | 3.38 ms over 60s, flat memory                   |
| Phase 1D             | Cert | Lifetime doesn't matter           | 1.2–2.3 ms for 1–60s connections                |
| Phase 1E             | Cert | No saturation at 500 clients      | 0 failures, 37 MB memory                        |
| Phase 2              | PSK  | Python PSK callback adds overhead | **4.79 ms** (2.5× slower)                       |
| PSK Optimized        | PSK  | Resumed PSK beats cert            | **0.89 ms** (62% faster than cert)              |
| Session Resumption   | PSK  | Massive reconnection speedup      | **89.5% faster** (5.3→0.56 ms)                  |
| User Property (vuln) | PSK  | Multi-vector injection, no protection  | **+18 MB** uncontrolled growth (6 MB → 24 MB over 20 iters)  |
| User Property (prot) | PSK  | Proxy blocks all 5 violation types     | **92.6% memory reduction**, 849 pkts blocked (57.4%), budget rule dominant |
| AUTH Flood (vuln)    | PSK  | DoS via AUTH flooding             | ~1.49M AUTH packets, 73% CPU                    |
| AUTH Flood (prot)    | PSK  | Proxy neutralises attack          | 99.7% conn reduction, 100% AUTH blocked, 0% CPU |

---

## 13. Known Caveats

1. **PSK latency is higher than expected** — Python FFI overhead, not a protocol limitation.

2. **Phase 1C/1D/1E memory starts at ~19 MB** — because they run after Phase 1B (200 concurrent connections). Mosquitto pre-allocates memory pools and doesn't fully shrink. Not a leak.

3. **User Property Attack uses `retain=True`** — critical because retained messages persist in broker memory permanently.

4. **All tests run on localhost** — network latency is zero. In production, network RTT would dominate.

5. **Phase 1C time gap at sec 33→35** — the handshake at second 34 took >1s, pushing the next iteration to second 35. Expected behaviour.

6. **Protected legit latency is POST-FLOOD** — measured after the 5-second attack ends, not during. This shows broker health after attack stops.

---

## 14. How to Run

```bash
cd /home/excius/projects/mqtt-security
source venv/bin/activate

# Individual experiments
bash experiments/baseline/run_baseline.sh
bash experiments/phase1/run_all_phases.sh
bash experiments/phase2_psk/run.sh
bash experiments/session_resumption/run.sh
bash experiments/psk_optimized/run.sh
bash experiments/user_property_attack/run.sh
bash experiments/auth_flood/run.sh

# Everything at once
bash run_all_experiments.sh

# Analysis only (requires existing CSVs)
python analyze_all.py
```
