# MQTT 5.0 Security — Experiment Results & Data Reference

This project evaluates the **performance and security** of MQTT 5.0 with TLS certificate-based authentication as the baseline, then measures the impact of TLS-PSK, session resumption, and two MQTT 5.0–specific attacks (User Property injection and AUTH flood). All experiments run against a local **Mosquitto 2.0.21** broker with **OpenSSL 3.5.4** and **paho-mqtt 2.1.0** on **Python 3.13.5**.

> **Protection Architecture:** Attack experiments (Sections 3 and 4) use a **broker-side security proxy** (`proxy/proxy_broker.py`) that sits between clients and Mosquitto. Both phases (vulnerable and protected) use the **same attack client** (`attack_client.py`) — the only difference is whether the proxy is deployed. Client-side protection is never used because the attacker controls the client and would simply bypass it.

---

## What We Did — Improvements & Mitigations

### 1. TLS-PSK Based Secure Communication

**The Problem:** Traditional TLS uses X.509 certificates requiring expensive public-key cryptography (RSA/ECDSA), certificate chain storage, parsing, and CA validation — all costly for constrained IoT devices.

**What We Did:**
Replaced certificate-based TLS with **TLS-PSK (Pre-Shared Key)** authentication. The client and broker share a secret key (`certs/psk.txt`) in advance. During the handshake, no certificates are exchanged — authentication uses symmetric crypto only.

**Implementation:**

- Configured Mosquitto with `psk_hint` and `psk_file` directives (`broker/mosquitto_psk.conf`)
- Used Python's `ssl.SSLContext.set_psk_client_callback()` to supply PSK identity + key during handshake
- Measured 50 iterations of PSK vs certificate handshakes

**Result:**

- PSK context setup is **faster** (0.19 ms vs 0.34 ms — no cert file loading)
- PSK broker uses **less memory** (~444 KB less RSS — no X.509 chain storage)
- PSK handshake itself is slower in Python (6.3 ms vs 2.2 ms) due to Python↔C FFI callback overhead and TLSv1.2 fallback. This is a **Python implementation limitation**, not a protocol limitation — in native C, PSK is faster.

---

### 2. TLS Session Resumption

**The Problem:** IoT devices frequently disconnect and reconnect (sleep cycles, mobility, unstable networks). Without session resumption, every reconnect triggers a full TLS handshake.

**What We Did:**
Enabled **TLS session caching and resumption**. After the first TLS-PSK handshake, the session object is captured (`tls.session`). On reconnect, passing `session=captured_session` to `wrap_socket()` allows OpenSSL to perform an abbreviated handshake reusing previously negotiated cryptographic parameters.

**Result:**

- Full new handshake: **5.32 ms** average
- Resumed handshake: **0.56 ms** average
- **89.5% reduction** in reconnection latency (9.5× speedup)
- PSK + Session Resumption (0.89 ms) is **62% faster** than certificate baseline (2.36 ms)

---

### 3. User Property Injection Mitigation (MQTT v5)

**The Problem:** MQTT 5.0 allows arbitrary key-value **User Properties** on PUBLISH packets. An attacker can craft PUBLISH messages that violate one or more of the broker's safety limits, forcing unbounded resource consumption — memory exhaustion (CWE-770). Because the attacker controls the client, client-side validation is ineffective.

**What We Did:**
Implemented **broker-side validation** using a security proxy that inspects every MQTT PUBLISH packet's user properties before forwarding to Mosquitto. The attack uses **5 distinct violation vectors** — each targeting a different proxy rule — with randomised packet counts per iteration for genuine statistical variation.

**Architecture:**

```
[attack_client.py] → [proxy_broker.py:8883] → [mosquitto:1884]
                      ↑ validates properties (5 rule types)
```

**Attack Vectors (one per proxy rule):**

| Vector | Violation                                                            | Payload size   | Rule triggered            |
| ------ | -------------------------------------------------------------------- | -------------- | ------------------------- |
| VT-1   | 25–40 properties × 2 KB values, `retain=True`                        | ~60 KB/packet  | Rule 1: max count         |
| VT-2   | Key length 300–600 bytes                                             | tiny           | Rule 2: key size          |
| VT-3   | Single value 5–10 KB, `retain=True`                                  | ~7 KB/packet   | Rule 3: value size        |
| VT-4   | 10 props × key≈220B + val≈230B = ~4500B total, `retain=True`         | ~4.5 KB/packet | Rule 4: packet payload    |
| VT-5   | 7–8 props × (82B key + 102B val) ≈ 1260 B, `retain=True`, 30–50/iter | ~1.3 KB/packet | Rule 5: cumulative budget |

All attack packets use unique per-iteration/per-packet topics so `retain=True` messages accumulate; the unprotected broker grows **~16 MB** over 20 iterations. VT-5 is calibrated so the 32 KB per-client budget is always exhausted (~26 packets pass, remainder dropped).

**Protection Rules (enforced at proxy):**

1. **Property Count Limit** — Max 10 user properties per packet
2. **Key Size Restriction** — Max 256 bytes per property key
3. **Value Size Restriction** — Max 256 bytes per property value
4. **Per-Packet Payload Budget** — Max 4,096 bytes total (sum of all key + value bytes) per packet
5. **Per-Client Cumulative Budget** — Max 32 KB total user-property payload across all packets from one client

**Result (20 iterations, randomised packet counts):**

- **Vulnerable:** 1,398 total packets reached broker, memory grew **+18 MB** (6,020 KB → 24,160 KB)
- **Protected:** 629 packets forwarded, 849 blocked (**57.4% block rate**)
- **Memory reduction: 92.6%** — protected broker grew only +1.3 MB vs +18 MB unprotected
- Drop breakdown: 186 Rule-1 (count) + 119 Rule-2 (key) + 121 Rule-3 (val) + 98 Rule-4 (payload) + **325 Rule-5 (budget)** — budget rule now the single largest contributor
- Every iteration has different per-rule drop counts — clear variation for time-series plots

---

### 4. AUTH Packet Flood Mitigation (MQTT v5 Enhanced Authentication)

**The Problem:** MQTT 5.0 allows clients to send AUTH Re-authenticate packets (reason code 0x19) during a session. A malicious client can flood the broker with rapid TLS connection cycling + AUTH packets, consuming CPU and degrading service (CWE-799). Client-side rate limiting is pointless since the attacker controls the client.

**What We Did:**
Implemented **broker-side protection** using the security proxy that rate-limits connections and blocks AUTH packets before they reach Mosquitto.

**Architecture:**

```
[attack_client.py] → [proxy_broker.py:8883] → [mosquitto:1884]
                      ↑ rate limits + blocks AUTH
```

**Protection Rules (enforced at proxy):**

1. **Connection Rate Limit** — Max 2 new connections per second (sliding window)
2. **AUTH Packet Blocking** — 0 AUTH Re-authenticate packets allowed (all dropped at proxy)
3. **Total Connection Cap** — Max 20 concurrent connections
4. **Authentication Timeout** — 2-second timeout, proxy force-closes stalled connections

**Result:**

- **Vulnerable:** ~3,300 flood connections/iter, ~149,000 AUTH packets/iter, legit latency 9.9 ms, CPU 73%
- **Protected:** 10 connections/iter (**99.7% reduction**), ~500 AUTH sent but **100% blocked** by proxy, conns rejected ~8,500/iter, post-flood legit latency 1.2 ms, CPU 0%
- Memory growth: vulnerable +2,296 KB vs protected +140 KB

---

## Project Architecture

| Layer          | Technology                                      |
| -------------- | ----------------------------------------------- |
| Broker         | Mosquitto 2.0.21 (port 1884 internal, 8883 PSK) |
| Security Proxy | `proxy/proxy_broker.py` (TLS-PSK termination)   |
| Base Security  | MQTT 5.0 + TLS 1.2 with PSK or X.509 certs      |
| Optimisation   | TLS-PSK, Session Resumption                     |
| Attack Surface | User Property Injection, AUTH Flood             |

**Broker configurations:**

- `broker/mosquitto_tls.conf` — Certificate-based TLS on :8883 (Baseline, Phase 1)
- `broker/mosquitto_psk.conf` — PSK-based TLS on :8883 (Phase 2, PSK Optimized, Session Resumption, Attacks)
- `broker/mosquitto_internal.conf` — Plain TCP on :1884 localhost only (behind proxy)

**Proxy deployment (attack experiments only):**

```
                   Protected Mode
[Attacker] --TLS-PSK:8883--> [proxy_broker.py] --TCP:1884--> [Mosquitto]
                              (inspect + filter)

                   Vulnerable Mode
[Attacker] --TLS-PSK:8883--> [Mosquitto]  (direct, no proxy)
```

---

## CSV File Reference — Deep Field Documentation

Each experiment produces CSV files with specific fields. Below is a comprehensive reference for every field, what it measures, how it is collected, and what values to expect.

---

### 1. Baseline — `experiments/baseline/results.csv`

| Column         | Type  | Description                                                     | How Collected                                                | Expected Range  |
| -------------- | ----- | --------------------------------------------------------------- | ------------------------------------------------------------ | --------------- |
| `iteration`    | int   | Test run number                                                 | Sequential counter (1–50)                                    | 1–50            |
| `handshake_ms` | float | Time to complete a single TLS certificate handshake             | `time.perf_counter()` around `ssl.do_handshake()`            | 0.9–3.7 ms      |
| `cpu_before`   | float | Broker CPU usage (%) sampled before the handshake               | `ps -p <pid> -o %cpu=` — lifetime average reported by the OS | 0.0–0.5%        |
| `cpu_after`    | float | Broker CPU usage (%) sampled after the handshake                | Same as above, sampled after a 0.1s delay                    | 0.0–0.5%        |
| `mem_kb`       | int   | Broker resident set size (RSS) in kilobytes after the handshake | `ps -p <pid> -o rss=`                                        | ~7,900–8,100 KB |

**What it shows:** Cost of a single MQTT 5.0 + TLS certificate handshake under zero load — the reference point for all other experiments.

---

### 2. Phase 1A — Sequential — `experiments/phase1/phase1A_sequential/results.csv`

| Column         | Type  | Description                                | How Collected         | Expected Range |
| -------------- | ----- | ------------------------------------------ | --------------------- | -------------- |
| `iteration`    | int   | Test run number                            | Sequential (1–50)     | 1–50           |
| `handshake_ms` | float | Single TLS certificate handshake time (ms) | `perf_counter()` diff | 1.1–3.4 ms     |
| `cpu_before`   | float | Broker CPU (%) before handshake            | `ps %cpu=`            | 0.1–0.3%       |
| `cpu_after`    | float | Broker CPU (%) after handshake             | `ps %cpu=`            | 0.1–0.3%       |
| `mem_kb`       | int   | Broker memory (KB) after handshake         | `ps rss=`             | ~8,076 KB      |

**What it shows:** 50 back-to-back certificate handshakes performed sequentially. Confirms no degradation over repeated handshakes — memory stays flat, latency is stable.

---

### 3. Phase 1B — Concurrent — `experiments/phase1/phase1B_concurrent/results.csv`

| Column           | Type  | Description                                          | How Collected                                       | Expected Range |
| ---------------- | ----- | ---------------------------------------------------- | --------------------------------------------------- | -------------- |
| `clients`        | int   | Number of simultaneous TLS connections attempted     | Test parameter (10, 25, 50, 100, 150, 200)          | 10–200         |
| `avg_latency_ms` | float | Mean handshake time across all clients (ms)          | Average of per-thread `perf_counter()` measurements | 4.8–14.3 ms    |
| `success`        | int   | Handshakes that completed successfully               | Count of threads that returned without exception    | = `clients`    |
| `failed`         | int   | Handshakes that failed (timeout, refused, TLS error) | Count of threads that raised an exception           | 0              |
| `cpu`            | float | Broker CPU usage (%) during the burst                | `ps %cpu=`                                          | 0.1–0.4%       |
| `mem_kb`         | int   | Broker memory (KB) after the burst                   | `ps rss=`                                           | 8.3–19.0 MB    |

**What it shows:** Scalability under concurrent load. Latency scales roughly linearly (~3× increase for 20× clients). Zero failures at all concurrency levels. Memory grows ~55 KB per concurrent client.

---

### 4. Phase 1C — Sustained Load — `experiments/phase1/phase1C_sustained/results.csv`

| Column         | Type  | Description                                        | How Collected              | Expected Range |
| -------------- | ----- | -------------------------------------------------- | -------------------------- | -------------- |
| `elapsed_sec`  | int   | Seconds elapsed since test start                   | `time.time() - start_time` | 0–59           |
| `handshake_ms` | float | TLS certificate handshake time at that moment (ms) | `perf_counter()` diff      | 1.2–4.8 ms     |
| `cpu_percent`  | float | Broker CPU usage (%) at sample time                | `ps %cpu=`                 | 0.3%           |
| `mem_kb`       | int   | Broker memory (KB) at sample time                  | `ps rss=`                  | ~19,496 KB     |

**What it shows:** One handshake per second for 60 seconds. Confirms no degradation over sustained load — memory stays completely flat, latency is stable.

---

### 5. Phase 1D — Connection Lifetime — `experiments/phase1/phase1D_lifetime/results.csv`

| Column         | Type  | Description                                     | How Collected                     | Expected Range |
| -------------- | ----- | ----------------------------------------------- | --------------------------------- | -------------- |
| `duration_s`   | int   | Duration the TLS connection was kept open (sec) | Test parameter (1, 5, 10, 30, 60) | 1–60           |
| `handshake_ms` | float | TLS certificate handshake time (ms)             | `perf_counter()` diff             | 1.2–2.3 ms     |
| `cpu`          | float | Broker CPU (%) while connection is held         | `ps %cpu=`                        | 0.2–0.3%       |
| `mem_kb`       | int   | Broker memory (KB) while connection is held     | `ps rss=`                         | ~19,000 KB     |

**What it shows:** Connection lifetime has zero resource cost. Handshake time is independent of how long the connection stays open. Memory and CPU are constant.

---

### 6. Phase 1E — Saturation — `experiments/phase1/phase1E_saturation/results.csv`

| Column    | Type  | Description                                    | How Collected                  | Expected Range |
| --------- | ----- | ---------------------------------------------- | ------------------------------ | -------------- |
| `clients` | int   | Number of concurrent TLS connections attempted | Test parameter (50–500)        | 50–500         |
| `success` | int   | Successful handshakes                          | Count of non-exception threads | = `clients`    |
| `failed`  | int   | Failed handshakes                              | Count of exception threads     | 0              |
| `cpu`     | float | Broker CPU usage (%)                           | `ps %cpu=`                     | 0.2–0.5%       |
| `mem_kb`  | int   | Broker memory (KB)                             | `ps rss=`                      | 19–36 MB       |

**What it shows:** Pushes to 500 concurrent clients. Zero failures at all levels. Memory growth is linear (~34 KB per client beyond 200). The broker has significant headroom.

---

### 7. Phase 2 — TLS-PSK — `experiments/phase2_psk/results.csv`

| Column         | Type  | Description                        | How Collected         | Expected Range |
| -------------- | ----- | ---------------------------------- | --------------------- | -------------- |
| `iteration`    | int   | Test run number                    | Sequential (1–50)     | 1–50           |
| `handshake_ms` | float | TLS-PSK handshake time (ms)        | `perf_counter()` diff | 2.9–7.7 ms     |
| `cpu_before`   | float | Broker CPU (%) before handshake    | `ps %cpu=`            | 0.0–0.5%       |
| `cpu_after`    | float | Broker CPU (%) after handshake     | `ps %cpu=`            | 0.3–0.5%       |
| `mem_kb`       | int   | Broker memory (KB) after handshake | `ps rss=`             | ~7,500 KB      |

**What it shows:** Direct PSK vs certificate comparison. PSK handshake is ~2.5× slower due to Python FFI callback overhead + TLSv1.2 fallback (certs use TLSv1.3). However, PSK uses less memory (~444 KB less RSS).

**Root cause of PSK being slower:**

1. **TLS version mismatch:** Certs negotiate TLSv1.3 (1-RTT), PSK falls to TLSv1.2 (2-RTT)
2. **Python FFI overhead:** `ssl.set_psk_client_callback()` crosses the Python↔C boundary per handshake

---

### 8. PSK Optimized Comparison — `experiments/psk_optimized/results.csv`

| Column         | Type   | Description                            | How Collected                                                           | Expected Range |
| -------------- | ------ | -------------------------------------- | ----------------------------------------------------------------------- | -------------- |
| `method`       | string | Authentication method tested           | One of: `cert_standard`, `psk_standard`, `psk_optimized`, `psk_resumed` | 4 values       |
| `iteration`    | int    | Test run number within each method     | Sequential (1–50)                                                       | 1–50           |
| `handshake_ms` | float  | Handshake latency (ms) for that method | `perf_counter()` diff                                                   | 0.3–10.3 ms    |
| `mem_kb`       | int    | Broker memory (KB) after handshake     | `ps rss=`                                                               | 7,400–8,100 KB |

**Method values:**

| Method          | Description                                             | Typical Latency |
| --------------- | ------------------------------------------------------- | --------------- |
| `cert_standard` | Standard TLS certificate handshake (TLSv1.3)            | ~2.4 ms         |
| `psk_standard`  | Standard TLS-PSK handshake (TLSv1.2, FFI overhead)      | ~6.4 ms         |
| `psk_optimized` | PSK with SSL context reuse (marginal improvement)       | ~7.3 ms         |
| `psk_resumed`   | PSK with TLS session resumption (abbreviated handshake) | ~0.9 ms         |

**What it shows:** `psk_resumed` (0.89 ms) is 62% faster than `cert_standard` (2.36 ms). Session resumption overcomes PSK's Python overhead.

---

### 9. Session Resumption — New Handshakes — `experiments/session_resumption/results_new_handshake.csv`

| Column         | Type  | Description                                    | How Collected         | Expected Range |
| -------------- | ----- | ---------------------------------------------- | --------------------- | -------------- |
| `iteration`    | int   | Test run number                                | Sequential (1–50)     | 1–50           |
| `handshake_ms` | float | Full (non-resumed) TLS-PSK handshake time (ms) | `perf_counter()` diff | 3.0–7.7 ms     |
| `cpu_before`   | float | Broker CPU (%) before handshake                | `ps %cpu=`            | 0.0–0.1%       |
| `cpu_after`    | float | Broker CPU (%) after handshake                 | `ps %cpu=`            | 0.0–0.1%       |
| `mem_kb`       | int   | Broker memory (KB) after handshake             | `ps rss=`             | ~7,500 KB      |

**What it shows:** Full PSK handshake cost when no session cache exists. This is the "before" baseline for session resumption comparison.

---

### 10. Session Resumption — Resumed Handshakes — `experiments/session_resumption/results_session_resumed.csv`

| Column         | Type  | Description                         | How Collected         | Expected Range |
| -------------- | ----- | ----------------------------------- | --------------------- | -------------- |
| `iteration`    | int   | Test run number                     | Sequential (1–50)     | 1–50           |
| `handshake_ms` | float | Resumed TLS-PSK handshake time (ms) | `perf_counter()` diff | 0.3–1.1 ms     |
| `cpu_before`   | float | Broker CPU (%) before handshake     | `ps %cpu=`            | 0.0–0.1%       |
| `cpu_after`    | float | Broker CPU (%) after handshake      | `ps %cpu=`            | 0.0–0.1%       |
| `mem_kb`       | int   | Broker memory (KB) after handshake  | `ps rss=`             | ~7,500 KB      |

**What it shows:** Handshake cost when a previous TLS session is resumed. 89.5% faster than new handshakes (0.56 ms vs 5.3 ms). For presentations, overlay both distributions on a histogram or show a paired comparison chart.

---

### 11. User Property Attack — Vulnerable — `experiments/user_property_attack/results_vulnerable.csv`

| Column        | Type  | Description                                                                | How Collected                     | Expected Range |
| ------------- | ----- | -------------------------------------------------------------------------- | --------------------------------- | -------------- |
| `iteration`   | int   | Attack iteration number                                                    | Sequential (1–20)                 | 1–20           |
| `normal_sent` | int   | Normal PUBLISH packets (1–5 small properties each)                         | `attack_client.py` stdout field 1 | 3–10           |
| `vt1_sent`    | int   | VT-1 packets sent (count overflow: 25–40 props × 2 KB values, retain=True) | `attack_client.py` stdout field 2 | 5–15           |
| `vt2_sent`    | int   | VT-2 packets sent (key overflow: key 300–600 bytes)                        | `attack_client.py` stdout field 3 | 2–10           |
| `vt3_sent`    | int   | VT-3 packets sent (value overflow: 5–10 KB per value, retain=True)         | `attack_client.py` stdout field 4 | 2–10           |
| `vt4_sent`    | int   | VT-4 packets sent (payload overflow: 10 props × key≈220B + val≈230B)       | `attack_client.py` stdout field 5 | 3–8            |
| `vt5_sent`    | int   | VT-5 packets sent (budget drain: 30–50 × ~1260B per pkt, retain=True)      | `attack_client.py` stdout field 6 | 30–50          |
| `total_sent`  | int   | Sum of all six packet-count fields                                         | `run.sh` arithmetic sum           | 40–100         |
| `cpu_before`  | float | Broker CPU (%) before the iteration                                        | `ps %cpu=`                        | 0.0–0.4%       |
| `cpu_after`   | float | Broker CPU (%) after the iteration                                         | `ps %cpu=`                        | 0.0–0.4%       |
| `mem_kb`      | int   | Broker RSS (KB) after the iteration                                        | `ps rss=`                         | grows          |

**What it shows:** Memory impact when all 5 attack vector types reach the broker with no filtering. VT-1 packets (~60 KB each retained) drive the bulk of growth. Packet counts vary per iteration.

**Key fields explained:**

- `total_sent` = sum of all six count fields — all reach the broker.
- `vt1_sent` is the heaviest memory contributor: each packet carries 25–40 props × 2 KB values retained to a unique topic, accumulating ~60 KB/packet in broker storage.
- `vt3_sent` is the second-heaviest: 5–10 KB retained per packet.
- `vt5_sent` (30–50/iter): Budget-drain packets are small enough to pass the 32 KB per-connection limit for the first ~26 packets, but still accumulate ~1.3 KB each in the unprotected broker.
- `mem_kb` grows ~900 KB per iteration on average: after 20 iterations vulnerable broker grows ~+18 MB.

---

### 12. User Property Attack — Protected — `experiments/user_property_attack/results_protected.csv`

| Column              | Type  | Description                                                 | How Collected                                                 | Expected Range |
| ------------------- | ----- | ----------------------------------------------------------- | ------------------------------------------------------------- | -------------- |
| `iteration`         | int   | Attack iteration number                                     | Sequential (1–20)                                             | 1–20           |
| `packets_forwarded` | int   | Packets that passed all 5 proxy rules → forwarded to broker | Proxy stats (`packets_forwarded`), read via SIGUSR1 JSON dump | 28–36          |
| `packets_dropped`   | int   | Total packets blocked by any proxy rule                     | Proxy stats (`packets_dropped`), SIGUSR1 JSON dump            | 26–63          |
| `prop_count_drops`  | int   | Drops triggered by Rule 1 (property count > 10)             | Proxy stats (`prop_count_drops`), SIGUSR1 JSON dump           | varies         |
| `key_size_drops`    | int   | Drops triggered by Rule 2 (key > 256 bytes)                 | Proxy stats (`key_size_drops`), SIGUSR1 JSON dump             | varies         |
| `val_size_drops`    | int   | Drops triggered by Rule 3 (value > 256 bytes)               | Proxy stats (`val_size_drops`), SIGUSR1 JSON dump             | varies         |
| `payload_drops`     | int   | Drops triggered by Rule 4 (per-packet payload > 4096 bytes) | Proxy stats (`payload_drops`), SIGUSR1 JSON dump              | varies         |
| `budget_drops`      | int   | Drops triggered by Rule 5 (cumulative budget > 32 KB)       | Proxy stats (`budget_drops`), SIGUSR1 JSON dump               | 6–26           |
| `cpu_before`        | float | Broker CPU (%) before the iteration                         | `ps %cpu=`                                                    | 0.0%           |
| `cpu_after`         | float | Broker CPU (%) after the iteration                          | `ps %cpu=`                                                    | 0.0%           |
| `mem_kb`            | int   | Broker RSS (KB) after the iteration                         | `ps rss=`                                                     | 3,000–4,300 KB |

**What it shows:** Same multi-vector attack through the proxy. All 5 drop-type columns are non-zero in virtually every iteration; `budget_drops` is consistently the largest category because VT-5 sends 30–50 packets but the 32 KB budget exhausts after ~26, causing 4–24 drops per iteration per iteration.

**Key fields explained:**

- `packets_dropped` = `prop_count_drops + key_size_drops + val_size_drops + payload_drops + budget_drops` — holds exactly for every row.
- `packets_forwarded` = normal packets (3–10) + VT-5 packets that pass budget (~26 per iter). This is correct and expected — those VT-5 packets are individually compliant until the cumulative limit is reached.
- `budget_drops` is the dominant category (6–26/iter) because VT-5 sends 30–50 packets but budget is exhausted after ~26, so the remaining 4–24 are dropped.
- `prop_count_drops` / `key_size_drops` / `val_size_drops` / `payload_drops` each track one attack vector, with counts equal to that iteration's VT-n packet count.
- `mem_kb` grows slowly (+57 KB/iter): only the ~26 forwarded VT-5 retain packets (~1.3 KB each) reach the broker; all large VT-1/VT-3/VT-4 are blocked.

---

### 13. AUTH Flood Attack — Vulnerable — `experiments/auth_flood/results_vulnerable.csv`

| Column              | Type  | Description                                                        | How Collected                                                                           | Expected Range                 |
| ------------------- | ----- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | ------------------------------ |
| `iteration`         | int   | Test run number                                                    | Sequential (1–10)                                                                       | 1–10                           |
| `flood_conns`       | int   | Successful TLS+CONNECT connections made by the attacker            | `attack_client.py` `FloodStats.total_conns` — incremented when `wrap_socket()` succeeds | ~3,200–3,400/iter              |
| `flood_attempts`    | int   | Total connection attempts (including failed ones)                  | `FloodStats.total_attempts` — incremented on every `create_connection()` call           | = `flood_conns` (most succeed) |
| `auth_packets_sent` | int   | AUTH Re-authenticate packets successfully sent to broker           | `FloodStats.total_auths` — incremented on each `tls.sendall(auth_pkt)`                  | ~145,000–154,000/iter          |
| `legit_latency_ms`  | float | Legitimate client's TLS-PSK handshake time during active flood     | Separate `TLSHandshakeMeasurer.measure_psk_handshake()` call mid-attack                 | 7–17 ms                        |
| `legit_success`     | int   | Whether the legitimate client connected successfully (1=yes, 0=no) | 1 if no exception, 0 if connection refused/timeout                                      | 1                              |
| `cpu_before`        | float | Broker CPU (%) before the attack iteration                         | `ps %cpu=` (lifetime average)                                                           | 0.0–72%                        |
| `cpu_after`         | float | Broker CPU (%) after the attack iteration                          | `ps %cpu=`                                                                              | 73%                            |
| `mem_kb`            | int   | Broker RSS (KB) after the attack iteration                         | `ps rss=`                                                                               | 8,200–8,400 KB                 |

**What it shows:** During each 5-second iteration, 10 concurrent attack threads rapidly cycle TLS connections and flood AUTH packets directly to the broker (no proxy). The broker must process every connection and AUTH packet.

**Key fields explained:**

- `flood_conns` vs `flood_attempts`: In vulnerable mode these are usually equal because the broker accepts all connections. When a proxy is present, `flood_conns` drops dramatically (rate limited) while `flood_attempts` stays high.
- `auth_packets_sent=~149,000`: Each of the ~3,300 connections sends up to 50 AUTH packets before the broker disconnects it. This represents the massive CPU load imposed on the broker.
- `legit_latency_ms`: A separate legitimate client measures its TLS handshake latency while the flood is active. Higher values indicate the broker is under stress. Values of 7–17 ms compared to ~2 ms baseline show significant degradation.
- `cpu_after=73%`: Lifetime average CPU reported by `ps`. The broker is heavily loaded processing thousands of TLS handshakes and AUTH packet parsing per second.

---

### 14. AUTH Flood Attack — Protected — `experiments/auth_flood/results_protected.csv`

| Column                 | Type  | Description                                                      | How Collected                                                            | Expected Range |
| ---------------------- | ----- | ---------------------------------------------------------------- | ------------------------------------------------------------------------ | -------------- |
| `iteration`            | int   | Test run number                                                  | Sequential (1–10)                                                        | 1–10           |
| `flood_conns`          | int   | Connections the proxy allowed through to the broker              | `attack_client.py` output — but proxy rate-limits to ~2/sec              | ~10            |
| `flood_attempts`       | int   | Total connection attempts by attacker (mostly rejected by proxy) | `FloodStats.total_attempts`                                              | ~8,400–8,600   |
| `auth_packets_sent`    | int   | AUTH packets attacker managed to send (within allowed conns)     | `FloodStats.total_auths` — only possible on the ~10 accepted connections | 500            |
| `auth_packets_blocked` | int   | AUTH packets the proxy intercepted and dropped                   | Proxy stats `auth_packets_blocked`, read via SIGUSR1 JSON dump           | 500            |
| `conns_rejected`       | int   | Connection attempts rejected by proxy's rate limiter             | Proxy stats `connections_rejected`, read via SIGUSR1 JSON dump           | ~8,400–8,600   |
| `legit_latency_ms`     | float | Legitimate client's TLS handshake time measured AFTER flood ends | Separate `TLSHandshakeMeasurer` call post-flood (broker recovery check)  | 0.7–1.4 ms     |
| `legit_success`        | int   | Whether the legitimate client connected (1=yes, 0=no)            | 1 if no exception, 0 otherwise                                           | 1              |
| `cpu_before`           | float | Broker CPU (%) before the attack iteration                       | `ps %cpu=`                                                               | 0.0%           |
| `cpu_after`            | float | Broker CPU (%) after the attack iteration                        | `ps %cpu=`                                                               | 0.0%           |
| `mem_kb`               | int   | Broker RSS (KB) after the attack iteration                       | `ps rss=`                                                                | 3,000–3,100 KB |

**What it shows:** Same attack, but through the security proxy. The proxy rate-limits connections and blocks all AUTH packets before they reach Mosquitto.

**Key fields explained:**

- `flood_conns=10`: The proxy's rate limiter allows only ~2 connections/second over the 5-second attack — most connections are rejected at the proxy layer.
- `flood_attempts=~8,500`: The attacker still tries ~8,500 connections, but only ~10 succeed through the proxy.
- `auth_packets_sent=500`: On the ~10 accepted connections (50 AUTH packets each = 500 total). These are sent BY the attacker but blocked BY the proxy.
- `auth_packets_blocked=500`: 100% of AUTH packets are dropped at the proxy. Zero reach Mosquitto.
- `conns_rejected=~8,500`: Proxy rejects ~99.9% of connection attempts via rate limiting.
- `legit_latency_ms=0.7–1.4ms`: Measured POST-FLOOD (after the 5-second attack ends). The low latency confirms Mosquitto was never stressed — the proxy absorbed the entire attack. This is much lower than the vulnerable mode's 7–17 ms because the broker was essentially idle.
- `cpu_before=0.0, cpu_after=0.0`: The broker stays at 0% CPU — it never sees the flood traffic.
- `mem_kb=~3,000`: Broker memory is minimal — only ~10 connections made it through, and those were cleaned up by the proxy's timeout enforcement.

---

## Summary Comparison Table

| Experiment        | Auth Type | Handshake Latency | Memory Profile       | Key Finding                                  |
| ----------------- | --------- | ----------------- | -------------------- | -------------------------------------------- |
| Baseline          | TLS Cert  | ~1.9 ms avg       | 8 MB (stable)        | Reference point for all comparisons          |
| Phase 1A          | TLS Cert  | ~2.1 ms avg       | 8 MB (stable)        | No degradation under sequential load         |
| Phase 1B          | TLS Cert  | 4.8–14.3 ms       | 8–19 MB              | Linear scaling, zero failures at 200 clients |
| Phase 1C          | TLS Cert  | ~3.3 ms avg       | 19 MB (flat)         | Stable over 60s sustained load               |
| Phase 1D          | TLS Cert  | ~1.8 ms avg       | 19 MB (flat)         | Connection lifetime has no resource cost     |
| Phase 1E          | TLS Cert  | N/A               | 19–37 MB             | Zero failures at 500 clients                 |
| Phase 2 PSK       | TLS-PSK   | ~4.7 ms avg       | 7.5 MB (stable)      | 2.5× slower than cert (Python FFI overhead)  |
| PSK Optimized     | TLS-PSK   | 0.9–7.3 ms        | 7.5–8.0 MB           | Resumed PSK 62% faster than cert             |
| Session (new)     | TLS-PSK   | ~5.3 ms avg       | 7.5 MB (stable)      | Full PSK handshake baseline                  |
| Session (resumed) | TLS-PSK   | ~0.55 ms avg      | 7.5 MB (stable)      | **89.5% faster** than new handshake          |
| User Prop (vuln)  | TLS-PSK   | N/A               | 9→41 MB (+35 MB)     | Unbounded memory growth, no protection       |
| User Prop (prot)  | TLS-PSK   | N/A               | 3.0→3.2 MB (+0.2 MB) | **99.6% memory reduction** via proxy         |
| AUTH Flood (vuln) | TLS-PSK   | 9.9 ms (legit)    | 8.2→8.3 MB           | ~1.49M AUTH packets, CPU 73%, legit degraded |
| AUTH Flood (prot) | TLS-PSK   | 1.2 ms (legit)    | 3.0→3.1 MB           | **99.7% conn reduction**, 100% AUTH blocked  |

---

## How to Run

```bash
# Activate Python environment
source venv/bin/activate

# Run individual experiments
bash experiments/baseline/run_baseline.sh
bash experiments/phase1/run_all_phases.sh        # Runs 1A through 1E
bash experiments/phase2_psk/run.sh
bash experiments/session_resumption/run.sh
bash experiments/psk_optimized/run.sh
bash experiments/user_property_attack/run.sh     # Vulnerable + Proxy-protected
bash experiments/auth_flood/run.sh               # Vulnerable + Proxy-protected

# Run all experiments + unified analysis
bash run_all_experiments.sh

# Run analysis only (requires CSV results to exist)
python analyze_all.py
```

Each script manages its own broker instance (starts/stops automatically). Results are written to the CSV files listed above.

---

## File Structure

```
mqtt-security/
├── README.md                          # This file
├── CONTEXT.md                         # Technical context and implementation details
├── analyze_all.py                     # Unified analysis of all experiments
├── run_all_experiments.sh             # Master runner for all experiments
│
├── broker/
│   ├── mosquitto_tls.conf             # Certificate-based TLS config (:8883)
│   ├── mosquitto_psk.conf             # PSK-based TLS config (:8883)
│   └── mosquitto_internal.conf        # Plain TCP config (:1884, behind proxy)
│
├── certs/
│   ├── ca.crt, ca.key, ca.srl         # Certificate authority
│   ├── server.crt, server.csr, server.key  # Server certificate
│   └── psk.txt                        # Pre-shared key file (client1:0123456789abcdef)
│
├── proxy/
│   └── proxy_broker.py                # Security proxy (TLS-PSK termination + MQTT inspection)
│
├── experiments/
│   ├── common/
│   │   └── measurement.py             # TLSHandshakeMeasurer + CPUMonitor (shared)
│   │
│   ├── baseline/                      # Certificate TLS baseline (50 iterations)
│   ├── phase1/
│   │   ├── phase1A_sequential/        # Sequential cert handshakes
│   │   ├── phase1B_concurrent/        # Concurrent cert handshakes (10–200 clients)
│   │   ├── phase1C_sustained/         # Sustained load (60 seconds)
│   │   ├── phase1D_lifetime/          # Connection lifetime test
│   │   └── phase1E_saturation/        # Saturation test (50–500 clients)
│   │
│   ├── phase2_psk/                    # TLS-PSK handshake comparison
│   ├── psk_optimized/                 # 4-method PSK comparison (cert/psk/optimized/resumed)
│   ├── session_resumption/            # TLS session resumption (new vs resumed)
│   │
│   ├── user_property_attack/          # User Property injection attack
│   │   ├── attack_client.py           # Sends oversized user properties
│   │   ├── run.sh                     # Vulnerable + proxy-protected phases
│   │   └── analyze.py                 # Per-experiment analysis
│   │
│   └── auth_flood/                    # AUTH packet flood attack
│       ├── attack_client.py           # 10-thread TLS+AUTH flood
│       ├── run.sh                     # Vulnerable + proxy-protected phases
│       └── analyze.py                 # Per-experiment analysis
```
