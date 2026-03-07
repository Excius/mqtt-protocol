"""
Analyze AUTH Flood attack results.
Compare vulnerable (flood, no protection) vs protected (rate-limited) MQTT.

CSV schema:
  iteration, flood_conns, auth_packets_sent, legit_latency_ms,
  legit_success, cpu_before, cpu_after, mem_kb
"""

import csv
from pathlib import Path
import statistics

DIR = Path(__file__).parent


def load_csv(filename):
    data = []
    filepath = DIR / filename
    if not filepath.exists():
        return data
    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append({
                "iteration": int(row["iteration"]),
                "flood_conns": int(row["flood_conns"]),
                "auth_packets_sent": int(row["auth_packets_sent"]),
                "legit_latency_ms": float(row["legit_latency_ms"]),
                "legit_success": int(row["legit_success"]),
                "cpu_before": float(row["cpu_before"]),
                "cpu_after": float(row["cpu_after"]),
                "mem_kb": int(row["mem_kb"]),
            })
    return data


def fmt(values):
    m = statistics.mean(values)
    s = statistics.stdev(values) if len(values) > 1 else 0.0
    return m, s


def analyze():
    vuln = load_csv("results_vulnerable.csv")
    prot = load_csv("results_protected.csv")

    if not vuln:
        print("No vulnerable results found. Run: bash run.sh")
        return
    if not prot:
        print("No protected results found. Run: bash run.sh")
        return

    print("=" * 70)
    print("  MQTT 5.0 AUTH FLOOD ATTACK — RESULTS ANALYSIS")
    print("=" * 70)
    print()

    # ── Vulnerable ───────────────────────────────────────────────────────
    v_conns   = [d["flood_conns"]       for d in vuln]
    v_auths   = [d["auth_packets_sent"] for d in vuln]
    v_lat     = [d["legit_latency_ms"]  for d in vuln if d["legit_latency_ms"] > 0]
    v_success = [d["legit_success"]     for d in vuln]
    v_cpu_d   = [d["cpu_after"] - d["cpu_before"] for d in vuln]
    v_mem     = [d["mem_kb"]            for d in vuln]

    print("  VULNERABLE MQTT (Auth Flood, No Protection)")
    print("  " + "-" * 52)
    print(f"    Total flood connections:       {sum(v_conns)}")
    print(f"    Flood conns / iteration (avg): {statistics.mean(v_conns):.1f}")
    print(f"    Total AUTH packets sent:       {sum(v_auths)}")
    print(f"    AUTH packets / iter (avg):     {statistics.mean(v_auths):.1f}")
    if v_lat:
        m, s = fmt(v_lat)
        print(f"    Legit client latency:          {m:.3f} ± {s:.3f} ms")
    else:
        print(f"    Legit client latency:          ALL FAILED")
    sr = sum(v_success) / len(v_success) * 100
    print(f"    Legit success rate:            {sum(v_success)}/{len(v_success)} ({sr:.0f}%)")
    if v_cpu_d:
        print(f"    CPU delta (avg):               {statistics.mean(v_cpu_d):.2f}%")
    print(f"    Memory range:                  {min(v_mem)}–{max(v_mem)} KB")
    print(f"    Memory growth:                 {v_mem[-1] - v_mem[0]} KB")
    print()

    # ── Protected ────────────────────────────────────────────────────────
    p_conns   = [d["flood_conns"]       for d in prot]
    p_auths   = [d["auth_packets_sent"] for d in prot]
    p_lat     = [d["legit_latency_ms"]  for d in prot if d["legit_latency_ms"] > 0]
    p_success = [d["legit_success"]     for d in prot]
    p_cpu_d   = [d["cpu_after"] - d["cpu_before"] for d in prot]
    p_mem     = [d["mem_kb"]            for d in prot]

    print("  PROTECTED MQTT (Rate Limited, AUTH Blocked)")
    print("  " + "-" * 52)
    print(f"    Managed connections:           {sum(p_conns)}")
    print(f"    Conns / iteration (avg):       {statistics.mean(p_conns):.1f}")
    print(f"    AUTH packets sent:             {sum(p_auths)} (0 = all blocked)")
    if p_lat:
        m, s = fmt(p_lat)
        print(f"    Legit client latency:          {m:.3f} ± {s:.3f} ms")
    else:
        print(f"    Legit client latency:          ALL FAILED")
    sr = sum(p_success) / len(p_success) * 100
    print(f"    Legit success rate:            {sum(p_success)}/{len(p_success)} ({sr:.0f}%)")
    if p_cpu_d:
        print(f"    CPU delta (avg):               {statistics.mean(p_cpu_d):.2f}%")
    print(f"    Memory range:                  {min(p_mem)}–{max(p_mem)} KB")
    print(f"    Memory growth:                 {p_mem[-1] - p_mem[0]} KB")
    print()

    # ── Comparison ───────────────────────────────────────────────────────
    print("  COMPARISON")
    print("  " + "-" * 52)

    v_lat_avg = statistics.mean(v_lat) if v_lat else -1
    p_lat_avg = statistics.mean(p_lat) if p_lat else -1

    if v_lat_avg > 0 and p_lat_avg > 0:
        lat_increase = ((v_lat_avg - p_lat_avg) / p_lat_avg) * 100
        print(f"    Legit latency (vulnerable):    {v_lat_avg:.3f} ms")
        print(f"    Legit latency (protected):     {p_lat_avg:.3f} ms")
        if lat_increase > 0:
            print(f"    Latency increase under attack: +{lat_increase:.1f}%")
        else:
            print(f"    Latency difference:            {lat_increase:.1f}%")
    else:
        lat_increase = 0

    v_sr = sum(v_success) / len(v_success) * 100
    p_sr = sum(p_success) / len(p_success) * 100
    print(f"    Success rate (vulnerable):     {v_sr:.0f}%")
    print(f"    Success rate (protected):      {p_sr:.0f}%")

    conn_reduction = sum(v_conns) - sum(p_conns)
    print(f"    Connection reduction:          {conn_reduction} fewer flood conns")
    print(f"    AUTH packets (vulnerable):     {sum(v_auths)}")
    print(f"    AUTH packets (protected):      {sum(p_auths)}")

    v_mem_g = v_mem[-1] - v_mem[0]
    p_mem_g = p_mem[-1] - p_mem[0]
    print(f"    Memory growth (vulnerable):    {v_mem_g} KB")
    print(f"    Memory growth (protected):     {p_mem_g} KB")
    print()

    # ── Per-iteration detail ─────────────────────────────────────────────
    print("  ITERATION-BY-ITERATION")
    print("  " + "-" * 52)
    hdr = (f"  {'It':>3}  {'Conns':>6} {'AUTH':>6} {'Legit(ms)':>10} "
           f"{'OK':>3} {'CPU%':>6} {'Mem':>7}  |  "
           f"{'Conns':>6} {'Legit(ms)':>10} {'OK':>3} {'Mem':>7}")
    print(hdr)
    print(f"       {'── VULNERABLE ──':^36}  |  {'── PROTECTED ──':^28}")
    for v, p in zip(vuln, prot):
        cd = v["cpu_after"] - v["cpu_before"]
        print(f"  {v['iteration']:3d}  {v['flood_conns']:6d} {v['auth_packets_sent']:6d} "
              f"{v['legit_latency_ms']:10.3f} {v['legit_success']:3d} {cd:6.1f} "
              f"{v['mem_kb']:7d}  |  "
              f"{p['flood_conns']:6d} {p['legit_latency_ms']:10.3f} "
              f"{p['legit_success']:3d} {p['mem_kb']:7d}")
    print()

    # ── Verdict ──────────────────────────────────────────────────────────
    print("  SECURITY VERDICT")
    print("  " + "-" * 52)
    if sum(v_auths) > 0:
        print(f"    VULNERABILITY CONFIRMED: {sum(v_auths)} AUTH packets flooded")
        print(f"    the broker across {sum(v_conns)} connections in {len(vuln)} iterations.")
    if v_lat_avg > 0 and p_lat_avg > 0 and lat_increase > 20:
        print(f"    DOS IMPACT: Legit latency increased by {lat_increase:.0f}% under attack.")
    if v_sr < 100:
        print(f"    SERVICE DEGRADATION: {100 - v_sr:.0f}% of legit attempts FAILED.")
    if p_sr == 100 and p_lat_avg > 0:
        print(f"    PROTECTION EFFECTIVE: All legit clients succeeded ({p_lat_avg:.3f} ms).")
        print(f"    Rate limiting + AUTH blocking fully mitigates the attack.")
    print()
    print("=" * 70)


if __name__ == "__main__":
    analyze()
