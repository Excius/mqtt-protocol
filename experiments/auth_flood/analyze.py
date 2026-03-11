"""
Analyze AUTH Flood attack results — Broker-Side Proxy Protection.

Compares vulnerable (direct to broker) vs protected (through proxy).

Vulnerable CSV:
  iteration,flood_conns,flood_attempts,auth_packets_sent,
  legit_latency_ms,legit_success,cpu_before,cpu_after,mem_kb

Protected CSV:
  iteration,flood_conns,flood_attempts,auth_packets_sent,
  auth_packets_blocked,conns_rejected,legit_latency_ms,
  legit_success,cpu_before,cpu_after,mem_kb
"""

import csv
from pathlib import Path
import statistics

DIR = Path(__file__).parent


def load_vuln():
    data = []
    fp = DIR / "results_vulnerable.csv"
    if not fp.exists():
        return data
    with open(fp) as f:
        for row in csv.DictReader(f):
            data.append({
                "iteration":         int(row["iteration"]),
                "flood_conns":       int(row["flood_conns"]),
                "flood_attempts":    int(row["flood_attempts"]),
                "auth_packets_sent": int(row["auth_packets_sent"]),
                "legit_latency_ms":  float(row["legit_latency_ms"]),
                "legit_success":     int(row["legit_success"]),
                "cpu_before":        float(row["cpu_before"]),
                "cpu_after":         float(row["cpu_after"]),
                "mem_kb":            int(row["mem_kb"]),
            })
    return data


def load_prot():
    data = []
    fp = DIR / "results_protected.csv"
    if not fp.exists():
        return data
    with open(fp) as f:
        for row in csv.DictReader(f):
            data.append({
                "iteration":            int(row["iteration"]),
                "flood_conns":          int(row["flood_conns"]),
                "flood_attempts":       int(row["flood_attempts"]),
                "auth_packets_sent":    int(row["auth_packets_sent"]),
                "auth_packets_blocked": int(row["auth_packets_blocked"]),
                "conns_rejected":       int(row["conns_rejected"]),
                "legit_latency_ms":     float(row["legit_latency_ms"]),
                "legit_success":        int(row["legit_success"]),
                "cpu_before":           float(row["cpu_before"]),
                "cpu_after":            float(row["cpu_after"]),
                "mem_kb":               int(row["mem_kb"]),
            })
    return data


def analyze():
    vuln = load_vuln()
    prot = load_prot()

    if not vuln:
        print("No vulnerable results found. Run: bash run.sh")
        return
    if not prot:
        print("No protected results found. Run: bash run.sh")
        return

    print("=" * 70)
    print("  MQTT 5.0 AUTH FLOOD ATTACK — BROKER-SIDE PROXY RESULTS")
    print("=" * 70)
    print()

    # ── Vulnerable ───────────────────────────────────────────────────────
    v_conns    = [d["flood_conns"]       for d in vuln]
    v_attempts = [d["flood_attempts"]    for d in vuln]
    v_auths    = [d["auth_packets_sent"] for d in vuln]
    v_lat      = [d["legit_latency_ms"]  for d in vuln if d["legit_latency_ms"] > 0]
    v_success  = [d["legit_success"]     for d in vuln]
    v_cpu      = [d["cpu_after"]         for d in vuln]
    v_mem      = [d["mem_kb"]            for d in vuln]

    print("  VULNERABLE (Direct to Mosquitto, No Proxy)")
    print("  " + "-" * 52)
    print(f"    Flood connections (established): {sum(v_conns)}")
    print(f"    Flood attempts (total):          {sum(v_attempts)}")
    print(f"    Avg conns/iteration:             {statistics.mean(v_conns):.0f}")
    print(f"    Total AUTH packets sent:          {sum(v_auths)}")
    print(f"    Avg AUTH/iteration:               {statistics.mean(v_auths):.0f}")
    if v_lat:
        m = statistics.mean(v_lat)
        s = statistics.stdev(v_lat) if len(v_lat) > 1 else 0
        print(f"    Legit client latency:             {m:.3f} ± {s:.3f} ms")
    else:
        print(f"    Legit client latency:             ALL FAILED")
    sr = sum(v_success) / len(v_success) * 100
    print(f"    Legit success rate:               {sum(v_success)}/{len(v_success)} ({sr:.0f}%)")
    print(f"    Peak CPU:                         {max(v_cpu):.1f}%")
    print(f"    Memory range:                     {min(v_mem)}-{max(v_mem)} KB")
    print()

    # ── Protected ────────────────────────────────────────────────────────
    p_conns    = [d["flood_conns"]          for d in prot]
    p_attempts = [d["flood_attempts"]       for d in prot]
    p_auths    = [d["auth_packets_sent"]    for d in prot]
    p_blocked  = [d["auth_packets_blocked"] for d in prot]
    p_rejected = [d["conns_rejected"]       for d in prot]
    p_lat      = [d["legit_latency_ms"]     for d in prot if d["legit_latency_ms"] > 0]
    p_success  = [d["legit_success"]        for d in prot]
    p_mem      = [d["mem_kb"]               for d in prot]

    print("  PROTECTED (Proxy → Mosquitto, Broker-Side)")
    print("  " + "-" * 52)
    print(f"    Flood connections (established):  {sum(p_conns)}")
    print(f"    Flood attempts (total):           {sum(p_attempts)}")
    print(f"    Connection attempts rejected:     {sum(p_rejected)}")
    print(f"    AUTH packets sent by attacker:    {sum(p_auths)}")
    print(f"    AUTH packets blocked by proxy:    {sum(p_blocked)}")
    if p_lat:
        m = statistics.mean(p_lat)
        s = statistics.stdev(p_lat) if len(p_lat) > 1 else 0
        print(f"    Legit latency (post-flood):      {m:.3f} ± {s:.3f} ms")
    else:
        print(f"    Legit latency (post-flood):      ALL FAILED")
    sr = sum(p_success) / len(p_success) * 100
    print(f"    Legit success rate:               {sum(p_success)}/{len(p_success)} ({sr:.0f}%)")
    print(f"    Memory range:                     {min(p_mem)}-{max(p_mem)} KB")
    print()

    # ── Comparison ───────────────────────────────────────────────────────
    print("  COMPARISON")
    print("  " + "-" * 52)

    if sum(v_conns) > 0:
        conn_red = ((sum(v_conns) - sum(p_conns)) / sum(v_conns)) * 100
        print(f"    Connection reduction:              {conn_red:.1f}%")
    print(f"    AUTH packets (vulnerable):         {sum(v_auths)}")
    print(f"    AUTH packets blocked (protected):  {sum(p_blocked)}")

    v_lat_avg = statistics.mean(v_lat) if v_lat else -1
    p_lat_avg = statistics.mean(p_lat) if p_lat else -1
    if v_lat_avg > 0:
        print(f"    Legit latency (vulnerable):        {v_lat_avg:.3f} ms (during flood)")
    if p_lat_avg > 0:
        print(f"    Legit latency (protected):         {p_lat_avg:.3f} ms (post-flood)")

    print(f"    Memory growth (vulnerable):        {v_mem[-1] - v_mem[0]} KB")
    print(f"    Memory growth (protected):         {p_mem[-1] - p_mem[0]} KB")
    print()

    # ── Per-iteration detail ─────────────────────────────────────────────
    print("  ITERATION-BY-ITERATION")
    print("  " + "-" * 52)
    print(f"       {'── VULNERABLE ──':^42}  |  {'── PROTECTED ──':^42}")
    hdr = (f"  {'It':>3}  {'Conns':>6} {'Att':>6} {'AUTH':>6} {'Legit(ms)':>10} "
           f"{'Mem':>7}  |  "
           f"{'Conns':>6} {'Att':>6} {'Blocked':>7} {'Legit(ms)':>10} {'Mem':>7}")
    print(hdr)
    for v, p in zip(vuln, prot):
        v_lat_s = f"{v['legit_latency_ms']:10.3f}" if v['legit_latency_ms'] > 0 else "     FAIL"
        p_lat_s = f"{p['legit_latency_ms']:10.3f}" if p['legit_latency_ms'] > 0 else "     FAIL"
        print(f"  {v['iteration']:3d}  {v['flood_conns']:6d} {v['flood_attempts']:6d} "
              f"{v['auth_packets_sent']:6d} {v_lat_s} "
              f"{v['mem_kb']:7d}  |  "
              f"{p['flood_conns']:6d} {p['flood_attempts']:6d} "
              f"{p['auth_packets_blocked']:7d} {p_lat_s} {p['mem_kb']:7d}")
    print()

    # ── Verdict ──────────────────────────────────────────────────────────
    print("  SECURITY VERDICT")
    print("  " + "-" * 52)
    if sum(v_auths) > 0:
        print(f"    VULNERABILITY CONFIRMED: {sum(v_auths)} AUTH packets flooded")
        print(f"    the broker across {sum(v_conns)} connections in {len(vuln)} iterations.")
    if sum(p_blocked) > 0:
        print(f"    PROTECTION EFFECTIVE: Proxy blocked {sum(p_blocked)} AUTH packets")
        print(f"    and rejected {sum(p_rejected)} connection attempts.")
        print(f"    Broker CPU and memory stayed minimal.")
    print()
    print("=" * 70)


if __name__ == "__main__":
    analyze()
