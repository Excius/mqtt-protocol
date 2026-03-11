"""
Analyze User Property Injection attack results — Broker-Side Proxy Protection.

Compares vulnerable (direct to broker) vs protected (through proxy).

Vulnerable CSV:
  iteration,packets_sent,packets_rejected,cpu_before,cpu_after,mem_kb

Protected CSV:
  iteration,packets_forwarded,packets_dropped,cpu_before,cpu_after,mem_kb
"""

import csv
from pathlib import Path
import statistics

DIR = Path(__file__).parent


def load_csv(filename, col_map):
    """Load CSV with column name mapping."""
    data = []
    fp = DIR / filename
    if not fp.exists():
        return data
    with open(fp) as f:
        for row in csv.DictReader(f):
            d = {}
            for key, conv in col_map.items():
                d[key] = conv(row[key])
            data.append(d)
    return data


def analyze():
    vuln = load_csv("results_vulnerable.csv", {
        "iteration": int,
        "packets_sent": int,
        "packets_rejected": int,
        "cpu_before": float,
        "cpu_after": float,
        "mem_kb": int,
    })
    prot = load_csv("results_protected.csv", {
        "iteration": int,
        "packets_forwarded": int,
        "packets_dropped": int,
        "cpu_before": float,
        "cpu_after": float,
        "mem_kb": int,
    })

    if not vuln:
        print("No vulnerable results found. Run: bash run.sh")
        return
    if not prot:
        print("No protected results found. Run: bash run.sh")
        return

    print("=" * 70)
    print("  USER PROPERTY INJECTION — BROKER-SIDE PROXY RESULTS")
    print("=" * 70)
    print()

    # ── Vulnerable ───────────────────────────────────────────────────────
    vuln_sent = [d["packets_sent"] for d in vuln]
    vuln_mem  = [d["mem_kb"]       for d in vuln]

    print("  VULNERABLE (Direct to Mosquitto, No Proxy)")
    print("  " + "-" * 52)
    print(f"    Total packets sent:       {sum(vuln_sent)} (all reach broker)")
    print(f"    Avg packets/iteration:    {statistics.mean(vuln_sent):.1f}")
    print(f"    Packets rejected:         0 (no protection)")
    print(f"    Memory start:             {vuln_mem[0]} KB")
    print(f"    Memory end:               {vuln_mem[-1]} KB")
    print(f"    Memory growth:            +{vuln_mem[-1] - vuln_mem[0]} KB")
    print(f"    Growth/iteration:         ~{(vuln_mem[-1] - vuln_mem[0]) // len(vuln)} KB")
    print()

    # ── Protected ────────────────────────────────────────────────────────
    prot_fwd  = [d["packets_forwarded"] for d in prot]
    prot_drop = [d["packets_dropped"]   for d in prot]
    prot_mem  = [d["mem_kb"]            for d in prot]

    print("  PROTECTED (Proxy → Mosquitto, Broker-Side)")
    print("  " + "-" * 52)
    print(f"    Total forwarded:          {sum(prot_fwd)} (legitimate only)")
    print(f"    Total dropped:            {sum(prot_drop)} (attack blocked)")
    print(f"    Memory start:             {prot_mem[0]} KB")
    print(f"    Memory end:               {prot_mem[-1]} KB")
    print(f"    Memory growth:            +{prot_mem[-1] - prot_mem[0]} KB")
    total_pkts = sum(prot_fwd) + sum(prot_drop)
    if total_pkts > 0:
        block_rate = sum(prot_drop) / total_pkts * 100
        print(f"    Attack block rate:        {block_rate:.1f}%")
    print()

    # ── Comparison ───────────────────────────────────────────────────────
    print("  COMPARISON")
    print("  " + "-" * 52)

    v_growth = vuln_mem[-1] - vuln_mem[0]
    p_growth = prot_mem[-1] - prot_mem[0]

    print(f"    Memory growth (vulnerable): +{v_growth} KB")
    print(f"    Memory growth (protected):  +{p_growth} KB")
    if v_growth > 0:
        reduction = ((v_growth - p_growth) / v_growth) * 100
        print(f"    Memory reduction:           {reduction:.1f}%")
    print(f"    Total packets to broker:    {sum(vuln_sent)} (vuln) vs {sum(prot_fwd)} (prot)")
    print(f"    Attack packets blocked:     {sum(prot_drop)}")
    print()

    # ── Memory trend ─────────────────────────────────────────────────────
    print("  MEMORY TREND (KB)")
    print("  " + "-" * 52)
    print(f"  {'Iter':<6} {'Vulnerable':<14} {'Protected':<14} {'Savings':<12}")
    for v, p in zip(vuln, prot):
        delta = v["mem_kb"] - p["mem_kb"]
        print(f"  {v['iteration']:<6} {v['mem_kb']:<14} {p['mem_kb']:<14} {delta:<12}")
    print()

    # ── Verdict ──────────────────────────────────────────────────────────
    print("  SECURITY VERDICT")
    print("  " + "-" * 52)
    if v_growth > 1000:
        print(f"    VULNERABILITY CONFIRMED: Broker memory grew +{v_growth} KB")
        print(f"    ({v_growth // 1024} MB) under sustained injection attack.")
    if p_growth < 500:
        print(f"    PROTECTION EFFECTIVE: Proxy reduced growth to +{p_growth} KB")
        print(f"    and blocked {sum(prot_drop)} attack packets.")
    print()
    print("=" * 70)


if __name__ == "__main__":
    analyze()
