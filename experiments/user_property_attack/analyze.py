"""
Analyze User Property Injection attack results — Multi-Vector proxy protection.

Compares vulnerable (direct to broker) vs protected (through proxy).

Vulnerable CSV:
  iteration,normal_sent,vt1_sent,vt2_sent,vt3_sent,vt4_sent,vt5_sent,
  total_sent,cpu_before,cpu_after,mem_kb

Protected CSV:
  iteration,packets_forwarded,packets_dropped,prop_count_drops,key_size_drops,
  val_size_drops,payload_drops,budget_drops,cpu_before,cpu_after,mem_kb
"""

import csv
from pathlib import Path
import statistics

DIR = Path(__file__).parent


def load_csv(filename, col_map):
    """Load CSV with column name → type mapping, skip missing keys gracefully."""
    data = []
    fp = DIR / filename
    if not fp.exists():
        return data
    with open(fp) as f:
        for row in csv.DictReader(f):
            d = {}
            for key, conv in col_map.items():
                d[key] = conv(row[key]) if key in row else conv(0)
            data.append(d)
    return data


def analyze():
    vuln = load_csv("results_vulnerable.csv", {
        "iteration":    int,
        "normal_sent":  int,
        "vt1_sent":     int,
        "vt2_sent":     int,
        "vt3_sent":     int,
        "vt4_sent":     int,
        "vt5_sent":     int,
        "total_sent":   int,
        "cpu_before":   float,
        "cpu_after":    float,
        "mem_kb":       int,
    })
    prot = load_csv("results_protected.csv", {
        "iteration":          int,
        "packets_forwarded":  int,
        "packets_dropped":    int,
        "prop_count_drops":   int,
        "key_size_drops":     int,
        "val_size_drops":     int,
        "payload_drops":      int,
        "budget_drops":       int,
        "cpu_before":         float,
        "cpu_after":          float,
        "mem_kb":             int,
    })

    if not vuln:
        print("No vulnerable results found. Run: bash run.sh")
        return
    if not prot:
        print("No protected results found. Run: bash run.sh")
        return

    print("=" * 70)
    print("  USER PROPERTY INJECTION — MULTI-VECTOR PROXY PROTECTION RESULTS")
    print("=" * 70)
    print()

    # ── Vulnerable ───────────────────────────────────────────────────────
    vuln_total  = [d["total_sent"] for d in vuln]
    vuln_normal = [d["normal_sent"] for d in vuln]
    vuln_vt1    = [d["vt1_sent"]   for d in vuln]
    vuln_vt2    = [d["vt2_sent"]   for d in vuln]
    vuln_vt3    = [d["vt3_sent"]   for d in vuln]
    vuln_vt4    = [d["vt4_sent"]   for d in vuln]
    vuln_vt5    = [d["vt5_sent"]   for d in vuln]
    vuln_mem    = [d["mem_kb"]     for d in vuln]

    print("  VULNERABLE (Direct to Mosquitto, No Proxy)")
    print("  " + "-" * 52)
    print(f"    Total packets sent:         {sum(vuln_total)} (all reach broker)")
    print(f"    Avg total/iteration:        {statistics.mean(vuln_total):.1f}")
    print(f"    Normal packets:             {sum(vuln_normal)}")
    print(f"    VT-1 count overflow:        {sum(vuln_vt1)}")
    print(f"    VT-2 key size overflow:     {sum(vuln_vt2)}")
    print(f"    VT-3 value size overflow:   {sum(vuln_vt3)}")
    print(f"    VT-4 payload overflow:      {sum(vuln_vt4)}")
    print(f"    VT-5 budget exhaustion:     {sum(vuln_vt5)}")
    print(f"    Memory start:               {vuln_mem[0]} KB")
    print(f"    Memory end:                 {vuln_mem[-1]} KB")
    print(f"    Memory growth:              +{vuln_mem[-1] - vuln_mem[0]} KB")
    print()

    # ── Protected ────────────────────────────────────────────────────────
    prot_fwd       = [d["packets_forwarded"] for d in prot]
    prot_drop      = [d["packets_dropped"]   for d in prot]
    prot_cnt_drops = [d["prop_count_drops"]  for d in prot]
    prot_key_drops = [d["key_size_drops"]    for d in prot]
    prot_val_drops = [d["val_size_drops"]    for d in prot]
    prot_pay_drops = [d["payload_drops"]     for d in prot]
    prot_bgt_drops = [d["budget_drops"]      for d in prot]
    prot_mem       = [d["mem_kb"]            for d in prot]

    print("  PROTECTED (Proxy → Mosquitto, Broker-Side)")
    print("  " + "-" * 52)
    print(f"    Total forwarded:            {sum(prot_fwd)}")
    print(f"    Total dropped:              {sum(prot_drop)}")
    print(f"      Rule 1 (count drops):     {sum(prot_cnt_drops)}")
    print(f"      Rule 2 (key size drops):  {sum(prot_key_drops)}")
    print(f"      Rule 3 (val size drops):  {sum(prot_val_drops)}")
    print(f"      Rule 4 (payload drops):   {sum(prot_pay_drops)}")
    print(f"      Rule 5 (budget drops):    {sum(prot_bgt_drops)}")
    print(f"    Memory start:               {prot_mem[0]} KB")
    print(f"    Memory end:                 {prot_mem[-1]} KB")
    print(f"    Memory growth:              +{prot_mem[-1] - prot_mem[0]} KB")
    total_pkts = sum(prot_fwd) + sum(prot_drop)
    if total_pkts > 0:
        block_rate = sum(prot_drop) / total_pkts * 100
        print(f"    Attack block rate:          {block_rate:.1f}%")
    print()

    # ── Per-iteration drop breakdown ─────────────────────────────────────
    print("  PER-ITERATION DROP BREAKDOWN")
    print("  " + "-" * 70)
    hdr = f"  {'Iter':<5} {'Fwd':<6} {'Drop':<6} {'Cnt':<5} {'Key':<5} {'Val':<5} {'Pay':<5} {'Bgt':<5} {'MemKB':<8}"
    print(hdr)
    print("  " + "-" * 70)
    for p in prot:
        print(
            f"  {p['iteration']:<5} "
            f"{p['packets_forwarded']:<6} "
            f"{p['packets_dropped']:<6} "
            f"{p['prop_count_drops']:<5} "
            f"{p['key_size_drops']:<5} "
            f"{p['val_size_drops']:<5} "
            f"{p['payload_drops']:<5} "
            f"{p['budget_drops']:<5} "
            f"{p['mem_kb']:<8}"
        )
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
    print(f"    Packets to broker: {sum(vuln_total)} (vuln) vs {sum(prot_fwd)} (prot)")
    print(f"    Attack packets blocked:     {sum(prot_drop)}")
    print()

    # ── Verdict ──────────────────────────────────────────────────────────
    print("  SECURITY VERDICT")
    print("  " + "-" * 52)
    if v_growth > 1000:
        print(f"    VULNERABILITY CONFIRMED: Broker memory grew +{v_growth} KB")
        print(f"    ({v_growth // 1024:.1f} MB) under sustained multi-vector injection.")
    if p_growth < v_growth:
        print(f"    PROTECTION EFFECTIVE: Proxy reduced growth to +{p_growth} KB.")
        print(f"    Blocked {sum(prot_drop)} attack packets across 5 rule categories.")
    # Show which rules provided the most protection
    rule_labels = [
        ("VT-1 count ", sum(prot_cnt_drops)),
        ("VT-2 key   ", sum(prot_key_drops)),
        ("VT-3 value ", sum(prot_val_drops)),
        ("VT-4 payload", sum(prot_pay_drops)),
        ("VT-5 budget", sum(prot_bgt_drops)),
    ]
    if any(v > 0 for _, v in rule_labels):
        print()
        print("    Drops by rule:")
        for label, count in sorted(rule_labels, key=lambda x: -x[1]):
            bar = "#" * min(count, 40)
            print(f"      {label:<14} {count:>4}  {bar}")
    print()
    print("=" * 70)


if __name__ == "__main__":
    analyze()
