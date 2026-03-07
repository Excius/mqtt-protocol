"""
Analyze user property injection attack results.
Compare vulnerable (no validation) vs protected (with validation) MQTT.

CSV format: iteration,packets_sent,packets_rejected,cpu_before,cpu_after,mem_kb
"""
import csv
from pathlib import Path
import statistics

DIR = Path(__file__).parent


def load_csv(filename):
    """Load CSV results into list of dicts."""
    data = []
    filepath = DIR / filename
    if not filepath.exists():
        return data
    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append({
                "iteration": int(row["iteration"]),
                "packets_sent": int(row["packets_sent"]),
                "packets_rejected": int(row["packets_rejected"]),
                "cpu_before": float(row["cpu_before"]),
                "cpu_after": float(row["cpu_after"]),
                "mem_kb": int(row["mem_kb"]),
            })
    return data


def analyze():
    vuln = load_csv("results_vulnerable.csv")
    prot = load_csv("results_protected.csv")

    if not vuln:
        print("No vulnerable results found. Run: bash run.sh")
        return
    if not prot:
        print("No protected results found. Run: bash run.sh")
        return

    vuln_sent = [d["packets_sent"] for d in vuln]
    vuln_rejected = [d["packets_rejected"] for d in vuln]
    vuln_mem = [d["mem_kb"] for d in vuln]
    vuln_cpu = [d["cpu_after"] - d["cpu_before"] for d in vuln]

    prot_sent = [d["packets_sent"] for d in prot]
    prot_rejected = [d["packets_rejected"] for d in prot]
    prot_mem = [d["mem_kb"] for d in prot]
    prot_cpu = [d["cpu_after"] - d["cpu_before"] for d in prot]

    print("=" * 70)
    print("USER PROPERTY INJECTION ATTACK - RESULTS ANALYSIS")
    print("=" * 70)
    print()

    # --- Vulnerable ---
    print("VULNERABLE MQTT (No Validation)")
    print("-" * 45)
    print(f"  Packets sent (avg):     {statistics.mean(vuln_sent):.1f}")
    print(f"  Packets sent (total):   {sum(vuln_sent)}")
    print(f"  Packets rejected:       {sum(vuln_rejected)} (no validation)")
    print(f"  Memory start:           {vuln_mem[0]} KB")
    print(f"  Memory end:             {vuln_mem[-1]} KB")
    print(f"  Memory growth:          {vuln_mem[-1] - vuln_mem[0]} KB")
    print(f"  Memory peak:            {max(vuln_mem)} KB")
    if statistics.mean(vuln_cpu) > 0:
        print(f"  CPU delta (avg):        {statistics.mean(vuln_cpu):.2f}%")
    print()

    # --- Protected ---
    print("PROTECTED MQTT (With Validation)")
    print("-" * 45)
    print(f"  Packets sent (avg):     {statistics.mean(prot_sent):.1f}")
    print(f"  Packets sent (total):   {sum(prot_sent)}")
    print(f"  Packets rejected:       {sum(prot_rejected)} (blocked by validation)")
    print(f"  Memory start:           {prot_mem[0]} KB")
    print(f"  Memory end:             {prot_mem[-1]} KB")
    print(f"  Memory growth:          {prot_mem[-1] - prot_mem[0]} KB")
    print(f"  Memory peak:            {max(prot_mem)} KB")
    if statistics.mean(prot_cpu) > 0:
        print(f"  CPU delta (avg):        {statistics.mean(prot_cpu):.2f}%")
    print()

    # --- Comparison ---
    print("COMPARISON")
    print("-" * 45)

    vuln_growth = vuln_mem[-1] - vuln_mem[0]
    prot_growth = prot_mem[-1] - prot_mem[0]

    print(f"  Memory growth (vulnerable):  {vuln_growth} KB")
    print(f"  Memory growth (protected):   {prot_growth} KB")

    if vuln_growth > 0 and prot_growth >= 0:
        if prot_growth == 0:
            print(f"  Memory reduction:            100% (protected: zero growth)")
        else:
            reduction = ((vuln_growth - prot_growth) / vuln_growth) * 100
            print(f"  Memory reduction:            {reduction:.1f}%")

    total_vuln_sent = sum(vuln_sent)
    total_prot_sent = sum(prot_sent)
    total_prot_rejected = sum(prot_rejected)

    print(f"  Total packets to broker (vuln):  {total_vuln_sent}")
    print(f"  Total packets to broker (prot):  {total_prot_sent}")
    print(f"  Total attack packets blocked:    {total_prot_rejected}")

    if total_vuln_sent > 0:
        attack_block_rate = (total_prot_rejected / (total_prot_sent + total_prot_rejected)) * 100
        print(f"  Attack block rate:               {attack_block_rate:.1f}%")
    print()

    # --- Memory trend ---
    print("MEMORY TREND (KB)")
    print("-" * 45)
    print(f"  {'Iter':<6} {'Vulnerable':<14} {'Protected':<14} {'Delta':<10}")
    for v, p in zip(vuln, prot):
        delta = v["mem_kb"] - p["mem_kb"]
        marker = " <<<" if delta > 1000 else ""
        print(f"  {v['iteration']:<6} {v['mem_kb']:<14} {p['mem_kb']:<14} {delta:<10}{marker}")
    print()

    # --- Verdict ---
    print("SECURITY VERDICT")
    print("-" * 45)
    if vuln_growth > 1000:
        print(f"  VULNERABILITY CONFIRMED: Broker memory grew {vuln_growth}KB")
        print(f"  under attack without validation.")
    elif vuln_growth > 100:
        print(f"  VULNERABILITY DETECTED: Moderate memory growth ({vuln_growth}KB)")
    else:
        print(f"  NOTE: Memory growth was minimal ({vuln_growth}KB).")
        print(f"  Broker may be discarding properties quickly.")

    if prot_growth < 100:
        print(f"  PROTECTION EFFECTIVE: Memory stayed stable ({prot_growth}KB growth)")
        print(f"  with {total_prot_rejected} attack packets blocked.")
    else:
        print(f"  WARNING: Protected broker still grew {prot_growth}KB")

    print()
    print("=" * 70)


if __name__ == "__main__":
    analyze()
