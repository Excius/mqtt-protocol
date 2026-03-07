"""
Analyze session resumption results and compare against full handshakes.
"""
import csv
from pathlib import Path
import statistics

DIR = Path(__file__).parent

def analyze_results():
    """Analyze and compare new handshakes vs resumed sessions."""
    
    new_times = []
    resumed_times = []
    
    # Read new handshake results
    with open(DIR / "results_new_handshake.csv") as f:
        reader = csv.DictReader(f)
        for row in reader:
            new_times.append(float(row["handshake_ms"]))
    
    # Read resumed session results
    with open(DIR / "results_session_resumed.csv") as f:
        reader = csv.DictReader(f)
        for row in reader:
            resumed_times.append(float(row["handshake_ms"]))
    
    if not new_times or not resumed_times:
        print("No data available. Run run.sh first.")
        return
    
    # Calculate statistics
    new_mean = statistics.mean(new_times)
    new_median = statistics.median(new_times)
    new_stdev = statistics.stdev(new_times) if len(new_times) > 1 else 0
    new_min = min(new_times)
    new_max = max(new_times)
    
    resumed_mean = statistics.mean(resumed_times)
    resumed_median = statistics.median(resumed_times)
    resumed_stdev = statistics.stdev(resumed_times) if len(resumed_times) > 1 else 0
    resumed_min = min(resumed_times)
    resumed_max = max(resumed_times)
    
    # Calculate speedup
    speedup = new_mean / resumed_mean if resumed_mean > 0 else 0
    improvement_pct = ((new_mean - resumed_mean) / new_mean) * 100 if new_mean > 0 else 0
    
    print("=" * 70)
    print("SESSION RESUMPTION ANALYSIS")
    print("=" * 70)
    print()
    print("FULL HANDSHAKE TIMES (ms):")
    print(f"  Mean:     {new_mean:.3f}")
    print(f"  Median:   {new_median:.3f}")
    print(f"  Std Dev:  {new_stdev:.3f}")
    print(f"  Min:      {new_min:.3f}")
    print(f"  Max:      {new_max:.3f}")
    print()
    print("SESSION RESUMED TIMES (ms):")
    print(f"  Mean:     {resumed_mean:.3f}")
    print(f"  Median:   {resumed_median:.3f}")
    print(f"  Std Dev:  {resumed_stdev:.3f}")
    print(f"  Min:      {resumed_min:.3f}")
    print(f"  Max:      {resumed_max:.3f}")
    print()
    print("PERFORMANCE IMPROVEMENT:")
    print(f"  Speedup:       {speedup:.2f}x faster")
    print(f"  Improvement:   {improvement_pct:.1f}%")
    print(f"  Time Saved:    {new_mean - resumed_mean:.3f} ms per connection")
    print()
    print("=" * 70)


if __name__ == "__main__":
    analyze_results()
