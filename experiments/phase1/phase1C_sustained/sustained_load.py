"""
Phase 1C: Sustained load test.
Measures TLS cert handshake latency and broker stats over time
under continuous 1-connection-per-second load.
"""
import argparse
import csv
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.measurement import TLSHandshakeMeasurer, CPUMonitor

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"

CAFILE = str(CERTS_DIR / "ca.crt")
CERTFILE = str(CERTS_DIR / "server.crt")
KEYFILE = str(CERTS_DIR / "server.key")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--interval", type=float, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    measurer = TLSHandshakeMeasurer("localhost", 8883)
    start = time.time()
    count = 0

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["elapsed_sec", "handshake_ms", "cpu_percent", "mem_kb"])

        while time.time() - start < args.duration:
            try:
                handshake_ms = measurer.measure_cert_handshake(CAFILE, CERTFILE, KEYFILE)
                cpu, mem = CPUMonitor.get_broker_stats()
                elapsed = int(time.time() - start)

                writer.writerow([elapsed, f"{handshake_ms:.3f}", f"{cpu:.1f}", mem])
                f.flush()
                count += 1

                if count % 10 == 0:
                    print(f"  {elapsed}s: {handshake_ms:.3f}ms, cpu={cpu:.1f}%, mem={mem}KB")

            except Exception as e:
                print(f"  Error: {e}", file=sys.stderr)

            time.sleep(args.interval)

    print(f"  Total handshakes: {count}")


if __name__ == "__main__":
    main()

