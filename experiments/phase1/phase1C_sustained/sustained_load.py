import argparse
import csv
import time
import sys
import os

import paho.mqtt.client as mqtt

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from common.broker_stats import get_broker_stats

parser = argparse.ArgumentParser()
parser.add_argument("--duration", type=int, required=True)
parser.add_argument("--interval", type=float, required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

CAFILE = "certs/ca.crt"

start = time.time()

with open(args.output, "a", newline="") as f:
    writer = csv.writer(f)

    while time.time() - start < args.duration:
        c = mqtt.Client(protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        c.tls_set(ca_certs=CAFILE)
        c.connect("localhost", 8883)
        c.disconnect()

        cpu, mem = get_broker_stats()
        writer.writerow([int(time.time() - start), cpu, mem])

        time.sleep(args.interval)
