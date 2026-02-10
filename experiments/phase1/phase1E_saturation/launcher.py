import argparse
import multiprocessing as mp
import paho.mqtt.client as mqtt

parser = argparse.ArgumentParser()
parser.add_argument("--clients", type=int, required=True)
args = parser.parse_args()

CAFILE = "certs/ca.crt"


def try_connect(_):
    try:
        c = mqtt.Client(protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        c.tls_set(ca_certs=CAFILE)
        c.connect("localhost", 8883)
        c.disconnect()
        return 1
    except:
        return 0


pool = mp.Pool(args.clients)
results = pool.map(try_connect, range(args.clients))
pool.close()
pool.join()

success = sum(results)
failed = args.clients - success

print(f"{success},{failed}")
