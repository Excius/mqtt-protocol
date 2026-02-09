import time
import paho.mqtt.client as mqtt


def worker(results, idx, cafile):
    c = mqtt.Client(protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    c.tls_set(ca_certs=cafile)
    start = time.perf_counter()
    try:
        c.connect("localhost", 8883)
        c.disconnect()
        results[idx] = (time.perf_counter() - start) * 1000
    except:
        results[idx] = -1
