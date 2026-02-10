import time
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 8883
CAFILE = "certs/ca.crt"


def connect_once():
    c = mqtt.Client(protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    c.tls_set(ca_certs=CAFILE)
    start = time.perf_counter()
    c.connect(BROKER, PORT)
    c.disconnect()
    return (time.perf_counter() - start) * 1000


if __name__ == "__main__":
    print(connect_once())
