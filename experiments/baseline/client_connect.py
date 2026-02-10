import warnings
import time
import paho.mqtt.client as mqtt

warnings.filterwarnings("ignore", category=DeprecationWarning, module="paho.mqtt")

BROKER = "localhost"
PORT = 8883
CAFILE = "certs/ca.crt"


def measure_handshake():
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv5)

    client.tls_set(ca_certs=CAFILE)

    start = time.perf_counter()
    client.connect(BROKER, PORT, clean_start=mqtt.MQTT_CLEAN_START_FIRST_ONLY)
    client.disconnect()
    end = time.perf_counter()

    return (end - start) * 1000  # ms


if __name__ == "__main__":
    print(f"{measure_handshake():.3f}")
