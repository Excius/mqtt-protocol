import time
import sys
import paho.mqtt.client as mqtt


def run(duration):
    c = mqtt.Client(protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    c.tls_set(ca_certs="/etc/mosquitto/certs/ca.crt")
    c.connect("localhost", 8883)
    time.sleep(duration)
    c.disconnect()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
        run(duration)
