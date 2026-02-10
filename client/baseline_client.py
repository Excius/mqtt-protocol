import time
import paho.mqtt.client as mqtt

client = mqtt.Client(
    protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2
)
client.tls_set(ca_certs="certs/ca.crt")

start = time.time()
client.connect("localhost", 8883)
end = time.time()

print("TLS Handshake Time:", end - start)
client.disconnect()
