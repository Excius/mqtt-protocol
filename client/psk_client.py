import time
import psutil
import paho.mqtt.client as mqtt

# PSK configuration
PSK_IDENTITY = "client1"
PSK_KEY = "96cfb86578129e445587e77eaaeded7b"  # From psk.txt

client = mqtt.Client(
    protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2
)
# Set TLS with PSK instead of certificates
client.tls_psk_set(psk=PSK_KEY, psk_identity=PSK_IDENTITY)

# Measure initial CPU and memory
initial_cpu = psutil.cpu_percent(interval=0.1)
initial_mem = psutil.virtual_memory().used / (1024 * 1024)  # MB

print("Starting initial connection...")
start = time.time()
try:
    client.connect("localhost", 8883)
    end = time.time()
except Exception as e:
    print(f"Connection failed: {e}")
    exit(1)

# Measure post-connect CPU and memory
post_cpu = psutil.cpu_percent(interval=0.1)
post_mem = psutil.virtual_memory().used / (1024 * 1024)  # MB

handshake_time = end - start
cpu_usage = post_cpu - initial_cpu  # Approximate delta
mem_usage = post_mem - initial_mem  # Approximate delta

print(f"TLS Handshake Time: {handshake_time:.4f} s")
print(f"CPU Usage During Handshake: {cpu_usage:.2f} %")
print(f"Memory Usage Delta: {mem_usage:.2f} MB")

# Test reconnection (for session resumption)
client.disconnect()

# Reconnect to measure resumption latency
start_reconnect = time.time()
try:
    client.connect("localhost", 8883)
    end_reconnect = time.time()
except Exception as e:
    print(f"Reconnection failed: {e}")
    exit(1)

rjjnnneconnect_time = end_reconnect - start_reconnect
print(f"Reconnection Time (with resumption): {reconnect_time:.4f} s")

client.disconnect()
