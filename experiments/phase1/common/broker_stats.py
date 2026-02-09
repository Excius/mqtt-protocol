import subprocess


def get_broker_stats():
    pid = subprocess.check_output(["pidof", "mosquitto"]).decode().strip()
    cpu = subprocess.check_output(["ps", "-p", pid, "-o", "%cpu="]).decode().strip()
    mem = subprocess.check_output(["ps", "-p", pid, "-o", "rss="]).decode().strip()
    return float(cpu), int(mem)
