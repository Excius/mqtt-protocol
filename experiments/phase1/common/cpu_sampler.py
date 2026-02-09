import time
from .broker_stats import get_broker_stats


def sample_cpu(duration=5, interval=0.2):
    samples = []
    start = time.time()
    while time.time() - start < duration:
        cpu, _ = get_broker_stats()
        samples.append(cpu)
        time.sleep(interval)
    return sum(samples) / len(samples)
