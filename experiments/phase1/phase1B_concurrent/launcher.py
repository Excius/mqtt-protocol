import multiprocessing as mp
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from .client_worker import worker
from common.cpu_sampler import sample_cpu

N = 400

if __name__ == "__main__":
    manager = mp.Manager()
    results = manager.dict()
    jobs = []

    for i in range(N):
        p = mp.Process(target=worker, args=(results, i, "certs/ca.crt"))
        jobs.append(p)
        p.start()

    for j in jobs:
        j.join()

    latencies = [v for v in results.values() if v != -1]
    print(sum(latencies) / len(latencies),",", sample_cpu())
