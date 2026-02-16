import time
import json
from pathlib import Path

def timed(fn):
    start = time.perf_counter()
    result = fn()
    end = time.perf_counter()
    return result, (end - start) * 1000  # ms

def size_bytes(obj):
    return len(json.dumps(obj).encode("utf-8"))

def append_csv(row, path="experiments/results/results.csv"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    header = not Path(path).exists()
    with open(path, "a") as f:
        if header:
            f.write(",".join(row.keys()) + "\n")
        f.write(",".join(str(v) for v in row.values()) + "\n")
