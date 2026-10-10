#!/usr/bin/env python3
"""Local HTTP /ready load smoke benchmark, never a production JWT benchmark."""
import argparse
import concurrent.futures
import json
import math
import platform
import statistics
import time
import urllib.parse
import urllib.request


def percentile(values, n):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * n / 100) - 1)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:3000")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--output", default="benchmark-results.json")
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        parser.error("only local HTTP targets are permitted")
    if not 20 <= args.requests <= 10000 or not 1 <= args.concurrency <= 64:
        parser.error("requests must be 20..10000 and concurrency 1..64")
    target = args.url.rstrip("/") + "/ready"

    def request(_):
        start = time.perf_counter()
        with urllib.request.urlopen(target, timeout=5) as response:
            response.read(512)
            status = response.status
        return (time.perf_counter() - start) * 1000, status

    for i in range(5):
        if request(i)[1] != 200:
            raise RuntimeError("/ready warmup returned non-200")
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        results = list(executor.map(request, range(args.requests)))
    elapsed = time.perf_counter() - start
    if any(status != 200 for _, status in results):
        raise RuntimeError("non-200 response in the benchmark")
    samples = [value for value, _ in results]
    summary = {
        "route": "GET /ready (PostgreSQL and Redis)",
        "warning": "Local smoke benchmark only; does not measure authentication throughput",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "requests": args.requests,
        "concurrency": args.concurrency,
        "errors": 0,
        "duration_seconds": round(elapsed, 3),
        "throughput_rps": round(args.requests / elapsed, 2),
        "latency_ms": {
            "mean": round(statistics.mean(samples), 2),
            "p50": round(percentile(samples, 50), 2),
            "p95": round(percentile(samples, 95), 2),
            "p99": round(percentile(samples, 99), 2),
            "max": round(max(samples), 2),
        },
    }
    with open(args.output, "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)
        file.write("\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
