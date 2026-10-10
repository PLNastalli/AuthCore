# Local performance smoke tests

The standard-library-only benchmark measures the response time of **GET /ready**,
which queries PostgreSQL and Redis. This does **not** measure login, password
hashing, JWT signing, token refresh or real production throughput.

Run with a local development server:

```bash
python3 scripts/benchmark.py --url http://127.0.0.1:3000 --requests 200 --concurrency 8
```

The JSON result includes throughput, concurrent clients, failures and p50/p95/p99
latencies. The script rejects external URLs to avoid accidental load testing
of production services.

GitHub Actions runs a 100-request variant and uploads the JSON as an artifact
named `authcore-readiness-benchmark`. Results on shared CI runners are only
reproducible smoke evidence; to compare production performance, use a dedicated
test host, release configuration and a representative authentication workload.
