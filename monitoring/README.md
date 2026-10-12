# SecureShip Observability & Monitoring

This directory contains Prometheus and Grafana configurations to monitor the health, request latency, and security pipeline telemetry of SecureShip.

## 1. Exposed Metrics

SecureShip's FastAPI backend natively exposes Prometheus metrics at:
`http://localhost:8000/metrics`

Key metrics monitored:
- `http_requests_total`: Total API requests partitioned by route, method, and status code.
- `http_request_duration_seconds`: Histogram of API latency and P95/P99 percentiles.
- `python_gc_collections_total`: Memory and garbage collection activity.
- `process_resident_memory_bytes`: Memory consumption.

## 2. Running Prometheus & Grafana Locally

You can launch Prometheus using the provided config:
```bash
prometheus --config.file=monitoring/prometheus/prometheus.yml
```

Or run both in containers:
```bash
docker run -d -p 9090:9090 -v $(pwd)/monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus
docker run -d -p 3000:3000 grafana/grafana
```

Import the dashboard JSON located at `monitoring/grafana/dashboards/secureship_dashboard.json` into Grafana to view real-time charts.
