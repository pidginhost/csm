# Performance Monitor

CSM monitors server performance metrics and generates findings when thresholds are exceeded.

## Critical Checks (every 10 min)

| Check | What it monitors |
|-------|-----------------|
| `perf_load` | CPU load average vs core count (critical/high/warning thresholds) |
| `perf_php_processes` | PHP process count and total memory usage |
| `perf_memory` | Swap usage percentage and OOM killer activity |

## Deep Checks (every 60 min)

| Check | What it monitors |
|-------|-----------------|
| `perf_php_handler` | PHP handler type (DSO vs CGI vs FPM) and configuration |
| `perf_mysql_config` | MySQL my.cnf settings (buffer pool, connections, query cache) |
| `perf_redis_config` | Redis memory limits, persistence, eviction policy |
| `perf_error_logs` | Error log file sizes (bloat detection) |
| `perf_wp_config` | WordPress wp-config.php hardening and debug settings |
| `perf_wp_transients` | WordPress database transient bloat |
| `perf_wp_cron` | WordPress cron scheduling (missed crons, excessive events) |

## Web UI

The **Performance** page (`/performance`) shows real-time metrics:
- Server load and CPU usage
- PHP process and memory charts
- MySQL and Redis health
- WordPress performance indicators

## API

```
GET /api/v1/performance    Current performance metrics snapshot
```
