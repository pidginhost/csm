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

### MySQL telemetry auth

The MySQL panel runs `mysql -e "SHOW STATUS LIKE 'Threads_connected'"` from
the csm process. The client needs to authenticate against the local server,
and csm supports two setups out of the box:

- A `~/.my.cnf` for the csm runtime user with credentials for a MySQL
  account that holds at least the `PROCESS` privilege. cPanel and
  CloudLinux ship `/root/.my.cnf` for the root user; csm running as root
  picks it up automatically.
- A unix-socket grant for the csm OS user, e.g. on Debian/Ubuntu MariaDB:

  ```sql
  CREATE USER 'root'@'localhost' IDENTIFIED VIA unix_socket;
  GRANT PROCESS ON *.* TO 'root'@'localhost';
  ```

If neither is configured, the MYSQL card renders `n/a / n/a` instead of a
misleading `0 conn`. csm makes no attempt to connect over TCP or store
credentials on its own.

## API

```
GET /api/v1/performance    Current performance metrics snapshot
```
