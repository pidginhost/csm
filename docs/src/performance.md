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

The findings list also exposes admin-only fixes, per-row and as a **Bulk fix**
dropdown that applies one fix to every matching finding at once:

- `perf_error_logs`: truncate a bloated `error_log` in place. The inode is
  preserved so running PHP processes keep writing to the same file.
- `perf_wp_config`: disable `display_errors` in `.user.ini`, `php.ini`, or
  `.htaccess` by commenting the matched line and appending an Off override.
- `perf_wp_cron`: add `define('DISABLE_WP_CRON', true)` to `wp-config.php`
  and install a per-user system cron that runs `wp-cron.php` on a fixed
  interval. Disabling WP-Cron alone would stop scheduled WordPress tasks, so
  the cron is installed in the account owner's own crontab (visible and
  editable by the customer). The define is inserted before the
  "stop editing" marker (or the `wp-settings.php` require); the fix refuses a
  `wp-config.php` with no safe insertion point rather than corrupt it.

These actions are limited to configured account roots, reject symlinks and
unsupported file types, and remove the fixed row from the active findings
view after a successful edit.

### WP-Cron fix settings

Tune the WP-Cron remediation under **Settings -> Performance**:

- `performance.wp_cron_fix.interval_minutes` (default `5`, range 1-60): how
  often the installed system cron runs `wp-cron.php`. 5 minutes balances
  scheduled-task responsiveness against the load that HTTP-triggered WP-Cron
  creates.
- `performance.wp_cron_fix.php_bin` (default empty = auto-detect): the PHP
  interpreter for the cron line. CLI php is used instead of an HTTP request so
  the job never ties up a web worker.

To let the daemon apply this fix automatically on every WP-Cron finding, set
`auto_response.fix_wp_cron: true` (default `false`; requires
`auto_response.enabled: true`). It is opt-in because it edits customer
`wp-config.php` files and crontabs.

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

### Redis telemetry auth

The Redis panel connects to local Redis at `127.0.0.1:6379`. If Redis
requires a password, set `REDISCLI_AUTH` in the csm daemon environment.
The dashboard uses that password for its in-process Redis client.

## API

```
GET /api/v1/performance    Current performance metrics snapshot
POST /api/v1/perf/fix-error-log
POST /api/v1/perf/fix-display-errors
POST /api/v1/perf/fix-wp-cron
```
