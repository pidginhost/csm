# Performance Monitor

CSM monitors server performance metrics and generates findings when thresholds are exceeded.

## Critical Checks (every 10 min)

| Check | What it monitors |
|-------|-----------------|
| `perf_load` | CPU load average vs core count (critical/high/warning thresholds) |
| `perf_php_processes` | PHP process count and total memory usage |
| `perf_memory` | Swap usage percentage and OOM killer activity |

Host-wide OOM events are Critical; memory-cgroup limit events are Warning.
Both are reported when present in the last hour, with separate deduplication
identities for each scope and victim process.

## Deep Checks (default every 60 min, `thresholds.deep_scan_interval_min`)

| Check | What it monitors |
|-------|-----------------|
| `perf_php_handler` | PHP handler type (DSO vs CGI vs FPM) and configuration |
| `perf_mysql_config` | MySQL my.cnf settings (buffer pool, connections, query cache) |
| `perf_redis_config` | Redis memory limits, persistence, eviction policy |
| `perf_error_logs` | Bloated `error_log` files in every document root, with growth rate |
| `perf_wp_config` | WordPress wp-config.php hardening and debug settings |
| `perf_wp_transients` | WordPress database transient bloat |
| `perf_wp_cron` | WordPress cron scheduling (missed crons, excessive events) |
| `perf_wp_loopback` | WordPress sites calling themselves faster than WordPress's own schedulers, hour after hour |
| `perf_wp_myisam` | WordPress database tables still on the MyISAM storage engine |

### Bloated error logs

`perf_error_logs` scans the configured web roots plus every document root in
cPanel's domain map, so addon and subdomain sites are covered as well as
`public_html`. It walks three levels deep. Heavy trees such as `wp-content`,
`wp-admin` and `vendor` are not descended, but an `error_log` directly inside
one is checked: PHP writes the log next to the running script, so
`admin-ajax.php` errors land in `wp-admin/error_log`.

A log over `performance.error_log_warn_size_mb` (default 50) is a Warning and
only shows on this page. A log over `performance.error_log_critical_size_mb`
(default 1024) is High and alerts. Once a log has been seen for at least an
hour, the finding also shows how fast it grows per day. A log that shrinks or
is replaced by a new file, as on truncation or rotation, starts a new
baseline. A cancelled scan changes nothing; a scan that could not read part
of the tree keeps the logs it did not reach and updates the ones it did.

The finding keeps the same identity while the log grows, so it alerts at most
once a day and a dismissal sticks until the log crosses into the higher tier.
When more than 20 logs are bloated, the largest are reported.

### WordPress loopback requests

A WordPress site runs background work by sending a request to itself, a
loopback. WordPress's cron spawn and Action Scheduler's admin dispatch each
hold a 60-second lock, so one job reaches its own site at most once a minute.

`perf_wp_loopback` counts the last three complete local clock hours in every
active vhost log. It counts POST requests with WordPress's own User-Agent
from the loopback interface or one of the server's addresses. The count is
kept per job, meaning the full logged path plus the admin-ajax `action`;
shortened display names do not merge jobs. A job over 60 an hour in each of
the three hours is reported as a Warning on this page. The finding shows the
hourly counts, how many runs failed with a 5xx error, and the User-Agent.

Request timestamps record when requests started, but log lines are written
when they finish, so no part of a log can be skipped by its timestamps. The
check follows each active log instead: every run reads only what the log
gained since the previous run, and the hourly counts are kept in the scan
state. A rotated, truncated or replaced log is read from its start, and the
first run reads at most the last 8 MB of each log. Memory for distinct jobs
is bounded, and the scan stops at its deadline, including inside oversized
lines. A log that cannot be read, or exceeds the job budget, keeps its saved
position and its prior findings until a later run succeeds.

There are two usual causes:

- A plugin schedules its job for "now" and fires it from every page view.
  The job then runs about as often as the site is visited, crawlers included.
- A background queue such as Action Scheduler keeps re-dispatching itself
  because its backlog never drains.

The hour in progress is not counted. A site that reaches itself through a
proxy such as Cloudflare is missed when its log records the proxy's address
rather than the server's. Other tenants can also make requests from the
server's addresses, so this Warning is advisory: it does not establish which
site initiated a request, send alerts, or trigger a response action.

### WordPress MyISAM tables

MyISAM locks a whole table for every write. While one request writes, every
other request that reads or writes that table waits. On a busy site a burst
of uncached requests queues behind those locks until it holds every database
connection the account may open, and new visitors get database errors.
InnoDB locks single rows, so the same traffic keeps flowing.

`perf_wp_myisam` reads MySQL's table catalogue once per run, as root and
without site credentials, and matches the MyISAM tables against the
WordPress installs found by the shared discovery. Each install's database and
table prefix come from explicit string literals in its `wp-config.php`,
including an explicitly empty prefix. PHP expressions are not evaluated.
A table belongs to the install whose prefix matches it most closely, so two
sites sharing one database are reported separately. Dormant and suspended
installs still reserve their prefixes. Each database and prefix gets one
Warning on this page, listing the tables largest first with their total size.

Not reported:

- installs whose `DB_HOST` is another server; accepted hosts are `localhost`,
  loopback addresses and IP addresses bound to this server's interfaces
- TCP connections whose port differs from the catalogue server's port, and
  explicit local sockets whose path differs from that server's socket path
- hostname aliases other than `localhost`; DNS is not used to infer ownership
- document roots the panel no longer serves, and suspended accounts

An unreadable or unresolved configuration, or a failed catalogue query, keeps
prior findings until a later run succeeds. If a sibling's database or prefix
cannot be established, affected scopes are withheld rather than assigning its
tables to a shorter prefix. Configurations using dynamic or conditional database
settings need explicit literals for this check to resolve their scope.

To convert a site without losing data:

1. Put the site in maintenance mode so nothing writes during the change.
2. Take a full database dump and confirm it completed.
3. Run `ALTER TABLE <table> ENGINE=InnoDB` for each listed table, one at a
   time, and stop at the first error. Each statement copies the table and
   blocks writes to it while it runs.
4. Compare row counts before and after, then end maintenance mode.

Keep the server's strict SQL mode for the conversion. A table holding values
InnoDB would reject then fails with an error instead of having those values
silently adjusted.

## Web UI

The **Performance** page (`/performance`) shows real-time metrics:
- Server load and CPU usage
- PHP process and memory charts
- MySQL and Redis health
- WordPress performance indicators

PHP worker counts include LiteSpeed and PHP-FPM pool workers. The PHP-FPM
master is excluded from these request-worker counts; security process checks
continue to inspect it. Database memory comes from the MySQL or MariaDB server
process, independent of its PID-file location or wrapper-related arguments.

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
  editable by the customer). The cron is installed before the define is
  written, so a crontab failure leaves WordPress scheduling unchanged. The
  define is inserted before the "stop editing" marker (or the
  `wp-settings.php` require); insertion points inside multiline comments or
  heredocs are ignored, and the fix refuses a `wp-config.php` with no safe
  insertion point rather than corrupt it.

  The installed schedule is staggered per account and docroot (for example
  `7-59/15`) instead of a wall-clock-aligned `*/15`, so many managed sites do
  not all fire in the same second and spike the host load. Non-divisor
  intervals use a shifted minute list so the gap stays within the configured
  interval. The command also runs under `flock -n` with a per-docroot lock file
  in the account home, so a slow pass skips the next run instead of overlapping
  it. When both `auto_response.enabled` and `auto_response.fix_wp_cron` are
  enabled, managed crontab lines installed by older releases are upgraded on
  daemon start to this format. Their PHP interpreter changes only when an
  override is configured or the site's PHP version can be resolved
  unambiguously; otherwise, they keep their existing interpreter. Only lines
  under the `# CSM WP-Cron` marker are touched; customer-authored cron entries
  are never rewritten.

These actions are limited to configured account roots, reject symlinks and
unsupported file types, and remove the fixed row from the active findings
view after a successful edit.

### WP-Cron fix settings

Tune the WP-Cron remediation under **Settings -> Performance**:

- `performance.wp_cron_fix.interval_minutes` (default `15`, range 1-60): how
  often the installed system cron runs `wp-cron.php`. The interval only
  bounds task latency -- WordPress keeps its own event schedule and a cron
  pass with nothing due is a wasted full bootstrap -- so 15 minutes is right
  for most sites. Lower it per host only when busy stores need tighter
  Action Scheduler latency.
- `performance.wp_cron_fix.php_bin` (default empty): overrides the PHP
  interpreter for the cron line. Leave it empty and each site runs under the
  PHP version its own vhost is set to when cPanel's domain map provides an
  unambiguous version. A vhost set to inherit runs the version named by the
  nearest cPanel-generated handler block that maps `.php` in its `.htaccess`
  chain, up to the account home. Empty blocks leave the parent mapping in
  effect. The lookup refuses symlinked directories and files, special files,
  and oversized files; an unreadable nearer file stops inheritance. CSM falls
  back to the detected CLI interpreter when neither gives a usable, installed
  version; an existing managed job keeps its interpreter while the map is
  unavailable. Setting a value pins that one interpreter for every
  managed site. CLI php is used instead of an HTTP request so the job never
  ties up a web worker.

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
