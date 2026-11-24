# Performance Monitor

CSM monitors server performance metrics and generates findings when thresholds are exceeded. Three checks run every 10 minutes, and the rest run with the deep scan. The Performance page in the Web UI shows the live metrics and offers fixes for some findings.

## Critical Checks (every 10 min)

| Check | What it monitors |
|-------|-----------------|
| `perf_load` | CPU load average vs core count (critical/high/warning thresholds) |
| `perf_php_processes` | PHP process count and total memory usage |
| `perf_memory` | Swap usage percentage and OOM killer activity |

Host-wide OOM events are Critical. Memory-cgroup limit events are Warning. CSM reports both when they are present in the last hour. Each scope and victim process has its own deduplication identity.

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

`perf_error_logs` scans the configured web roots plus every document root in cPanel's domain map. Addon and subdomain sites are covered as well as `public_html`.

The scan walks three levels deep. It does not descend into heavy trees such as `wp-content`, `wp-admin` and `vendor`, but it checks an `error_log` directly inside one. PHP writes the log next to the running script, so `admin-ajax.php` errors land in `wp-admin/error_log`.

| Log size | Severity | Where you see it |
|----------|----------|------------------|
| Over `performance.error_log_warn_size_mb` (default 50) | Warning | Only on the Performance page |
| Over `performance.error_log_critical_size_mb` (default 1024) | High | The finding alerts |

When more than 20 logs are bloated, the largest are reported.

The finding keeps the same identity while the log grows. This has three effects:

- Alert email and the webhook send it once.
- History records it at most once a day.
- A dismissal sticks until the log crosses into the higher tier.

Once a log has been seen for at least an hour, the finding also shows how fast it grows per day. A log that shrinks or is replaced by a new file, as on truncation or rotation, starts a new baseline.

A cancelled scan changes nothing. A scan that could not read part of the tree keeps the logs it did not reach and updates the ones it did.

### WordPress loopback requests

A WordPress site runs background work by sending a request to itself, a loopback. WordPress's cron spawn and Action Scheduler's admin dispatch each hold a 60-second lock, so one job reaches its own site at most once a minute.

`perf_wp_loopback` reports a job that runs more often than that. It counts the last three complete local clock hours in every active vhost log. The hour in progress is not counted.

- It counts POST requests with WordPress's own User-Agent from the loopback interface or one of the server's addresses.
- The count is kept per job. A job is the full logged path plus the admin-ajax `action`. Shortened display names do not merge jobs.
- A job over 60 an hour in each of the three hours is reported as a Warning on the Performance page.
- The finding shows the hourly counts, how many runs failed with a 5xx error, and the User-Agent.

There are two usual causes:

- A plugin schedules its job for "now" and fires it from every page view. The job then runs about as often as the site is visited, crawlers included.
- A background queue such as Action Scheduler keeps re-dispatching itself because its backlog never drains.

This Warning is advisory. Other tenants can also make requests from the server's addresses, so it does not establish which site initiated a request. It does not send alerts or trigger a response action.

A site that reaches itself through a proxy such as Cloudflare is missed when its log records the proxy's address rather than the server's.

[How the loopback check reads logs](#how-the-loopback-check-reads-logs) has the remaining rules.

### WordPress MyISAM tables

MyISAM locks a whole table for every write. While one request writes, every other request that reads or writes that table waits. On a busy site a burst of uncached requests queues behind those locks until it holds every database connection the account may open, and new visitors get database errors. InnoDB locks single rows, so the same traffic keeps flowing.

`perf_wp_myisam` reads MySQL's table catalogue once per run, as root and without site credentials. It matches the MyISAM tables against the WordPress installs found by the shared discovery. Each database and prefix gets one Warning on the Performance page, listing the tables largest first with their total size.

#### Converting a site to InnoDB

To convert a site without losing data:

1. Put the site in maintenance mode so nothing writes during the change.
2. Take a full database dump and confirm it completed.
3. Run `ALTER TABLE <table> ENGINE=InnoDB` for each listed table, one at a time, and stop at the first error. Each statement copies the table and blocks writes to it while it runs.
4. Compare row counts before and after, then end maintenance mode.

Keep the server's strict SQL mode for the conversion. A table holding values InnoDB would reject then fails with an error instead of having those values silently adjusted.

#### What is not reported

- Installs whose `DB_HOST` is another server. Accepted hosts are `localhost`, loopback addresses and IP addresses bound to this server's interfaces.
- TCP connections whose port differs from the catalogue server's port.
- Explicit local sockets whose path differs from the catalogue server's socket path.
- Hostname aliases other than `localhost`. CSM does not use DNS to infer ownership.
- Document roots the panel does not serve any more, and suspended accounts.

[How MyISAM tables are matched to installs](#how-myisam-tables-are-matched-to-installs) has the matching rules.

## Web UI

The **Performance** page (`/performance`) shows real-time metrics:

- Server load and CPU usage
- PHP process and memory charts
- MySQL and Redis health
- WordPress performance indicators

PHP worker counts include LiteSpeed and PHP-FPM pool workers. The PHP-FPM master is excluded from these request-worker counts; security process checks continue to inspect it.

Database memory comes from the MySQL or MariaDB server process, independent of its PID-file location or wrapper-related arguments.

### Fixes

The findings list also exposes admin-only fixes. Each is available per row and in a **Bulk fix** dropdown that applies one fix to every matching finding at once.

| Finding | What the fix does |
|---------|-------------------|
| `perf_error_logs` | Truncates a bloated `error_log` in place. The inode is preserved so running PHP processes keep writing to the same file. |
| `perf_wp_config` | Disables `display_errors` in `.user.ini`, `php.ini`, or `.htaccess` by commenting the matched line and appending an Off override. |
| `perf_wp_cron` | Adds `define('DISABLE_WP_CRON', true)` to `wp-config.php` and installs a per-user system cron that runs `wp-cron.php` on a fixed interval. See [The WP-Cron fix](#the-wp-cron-fix). |

These actions share the same safeguards:

- They are limited to configured account roots.
- They reject symlinks anywhere in the path, and unsupported file types.
- They refuse a file that changes before the edit lands.
- They remove the fixed row from the active findings view after a successful edit.

A successful Fix clears only the finding for that file, and the finding alerts again if the problem returns.

### The WP-Cron fix

Disabling WP-Cron alone would stop scheduled WordPress tasks. The fix therefore installs a system cron in the account owner's own crontab, where the customer can see and edit it.

- The cron is installed before the define is written, so a crontab failure leaves WordPress scheduling unchanged.
- The define is inserted before the "stop editing" marker, or before the `wp-settings.php` require.
- Insertion points inside multiline comments or heredocs are ignored.
- The fix refuses a `wp-config.php` with no safe insertion point rather than corrupt it.
- CLI php is used instead of an HTTP request, so the job never ties up a web worker.

[The installed cron line](#the-installed-cron-line) describes the schedule and the lock.

### WP-Cron fix settings

Tune the WP-Cron remediation under **Settings -> Performance**:

| Key | Default | Meaning |
|-----|---------|---------|
| `performance.wp_cron_fix.interval_minutes` | `15`, range 1-60 | How often the installed system cron runs `wp-cron.php`. |
| `performance.wp_cron_fix.php_bin` | empty | Overrides the PHP interpreter for the cron line. Setting a value pins that one interpreter for every managed site. |

The interval only bounds task latency. WordPress keeps its own event schedule, and a cron pass with nothing due is a wasted full bootstrap, so 15 minutes is right for most sites. Lower it per host only when busy stores need tighter Action Scheduler latency.

Leave `php_bin` empty and CSM chooses the interpreter per site. See [Which PHP interpreter the cron line uses](#which-php-interpreter-the-cron-line-uses).

To let the daemon apply this fix automatically on every WP-Cron finding, set `auto_response.fix_wp_cron: true` (default `false`; requires `auto_response.enabled: true`). It is opt-in because it edits customer `wp-config.php` files and crontabs.

### MySQL telemetry auth

The MySQL panel runs `mysql -e "SHOW STATUS LIKE 'Threads_connected'"` from the csm process. The client needs to authenticate against the local server, and csm supports two setups out of the box:

- A `~/.my.cnf` for the csm runtime user with credentials for a MySQL account that holds at least the `PROCESS` privilege. cPanel and CloudLinux ship `/root/.my.cnf` for the root user; csm running as root picks it up automatically.
- A unix-socket grant for the csm OS user, e.g. on Debian/Ubuntu MariaDB:

  ```sql
  CREATE USER 'root'@'localhost' IDENTIFIED VIA unix_socket;
  GRANT PROCESS ON *.* TO 'root'@'localhost';
  ```

If neither is configured, the MYSQL card renders `n/a / n/a` instead of a misleading `0 conn`. csm makes no attempt to connect over TCP or store credentials on its own.

### Redis telemetry auth

The Redis panel connects to local Redis at `127.0.0.1:6379`. If Redis requires a password, set `REDISCLI_AUTH` in the csm daemon environment. The dashboard uses that password for its in-process Redis client.

If csm cannot read Redis, the REDIS card renders `n/a` instead of an empty Redis. A Redis with no memory limit shows `no limit` with neutral styling.

## API

```
GET /api/v1/performance    Current performance metrics snapshot
POST /api/v1/perf/fix-error-log
POST /api/v1/perf/fix-display-errors
POST /api/v1/perf/fix-wp-cron
```

See the [API reference](api.md#performance-telemetry) for which `metrics` fields can be `null`.

## Details

This section is reference material: exact rules and rare cases.

### How the loopback check reads logs

Request timestamps record when requests started, but log lines are written when they finish. The check therefore cannot use timestamps to skip part of a log. The check follows each active log instead:

- Every run reads only what the log gained since the previous run. The hourly counts are kept in the scan state.
- A rotated, truncated or replaced log is read from its start.
- The first run reads at most the last 8 MB of each log.
- Memory for distinct jobs is bounded.
- The scan stops at its deadline, including inside oversized lines.
- A log that cannot be read, or exceeds the job budget, keeps its saved position and its prior findings until a later run succeeds.

### How MyISAM tables are matched to installs

- Each install's database and table prefix come from explicit string literals in its `wp-config.php`, including an explicitly empty prefix. PHP expressions are not evaluated.
- A table belongs to the install whose prefix matches it most closely, so two sites sharing one database are reported separately.
- Dormant and suspended installs still reserve their prefixes.
- An unreadable or unresolved configuration, or a failed catalogue query, keeps prior findings until a later run succeeds.
- If a sibling's database or prefix cannot be established, affected scopes are withheld rather than assigning its tables to a shorter prefix.
- Configurations using dynamic or conditional database settings need explicit literals for this check to resolve their scope.

### The installed cron line

The installed schedule is staggered per account and docroot (for example `7-59/15`) instead of a wall-clock-aligned `*/15`. Many managed sites then do not all fire in the same second and spike the host load. Non-divisor intervals use a shifted minute list so the gap stays within the configured interval.

The command also runs under `flock -n` with a per-docroot lock file in the account home. A slow pass skips the next run instead of overlapping it.

### Cron lines installed by older releases

When both `auto_response.enabled` and `auto_response.fix_wp_cron` are enabled, CSM upgrades managed crontab lines installed by older releases to this format on daemon start. Their PHP interpreter changes only when an override is configured or the site's PHP version can be resolved unambiguously. Otherwise they keep their existing interpreter.

Only lines under the `# CSM WP-Cron` marker are touched. Customer-authored cron entries are never rewritten.

### Which PHP interpreter the cron line uses

With `performance.wp_cron_fix.php_bin` empty, CSM picks the interpreter for each site in this order:

1. The PHP version the site's own vhost is set to, when cPanel's domain map provides an unambiguous version.
2. For a vhost set to inherit, the version named by the nearest cPanel-generated handler block that maps `.php` in its `.htaccess` chain, up to the account home.
3. The detected CLI interpreter, when neither gives a usable, installed version.

The `.htaccess` lookup follows these rules:

- Empty blocks leave the parent mapping in effect.
- The lookup refuses symlinked directories and files, special files, and oversized files.
- An unreadable nearer file stops inheritance.

An existing managed job keeps its interpreter while the map is unavailable.
