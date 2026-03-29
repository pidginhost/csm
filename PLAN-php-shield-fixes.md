# PHP Shield Fix Plan

Status: PLANNED
Decision: Keep in same binary (see rationale at bottom)

## Summary

Fix 7 issues in the PHP Shield feature. No architectural changes needed --
the `auto_prepend_file` approach is correct and the code is well-isolated
(2 Go files, 1 PHP file, ~210 lines of Go total). All issues are
implementation bugs or missing code, not design flaws.

---

## Step 1: Remove `php://input` consumption from shield PHP

**Files:** `configs/php_shield.php`, `cmd/csm/installer.go` (embedded copy)

**Problem:** `file_get_contents('php://input')` is a destructive read. Once
consumed, frameworks get an empty request body. Breaks WooCommerce, REST APIs,
Stripe webhooks, Gutenberg editor -- any POST endpoint reading raw body.

**Change:**
- Delete the entire "Check for base64-encoded request bodies" block
  (configs/php_shield.php lines 69-80)
- Keep the "Check for webshell command parameters" block (lines 82-90) --
  this inspects `$_POST`/`$_GET`/`$_REQUEST` arrays, not raw body, so it's safe
- Update the embedded minified copy in installer.go (lines 612-620) to match:
  remove the POST body reading there too (it was already missing `SUSPICIOUS_POST`
  but still worth keeping in sync)

**Verify:** The only I/O the shield does on non-blocked requests is the
parameter array checks -- no streams consumed.

---

## Step 2: Remove `SUSPICIOUS_POST` from Go daemon parser

**Files:** `internal/daemon/php_events.go`

**Problem:** The PHP side no longer emits `SUSPICIOUS_POST` events (removed
in Step 1), so the Go parser case is dead code.

**Change:**
- Remove the `case "SUSPICIOUS_POST":` block (php_events.go lines 75-81)
- The remaining event types stay: `BLOCK_PATH`, `WEBSHELL_PARAM`, `EVAL_FATAL`

---

## Step 3: Add config flag to disable PHP Shield monitoring

**Files:** `internal/config/config.go`, `internal/daemon/daemon.go`

**Problem:** The daemon always registers a watcher for `/var/run/csm/php_events.log`
even if PHP Shield was never installed. Every other optional feature (firewall,
challenge server, file monitor) has a config toggle. PHP Shield doesn't.

**Change in config.go:**
- Add to the `Config` struct, after the `Challenge` block:

```go
PHPShield struct {
    Enabled bool `yaml:"enabled"` // watch php_events.log (default: false)
} `yaml:"php_shield"`
```

Default is `false` -- the daemon won't watch the log unless the config says so.

**Change in daemon.go (`startLogWatchers`):**
- Make the `phpEventsLogPath` entry conditional:

```go
if d.cfg.PHPShield.Enabled {
    logFiles = append(logFiles, struct{ ... }{phpEventsLogPath, parsePHPShieldLogLine})
}
```

**Change in installer.go (`InstallPHPShield`):**
- After deploying the .ini files, also patch `csm.yaml` to set
  `php_shield.enabled: true` (so the daemon starts watching on next restart).

---

## Step 4: Add watcher retry for missing log files

**Files:** `internal/daemon/daemon.go`

**Problem:** If `php_events.log` doesn't exist when the daemon starts, the
watcher fails silently and is never retried. If PHP Shield creates the file
later (first blocked request), the daemon never notices. Requires manual
daemon restart.

**Change in `startLogWatchers()`:**
- For watchers that fail with `os.IsNotExist`, start a retry goroutine:

```go
w, err := NewLogWatcher(lf.path, d.cfg, lf.handler, d.alertCh)
if err != nil {
    if os.IsNotExist(err) {
        // Retry every 60s until file appears
        go d.retryLogWatcher(lf.path, lf.handler)
    } else {
        fmt.Fprintf(os.Stderr, "Warning: could not watch %s: %v\n", lf.path, err)
    }
    continue
}
```

The `retryLogWatcher` function polls once per minute, returns when the file
exists and the watcher starts successfully, or when the daemon stops.

---

## Step 5: Fix uninstall to clean up PHP Shield

**Files:** `cmd/csm/installer.go`

**Problem:** `Uninstall()` does not remove `/opt/csm/php_shield.php` or the
`zzz_csm_shield.ini` files across PHP versions. After uninstall, PHP keeps
trying to prepend a file that may or may not exist.

**Change:** Add to `Uninstall()`, before the "Remove binary and state" section:

```go
// Remove PHP Shield
os.Remove(phpShieldPath) // /opt/csm/php_shield.php
phpIniPaths := []string{
    "/opt/cpanel/ea-php74/root/etc/php.d/zzz_csm_shield.ini",
    "/opt/cpanel/ea-php80/root/etc/php.d/zzz_csm_shield.ini",
    "/opt/cpanel/ea-php81/root/etc/php.d/zzz_csm_shield.ini",
    "/opt/cpanel/ea-php82/root/etc/php.d/zzz_csm_shield.ini",
    "/opt/cpanel/ea-php83/root/etc/php.d/zzz_csm_shield.ini",
}
for _, p := range phpIniPaths {
    os.Remove(p)
}
os.RemoveAll("/var/run/csm")
fmt.Println("  PHP Shield removed")
```

Also add a glob fallback for future PHP versions:
```go
iniGlob, _ := filepath.Glob("/opt/cpanel/ea-php*/root/etc/php.d/zzz_csm_shield.ini")
for _, p := range iniGlob {
    os.Remove(p)
}
```

---

## Step 6: Add `csm disable --php-shield` command

**Files:** `cmd/csm/main.go`, `cmd/csm/installer.go`

**Problem:** No way to disable PHP Shield without manually deleting .ini files
and restarting LiteSpeed. Every other feature can be toggled via config.

**Change:**
- Add a `disable` subcommand (or flag on existing command) that:
  1. Removes `zzz_csm_shield.ini` from all PHP versions (same glob as uninstall)
  2. Sets `php_shield.enabled: false` in `csm.yaml`
  3. Prints "PHP Shield disabled. Restart PHP: systemctl restart lsws"
  4. Does NOT remove `/opt/csm/php_shield.php` (allows easy re-enable)

- Add matching `csm enable --php-shield` that:
  1. Re-creates the .ini files
  2. Sets `php_shield.enabled: true`
  3. Prints restart instruction

---

## Step 7: Add logging health check

**Files:** `configs/php_shield.php`

**Problem:** If `/var/run/csm/` isn't writable (e.g., after reboot on tmpfs
and before daemon starts), the shield silently drops all events. Admin
believes they're protected but no events reach the daemon.

**Change:**
- At the top of `csm_shield_log()`, after the `@mkdir`, add a writability
  check with a one-time syslog fallback:

```php
if (!is_writable($dir)) {
    // One-time fallback: write to PHP error_log so it appears in site logs
    if (!defined('CSM_SHIELD_LOG_WARNED')) {
        define('CSM_SHIELD_LOG_WARNED', true);
        error_log('CSM PHP Shield: cannot write to ' . $dir . ' — events will not be logged');
    }
    return;
}
```

This ensures the admin sees the problem in PHP error logs even if the
dedicated log path is broken.

---

## Step 8: Sync embedded shield with configs/ version

**Files:** `cmd/csm/installer.go`

**Problem:** The installer embeds a minified copy of the shield that is out
of sync with `configs/php_shield.php`. Two copies to maintain means they
inevitably diverge.

**Resolution:** `go:embed` cannot use `..` paths, so embedding from
`cmd/csm/installer.go` to `configs/php_shield.php` is not possible without
restructuring packages. Instead:
- The inline copy in `installer.go` is the deployed version (minified).
- `configs/php_shield.php` is the full documented source.
- `RedeployPHPShield()` + `deploy.sh` upgrade keeps the deployed file in sync.
- A CI lint step can be added later to verify the two stay functionally equivalent.

---

## Step 9: Auto-redeploy shield PHP on upgrade

**Files:** `scripts/deploy.sh`

**Problem:** The shield PHP file (`/opt/csm/php_shield.php`) is written once
by `csm install --php-shield` and never updated. The deploy script swaps the
Go binary and extracts assets, but the shield file is left at its original
version. This means shield fixes (e.g., the php://input removal) don't deploy
automatically.

The Go daemon restarts fine -- PHP requests are unaffected because the shield
is a static file loaded directly by PHP via `auto_prepend_file`, with zero
dependency on the running daemon. But the shield code itself gets stale.

**Change in `do_upgrade()`:**
After the assets are extracted and before `start_services`, add:

```bash
# Redeploy PHP Shield if it was previously installed
if [ -f "${INSTALL_DIR}/php_shield.php" ]; then
    echo "Updating PHP Shield..."
    "$BINARY_PATH" install --php-shield-only 2>/dev/null || true
fi
```

**Change in installer.go:**
Add a `--php-shield-only` flag that re-writes `/opt/csm/php_shield.php`
from the embedded content without touching .ini files or printing restart
instructions (the .ini files already point to the right path).

This way the shield PHP file stays in sync with the binary version after
every upgrade, without requiring a manual re-install or a LiteSpeed restart
(the file path doesn't change, only the content).

---

## Execution order

Steps 1-2 together (remove php://input + dead Go code), then 3-4 (config +
retry), then 5-6 (uninstall + disable), then 7-8 (polish). Each pair can be
a single commit.

## Testing

- `go build ./...` after each step
- `go test ./...` after each step
- Manual test on cluster6 after deploy:
  - Verify `csm install --php-shield` deploys correctly
  - Verify a POST to a WP REST endpoint still works (php://input not consumed)
  - Verify `curl -X POST 'http://site/uploads/test.php'` returns 403
  - Verify events appear in daemon log when PHP Shield blocks a request
  - Verify `csm disable --php-shield` removes .ini files
  - Verify `csm uninstall` removes all shield files

---

## Why keep in same binary

PHP Shield adds ~210 lines of Go to a 15K+ line codebase. It has zero extra
dependencies. The operational coupling is tight -- the daemon must watch the
log file regardless of where the parser lives. Splitting it out means:

- Two binaries to build, ship, and version
- Both still coordinate on `/var/run/csm/php_events.log`
- Duplicate installer/uninstaller code
- More deployment steps for the user
- Zero reduction in binary size (no deps removed)

The code is already well-isolated in `internal/daemon/php_events.go` (parser)
and `cmd/csm/installer.go:InstallPHPShield()` (deployment). Adding a config
toggle (Step 3) gives the same opt-in/opt-out control that a separate binary
would, without the deployment overhead.
