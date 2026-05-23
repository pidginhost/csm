# CSM Engineering Roadmap

Forward-looking engineering decisions that are committed to but not yet
implemented. Items move from here into commits + `CHANGELOG.md` entries
as they land, then drop off this list (git history + CHANGELOG are the
archive).

This file is for contributors. End-user documentation lives in `docs/`.

**Stable cross-references.** Older commits, CHANGELOG entries, and a
few code comments reference `ROADMAP item N` by the number that item
had when the commit was written. Those numbers are frozen in time and
no longer map onto the current list. To resolve a historical
`ROADMAP item N`, search `git log` and `CHANGELOG.md` rather than this
file.

---

## 1. Signed YARA Forge mirror automation

**Status:** planned. Detection lag risk: operators cannot enable
`signatures.yara_forge.enabled` without a CSM-signed `.sig` next to
each Forge ZIP, and YARAHQ does not publish `.sig` files.

### Decision

Operate a small mirror job. Pulls latest `YARAHQ/yara-forge` release,
downloads `core` / `extended` / `full` ZIPs, signs raw bytes with the
CSM Ed25519 rule-signing key, publishes ZIP + `<zip>.sig` + checksum
under a stable HTTPS path compatible with
`signatures.yara_forge.download_url` and the `{tier}` / `{version}`
placeholders. Retain N older releases for rollback. Operator example
enables Forge through `/etc/csm/conf.d/` without editing the main
`csm.yaml`.

### Acceptance

- Mirror run publishes latest Forge ZIPs, `.sig`, checksums.
- A CSM instance configured at the mirror URL records the installed
  Forge version.
- Missing / corrupt / mismatched signature fails closed.

### Size: 0.5-1 day.

---

## 2. `csm support-bundle` command

**Status:** planned. Triage workflow: operators today grep journal +
copy `state.json` by hand.

### Decision

New CLI `csm support-bundle <path>` produces a tar+zstd containing:
- `csm store export` output (manifest, bbolt snapshot, state, rules
  cache).
- Last N (default 2000) `journalctl -u csm` lines.
- `/etc/csm/csm.yaml` with secrets redacted (`smtp`, `webhook.url`,
  `abuseipdb_key`, `webui.auth_token`,
  `verified_session.admin_secret`, `captcha_fallback.secret_key`,
  plus whitelist-style redaction of any unknown `*_key` / `*_token`
  / `*_secret`).
- `system.txt` with `uname -a`, `csm version`, distro info, startup
  integrity hashes.

Live daemon required (mirrors `store export`).

### Out of scope

Auto-upload, encryption at rest (pipe through gpg).

### Size: 1 day.

---

## 3. Scheduled backup exports

**Status:** planned. `csm store export` needs an operator-managed
cron entry today.

### Decision

Top-level config block, hot-reloadable:

```yaml
backup:
  enabled: true
  schedule: "@daily"            # cron spec or @hourly|@daily|@weekly
  destination_dir: /var/backups/csm
  filename: "csm-{date}.csmbak"
  retention_days: 14
```

Daemon ticks schedule, calls `store.Export`, prunes archives older
than `retention_days`. Failures emit `backup_export_failed` Warning.

### Out of scope

Off-host destinations (S3 / SFTP). Encryption.

### Size: 1-2 days.

---

## 4. WordPress companion plugin for signed-cookie operator bypass

**Status:** planned. Closes UX gap on `/challenge/admin-token`: a
logged-in WP admin currently has no way to obtain the cookie without
manual curl.

### Decision

Plugin lives in separate repo (`pidginhost/csm-wp-bypass`). This
repo only:

- Documents `/challenge/admin-token` as a stable contract (breaking
  changes require a roadmap item).
- Adds a short integration note in `docs/src/challenge.md` linking
  the plugin repo.

Plugin behaviour (separate repo): reads `CSM_ADMIN_SECRET` from
`wp-config.php`, on `wp_login` for `manage_options` users POSTs to
the endpoint and sets the returned cookie.

### Size: 0.5 day (this repo); plugin itself ~2 days separately.

---

## 5. Per-account scanner mtime fairness and scan-cap hygiene

**Status:** planned. Same bug class the May 2026 `domlog_max_files`
fix closed for WP brute-force: `filepath.Glob` returns lex order, a
downstream cap cuts iteration short, late-alphabet accounts evade
the scanner under load.

### Decision

Six commits, each independently revertable.

1. **`5.1` Per-account scanner fairness.** Apply the `scanDomlogs`
   recipe (mtime-desc sort + `ctx.Err()` per-match + explicit cap)
   to:
   - `internal/checks/auth.go` (SSH `authorized_keys` glob, cPanel
     API token glob).
   - `internal/checks/emailpasswd.go` (Dovecot shadow glob).
   - `internal/checks/dbscan_magento.go`, `dbscan_joomla.go`,
     `dbscan_drupal.go`, `dbscan_opencart.go` (CMS config globs).

   Bound iteration with new `thresholds.account_scan_max_files`
   (default high; 100000 ceiling matches `domlog_max_files`). Add
   late-alphabet equity tests proving a late-sorted account under
   load still produces a finding.

2. **`5.2` Consolidate `scanDomlogs` and `scanDomlogsStats`.** The
   two functions in `bruteforce.go` duplicate ~85 lines of
   discovery + dedup + stale-filter + mtime-sort + cap. Extract
   `discoverFreshDomlogs(ctx, cfg)`; rebuild both callers as thin
   wrappers. Parity test pins identical selection under fixtures.

3. **`5.3` Promote `domlogTailLines` to config.** Hardcoded `500`
   in `bruteforce.go:26`. Move to `thresholds.domlog_tail_lines`
   (same plumbing as `domlog_max_files`).

4. **`5.4` Webshell-scan truncation visibility.**
   `internal/daemon/webshell_content.go:26` silently truncates at
   64 KiB. Add `csm_webshell_truncated_total` counter + Warning
   finding when truncation drops content. Visibility precedes any
   cap bump.

5. **`5.5` Log `EvalSymlinks` silent drops.** `bruteforce.go:238`
   and `scanDomlogsStats` discard symlink-resolve failures
   silently. Add `csm_domlog_evalsymlinks_dropped_total{reason}`.

6. **`5.6` Audit `crontabBase64BlobMaxBytes` cap.** Current 8192 in
   `crontabs.go:120`. Confirm by sampling production no realistic
   crontab payload exceeds it; raise or make configurable
   otherwise. Low priority.

### Acceptance

Per sub-item: TDD test demonstrating the bug pre-fix, then code,
then CHANGELOG entry in the same commit. No default behaviour
change. `make ci` clean.

### Out of scope

Per-account async walks. Default cap-value changes.

### Size: 2-3 days.

---

## 6. Second-pass scanner audit follow-ups

**Status:** planned. Same fairness / telemetry / silent-error
hygiene as item 5, applied to scanners item 5 did not reach.

### Decision

Nine commits, each independently revertable.

1. **`6.1` `CheckDatabaseObjects` mtime fairness.** `db_objects.go`
   iterates `/home/*/public_html/wp-config.php` in lex order. Has
   `ctx.Err()` per iteration but no mtime rank.

2. **`6.2` `CheckForwarders` ctx + mtime fairness.** `forwarder.go`
   iterates `/etc/valiases/*` and `/etc/vfilters/*` per mail
   domain. No `ctx.Err()` in either loop, no mtime rank.

3. **`6.3` `CheckFilesystem` mtime fairness.** `filesystem.go`
   iterates `/home/*/.config/*/*` for backdoor binaries with
   per-pattern ctx check but no per-match one and no mtime rank.

4. **`6.4` `CheckCrontabs` honour ctx + mtime fairness.**
   `crontabs.go` accepts `ctx` and ignores it. Per-user
   `/var/spool/cron/*` iter is unbounded.

5. **`6.5` `looksLikePHPWebshell` inner 64 KiB cap consistency.**
   Still trims own input to 64 KiB even after 5.4 covers fd reads.
   Either remove inner trim (caller owns cap) or wire the same
   `csm_realtime_content_scan_truncated_total` counter through it.

6. **`6.6` `fanotify.go` other read sites get truncation metric.**
   `checkHtaccess` (16 KiB), `checkUserINI` (4 KiB), `checkCrontab`
   (64 KiB) read from event fd without `recordReadTruncation`.

7. **`6.7` `validateReleaseSpoolDir` EvalSymlinks fallback
   hardening.** `emailav/quarantine.go` falls back to the cleaned
   path when `EvalSymlinks` errors on input or allowed entry.
   Containment check that does not verify real on-disk identity is
   defence in name only. Decision: fail-closed on resolve errors.

8. **`6.8` `domlogMaxAge` operator-tunable.** `bruteforce.go`
   hardcodes 30 min freshness cutoff. Same class as 5.3.

9. **`6.9` Targeted `tailFile` scan windows operator-tunable.**
   Two callsites worth tuning: `mailrate.go` 500-line Exim window
   on busy mail hosts, `bruteforce.go` 200-line `/var/log/messages`
   window on noisy-log hosts. Other `tailFile` sites stay
   hardcoded.

### Out of scope

Global check-runner timeout model. Per-account async walks.
Upstream fd read-size changes (await 5.4/6.6 metering data).

### Size: 2-3 days.

---

## 7. Realtime HTTP-flood / UA-spoof detector

**Status:** spec done, partial implementation. Memory: subagent
completed tasks 0-5 of a 7-task plan.

### Why

Current CSM scanners are batch (poll-driven). Real attacks (POST
brute-force, UA-spoof crawler floods) finish faster than one scan
cycle. The GET-scanner does not see them. Cluster6 incident
2026-05-21 (5.255.115.88) confirmed.

### Decision

Daemon-side realtime detector consumes Apache/LSWS/Nginx access-log
tail. Two signals:

1. **HTTP-flood.** Per-IP request-rate window with separate burst /
   sustained thresholds. Tracks POST-only and total separately.
2. **UA-spoof.** Claims-Googlebot/Bingbot but rDNS does not
   forward-confirm. Reuses the existing verified-crawler resolver
   (`internal/daemon/handlers_dovecot.go` pattern).

Emits Findings through the standard alert pipeline; routes through
auto-block escalation when severity-threshold tripped.

Finish remaining tasks (6, 7) of the original 7-task plan.

### Out of scope

Layer-4 SYN flood (firewall layer, not CSM). Per-URL pattern
matching (separate WAF concern).

### Size: 1-2 days remaining.

---

## 8. Fail-closed audit across security paths

**Status:** planned. Recent commits 4740e847 (`emailav`
`validateReleaseSpoolDir`) and d79ffe19 (`looksLikePHPWebshell`
inner cap) closed individual fail-open behaviours. Pattern suggests
more lurking.

### Why

Each fix shape: a security check returned the safe-looking value
on error (allowed the action, returned no-match on truncation,
fell back to unresolved path on `EvalSymlinks` error). Defence in
name only. One systematic pass beats one-at-a-time.

### Decision

Audit every security-decision path. For each:
- `EvalSymlinks` / `os.Stat` / `filepath.Abs` error → fail closed
  unless documented otherwise.
- `io.ReadFull` short read in content matcher → emit truncation
  metric (5.4 + 6.6 pattern), do not silently match-or-miss.
- File-not-found in policy lookup → return safe default + log,
  not "no entry = allowed".

Deliverable: one commit per audited file with a `// fail-closed:`
comment marking the decision, plus tests proving error paths emit
the expected severity.

### Acceptance

- `gosec` clean. `make ci` clean.
- For each touched file: a test demonstrates the pre-fix fail-open
  and the post-fix fail-closed.

### Size: 2-3 days.

---

## 9. Firewall state migration to bbolt

**Status:** planned. Item 7.1 cache landed (commit 48cc718a) and
killed the per-call 325 KiB read + parse + linear scan. Next
bottleneck: every mutator still rewrites the full `state.json` on
disk (fsync amplification + crash window between mutators).

### Decision

Move firewall state out of `state.json` into bbolt:

- Bucket `fw:blocked` keyed by IP, value `{added, expires, reason,
  source}` JSON or msgpack.
- Bucket `fw:allow_*`, `fw:port_*` parallel.
- Mutators wrap `bolt.Update`; readers use `bolt.View`. The 7.1
  in-memory cache stays as the hot-path index, invalidated by the
  same mtime/sequence number scheme.
- `csm store export` already snapshots bbolt; firewall state rides
  along for free.

Migration: one-shot importer in `csm firewall migrate-state` reads
existing `state.json`, writes bbolt buckets, renames the JSON to
`state.json.migrated-<timestamp>` for rollback.

### Out of scope

Replacing the in-memory cache (item 7.1 result stands).

### Size: 2-3 days.

---

## 10. Subprocess churn (item 7.4 follow-through)

**Status:** deferred pending re-measurement after item 7.1 + 7.2
deploy soak.

### Why

Item 7 audit on cluster6 saw libc/libpthread/librt loads followed
by exit (suggesting `os/exec.Command` churn). Live `strace -e
execve` over 30 s post-fix measured only 9 forks (6 `redis-cli`, 3
`mysql`, 1 unknown) at steady state. Below threshold for action.

### Decision

Re-measure on cluster6 in production after 3.7.0 soak. If
sustained fork rate stays under ~1/s, close as not-needed. If
above: replace `redis-cli` with `redis/go-redis` and `mysql` CLI
with `database/sql` MySQL driver.

### Size: 0 (close) or 1-2 days (implement).
