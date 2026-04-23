# Building & Testing

## Build

```bash
# Standard build (no YARA-X)
go build ./cmd/csm/

# Build with YARA-X support (requires libyara_x_capi)
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go build -tags yara ./cmd/csm/
```

## Test

```bash
go test ./... -count=1           # all tests
go test -race -short ./...       # CI mode (race detector, skip slow tests)
```

## Fuzz

CSM has a dozen parsers that read attacker-controlled input: Exim mainlog lines, Dovecot maillog lines, Apache Combined Log Format, /proc/net/tcp rows, wp-config.php bodies, /etc/shadow, auditd comm fields, and finding messages coming back from the WebUI.

Each parser has a Go fuzz target (files named `fuzz_parsers_test.go` under `internal/checks/` and `internal/daemon/`). Fuzz targets do two things:

1. Their seed corpus runs as part of the normal test suite. `go test ./...` executes every seed, so a known-bad input stays a regression test forever.
2. The actual fuzzer runs with `-fuzz=FuzzFoo`.

Run a target for a fixed time while investigating:

```bash
go test ./internal/checks/... -run=^$ -fuzz=^FuzzExtractPHPDefine$ -fuzztime=30s
```

Run only the seeds:

```bash
go test -run=Fuzz ./internal/checks/... ./internal/daemon/...
```

If the fuzzer finds a crasher it writes the failing input to `testdata/fuzz/FuzzFoo/<hash>`. Commit that file alongside the fix and the input becomes a permanent seed.

Adding a fuzz target:

```go
func FuzzMyParser(f *testing.F) {
    // Seeds: real-world valid shape, empty, malformed.
    f.Add("valid input")
    f.Add("")
    f.Add("corrupt/truncated")

    f.Fuzz(func(t *testing.T, s string) {
        _ = myParser(s)   // must not panic on any input
    })
}
```

Keep the target tight: call one function, assert it returns. Output verification belongs in a regular test.

## Lint

```bash
make lint                        # must pass before push
gofmt -l .                       # must produce no output
```

`make lint` uses repo-local cache directories under `.cache/` so the command behaves consistently in local shells, sandboxes, and CI runners.

Linter config in `.golangci.yml`: errcheck, govet, staticcheck, unused, ineffassign, gocritic, misspell, bodyclose, nilerr.

## CI/CD

GitLab CI (`.gitlab-ci.yml`) is the internal build pipeline. It runs lint/test/package jobs, publishes internal packages, mirrors to GitHub, and creates the public GitHub release artifacts.

| Stage | What it does |
|-------|-------------|
| **lint** | golangci-lint, gofmt, gosec (blocking), govulncheck |
| **test** | `go test -v -race -timeout=300s -covermode=atomic -coverprofile -coverpkg=./internal/... ./...` |
| **build-image** | Build CSM builder Docker image with YARA-X (manual trigger) |
| **build** | Two architectures: amd64 with YARA-X CGO, arm64 pure Go |
| **integration** | Spin up AlmaLinux + Ubuntu cloud servers via phctl, install CSM from the public mirror, run the integration test binary on both hosts, collect coverage. Only runs on `main` |
| **package** | RPM + DEB via nFPM |
| **sign** | Detached signatures on release artifacts |
| **publish** | Internal GitLab Generic Package Registry (versioned + `latest`) |
| **repo** | Publish RPM/DEB to the public `mirrors.pidginhost.com` apt/dnf repos |
| **pages** | Docs + coverage HTML (GitLab Pages preview) |
| **cleanup** | Remove old package versions |
| **release** | GitLab release on tags matching `v*` |
| **github** | Mirror to GitHub + upload release artifacts (auto on tag push) |

## Public Releases

To cut a release:

1. Move the `[Unreleased]` heading in `CHANGELOG.md` to the new version (e.g. `[2.4.2] - YYYY-MM-DD`), commit as `release: cut X.Y.Z`.
2. Tag and push:
   ```bash
   git tag vX.Y.Z
   git push origin main vX.Y.Z
   ```
3. Wait. The tag pipeline runs integration, publishes packages to the mirror, creates the GitHub release, and uploads every artifact including the fresh `merged-coverage.out`. No manual pipeline clicks needed.

The coverage badge rebuilds automatically once the GitHub release exists, because the Pages workflow fetches `merged-coverage.out` from the latest release that carries one (it walks back through releases if the newest is missing the asset).

Installs and upgrades on end-user servers come from the GitHub release artifacts or the apt/dnf mirror. The internal GitLab package registry is operational tooling only.

## Code Conventions

- **Imports:** stdlib, blank line, third-party, blank line, internal. Use `goimports -local github.com/pidginhost/csm`
- **Errors:** Return up the call stack. Wrap with `fmt.Errorf("context: %w", err)`
- **Store:** `store.Global()` singleton bbolt DB. Always nil-check.
- **State:** `state.Store` handles finding dedup, alert throttling, baseline tracking, latest findings persistence. Passed to subsystems at init
- **Web UI:** Vanilla JS, no framework, no build step. Tabler CSS framework. All API calls via `CSM.apiUrl()` / `CSM.post()`. Escape with `CSM.esc()`.
- **Logging:** New code should use `internal/log` (wraps `log/slog`). Legacy `fmt.Fprintf(os.Stderr, "[%s] ...", ts())` call sites remain valid until migrated.

## Structured Logging (slog)

CSM's daemon emits ~190 log lines via `fmt.Fprintf(os.Stderr, "[%s] ...", ts())`. The `internal/log` package provides a drop-in slog wrapper so operators can opt into JSON output for log-shipping pipelines (Loki, ELK, Datadog) without a big bang migration.

### Operator controls

Two environment variables, read once at daemon startup:

| Variable | Values | Default | Effect |
|----------|--------|---------|--------|
| `CSM_LOG_FORMAT` | `text`, `json` | `text` | Output handler |
| `CSM_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` | Minimum log level |

Set via systemd drop-in:

```ini
# /etc/systemd/system/csm.service.d/logging.conf
[Service]
Environment="CSM_LOG_FORMAT=json"
Environment="CSM_LOG_LEVEL=info"
```

Then `systemctl daemon-reload && systemctl restart csm`.

### Writing new logging code

```go
import csmlog "github.com/pidginhost/csm/internal/log"

csmlog.Info("scan complete", "findings", len(f), "duration_ms", d.Milliseconds())
csmlog.Warn("log not found, will retry", "path", path, "retry_in", "60s")
csmlog.Error("alert dispatch failed", "err", err, "channel", "email")
```

Keys should be snake_case. Values should be machine-parseable (numbers, strings, booleans) -- avoid formatted strings when you can pass the raw value.

### Migrating legacy call sites

Migration is incremental and optional. The legacy format stays valid. Start with the hottest subsystems (alert dispatch, firewall operations, WAF handlers) where structured fields provide the most value, then work outward. Do not batch-convert -- each subsystem should get a dedicated commit with before/after log samples in the PR description.

Keep the `[TIMESTAMP]` prefix of journalctl lines readable by humans: slog's text handler uses `time=... level=... msg=...` which is also human-parseable, so journalctl viewers still work.

## YARA-X Worker Process

CSM runs YARA-X in a supervised child process by default (since the
2026-04-23 default-flip). The goal is blast-radius control: a cgo
crash inside yara_x_capi (the 2026-04-16 production incident) stays
contained to the child and the daemon keeps its fanotify watchers,
log watchers, and firewall engine alive. See `ROADMAP.md` (Related
work already landed → "YARA-X process isolation") for the decision
record.

The knob is a tri-state `*bool`: omit it (or set `true`) for the
default-on child process; set `false` to fall back to the in-process
scanner.

```yaml
signatures:
  # yara_worker_enabled: true    # default; omit for default-on
  # yara_worker_enabled: false   # explicit opt-out → in-process
```

When on, daemon startup:

1. Does *not* call `yara.Init()` in the daemon process.
2. Builds a `yaraworker.Supervisor` and calls `Start(ctx)`.
3. The supervisor runs `exec.Command(/opt/csm/csm, "yara-worker",
   "--socket", "/var/run/csm/yara-worker.sock", "--rules-dir",
   <rulesDir>)`.
4. Supervisor waits for the worker's first `Ping` before returning.
5. Installs itself as `yara.SetActive(...)` so the existing
   `yara.Active()` callers (fanotify, rule reload) route transparently
   through the IPC.

Operator view:

- `ps axf` shows the daemon with one `csm yara-worker` child.
- New socket: `/var/run/csm/yara-worker.sock` (0600, root-only).
- Crashes produce a Critical `yara_worker_crashed` finding (rate-
  limited to one per minute) and restart with exponential backoff
  (1 s, 2 s, 4 s, capped at 60 s). Restarts reset to 1 s after the
  worker stays up for 30 s.
- A `csm update-rules` run that completes triggers the supervisor's
  in-process `Reload` (the worker recompiles). Escalate to a full
  worker restart from Go code via `Supervisor.RestartWorker()`.

Emailav under worker mode: the IPC wire format carries string-valued
rule metadata on every match (`yaraipc.Match.Meta` /
`yara.Match.Meta`). The emailav adapter consumes
`Meta["severity"]` via `yara.Active()`, so both in-process and worker
backends produce the same verdict shape. Non-string metadata (ints,
floats, bytes) is deliberately dropped at the worker boundary; add a
typed value struct here only if a future consumer actually needs one.

Testing:

- Unit-level: `internal/yaraipc` (protocol framing + round-trip) and
  `internal/yaraworker` (handler adapter, Run, supervisor). The
  supervisor tests re-invoke the test binary as a mock worker via the
  standard `TestMain` + env-var helper-process pattern, including a
  real `SIGKILL`-driven signal-death test that exercises the
  `syscall.WaitStatus.Signaled()` branch.
- Integration: staged in the GitLab pipeline's `integration` stage
  against AlmaLinux + Ubuntu cloud servers.

## Building the Documentation

```bash
cd docs
mdbook build              # generates docs/book/
mdbook serve              # local preview at http://localhost:3000
```
