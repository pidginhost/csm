# Building & Testing

## Toolchain and prerequisites

Use the Go version required by `go.mod` (currently 1.27.1), including its
formatter. A newer local formatter can disagree with the pinned CI linter.
For an installed Go launcher that supports toolchain selection:

```bash
export GOTOOLCHAIN=go1.27.1
export PATH="$(go env GOROOT)/bin:$PATH"
go version
```

Linux tests need PHP CLI and python3-cryptography for the shipped PHP runtime
and release verification regressions. The release-verifier tests skip when the
module is absent and fail when `CSM_REQUIRE_PYTHON_VERIFIER=1`, which the CI
test jobs set so a missing module cannot pass as a silent skip. The Web UI
JavaScript tests need Node 24 or newer the same way: they skip without it and
fail when `CSM_REQUIRE_NODE=1`, which the CI test job sets. Builds with `yara,journal,bpf` also need
CGO, pkg-config, YARA-X 1.20.0 and the systemd
development library. Use the release builder or the documented test images.
CI selects the module toolchain with `GOTOOLCHAIN=auto`; the older Go versions
in its bootstrap images are not the module requirement.

## Build

```bash
# Standard build (no YARA-X)
go build ./cmd/csm/

# Build with YARA-X support (requires libyara_x_capi)
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go build -tags yara ./cmd/csm/
```

## Test

The default CI job runs every package with the race detector, no extra build
tags, and a 30-minute per-package timeout. Run its exact test command on Linux:

```bash
go test -v -race -timeout=30m -covermode=atomic -coverprofile=coverage.out -coverpkg=./internal/... ./...
```

`make test` and the test step of `make ci` use `-short` for local iteration;
they do not reproduce the full CI suite. Neither default command tests the
shipped optional backends. The additional required production job runs:

```bash
scripts/production-tests.sh portable
```

That script selects all packages with `yara,journal,bpf`, `-race`, `-count=1`,
`-p=2` and `-timeout=30m`, retains JSON execution evidence, and checks the test
inventory. See [production and kernel tests](production-tests.md) for the
builder, tagged lint/security commands and required kernel execution.

On macOS, use `scripts/go-linux.sh` for Linux code. Build the repository's
PHP-enabled test image once with an available container builder:

```bash
docker build -f build/Dockerfile.systemd-test -t csm-linux-test .
GO_LINUX_RUNTIME=docker GO_LINUX_IMAGE=csm-linux-test scripts/go-linux.sh \
  bash -ec 'apt-get update -qq && apt-get install -y --no-install-recommends python3-cryptography
    go test -v -race -timeout=30m -covermode=atomic -coverprofile=coverage.out -coverpkg=./internal/... ./...'
```

The wrapper derives the default Go version from `go.mod`, shares persistent
caches across worktrees, and grants fanotify/nftables capabilities. Its plain
Go image does not include PHP, python3-cryptography or the production CGO
libraries. The command above installs Python's verifier in the disposable
test container. An image built
with another runtime can be selected through `GO_LINUX_RUNTIME` and
`GO_LINUX_IMAGE`; local test execution still goes through the wrapper.
Kernel firewall regressions use isolated network namespaces:

```bash
scripts/go-linux.sh go test -tags nftkernel ./internal/firewall -race -count=1
```

The separate [kernel gate](production-tests.md#kernel-runner) requires an
isolated Linux runner with the documented boot capabilities. A successful
macOS or default-tag suite does not demonstrate BPF LSM attachment.

## Fuzz

CSM has fuzz targets for parsers that read attacker-controlled input, including Exim mainlog lines, Dovecot maillog lines, Apache Combined Log Format, /proc/net/tcp rows, wp-config.php bodies, /etc/shadow, auditd comm fields, and finding messages coming back from the WebUI.

Fuzz targets live in `*fuzz*test.go` files across the internal packages and scripts. Fuzz targets do two things:

1. Their seed corpus runs as part of the normal test suite. `go test ./...` executes every seed, so a known-bad input stays a regression test forever.
2. The actual fuzzer runs with `-fuzz=FuzzFoo`.

Run a target for a fixed time while investigating:

```bash
go test ./internal/checks/... -run=^$ -fuzz=^FuzzExtractPHPDefine$ -fuzztime=30s
```

Run only the seeds:

```bash
go test -run=Fuzz ./...
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
make fmt-check                   # checks tracked Go files with the pinned formatter
```

`make lint` uses repo-local cache directories under `.cache/` and a five-minute
timeout, matching `.golangci.yml` and CI. Install the pinned tools with
`make tools`; golangci-lint is 2.11.4. It lints the Linux build, so a macOS
host checks the code that ships rather than reporting its linux-only callers
as unused. Production-tag lint needs the Linux CGO libraries described in
[production tests](production-tests.md).

`make sec`, `make vuln`, and `make check-fixtures` are the local security,
vulnerability and fixture checks. For an aggregate local check use `make ci`,
then run the full default and production commands above. Passing local checks
does not replace the required kernel and cloud jobs.

Linter config in `.golangci.yml`: errcheck, govet, staticcheck, unused, ineffassign, gocritic, misspell, bodyclose, nilerr.

## CI/CD

GitLab CI (`.gitlab-ci.yml`) is the internal build pipeline. It runs lint/test/package jobs, publishes internal packages, mirrors to GitHub, and creates the public GitHub release artifacts.

| Stage | What it does |
|-------|-------------|
| **.pre** | Release preflight rejects version tags without a usable cPanel image. |
| **lint** | Pinned golangci-lint and formatter, vet, blocking gosec/govulncheck, fixture privacy, and Prometheus config validation. |
| **test** | Full default-tag race/coverage suite (30-minute package timeout), shipped-tag lint/security/race gate, required kernel/service gate, and four pinned clean-application gates. |
| **build-image** | Build CSM builder Docker image with YARA-X (manual trigger) |
| **build** | amd64 and arm64 release binaries with YARA-X CGO and the `yara journal bpf` build tags. arm64 builds use QEMU/buildx. |
| **package** | RPM + DEB via nFPM |
| **integration** | Spin up cloudv-1 AlmaLinux and Ubuntu hosts plus the configured clean cPanel image via phctl, install the pipeline-built amd64 packages, run the integration test binary, collect coverage, and confirm every test server was really deleted. `main` integration is manual and can omit cPanel; version tags require the cPanel image, baseline-to-candidate package upgrade, installer, WHM, mail watcher and forward guard checks. |
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
   `CHANGELOG.md` holds one block of ten minor versions. The first release of a new block (3.40.0, 3.50.0, 4.0.0) moves the previous block and its link references to `docs/changelog/<first>-<last>.md` and adds that file to the archive list at the top of `CHANGELOG.md`.
2. Tag and push:
   ```bash
   git tag vX.Y.Z
   git push origin main vX.Y.Z
   ```
3. Wait. The tag pipeline runs integration, publishes packages to the mirror, creates the GitHub release, and uploads every artifact including the fresh `merged-coverage.out`. No manual pipeline clicks needed.

Tag pipelines require `INTEGRATION_CPANEL_IMAGE` to name a clean cPanel CI
image, or `CSM_RELEASE_WITHOUT_CPANEL` to state why no image is available.
`INTEGRATION_CPANEL_PACKAGE` optionally selects its compute package and
defaults to `cloudv-2`. A release taken without cPanel coverage records
`cpanel_coverage: "absent"` in `dist/cpanel-release.json`; see
[cPanel release tests](cpanel-release-tests.md).

Tag-specific `publish` dependencies require preflight, fixtures, corpus,
production tags, kernel tests, signed artifacts and integration. Repository
publication and the GitLab release depend on `publish`; the GitHub release
also directly requires integration and the test gates. A missing `csm-kernel`
runner leaves publication pending. A missing cPanel image fails tag preflight.
See [cPanel release tests](cpanel-release-tests.md) for image acceptance and
[the roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#release-readiness-gates)
for remaining operational readiness work. These configured dependencies are
not evidence of a successful live release run.

The coverage badge rebuilds automatically once the GitHub release exists, because the Pages workflow fetches `merged-coverage.out` from the latest release that carries one (it walks back through releases if the newest is missing the asset).

Installs and upgrades on end-user servers come from the GitHub release artifacts or the apt/dnf mirror. The internal GitLab package registry is operational tooling only.

## Code Conventions

- **Imports:** stdlib, blank line, third-party, blank line, internal. Use `goimports -local github.com/pidginhost/csm`
- **Errors:** Return up the call stack. Wrap with `fmt.Errorf("context: %w", err)`
- **Store:** `store.Global()` singleton bbolt DB. Always nil-check.
- **State:** `state.Store` handles finding dedup, alert throttling, baseline tracking, latest findings persistence. Passed to subsystems at init
- **Web UI:** Vanilla JS, no framework, no build step. Tabler CSS framework. Use `CSM.get()` / `CSM.post()` / `CSM.delete()` for API calls. Escape string-built markup with `CSM.esc()`; prefer DOM APIs for attacker-controlled values.
- **Logging:** New code should use `internal/log` (wraps `log/slog`). Legacy `fmt.Fprintf(os.Stderr, "[%s] ...", ts())` call sites remain valid until migrated.

### Attack event storage

Attack events live in `attacks:events`; `attacks:events:ip` stores empty values
under `<ip>/<TimeKey>` keys. The writer chooses an unused primary key inside
the write transaction because batch counters can repeat for the same timestamp.
Primary rows, index entries and the event count are updated atomically, including
count-cap pruning.

Address queries walk the index newest-first and resolve primary rows until the
requested limit is met. Older index entries can still contain a full event copy;
the reader falls back to that copy if the primary row is missing, malformed or
belongs to another address. Both forms must match the requested address. The UTC
time-key migration preserves index values verbatim, so readers must keep handling
both forms until older entries age out.

## Structured Logging (slog)

Legacy daemon call sites emit log lines via `fmt.Fprintf(os.Stderr, "[%s] ...", ts())`. The `internal/log` package provides a drop-in slog wrapper so operators can opt into JSON output for log-shipping pipelines (Loki, ELK, Datadog) without a big bang migration.

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
log watchers, and firewall engine alive. Wiring lives in
`internal/daemon/yara_backend.go`; process supervision lives in
`internal/yaraworker/supervisor.go`. Completed work is recorded in
`CHANGELOG.md` and git history.

The knob is a tri-state `*bool`: omit it (or set `true`) for the
default-on child process; set `false` to fall back to the in-process
scanner.

```yaml
signatures:
  # yara_worker_enabled: true    # default; omit for default-on
  # yara_worker_enabled: false   # explicit opt-out -> in-process
```

When on, daemon startup:

1. Does *not* call `yara.Init()` in the daemon process.
2. Builds a `yaraworker.Supervisor` and calls `Start(ctx)`.
3. The supervisor executes the running daemon binary with `yara-worker`,
   the worker socket path and the configured rules directory.
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
- The crash finding is emitted before a restart is attempted, while YARA
  scans cannot run. Scans can resume once a replacement worker serves
  requests; they do not wait for the 30 s health check. The finding does
  not confirm a successful restart or recovery.
- `csm doctor` reports `watcher: yara_worker` as failed from a crash until
  a restarted worker has stayed up for 30 s, so a worker that keeps
  crashing shortly after each restart keeps doctor failing. This also
  covers crashes between initial readiness and backend activation.
  Shutdown waits for any in-flight recovery callback to finish.
- A `csm update-rules` run that completes triggers the supervisor's
  in-process `Reload` (the worker recompiles). Escalate to a full
  worker restart from Go code via `Supervisor.RestartWorker()`. An explicit
  restart also marks the watcher failed until the replacement stays up.

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
- Integration: staged in the GitLab pipeline's `integration` stage against
  AlmaLinux, Ubuntu, and the configured clean cPanel release image.

## Building the Documentation

```bash
cd docs
mdbook build              # generates docs/book/
mdbook serve              # local preview at http://localhost:3000
```

## Clean application corpus

The same job measures the shipped rules against long uninterrupted base64,
hex and word runs, dense variable calls, and PDF-shaped streams. It discards
one warm-up and scores the fastest of two further scans against a 5-second
per-file budget. Each attempt has a 10-second engine timeout; a timeout never
counts as a completed scan, and a cold timeout alone cannot fail the gate.
Both scored attempts timing out fails it. The job shares the heavy-test
resource group to avoid competing with other heavy tests in this project.

A rule with no literal atom to match on can still pass match tests while
stalling mail delivery. Investigate slow rules with `yr scan --profiling`.
Run the gate and its fixture/timing checks locally with YARA-X installed:

```bash
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go test -count=1 -v -tags yara ./internal/yara -run 'TestShippedRulesScanWithinBudget|TestRuleScanBudget'
```

Every pipeline runs the required [clean-corpus gate](clean-corpus.md) in the production YARA-X builder image. Package publication and GitHub releases depend on its success.

See [cPanel release tests](cpanel-release-tests.md) for the required image, upgrade baseline, release dependencies and retained evidence.

Production tag selection, execution artifacts, and the required isolated kernel runner are described in [Production build and kernel tests](production-tests.md).

`make check-fixtures` is also a blocking GitLab job and publication dependency.
It checks all tracked and unignored files under `testdata` and `fixtures`,
including files without extensions. Scanner failures stop the check; reports
identify the file and line without printing the suspected address. The
[fixture sanitisation rules](https://github.com/pidginhost/csm/blob/main/internal/daemon/testdata/php_relay/SANITISE.md)
describe the additional manual privacy review.
