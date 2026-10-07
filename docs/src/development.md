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
CGO, pkg-config, YARA-X 1.21.0 and the systemd
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
go test -race -timeout=30m -covermode=atomic -coverprofile=coverage.out -coverpkg=./internal/... ./...
```

`make test` and the test step of `make ci` use `-short` for local iteration;
they do not reproduce the full CI suite. `make test-full` runs the default-tag
suite with the CI flags (no `-short`, fresh results, the 30-minute package
timeout). Neither default command tests the shipped optional backends. The additional required production job runs:

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
    go test -race -timeout=30m -covermode=atomic -coverprofile=coverage.out -coverpkg=./internal/... ./...'
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

`make lint` uses repo-local cache directories under `.cache/` and the timeout
set in `.golangci.yml`, the same one CI uses. Install the pinned tools with
`make tools`; the golangci-lint version is `GOLANGCI_LINT_VERSION` in the
Makefile, and CI runs the same release. It lints the Linux build, so a macOS
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

The Pages workflow builds the coverage report and badge from `merged-coverage.out` of the latest GitHub release that carries one (it walks back through releases if the newest is missing the asset), and renders it against that release tag's sources, so a file removed since the release does not break it. A failed release-list request or response parse stops the workflow. Mirrored pushes to main that change the docs, README, workflow or coverage renderer can run before the new release's assets exist and show the previous release. The release job requests another Pages run after uploading the assets to refresh the badge; a manual workflow run can retry a missed refresh.

Installs and upgrades on end-user servers come from the GitHub release artifacts or the apt/dnf mirror. The internal GitLab package registry is operational tooling only.

## Code Conventions

- **Imports:** stdlib, blank line, third-party, blank line, internal. Use `goimports -local github.com/pidginhost/csm`
- **Errors:** Return up the call stack. Wrap with `fmt.Errorf("context: %w", err)`
- **Store:** `store.Global()` singleton bbolt DB. Always nil-check.
- **State:** `state.Store` handles finding dedup, alert throttling, baseline tracking, latest findings persistence. Passed to subsystems at init
- **Web UI:** Vanilla JS, no framework, no build step, and syntax up to ES2019 (a test rejects later syntax). Tabler CSS framework. Each script keeps its helpers in a function scope and adds only to the `CSM` namespace; the shared runtime is `csm-core.js`, `csm-format.js`, `csm-page.js` and `csm-live.js`. Use `CSM.get()` / `CSM.post()` / `CSM.delete()` for API calls. Escape string-built markup with `CSM.esc()`; prefer DOM APIs for attacker-controlled values. Run the script tests with `node --test ui/`.
- **API responses:** answer through `writeJSONError`, `writeOK`, `writeItems` / `writeAll` / `writeCapped` and `writeJSON`, so every route follows the contract in [API Reference](api.md): JSON errors, `ok` on actions, lists under `items`, UTC instants, durations in seconds and severity labels.
- **Logging:** New code should use `internal/log` (wraps `log/slog`). Legacy `fmt.Fprintf(os.Stderr, "[%s] ...", ts())` call sites remain valid until migrated.

### Response admission primitives

`internal/admission` is a standard-library-only package. The daemon's
admission owner (`internal/admissionowner`) wires it into live responses and
detectors submit through its ingress, described below. Its persisted enum
values are fixed by golden tests.
`Assess` sets `ReassessBy` to the first instant the current class or severity
falls, or all roots become stale, without new evidence. Redundant evidence
can preserve the tier after another root expires. Each corroborating pair
lasts until its local root loses freshness or its support expires; the
longest-lived pair determines how long corroboration remains available.
Equal deadlines and input order do not affect the result. Direct compromise
evidence may expire while corroboration continues to preserve the same class.

Policy lookups can overlap across registration, minting and validation, so
they must be immutable or safe for concurrent use. Callers must serialize
every operation on an inventory generation tracker. Off cPanel, hosting
inventory reads account directories without checking mount state: an empty
readable root contributes no accounts, while other readable roots still do.
An unreadable required root fails the whole snapshot. A changed incarnation
token gives an account a new generation, even when the account was replaced
between two observations. Every account carries one: cPanel's recorded
creation date, elsewhere the device, inode and birth time of its home
directory. An account whose token cannot be read, whose home is not a
directory or whose Linux filesystem supplies no birth time fails the
snapshot, including a home listed as a symlink. The cPanel creation date
must be a positive integer recorded exactly once. Tenant edits do not change
the token.

The admission ledger (`store.AdmissionLedger`) keeps this state durably in
the daemon's state database, in `adm:` buckets it creates the first time it
is opened. The daemon's admission owner (`internal/admissionowner`) opens it
at startup and holds the only handle: one goroutine makes every change,
records clock readings on a timer, applies the ceiling at startup and, after
a reading at the saved limit, on reload or the first tick that sees a changed
configured value, refreshes the inventory from
complete reads, delivers audit rows to the action log and notices through
the queue-health path with their own pacing, and reads status on a timer.
Once the ingress has made new decisions, the owner drains it on a short
timer. Each group is frozen before its fresh clock reading, so concurrent
submissions wait for a reading that includes their observation time. A
clean stop drains all held work and checkpoints final decisions before
closing the generation. A failed drain, including its clock or publication
step, closes admission until a drain succeeds. Its cause survives tick,
inventory and reload recovery, so a lasting failure is one stop with its cause.
A drain whose only failure is a damaged ledger record is not a failed drain:
the arrivals naming that record are discarded and counted lost, the rest
commits, admission stays open, and status and `csm doctor` keep the damage
cause until the daemon restarts. If a later write, checkpoint or snapshot
fails in that drain, admission closes until a drain succeeds; recovery
clears the drain failure but keeps the damage cause for the discarded work.
Failed ceiling reloads stay pending until a tick applies and revalidates
them; inventory refreshes cannot reopen admission in the meantime.
One owner serializes every write, and each call
is one transaction, so a failed call changes nothing. Admission time
comes only from recorded clock readings: a wall clock that steps back never
lowers it, a new boot credits no elapsed time, and a reopened ledger admits
no new work until it records a fresh reading. Evidence is immutable once
published, and later reports of the same observation are kept as bounded
links. A candidate takes its entry, check and finding link from its primary
evidence, coalesces repeated requests without refreshing its queue age, and
moves from queued through reserved and executing to one outcome. A proven
failure may requeue after a backoff, with at most three attempts in total;
an unknown outcome never retries. Reserve and Execute report whether the
call granted the step; reading back an attempt that is already reserved or
running grants nothing, and the later applier must reconcile it before any
effect is replayed.

Schema 2 of the ledger adds its queue, and the first open upgrades a schema
1 ledger in the same transaction; legacy work that cannot fit the unassessed
general partition refuses the upgrade intact. Ingress, queued and in-flight
work share 1000 positions; 200 take only direct compromise or corroborated
evidence. Each partition reserves 64 positions for memory transfers, so
durable work cannot consume handoff space. In a full partition each verified
scope has a fair share: a scope at its share can only replace its own
lowest-tier, newest candidate with stronger work, and a scope below its
share takes one position from the scope most over its share. A displaced
candidate ends as queue overflow. Queued candidates end at their age-out, or
at their effect expiry while waiting to retry, and are assessed again when a
root's freshness changes; an inventory refresh ends those whose roots name a
retired account. The scheduler serves the reserved lane first, alternating
direct and corroborated turns, then the general lane at C3:C2:C1 4:2:1.
Inside a class, verified scopes rotate, a scope serves Critical:High:Warning
4:2:1 and a severity serves its oldest candidate; deficit accounting lets a
candidate that costs several block units wait its turn without starving. The
scheduler's position persists, and every pick is revalidated before it is
returned. Detectors hand work to a nonblocking ingress that applies the same
fair shares against the owner's latest snapshot of the queue. It judges
freshness at that snapshot's admission time advanced by elapsed monotonic
time, so an idle owner does not make new evidence look future-dated. Durable
victims remain counted until commit. Reports arriving during a drain remain
held for a later report-only commit, and overflow counts persist with their
links. Ingress cursor progress and loss counts are checkpointed even when
only refusals occurred; publication cannot overwrite later memory decisions.
The owner persists held items in groups; an ingress generation that ends
without a clean close is recorded as interrupted, since its unpersisted
items cannot be counted. A failed snapshot after a committed drain stops new
submissions until the owner publishes a snapshot at least as new as that
commit, from the same ingress generation. Shared queue damage retains the
whole handoff; only arrivals carrying damage are discarded.

Schema 3 of the ledger adds the emergency ceiling; the first open upgrades
a schema 1 or 2 ledger in the same transaction, with empty buckets because
its recent spend is unknown. The engine sets the hourly ceiling L; a fifth
of it, rounded up, is reserved for direct compromise and corroborated work,
and the general lane cannot spend it. Each lane refills a token bucket at
its hourly rate from elapsed time within a boot, up to ten minutes of that
rate with a one-unit floor for a nonzero lane, and the first limit of a new
ledger fills both buckets once. A new ledger takes that first limit together
with the legacy hourly block count, charged at the end of its hour and
subtracted from the fill; a count that cannot be read starts the ledger
without credit. The reader rejects null scalar values and uses the last
instance of a repeated local hour, even when other hours separate its
instances. Retained import reads validate the ceiling totals and the
charge links to ordinary attempts. A later limit only clips saved credit; the
owner checkpoints elapsed time at the saved rate before changing it. Every
reservation, retry included, is charged to the lane its schedule picked, in
the reservation's transaction, after a reserved lane is rechecked against
the candidate's current assessment. A readback grants and charges nothing;
its lane must be zero or equal the recorded lane, including when an
upgraded attempt has no recorded lane. A charge counts until a full hour of
admission time and of elapsed time have both passed, so neither downtime
nor a forward clock step releases it early. Schedules serve no more than
each lane can charge, and the ledger's next wake includes when waiting work
gains budget. Challenge work is never charged, but still waits in the
shared scheduler until its separate bound is implemented.

Schema 4 adds storage accounting; the first open upgrades a schema 1, 2 or
3 ledger in the same transaction. Evidence stays stored while a candidate
names it as a root. Evidence no candidate names, and candidates that ended
before any attempt, each wait in a bounded ring and leave oldest first, so
rejected traffic cannot allocate rows without bound. A candidate's details
become history at its first reservation: each reservation charges the
growth of their largest possible size to the allowance of its lane, and a
fifth of the fixed history budget is reserved for direct compromise and
corroborated work. Each allowance admits history at a rate that spreads its
size over the seven-day review window and saves at most ten minutes of that
rate, so a flood cannot fill a week of history in an hour. Scopes earn
history turns in fixed quanta, so large records cannot take more than their
share, and a record that has earned its turn holds its lane until the
credit covers it. An ended candidate's details are kept through the review
window and, for a verified effect, for as long as the effect can last. They
are retired after thirty days, or earlier when an allowance needs the room,
oldest first. An unresolved outcome is pinned in a separate recovery reserve
until recovery settles it, and new work waits while that reserve is full.
Tick refills the allowances and retires history at its target in the
clock's transaction. The next wake runs the scheduler read-only; unassessed
or overdue queue entries wake immediately for a sweep. Report links stay
readable after a policy change.

Schema 5 adds the outbox; the first open upgrades a schema 1 to 4 ledger
in the same transaction. Every admitted step of an attempt (reservation,
execution, outcome) writes an audit row in its own transaction, and the
reservation holds room for all three in the recovery reserve, which the
outbox shares; ended history is retired only after its rows are
acknowledged. Response gaps are recorded in the transaction that causes
them as coalesced notices, one record per reason, check and action family,
with a bounded count of examples, a fixed overflow record per kind and a
fixed Critical summary that no flood can refuse. Records may use only a
fixed share of the reserve, a key is due for delivery at most once an hour
and a summary once a minute after acknowledged delivery. Acknowledgements
carry the count and first-event time of the record read, so a repeated
acknowledgement cannot consume a later record under a reused key. An audit
row's acknowledgement carries the row's time as well, so one held past the
row's retirement cannot remove the row a re-minted attempt writes later. Queue
events and attempt outcomes are also counted into five-minute, hourly and
daily buckets. `Status` reads every section in one read transaction without
the ledger's lock or a current clock, each section with its own error, and
the pure doctor rules turn it and the ingress's own health into fixed rows.
Missing buckets fail the sections that read them; an unreadable database
fails every section. Quiet notice indexes are checked with their records.
Health snapshots own copies of the admission view, and a clean ingress
generation clears the interruption marker.

Schema 6 adds offense episodes; the first open upgrades a schema 1 to 5
ledger in the same transaction, without inventing episodes for candidates
queued before. Each ledger draws episode IDs from its own random nonce and
a counter, so IDs never repeat, even in a ledger created again after loss.
Opening proves every episode row against the candidates it names.
History entries written before episode accounting keep their charges and
encoding at upgrade. New entries require the episode allowance; an older
entry is exempt only while it has no row for its episode.
The ledger, not the caller, assigns each arrival its episode and
generation when it persists the arrival; an arrival that names either is
refused. Responses of every kind at one target share its episode. An
observation made within an hour of the episode's last one, or while its
work is queued or in flight, joins it; a later one opens the next episode,
and one older than the previous episode's end, or already accepted by
that episode while its work held it open, is refused as stale. A
degraded clock reading never ends an episode. Episode placement refuses an
observation dated after the ledger's current reading, even within
assessment's clock-skew tolerance. This keeps future times out of observation
frontiers and prevents an early episode boundary. A queued candidate coalesces
later observations before its first attempt. A queued retry remains live
but answers new arrivals without coalescing; one that ended before any
attempt is followed only by a later observation of that kind. Once a candidate has an attempt, later observations
of its episode are refused as an existing effect, which raises no notice,
and still extend the episode. An episode row lives only as long as a
candidate it names: ring eviction and history retirement clear that
candidate reference but retain its generation and attempt proof while
another candidate holds the row. The last retained candidate takes the
row, and each admitted
candidate's history charge covers a row. A target without a row opens a
new episode, so a retired candidate's ID is never minted again. A
verified block ends its episode at the block's original expiry instead of
an hour after the last observation; an unknown outcome or a response of
another kind does not.

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
same run scans every tracked and unignored file for private names when
`CSM_PRIVATE_TERMS` (or `-terms`) names a file holding one case-insensitive
regular expression per line. That file stays outside the repository: the
GitLab job receives it as a file-type CI variable and fails without it
(`-require-terms`), while a local run without one prints a skip notice. Reports
name the file and line, never the matched text. The
[fixture sanitisation rules](https://github.com/pidginhost/csm/blob/main/internal/daemon/testdata/php_relay/SANITISE.md)
describe the additional manual privacy review.
