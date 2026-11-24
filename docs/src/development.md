# Building & Testing

This page is for developers who change CSM. The first half covers the toolchain, the build, the test, fuzz and lint commands, the CI pipeline and the release steps. The second half is reference material on internals you must understand before you change them: logging, worker processes, the YARA-X worker and response admission.

## Toolchain and prerequisites

Use the Go version required by `go.mod` (currently 1.27.4), including its formatter. A newer local formatter can disagree with the pinned CI linter. For an installed Go launcher that supports toolchain selection:

```bash
export GOTOOLCHAIN=go1.27.4
export PATH="$(go env GOROOT)/bin:$PATH"
go version
```

Some tests and builds need more than Go:

| What you run | What it needs |
|--------------|---------------|
| Linux tests | PHP CLI and python3-cryptography, for the shipped PHP runtime and the release verification regressions. |
| Web UI JavaScript tests | Node 24 or newer. |
| Builds with `yara,journal,bpf` | CGO, pkg-config, YARA-X 1.24.0 and the systemd development library. Use the release builder or the documented test images. |

Two of these tests skip when their dependency is missing, and CI turns that skip into a failure so a missing dependency cannot pass silently:

- The release-verifier tests skip when the python3-cryptography module is absent. They fail when `CSM_REQUIRE_PYTHON_VERIFIER=1`, which the CI test jobs set.
- The Web UI JavaScript tests skip without Node. They fail when `CSM_REQUIRE_NODE=1`, which the CI test job sets.

### Where the versions are pinned

`go.mod` sets the Go release. The Makefile pins the Go analysers. CI images ship the module toolchain and run with `GOTOOLCHAIN=local`, so a stale image fails instead of downloading another toolchain in every job.

A pipeline test checks the image definitions and the versions on this page. When the CI tools image tag changes, update the full tag in its build examples too.

CI jobs print the versions they ran with:

- Jobs on the shared Go runner print the Go version.
- Analyser jobs also print the scanner version.
- The kernel job prints the Go version recorded by the test service when its `production-results/kernel/engines.txt` report is available.

## Build

```bash
# Standard build (no YARA-X)
go build ./cmd/csm/

# Build with YARA-X support (requires libyara_x_capi)
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go build -tags yara ./cmd/csm/
```

## Test

### The default CI suite

The default CI job runs every package with the race detector, no extra build tags, and a 30-minute per-package timeout. Run its exact test command on Linux:

```bash
go test -race -timeout=30m -covermode=atomic -coverprofile=coverage.out -coverpkg=./internal/... ./...
```

The make targets differ from that command:

| Command | What it runs |
|---------|--------------|
| `make test` | The suite with `-short`, for local iteration. It does not reproduce the full CI suite. |
| The test step of `make ci` | The same `-short` run. |
| `make test-full` | The default-tag suite with the CI flags: no `-short`, fresh results, the 30-minute package timeout. |

None of these default-tag commands tests the shipped optional backends.

### The production-tag suite

The additional required production job runs:

```bash
scripts/production-tests.sh portable
```

That script selects all packages with `yara,journal,bpf`, `-race`, `-count=1`, `-p=2` and `-timeout=30m`. It retains JSON execution evidence and checks the test inventory. See [production and kernel tests](production-tests.md) for the builder, the tagged lint and security commands, and the required kernel execution.

### Running Linux tests from macOS

On macOS, use `scripts/go-linux.sh` for Linux code. Build the repository's PHP-enabled test image once with an available container builder:

```bash
docker build -f build/Dockerfile.systemd-test -t csm-linux-test .
GO_LINUX_RUNTIME=docker GO_LINUX_IMAGE=csm-linux-test scripts/go-linux.sh \
  bash -ec 'apt-get update -qq && apt-get install -y --no-install-recommends python3-cryptography
    go test -race -timeout=30m -covermode=atomic -coverprofile=coverage.out -coverpkg=./internal/... ./...'
```

The wrapper derives the default Go version from `go.mod`, shares persistent caches across worktrees, and grants fanotify and nftables capabilities. Its plain Go image does not include PHP, python3-cryptography or the production CGO libraries. The command above installs Python's verifier in the disposable test container.

You can select an image built with another runtime through `GO_LINUX_RUNTIME` and `GO_LINUX_IMAGE`. Local test execution still goes through the wrapper.

### Kernel tests

Kernel firewall regressions use isolated network namespaces:

```bash
scripts/go-linux.sh go test -tags nftkernel ./internal/firewall -race -count=1
```

The separate [kernel gate](production-tests.md#kernel-runner) requires an isolated Linux runner with the documented boot capabilities. A successful macOS or default-tag suite does not demonstrate BPF LSM attachment.

### How some tests are built

A few tests are written in a way that looks odd until you know the reason.

Scratch folders and source inventories:

- Some tests keep scratch folders under their package directory, because system temporary directories change the behavior they test.
- Source inventories skip a folder removed during their walk. A missing root or a failed read still fails.

Process-context and file fixtures:

- Process-context unit tests stub start times for synthetic PIDs, so unrelated processes cannot supply cache identity evidence. UID and command mismatches are checked separately.
- Atomic replacement fixtures require newer birth times only when testing WAF log replacement. Plugin-copy tests also work without filesystem birth-time support.

Admission tests:

- Admission retry tests repeat evidence with its original observation timestamp and check the refusal reason. Changing that timestamp creates conflicting evidence and bypasses episode placement.
- Forged-account flood tests keep the host and the real account backlogged in each evidence class and check repeated alternating turns. A single account pick can pass through sort order alone.

### Antispam learning benchmarks

Run the learning benchmarks on Linux with repeated iterations:

```bash
TMPDIR=/var/tmp/csm-gotest go test ./internal/antispam/learn ./internal/antispam/learnwatch -run '^$' -bench . -benchtime=3x -count=3
```

How an iteration is set up:

- Each publication iteration starts with one live anchor and adds one new contributor.
- Each flood iteration starts from an empty baseline before new messages arrive.
- Database state is reset between iterations. Setup and cleanup are excluded from timings.
- The flood wait metric is the mean across iterations.

The benchmarks check four things: publication commits, discovery visits the corpus, the second account submits before the flood finishes, and audit coverage completes.

Storage metrics count logical keys and values, including contribution charges, account usage and pending-message indexes. They exclude bbolt page overhead and anchor message bodies.

These fixed workloads do not establish maximum database sizes or production latency. Message names, contributor mixes, filesystem performance and native rspamd calls change the cost. Runtime allowances remain unchanged.

## Fuzz

CSM has fuzz targets for parsers that read attacker-controlled input, including Exim mainlog lines, Dovecot maillog lines, Apache Combined Log Format, /proc/net/tcp rows, wp-config.php bodies, /etc/shadow, auditd comm fields, and finding messages coming back from the WebUI.

Fuzz targets live in `*fuzz*test.go` files across the internal packages and scripts. A fuzz target does two things:

1. Its seed corpus runs as part of the normal test suite. `go test ./...` executes every seed, so a known-bad input stays a regression test forever.
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

Install the pinned tools with `make tools`. The golangci-lint version is `GOLANGCI_LINT_VERSION` in the Makefile, and CI runs the same release.

`make lint` works this way:

- It uses repo-local cache directories under `.cache/`.
- It uses the timeout set in `.golangci.yml`, the same one CI uses.
- It lints the Linux build. A macOS host therefore checks the code that ships, and does not report its linux-only callers as unused.

Production-tag lint needs the Linux CGO libraries described in [production tests](production-tests.md).

The linters configured in `.golangci.yml` are errcheck, govet, staticcheck, unused, ineffassign, gocritic, misspell, bodyclose and nilerr.

### Security and fixture checks

`make sec`, `make vuln`, and `make check-fixtures` are the local security, vulnerability and fixture checks. For an aggregate local check use `make ci`, then run the full default and production commands above. Passing local checks does not replace the required kernel and cloud jobs.

The gosec pin includes the upstream module loader fix. Version 2.30.0 can split large packages in deeply nested checkouts and report false type errors. Keep this pin aligned in the Makefile and both build images until a tagged release includes the fix.

## CI/CD

GitLab CI (`.gitlab-ci.yml`) is the internal build pipeline. It runs the lint, test and package jobs, publishes internal packages, mirrors to GitHub, and creates the public GitHub release artifacts.

| Stage | What it does |
|-------|-------------|
| **.pre** | Manual CI tools and builder image builds (amd64 and arm64) block dependent jobs when their definitions change on a branch. |
| **preflight** | Release preflight rejects version tags without a usable cPanel image, after required images are built. |
| **lint** | Pinned golangci-lint and formatter, vet, blocking gosec/govulncheck, fixture privacy, and Prometheus config validation. |
| **test** | Full default-tag race/coverage suite (30-minute package timeout), shipped-tag lint/security/race gate, required kernel/service gate, four pinned clean-application gates, and the attack replay corpus. |
| **build** | amd64 and arm64 release binaries with YARA-X CGO and the `yara journal bpf` build tags. arm64 builds run under QEMU in rootless BuildKit. |
| **package** | RPM + DEB via nFPM |
| **integration** | Installs the pipeline-built packages on fresh test servers and runs the integration tests. See [The integration stage](#the-integration-stage). |
| **sign** | Detached release-key signatures on `main` and tag builds, before anything publishes them |
| **publish** | Internal GitLab Generic Package Registry (versioned + `latest`) |
| **repo** | Publish RPM/DEB to the public `mirrors.pidginhost.com` apt/dnf repos |
| **pages** | Docs + coverage HTML (GitLab Pages preview) |
| **cleanup** | Remove old package versions |
| **release** | GitLab release on tags matching `v*` |
| **github** | Mirror to GitHub + upload release artifacts (auto on tag push) |

### The integration stage

The integration stage does this:

1. It spins up cloudv-1 AlmaLinux and Ubuntu hosts, plus the configured clean cPanel image, via phctl.
2. It installs the pipeline-built amd64 packages.
3. It runs the integration test binary and collects coverage.
4. It confirms every test server was really deleted.

`main` integration is manual and can omit cPanel. Version tags require the cPanel image and these checks: baseline-to-candidate package upgrade, installer, WHM, mail watcher and forward guard.

### Which pipelines run what

Release builds and preflight run in branch and tag pipelines, including scheduled and manually started runs. They are excluded from merge-request pipelines. Merge requests use the checks in the branch pipeline.

The default suite executes on every pipeline, even when compiled packages are cached.

### Image jobs

When an image definition changes on a branch, run its blocking manual image jobs: ci-tools, or both builder architectures. Preflight waits for those builds. Both release builds wait for preflight while still running alongside lint and tests.

### Caches

Lint and test jobs use the shared Go cache runner. Compiled and analysis caches rotate with the CI tools and builder image tags, because Go does not detect changes to installed C libraries. Module downloads remain shared. Release build and package jobs stay on separate runners and do not consume these caches.

### Retries and cancellation

| Jobs | Retry | Cancelled by a newer push to the same ref |
|------|-------|-------------------------------------------|
| Preflight, lint, test, build and package | Up to twice when the runner, registry, scheduler or API fails. A failing script is not retried. | Lint and test jobs of the older pipeline are cancelled. |
| Integration, kernel tests and publishing | Never | Never |

Inside the integration job, the Ubuntu package index update is retried while the mirror syncs. The image repair and the CSM install run once.

### Coverage

The test job uses `gocover-cobertura -strict`, so unresolved package information fails coverage conversion. A successful test job must include every covered package in its report.

### The govulncheck pin

Keep govulncheck at v1.9.0 in the Makefile and CI tools image for Go 1.27.4. Version v1.10.0 fails to type-check that toolchain's standard library with "requires go1.27 or later" errors. Recheck that failure before lifting the pin.

### Gates every pipeline runs

Every pipeline runs the required [clean-corpus gate](clean-corpus.md) in the production YARA-X builder image. Package publication and GitHub releases depend on its success. The [attack replay corpus](attack-corpus.md) gate runs the same way and gates the same jobs.

More detail is on these pages:

- [cPanel release tests](cpanel-release-tests.md) covers the required image, the upgrade baseline, release dependencies and retained evidence.
- [Production build and kernel tests](production-tests.md) covers production tag selection, execution artifacts, and the required isolated kernel runner.

## Clean application corpus

### Rule scan time budget

The job that runs the [clean-corpus gate](clean-corpus.md) also measures the shipped rules against long uninterrupted base64, hex and word runs, dense variable calls, and PDF-shaped streams. A rule with no literal atom to match on can still pass match tests while stalling mail delivery.

The job scores scan time this way:

- It discards one warm-up scan and scores the fastest of two further scans against a 5-second per-file budget.
- Each attempt has a 10-second engine timeout. A timeout never counts as a completed scan.
- A cold timeout alone cannot fail the gate. Both scored attempts timing out fails it.

The job shares the heavy-test resource group, to avoid competing with other heavy tests in this project.

Investigate slow rules with `yr scan --profiling`. Run the gate and its fixture and timing checks locally with YARA-X installed:

```bash
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go test -count=1 -v -tags yara ./internal/yara -run 'TestShippedRulesScanWithinBudget|TestRuleScanBudget'
```

### Fixture privacy check

`make check-fixtures` is also a blocking GitLab job and a publication dependency. It checks all tracked and unignored files under `testdata` and `fixtures`, including files without extensions. Scanner failures stop the check. Reports identify the file and line without printing the suspected address.

The same run can scan every tracked and unignored file for private names:

- It does so when `CSM_PRIVATE_TERMS` (or `-terms`) names a file holding one case-insensitive regular expression per line.
- That file stays outside the repository. The GitLab job receives it as a file-type CI variable and fails without it (`-require-terms`). A local run without one prints a skip notice.
- Reports name the file and line, never the matched text.
- Filenames are checked too. A matching filename is reported with its path redacted.

The [fixture sanitisation rules](https://github.com/pidginhost/csm/blob/main/internal/daemon/testdata/php_relay/SANITISE.md) describe the additional manual privacy review.

Attack replay payloads are checked this way:

- Payloads are decoded in memory before checking.
- Every data file in a sample directory is decoded regardless of its suffix. `.b64` files are decoded elsewhere in the attack corpus test data too.
- Manifests, corpus-root notes and saved Go fuzz seeds are checked as plain text.
- Invalid base64 fails the check, and diagnostics never print decoded content.

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

Installs and upgrades on end-user servers come from the GitHub release artifacts or the apt/dnf mirror. The internal GitLab package registry is operational tooling only.

### What a tag pipeline requires

A tag pipeline needs one of two variables:

- `INTEGRATION_CPANEL_IMAGE` names a clean cPanel CI image.
- `CSM_RELEASE_WITHOUT_CPANEL` states why no image is available.

`INTEGRATION_CPANEL_PACKAGE` optionally selects the image's compute package and defaults to `cloudv-2`. A release taken without cPanel coverage records `cpanel_coverage: "absent"` in `dist/cpanel-release.json`. See [cPanel release tests](cpanel-release-tests.md).

The publishing jobs depend on the gates like this:

- Tag-specific `publish` dependencies require preflight, unit tests, fixtures, corpus, production tags, kernel tests, signed artifacts and integration.
- Repository publication and the GitLab release depend on `publish`.
- The GitHub release also directly requires integration and the test gates.

A missing `csm-kernel` runner leaves publication pending. A missing cPanel image fails tag preflight.

See [cPanel release tests](cpanel-release-tests.md) for image acceptance and [the roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#release-readiness-gates) for remaining operational readiness work. These configured dependencies are not evidence of a successful live release run.

### Coverage report on Pages

The Pages workflow builds the coverage report and badge from `merged-coverage.out` of the latest GitHub release that carries one. It walks back through releases if the newest is missing the asset. It renders the report against that release tag's sources, so a file removed since the release does not break it. A failed release-list request or response parse stops the workflow.

Mirrored pushes to main that change the docs, README, workflow or coverage renderer can run before the new release's assets exist, and then show the previous release. The release job requests another Pages run after uploading the assets, to refresh the badge. A manual workflow run can retry a missed refresh.

## Building the Documentation

```bash
cd docs
mdbook build              # generates docs/book/
mdbook serve              # local preview at http://localhost:3000
```

## Code Conventions

| Area | Convention |
|------|------------|
| Imports | Order them as stdlib, blank line, third-party, blank line, internal. Use `goimports -local github.com/pidginhost/csm`. |
| Errors | Return them up the call stack. Wrap with `fmt.Errorf("context: %w", err)`. |
| Store | `store.Global()` is the singleton bbolt DB. Always nil-check it. |
| State | `state.Store` handles finding dedup, alert throttling, baseline tracking and latest findings persistence. It is passed to subsystems at init. |
| Logging | New code should use `internal/log`, which wraps `log/slog`. Legacy `fmt.Fprintf(os.Stderr, "[%s] ...", ts())` call sites remain valid until migrated. |

### Web UI code

- The Web UI is vanilla JS with no framework and no build step. It uses the Tabler CSS framework.
- Use syntax up to ES2019. A test rejects later syntax.
- Each script keeps its helpers in a function scope and adds only to the `CSM` namespace.
- The shared runtime is `csm-core.js`, `csm-format.js`, `csm-page.js` and `csm-live.js`.
- Use `CSM.get()` / `CSM.post()` / `CSM.delete()` for API calls.
- Escape string-built markup with `CSM.esc()`. Prefer DOM APIs for attacker-controlled values.
- Run the script tests with `node --test ui/`.

### API responses

Answer through `writeJSONError`, `writeOK`, `writeItems` / `writeAll` / `writeCapped` and `writeJSON`. Every route then follows the contract in [API Reference](api.md): JSON errors, `ok` on actions, lists under `items`, UTC instants, durations in seconds and severity labels.

## Structured Logging (slog)

Legacy daemon call sites emit log lines via `fmt.Fprintf(os.Stderr, "[%s] ...", ts())`. The `internal/log` package provides a drop-in slog wrapper. Operators can opt into JSON output for log-shipping pipelines (Loki, ELK, Datadog) without a big bang migration.

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

- Keys should be snake_case.
- Values should be machine-parseable: numbers, strings, booleans. Avoid formatted strings when you can pass the raw value.
- Pass paths and errors as they are. The text handler quotes and escapes any value with whitespace, a quote or a control character, so a value quoted beforehand is escaped twice.

### Migrating legacy call sites

Migration is incremental and optional. The legacy format stays valid.

- Start with the hottest subsystems (alert dispatch, firewall operations, WAF handlers), where structured fields provide the most value, then work outward.
- Do not batch-convert. Each subsystem should get a dedicated commit with before/after log samples in the PR description.
- Keep the `[TIMESTAMP]` prefix of journalctl lines readable by humans. slog's text handler uses `time=... level=... msg=...`, which is also human-parseable, so journalctl viewers still work.

## Worker processes

Code that parses attacker-controlled input and can loop, crash or exhaust memory runs in a child process under `internal/workerproc`. The daemon can kill a child. It cannot stop a stuck goroutine.

### Protocol

The launcher gives the child one Unix socket as both fd 0 and fd 1. Worker diagnostics must go to stderr, because stdout carries the protocol socket.

- A frame is a 4-byte big-endian length followed by a JSON envelope, and it may carry descriptors.
- The length is checked against a cap before anything is allocated.
- Passing a descriptor never calls `Fd()`, so the caller's pipe keeps its nonblocking mode and deadlines.
- Request descriptors are duplicated before launch, and the caller may close its files once a call returns.

`workerproc.Handshake` sends `hello` and checks the child's protocol version before any real request. It honors cancellation and the context deadline, refuses reply descriptors and clears the socket deadline before returning.

### Failures and the breaker

A request that misses its deadline kills and reaps the worker, and that worker is never used again. Any other round-trip failure does the same, and its error matches `workerproc.ErrWorkerFailed` with its text unchanged. A failed start matches `ErrSpawn`, not `ErrWorkerFailed`.

Three failures in a row pause spawning for 60 seconds, then one trial request is let through. This pause is the breaker. Each supervisor publishes a `requests` queue-health row.

Some errors are not worker failures and never count toward the breaker:

- Caller cancellation, including during launch, does not count. A canceled trial restarts the breaker cooldown.
- The daemon running out of descriptors (EMFILE or ENFILE) while duplicating request descriptors or starting a child does not count. The request counts as lost work, but the healthy worker stays. Outside load can push the daemon to its descriptor limit, and that must not switch a worker off.
- PHP parser panics reported in a valid reply count as lost requests but do not replace the worker.

`Config.BreakOnSpawnOnly` narrows the breaker to failed starts. The mail parse workers set it. A refused extraction delivers mail unscanned under `fail_mode: open`, so crafted mail that kills workers must not open the breaker for unrelated messages. Each message then costs at most one spawn. Every successful start resets the failed-start count, even if that worker then fails on its input or the caller cancels the request.

A known limit: when the daemon is at its descriptor limit, the kernel drops descriptors a reply carries. That looks the same as a worker sending too many, so it counts as a worker failure, classified as a crash and not as a protocol violation.

### Failure reasons

`workerproc.FailureReason` classifies counted failures as `timeout`, `protocol`, `crash`, `oom`, or `spawn`, including through wrapped errors. Diagnostic text and underlying errors remain unchanged.

- Malformed frames and rejected descriptors are protocol failures.
- A broken socket is a crash, unless the process reports an OOM kill.

### How an OOM kill is detected

The daemon cannot read a unit worker's kill from the unit's own cgroup. By the time it sees the worker die, systemd has removed that cgroup and its counters.

On cgroup v2:

- Each supervisor uses its own slice. The slice's `memory.events` counts its children's kills and outlives them. The daemon compares it with its value at start.
- Before that snapshot, startup waits for any previous unit's cgroup to disappear, bounded by `StartTimeout`. A reaped `systemd-run` client alone does not prove its service has exited.
- Standalone CLI scans include their process ID in the prefix to keep their slices distinct.

On cgroup v1:

- That counter is not hierarchical, so an eventfd on `memory.oom_control` reports the kill as it happens.
- OOM and removal notifications are counted together, even when they arrive in separate reads.
- A single notification with the directory gone remains undecided until the watch closes after the client's exit.

### Hooks and counters

`Config.OnFailure` receives each counted failure while the supervisor lock is held. The callback must return promptly and must not call back into the supervisor.

`Stats.Kills` counts these failures by reason, including failed starts, and returns an independent snapshot.

`Config.OnJob` receives one outcome for every request that reached the breaker:

- `ok`, with the worker's memory use after the job (0 when unknown);
- a failure reason;
- `refused`, when the breaker turned the request away.

`Config.OnJob` runs under the same lock and rules as `OnFailure`. The daemon feeds it into the `csm_parse_worker_*` metrics.

Some events are not reported:

| Event | `OnFailure` and `Stats.Kills` | `OnJob` |
|-------|-------------------------------|---------|
| Cancellation | Not reported | Not reported |
| A stopped supervisor | Not reported | Not reported |
| Local descriptor exhaustion before the round trip | Not reported | Not reported |
| A breaker refusal | Not reported | Reported as `refused` |

### Retiring workers

Retirement keeps the reply and is not a failure.

- `Config.MaxJobs` retires a worker after that many requests.
- `Process.Retire` lets a launcher retire a worker after a request, for example over a memory threshold.
- `Config.IdleTimeout` stops a worker left unused. The idle countdown restarts only after a served request and never stops a worker in the middle of one.

`Config.MaxJobs` and `Config.IdleTimeout` default to zero. The PHP taint worker leaves them at those defaults.

### Inputs that keep failing

`workerproc.Strikes` remembers inputs that made a worker fail. Two failures within 24 hours block an input, for at most 1,024 inputs. `NewStrikesWith` sets a different limit and window. A failure counts only if it falls within the window of the one before it.

- The phishing check keys it by the zip's SHA-256. It reports a blocked zip with the `phishing_kit_archive_unscannable` warning and does not retry it on every scan.
- The spool watcher keys it by Exim message ID. It also counts kills per message source, with a limit of three in ten minutes.

### Which workers exist

- The PHP taint worker (`csm phptaint-worker`) runs through `UnitLauncher` as `csm-phptaint-worker-<generation>`, with the parse worker's lockdown and a 512 MiB memory cap.
- The archive parse worker and the mail extractor are described under [Parse worker units](#parse-worker-units).
- The YARA workers run through `UnitLauncher` too. See [YARA-X Worker Process](#yara-x-worker-process).

### Parse worker units

The archive parse worker (`csm parse-worker`) runs through `UnitLauncher`. Each worker is a transient systemd unit started with `systemd-run --pipe`, named `csm-parse-worker-<slot>-<generation>`, with the properties listed in [service confinement](service-confinement.md). There is no fallback to running it directly.

The daemon installs one lazy zip lister, using slot `zip0`, before scans start. The lister publishes `archive_list.requests` and is stopped during daemon shutdown.

| Limit | Value |
|-------|-------|
| Requests before the worker retires | 1,000 |
| Idle time before the worker retires | ten minutes |
| Timeout of each archive RPC | 30 seconds |
| Unit startup timeout | ten seconds, separate from the RPC timeout |
| Reaping | can take another ten seconds |

#### Memory checks at start

After the hello exchange, and before an archive request, the launcher does four things:

1. It checks that the worker's main PID is in that unit's own memory cgroup.
2. It reads back the RAM cap.
3. It caps swap.
4. It reads current usage.

How swap is capped depends on the cgroup version:

| cgroup | With swap accounting | Without swap accounting |
|--------|----------------------|-------------------------|
| v1 | Caps memory and swap together. | Sets swappiness to zero. |
| v2 | Disables swap. | Requires a host with no active swap. |

A missing cgroup, a cap that does not read back, unreadable counters, or usage already over the cap fail the start. Process RSS polling cannot replace this check: it misses memfd pages and other processes in the unit.

#### Memory watchdog and retirement

A watchdog reads the cgroup counters every 500 ms. It kills a worker over its cap, or one whose usage cannot be read. It skips a tick when the daemon itself runs out of descriptors (EMFILE or ENFILE).

Memory kills are identified by the watchdog or by the unit's cgroup OOM counter. A missing or unreadable counter alone is not evidence of an OOM kill.

A worker over three quarters of its cap after a request is retired. Units also retire at three quarters of their lifetime cap. The supervisor checks retirement before reusing an idle worker, as well as after a request, so expired workers get no new input.

#### Kill and cleanup

Kill closes the socket at once and asks systemd to kill the unit by name. It never signals a PID and never blocks.

The daemon attempts to kill leftover `csm-parse-worker-*` units at startup, with a 30-second timeout. Cleanup failures are logged, and lister initialization still proceeds. Disabling scheduled phishing checks does not disable cleanup or archive listings for requested account scans.

#### Archive listing

The worker gets an open zip descriptor, never a path. It reads the descriptor with positional reads, so the daemon's file offset stays put. It returns entry names in a memfd it seals against writes, growth and shrinkage.

The daemon treats every reply byte as hostile:

- It checks the seals, then the size, every record and the entry count, before the visitor sees one name.
- Records are charged against the request's directory budget, never a size the worker reports.
- A malformed reply kills the worker and matches `workerproc.ErrWorkerFailed`.
- An archive the worker could not read reports itself incomplete, without counting as lost work.

A worker can still leave names out: validating the reply does not verify the archive. Name classification stays in `internal/checks`.

#### Mail extraction

`workerproc.Pool` holds a fixed number of supervisors, one per slot, and `Call` names the slot. The mail extractor (`parseworker.Extractor`, op `extract_message`) sizes its pool from `email_av.scan_concurrency` and names units `csm-parse-worker-mail<slot>-<generation>`.

The mail extraction API accepts open spool header and body descriptors. Spool event descriptors are close-on-exec, so worker launch commands cannot inherit queued messages.

The worker writes each non-empty attachment to a memfd sealed against writes, growth and shrinkage. The reply is bounded:

| Field | Limit |
|-------|-------|
| Parts in a reply | at most 200 |
| Names, content types and archive names | cut to 255 bytes |
| The partial reason | cut to 512 bytes |
| From, Subject and each recipient | cut to 998 bytes |
| Recipients | at most 100 |

The daemon validates the reply:

- It must be one UTF-8 JSON object with a `parts` field, which may be null for an empty result.
- Each part must have a readable, sealed descriptor of the claimed size.
- Individual sizes and their total must fit the request's limits without integer overflow.
- An invalid reply discards all parts and kills the worker with reason `protocol`.

The spool watcher extracts every message through the extractor. Each scan goroutine owns one worker slot, because parts are charged to the memory cgroup of the worker that wrote them. A failed extraction becomes a partial result naming the failure, never an error.

Replacement and shutdown follow these rules:

- Watcher replacement waits for the previous scan goroutines to finish before reusing their slots.
- On shutdown, queued spool events release their descriptors without starting extractions.
- The daemon waits for active scans and watcher restarts to finish before stopping or clearing the parse pools.
- If a panic unwinds the daemon before shutdown is signalled, cleanup skips that wait so the process can exit.
- Extractor lookup and removal share the watcher lifecycle lock, because a replacement may still be starting.

#### Tests

Unit tests use temporary proc and cgroup trees, never the host's. The kernel tests in `internal/workerproc/unit_kernel_test.go` run real units as root on the CI kernel runner.

### Hardening undo storage

The root hardening worker saves what it changes, so a fix can be undone. It owns `/var/lib/csm-hardening-undo` with mode `0700`. Each `<name>.json` record is a root-owned regular file with mode `0600`.

- Requests carry fix names only. Saved values come from the worker.
- The daemon may list record names read-only, without opening their contents.
- Applying a fix writes its record.

The undo worker reads one fix's record, restores what it lists while the host still holds the applied state, and removes the record once the fix is undone. The web UI starts it for `POST /api/v1/hardening/undo` and writes the `operate.undo_hardening` action log record, since the worker has no action log. The undo worker runs under the apply worker's unit name, so systemd never runs the two at once.

#### When the setting is already back

Before checking that the host still holds the applied state, undo checks whether every element of the record already holds its earlier state:

- the SSH block value or its absence, and the global lines enabled in recorded order with no remaining CSM-disabled lines for that keyword;
- the sysctl runtime and drop-in values;
- the tweak value;
- each PHP drop-in's key;
- the owner and mode;
- open compiler access for the script method;
- the `UPDATES` values.

If they all do, undo changes nothing, removes the record and reports `undone`. An operator who reset a setting by hand is then not left with an Undo button that only refuses. For tweaks, no value and an empty one count as the same, since WHM's own reset leaves no value.

#### When a restore step fails

| Failure | What undo does |
|---------|----------------|
| A sysctl runtime restore fails | Puts the applied runtime value and drop-in back. |
| A PHP drop-in write fails | Puts the applied drop-ins back. |
| A cPanel command, or an owner or mode restore, fails | Rolls back the completed steps too. |
| A configuration write fails after rename | Restores the applied content. |
| The rollback also fails | The error names the recovery failure and the record stays. |
| The undo would rewrite a symlinked sysctl drop-in | Fails before anything changes. |
| An SSH managed block was nested, duplicated, or moved into a Match section | Undo refuses. |

A failed service reload is handled as on apply. Once `sshd -t` passed, the restored files stay, the undo reports `undone` with the apply's manual reload note, and the record goes. A host where a reload always fails can therefore still undo.

#### WHM tweak settings

`whmapi1 set_tweaksetting` saves a setting only when given a value, and cPanel validates the value. Undo therefore refuses in two cases:

- The earlier tweak value is missing or empty.
- The call refuses the earlier value with `metadata.result` 0.

In both cases undo keeps the record and the applied value, and points to WHM Tweak Settings. A failed command or an unreadable reply is still a failure.

The apply result says undo will need WHM Tweak Settings when the recorded earlier tweak value was absent or empty, including after repeated applies.

#### The cPanel updates file

The `cp_updates` record holds the whole file before and after the apply. Undo works out the apply's edits by comparing the two. The apply either set the first active `UPDATES` line (even if it was already daily) or added one, and it commented out any later active `UPDATES` lines. A record with any other edit is refused as not matching the fix.

Undo checks only the current active `UPDATES` lines against the applied value, and restores only those lines:

- It enables commented duplicates in place, or after the restored line when a cPanel save dropped the comments.
- Missing duplicates follow the nearest surviving earlier setting, so their original order is preserved.
- If only some identical comments survived, undo refuses. It does not guess which comment the apply created.
- Every other line stays as it is.

#### What apply records

- Each successful sysctl runtime change is recorded before the next command. Its record is then updated after the drop-in is saved.
- PHP records grow after each successful scan-directory write. A later stalled operation then does not lose recovery information for completed changes.
- SSH capture accepts both whitespace and equals separators. It keeps the first value for each keyword in the managed block, matching sshd's interpretation of edited settings.

#### Applying a fix again

A fix can be applied again, as a retry after a partial apply or over a setting that still holds what CSM set. The apply reads the fix's record before changing anything.

- Each setting that still holds the earlier apply's value keeps the state from before that apply.
- A setting changed by hand since keeps the state found now.
- PHP drop-ins this apply did not write keep their earlier entries.
- Permissions, owner and group are compared independently, so editing one does not lose the original state of the others.

Global SSH lines that CSM still holds disabled stay in the record in their current file order, also when the block value was edited or removed by hand. Removed or edited comments are not carried forward, and uncommenting a line does not record it twice.

In three cases the fix still applies, the record is removed, and the result says undo is unavailable:

- The existing record cannot be read.
- The state before the change cannot be read.
- The new record cannot be written.

#### How the store writes files

- Store operations validate fix names before constructing record paths.
- They use directory-relative, no-follow opens and check ownership and permissions on opened inodes.
- Each write uses a private temporary file, syncs its data, then renames it and syncs the directory.
- Creating the store also syncs its parent. Deleting a record syncs the store, including on a deletion retry.
- A sync failure is returned to the caller. A failure after rename or unlink can mean the change is visible but not yet durable.

## YARA-X Worker Process

By default CSM never compiles or scans YARA rules in the root daemon. Two kinds of `csm yara-worker` process run through `workerproc.UnitLauncher` with the parse worker's lockdown: no root, no network, no account files, a memory cap and a lifetime cap.

`signatures.yara_worker_enabled: false` runs YARA-X inside the root daemon instead. `csm validate` warns about it.

| Part | Where it lives |
|------|----------------|
| Wiring | `internal/daemon/yara_backend.go` |
| Daemon side, `yaraworker.Backend` | `internal/yaraworker/backend.go` |
| Worker side, `yaraworker.Serve` | `internal/yaraworker/worker.go` |

### The compile unit

The compile unit, `csm-yara-compile-worker-<generation>`, runs for one compile.

| Limit | Value |
|-------|-------|
| Memory cap | 1 GiB |
| File size, which bounds its reply | up to 256 MiB |
| Unit lifetime | five minutes |
| Time the daemon allows for the compile request | two minutes |

A compile goes like this:

1. The daemon reads the rule files, with the trust check and disabled-rule stripping, and passes their text in one sealed memfd.
2. The worker compiles with includes disabled, so rule text comes only from that memfd.
3. The worker returns `Rules.WriteTo` output in a sealed memfd.
4. The daemon copies it into its own sealed memfd and keeps it.

### The scan unit

The scan unit, `csm-yara-worker-<generation>`, is a single worker. It cannot write files and has a 24-hour lifetime.

Its memory cap is 512 MiB plus the larger of `thresholds.full_scan_max_file_mb` and, with mail scanning on, `email_av.max_attachment_size`. Both are read from the live config at each launch.

Before the supervisor may send the worker a scan, the launcher loads the kept rules into it. A restart loads them again and never recompiles: 55 ms for the shipped rules, about 3.4 s for Forge full.

### Rules common to both units

Both units run with `MemoryDenyWriteExecute=no` (`UnitConfig.AllowExecutableMemory`). wasmtime maps the compiled rules executable, and with the denial the load fails as "invalid YARA-X compiled rules file". No `RLIMIT_AS` is set. The cgroup cap is the limit.

At startup the daemon attempts to kill leftover units of both prefixes. Cleanup failures are logged without preventing startup.

### Rule reloads

A reload compiles in a new compile unit. Compiles run one at a time. A canceled startup retry stops waiting even when a rule update is already compiling.

| Result | What happens |
|--------|--------------|
| The compile succeeds | The new rules replace the kept ones. The scan worker on the old rules retires before its next request, and a background warm-up starts its replacement. |
| The compile fails | The current rules stay. With none loaded, the failure is `CompileError()`. |

Forge downloads are compile-tested in the compile unit before they are installed. The merged reload afterwards can still fail:

- If it fails because the compile unit could not run, the new tier stays on disk, its version is not recorded, and a Critical `yara_backend_unavailable` finding says so.
- Only rules that do not compile, or a collapsed rule count, roll the tier back.

### Failures and findings

The backend is active from boot, before the first compile. While no rules are loaded because a compile failed or could not run, every scan returns an error, never a clean result.

#### Compile failures

The boot compile runs before the daemon reports ready to systemd, so it is bounded to 45 seconds. A compile that cannot start, crashes, times out or outlives that bound is retried in the background with backoff. When the boot attempt and three retries have failed, a Critical `yara_backend_unavailable` finding fires.

Rules that do not compile raise Critical `yara_worker_compile_failed` and are not retried. So does a rule set the compile unit cannot fit:

- more than 1024 rule files, which is refused before a unit starts;
- an out-of-memory kill under the 1 GiB cap;
- compiled rules over 256 MiB.

Each message names `signatures.yara_worker_enabled: false`, which compiles in the daemon.

#### Scan worker failures

Any counted scan worker failure (failed start, timeout, crash, out of memory, protocol) marks `watcher: yara_worker` failed and raises Critical `yara_worker_crashed`, at most once a minute after the last alert. An attached worker is killed. The next request starts a replacement, and a served request marks the watcher attached again.

Only failed starts count toward the worker breaker (`BreakOnSpawnOnly`). Content that kills the worker costs one restart per scan and cannot switch YARA off for other files.

#### Content that keeps killing the worker

The backend keeps `workerproc.Strikes` by SHA-256 of exactly the bytes sent for scanning.

- Content with two scan worker failures within a day is refused as a scan error, without starting another worker.
- The check and failure recording run under the supervisor's request lock (`Supervisor.CallGuarded`), so queued copies see the failures ahead of them.
- A failure is recorded against the rules the worker actually loaded, even if a reload lands while it starts.
- Failed starts, cancellation, breaker refusals and descriptor pressure do not strike content.
- Hashing runs only while an unexpired strike is recorded, or to record a new failure.
- Records expire a day after the last failure, and a successful rule reload clears them.
- The list holds at most 1024 content hashes, evicting the oldest failure when full.

### Wire contract

The workers speak workerproc frames on the unit's socket pair.

| Op | Request descriptors | Reply |
|---|---|---|
| `hello` | 0 | protocol version |
| `compile` | 1: rule texts back to back, named and sized by `sources` | `rule_count` and a sealed memfd of compiled rules, or `compile_error` and no descriptor |
| `load` | 1: compiled rules | `rule_count` |
| `ping` | 0 | `rule_count` of the loaded rules |
| `scan_fd` | 1: content, read positionally up to `max_bytes` | `matches`, always an array |

- Malformed requests get an error frame, which kills the worker.
- A rule compile error is a result, never a worker failure, and its text is cut to fit the frame.
- Scans need a regular descriptor and every requested byte. The worker gets its own read-only open of a file.
- Byte scans travel as sealed memfds, so the frame cap does not limit them.
- With no rules, or every rule disabled, byte scans answer clean without a worker unless compilation failed, and mail-part scans fail.

### Testing

`internal/yaraworker` launches the test binary as the worker with a fake engine (`helper_test.go`), including fault modes for crashes, hung loads and bad compile replies. Tests tagged `yara` run the real engine, including backend recovery from invalid rules with disabled rules still excluded. Unit lockdown is verified on the CI kernel runner and on scratch hosts.

## Response admission primitives

This section is reference material for people who change response admission. Admission is the path that decides whether an automatic response, such as an IP block, goes ahead. [Auto-Response](auto-response.md) describes it from the operator's side.

`internal/admission` is a standard-library-only package. Its persisted enum values are fixed by golden tests.

The section uses these terms:

- The ledger (`store.AdmissionLedger`) is the durable admission state in the daemon's state database.
- The owner (`internal/admissionowner`) is the daemon component that holds the only ledger handle and makes every change.
- The engine is the firewall engine that applies and removes blocks.
- Evidence is what a detector observed. A candidate is one queued response, and the pieces of evidence it names are its roots.
- A pick is a candidate that a schedule selected. A member is one pick in an engine batch.
- An attempt is one try at running a candidate. Its outcome is applied (verified), failed or unknown.
- A class (C1 to C3) is the priority of a candidate. A tier is a class and severity pair, such as (C2, High). Only the tier decides which block may replace another.
- A lane is the service a pick draws on: the reserved lane, for direct compromise and corroborated evidence, or the general lane. A partition is the part of the queue or of the block set that belongs to a lane.
- A scope is the fairness unit: a verified owner (the host or one hosting account) and an action family.
- An episode groups the observations made at one target close together in time.
- An observe preview runs a candidate through admission without applying anything. A forecast is the dry-run prediction of what a block would do.

### Assessment

`Assess` sets `ReassessBy` to the first instant at which, without new evidence, the current class or severity falls or all roots become stale.

- Redundant evidence can preserve the tier after another root expires.
- Each corroborating pair lasts until its local root loses freshness or its support expires. The longest-lived pair determines how long corroboration remains available.
- Equal deadlines and input order do not affect the result.
- Direct compromise evidence may expire while corroboration continues to preserve the same class.

### Slot limits

`SlotLimits.Take` adds a scope holding only for one-unit `block_ip` work. Zero-cost and multi-unit work do not add holdings, even when marked as eviction-capable. Free slots still decrease by the granted cost.

### Effect records

An effect record is an automatic block's hold on a slot of the temporary block set.

- Effect records use an expiry-ordered key followed by the action ID.
- Decoding requires a canonical value that reproduces the key and all recorded fields.
- Records and intents without an eviction keep their version 1 encoding.
- Only records still holding slots contribute to occupancy and expiry wakes.
- Only a live ledger has effect records.

The effect records' partition tally rejects negative counts, underflow and overflow. A failed addition returns the original tally. Combining a tally with set occupancy also returns an error and the original occupancy if either partition's total is invalid or overflows.

Startup readers report an error if the effects bucket disagrees with the schema or an effect is a nested bucket. They do not treat damaged eviction storage as an absent record.

### The capacity notice

A full-set deferral raises the capacity notice for any assessed tier in a live ledger. A preview ledger raises it only for Critical work. A live rotation also raises it.

Notice allocation preserves the new attempt's recovery hold. Insufficient room sends the notice to its fixed overflow record.

### Victims and evictions

A block that finds the set full can take the slot of another block, its victim. Taking the slot of a strictly lower-tier block is an eviction.

Victim references accept either of two forms:

- an admission attempt ID;
- an import's name, which is `eff_` followed by 32 lowercase hex digits.

Record keys remain attempt IDs. An import has no record key.

A pending block that evicts names its victim in its effect record and its intent. An admission victim's record names the block that claimed it. What happens to the claim depends on the block's outcome:

| Outcome of the claiming block | What happens to the victim claim |
|-------------------------------|----------------------------------|
| Application verified, victim's removal proven | The victim's record stops holding a slot. It is marked gone at the evicting block's outcome. |
| Verified, but the block never removed its victim | The claim is released. |
| Removal unproven | The outcome is unknown, never verified. |
| Definite failure | The claim is released. |
| Unknown | The claim is kept through retirement until the victim expires. |
| The reservation expired without running | The claim is released. |

Expiry can remove either record first. A late definite outcome still ends the claim using the retained intent.

A partition that holds more than its limit allows no replacement until the complete state fits again. While a lane has no usable slot and no strictly lower victim, the scheduler does not pick that lane's work, and each waiting scope keeps the turns it has earned.

### Imports

An import is a stamped legacy block that the firewall lists each turn. It can be a victim, but it has no record of its own.

- Imports have the fixed tier (C2, High) and occupy general slots.
- Only the claiming block's record and intent name an import, by its `eff_` name. No other block claims it while that record does.
- Opening the ledger rejects a second claim on the same import. It also rejects an import claim unless the claiming block holds a general slot and its tier is above the import tier.
- Execution uses the current turn's list. A missing or changed import drops the claim.
- A member's sweep also ends its import claim. A delayed outcome may still name the import in its intent without looking for a victim record.
- Imports never rotate.
- Imports have no durable cleanup record. A restart before retirement restores the import only until its original expiry.

Scheduling, reservations, observe previews and wake calculations share the turn's import list. They count at least as many general imports as it names, while preserving a larger occupancy count.

What each of those writes differs:

- Observe previews write no claim or effect record.
- Wake calculations write nothing.
- A preview reports the block whose slot it took, so the owner counts previewed replacements in status. A readback reports none.

The codecs keep their existing versions. An older build refuses a ledger containing import claims, so such a ledger must stay on a compatible build. A ledger that never executed has no such claims.

### Gone records

A gone record is the record of a verified block that the firewall has stopped holding. A gone record holds no slot, so waiting work can take it. The record stays until its expiry sweep.

A record becomes gone in two ways:

- A verified eviction marks its victim's record gone at the evicting block's outcome.
- A verified block that two consecutive firewall answers do not hold is gone from the first of them. It does not matter what removed it: an operator unblock, undo or flush, or a lost kernel element.

The two-answer count works like this:

- A held answer in between starts the count again.
- The count lives in memory, so a restart only delays the mark.
- Failed answers keep all earlier misses and count nothing new.
- Bounded batches get two answered checks before advancing, so a larger configured capacity cannot hide later records.
- If something else changed the record between the two answers, the check does not mark it and leaves it to that change.

#### How the owner asks the firewall

The owner asks at most once a minute, and only while the ledger counts a verified block. The firewall answers with the retirement rule reversed and writes nothing. It counts an address as held in two cases:

- A firewall set element is still present for the address, and no other action has a verified row that accounts for that element. This holds even after a forward wall step makes the block's own row look expired.
- The firewall cannot read the address's family.

A failed or short answer marks nothing and counts as no miss.

#### Schema 14

The first stored gone record moves the ledger to schema 14, which older builds refuse.

- Schema 14 requires the live-start marker, effect bucket and tally even after all records expire.
- A check that marks nothing leaves the schema unchanged.
- Preview and forecast hosts never write schema 14, because only a live ledger has effect records.

#### Removing the firewall state row

A slot the ledger has stopped counting must not come back through the firewall's saved state.

- Startup drops the state row of an admission-record victim whose eviction the ledger verified, and of a block the ledger marked gone. A restart then cannot restore the element.
- A running owner retires the row of a block it marks gone as it retires an evicted victim's row. A firewall reload then cannot restore it either.

A cleanup pass that clears no row is retried twice at once, then after waits that double from two seconds to a minute. A row that leaves ends the wait. A new eviction goes ahead of the waiting rows and is tried at once.

### Equal-tier rotation

Eviction needs a strictly lower victim. A live ledger on a trusted clock may instead rotate an equal-tier record out of a full partition for fresh work. Fresh work is work whose episode row has had no verified response. Work queued without an episode row is never fresh.

The victim of a rotation must meet all of these:

- It is a verified record of exactly the work's tier.
- It is in the partition of the work's own lane.
- Its 30-minute hold has passed on both the admission clock and the ceiling's elapsed time since its verified application.

A reboot grants no elapsed time, and a degraded reading allows no rotation.

#### How a partition is shared

Each partition is shared among its active scopes, using the queue's integer share rule. The active scopes are:

- the scopes whose unexpired, unclaimed records hold its slots;
- the scopes of queued work that would hold one at the last schedule cycle;
- the requester's scope.

A partition's remainder cursor decides which scope gets the leftover share. A live schedule cycle that runs on a trusted clock reading and reads the victim pool moves each partition's cursor to the next active scope before it picks anything. It stores the cursor beside the queue cursors, so reservations share the set as their cycle did. A preview ledger never moves it.

| Requester | What it may rotate |
|-----------|--------------------|
| Its share is zero | Nothing. It waits for a later cursor turn. |
| It is at or over a positive share | Only its own scope's records. |
| It is below its share | Only records of the scope with the greatest excess. |

For a requester below its share, the scope with the greatest excess is chosen among those holding a verified record of its tier in that partition at another address. The rotation never takes that scope below its share. The requester waits if that scope has no record whose hold passed.

The oldest application, then the lowest action, goes first.

#### What a rotation records

- The claim and its outcome are those of an eviction.
- Opening the ledger accepts an equal-tier claim only inside the block's own lane partition.
- An older build refuses a ledger holding a rotation claim or a moved set cursor.
- Saved ceiling turns keep their earned credits through slot pressure and restart. Backoff keeps its existing release behavior.

### Policy lookups and hosting inventory

Policy lookups can overlap across registration, minting and validation, so they must be immutable or safe for concurrent use. Callers must serialize every operation on an inventory generation tracker.

Off cPanel, hosting inventory reads account directories without checking mount state:

- An empty readable root contributes no accounts, while other readable roots still do.
- An unreadable required root fails the whole snapshot.

#### Incarnation tokens

Every account carries an incarnation token. On cPanel it is the recorded creation date. Elsewhere it is the device, inode and birth time of the account's home directory. Tenant edits do not change the token.

A changed token gives an account a new generation, even when the account was replaced between two observations.

These cases fail the snapshot:

- The account's token cannot be read.
- The account's home is not a directory. This includes a home listed as a symlink.
- The account's Linux filesystem supplies no birth time.
- The cPanel creation date is missing, empty, overlong or overflowing. It must contain only decimal digits and be recorded exactly once.

cPanel records zero for its own system entries. Recreating one between observations keeps its generation when the token stays the same. An observed absence retires the generation even for a zero-dated entry.

### The ledger and its owner

The admission ledger (`store.AdmissionLedger`) keeps this state durably in the daemon's state database, in `adm:` buckets it creates the first time it is opened.

The daemon's admission owner (`internal/admissionowner`) opens the ledger at startup and holds the only handle. After its first clock reading and ceiling, and before ingress or admission, it settles what a previous process left outstanding. See [Settling after a restart](#settling-after-a-restart).

One goroutine makes every change. It also does this:

- It records clock readings on a timer.
- It applies the ceiling at startup. After a reading at the saved limit, it applies it again on reload or on the first tick that sees a changed configured value.
- It refreshes the inventory from complete reads.
- It delivers audit rows to the action log, and notices through the queue-health path, each with their own pacing.
- It reads status on a timer.
- Each hour it appends counts of its decisions to the action log.

One owner serializes every write, and each call is one transaction, so a failed call changes nothing.

Failed ceiling reloads stay pending until a tick applies and checks them again. Inventory refreshes cannot reopen admission in the meantime.

#### Drains

Detectors submit work to an in-memory ingress. Once the ingress has made new decisions, the owner drains it on a short timer. Each group is frozen before its fresh clock reading, so concurrent submissions wait for a reading that includes their observation time.

A clean stop drains all held work and checkpoints final decisions before closing the generation.

| Case | What the owner does |
|------|---------------------|
| A drain fails, including its clock or publication step | Admission closes until a drain succeeds. |
| The only failure is a damaged ledger record | This is not a failed drain. The arrivals naming that record are discarded and counted lost, the rest commits, and admission stays open. |
| A later write, checkpoint or snapshot fails in that same drain | Admission closes until a drain succeeds. |

Recovery by a tick, an inventory refresh or a reload does not clear the cause of a failed drain. A failure that lasts is therefore reported as one stop, with its original cause.

For a damaged record, status and `csm doctor` keep the damage cause until the daemon restarts. If admission closed in that drain, recovery clears the drain failure but keeps the damage cause for the discarded work.

#### Wiring into the response funnels

The daemon wires the owner into the response funnels (`checks.SetResponseAdmission`) while it runs.

- Each automatic response the legacy funnels select is minted as evidence and submitted to the ingress.
- Derived responses carry the root evidence that caused them. The derived responses are challenge timeout, central, incident, mail subnet, ASN crawl, netblock and permanent block.
- Legacy blocking never waits for admission, and admission's outcome never changes a legacy decision.

The owner serves its queue as observe previews. A schedule reserves and charges each pick and ends it observed in one transaction, so a crash cannot leave a preview reserved.

#### Admission time

Admission time comes only from recorded clock readings.

- A wall clock that steps back never lowers it.
- A new boot credits no elapsed time.
- A reopened ledger admits no new work until it records a fresh reading.

#### Evidence and candidates

Evidence is immutable once published. Later reports of the same observation are kept as bounded links.

| A later mint of the same evidence | Result |
|-----------------------------------|--------|
| Differs only in its owner, because the inventory changed between the two mints | Refused as a stale identity. |
| Differs in its owner and any other field, including the finding | The record is invalid. |

A candidate takes its entry, check and finding link from its primary evidence. It coalesces repeated requests without refreshing its queue age. It moves from queued through reserved and executing to one outcome.

- A proven failure may requeue after a backoff, with at most three attempts in total.
- An unknown outcome never retries.
- Reserve and Execute report whether the call granted the step. Reading back an attempt that is already reserved or running grants nothing.

Candidate records come in two versions:

- A record without an existing-effect link keeps version 1 and its original encoding.
- A refused existing-effect candidate can carry the block name and expiry in version 2.

A candidate's maximum encoded size includes the link only when present. Attempts and audit rows keep their existing formats.

#### Settling after a restart

A new process settles what the previous one left outstanding before it reserves anything. Nothing is dispatched again.

| What the previous process left | Result |
|--------------------------------|--------|
| A reservation. It recorded no intent, so it dispatched nothing. | It fails and may retry. |
| A running attempt | It ends unknown. |

These rules also apply:

- A handle that has granted a reservation refuses to settle.
- An unknown outcome needs the intent its attempt recorded until that uncertainty is retired, including when reading the outcome back.
- A missing intent or intent bucket returns a corrupt-record error without changing the ledger.
- An empty ledger settles without a clock reading.

#### Kill-point tests of the owner

The owner's kill-point tests stop it at each step of a block turn and of audit delivery, then start a new owner on the same ledger. After the restart the tests expect this:

- A reservation has failed and retries as its next attempt.
- A running attempt is unknown and holds its address until it retires.
- The startup reads hold back every row whose outcome did not finish as applied.
- The consumers see only outcomes that finished as applied.
- No attempt reaches the engine twice.
- Original attempts keep their charges. Retries consume new charges without renewing the original expiry.

Synthetic clocks keep the scenarios independent of runner load.

### Ledger schemas

The ledger's schema number rises as it stores new kinds of data. Older builds refuse an unknown schema and do not misread it. A write never lowers the schema.

| Schema | What it adds or what first writes it |
|--------|--------------------------------------|
| 2 | The queue |
| 3 | The emergency ceiling |
| 4 | Storage accounting |
| 5 | The outbox |
| 6 | Offense episodes |
| 7 | Execution intents |
| 8 | A linked existing-effect record |
| 9 | A `verdict_allow` record or a dry-run ending |
| 10 | The first `disabled` record, or an ingress checkpoint carrying disabled refusal counts |
| 11 | The live start |
| 13 | The first episode row with a positive elapsed end |
| 14 | The first stored gone record |
| 15 | An answered block frontier without candidate references, or a block line that records its latest verified generation |

Each schema from 2 to 7 is created by an upgrade: the first open upgrades any earlier schema in the same transaction. The sections below give each schema's rules.

This build opens schemas 7 to 15 without rewriting them. An unchanged schema-7 ledger stays readable by older builds until a write needs a newer format.

Ledger buckets without schema metadata are an error, including unfamiliar buckets.

### The queue (schema 2)

Schema 2 of the ledger adds its queue. The first open upgrades a schema 1 ledger in the same transaction. Legacy work that cannot fit the unassessed general partition refuses the upgrade and leaves the ledger intact.

#### Positions and fair shares

Ingress, queued and in-flight work share 1000 positions. Of those, 200 take only direct compromise or corroborated evidence. Each partition reserves 64 positions for memory transfers, so durable work cannot consume handoff space.

In a full partition each verified scope has a fair share:

- A scope at its share can only replace its own lowest-tier, newest candidate with stronger work.
- A scope below its share takes one position from the scope most over its share.
- A displaced candidate ends as queue overflow.

#### When queued candidates end

- A queued candidate ends at its age-out, or at its effect expiry while it waits to retry.
- It is assessed again when a root's freshness changes.
- An inventory refresh ends the candidates whose roots name a retired account.

#### Service order

The scheduler serves in this order:

1. The reserved lane first, alternating direct and corroborated turns.
2. Then the general lane, with classes C3, C2 and C1 served in the ratio 4:2:1.

Inside a class, verified scopes rotate. A scope serves Critical, High and Warning in the ratio 4:2:1. A severity serves its oldest candidate.

Deficit accounting lets a candidate that costs several block units wait its turn without starving. The scheduler's position persists, and every pick is checked again before it is returned.

The caller can name two kinds of candidate to a schedule:

| The caller names a candidate as | What the schedule does |
|---------------------------------|------------------------|
| Pending, such as one waiting for the panel's verdict | Passes over it. It is never picked or deferred, its scope keeps its turns, and the next wake waits only for its deadline. |
| Allowed | Ends it without a charge. It is picked as uncharged work at no ceiling or history cost, even with both spent, and wakes the owner at once. |

#### The ingress

Detectors hand work to a nonblocking ingress. The ingress applies the same fair shares against the owner's latest snapshot of the queue.

- It judges freshness at that snapshot's admission time advanced by elapsed monotonic time, so an idle owner does not make new evidence look future-dated.
- Durable victims remain counted until commit.
- Reports arriving during a drain remain held for a later report-only commit, and overflow counts persist with their links.
- Ingress cursor progress and loss counts are checkpointed even when only refusals occurred. Publication cannot overwrite later memory decisions.
- The owner persists held items in groups.
- An ingress generation that ends without a clean close is recorded as interrupted, since its unpersisted items cannot be counted.
- A failed snapshot after a committed drain stops new submissions until the owner publishes a snapshot at least as new as that commit, from the same ingress generation.
- Shared queue damage retains the whole handoff. Only arrivals carrying damage are discarded.

#### Queue regression tests

- The tests reopen the ledger during unfinished scope and reserved sub-lane rotations, then check service order across the restart.
- Overload recovery uses elapsed-time refill and verifies each reservation's charge, so a fresh cursor or an uncharged pick cannot satisfy the test.
- Free-slot rotation tests require a granted reservation, its stored effect, and the expected occupancy and charge, including after a limit increase. A missing effect must fail. It must not count as proof that no victim was taken.

### The emergency ceiling (schema 3)

Schema 3 of the ledger adds the emergency ceiling, an hourly limit. The first open upgrades a schema 1 or 2 ledger in the same transaction, with empty buckets because its recent spend is unknown.

The engine sets the hourly ceiling L. A fifth of it, rounded up, is reserved for direct compromise and corroborated work, and the general lane cannot spend it.

#### Token buckets

Each lane refills a token bucket at its hourly rate, from elapsed time within a boot. A bucket holds up to ten minutes of that rate, with a one-unit floor for a nonzero lane.

The first limit of a new ledger fills both buckets once. A new ledger takes that first limit together with the legacy hourly block count. The count is charged at the end of its hour and subtracted from the fill. A count that cannot be read starts the ledger without credit.

The reader of the legacy count rejects null scalar values. It uses the last instance of a repeated local hour, even when other hours separate its instances. Retained import reads validate the ceiling totals and the charge links to ordinary attempts.

A later limit only clips saved credit. The owner checkpoints elapsed time at the saved rate before changing it.

#### Charges

- Every reservation, retry included, is charged to the lane its schedule picked. The charge is made in the reservation's transaction, after a reserved lane is rechecked against the candidate's current assessment.
- A readback grants and charges nothing. Its lane must be zero or equal the recorded lane, including when an upgraded attempt has no recorded lane.
- A charge counts until a full hour of admission time and of elapsed time have both passed. Neither downtime nor a forward clock step releases it early.
- Schedules serve no more than each lane can charge. The ledger's next wake includes when waiting work gains budget.
- Challenge work spends fair-turn and history budgets without spending ceiling units.

### Storage accounting (schema 4)

Schema 4 adds storage accounting. The first open upgrades a schema 1, 2 or 3 ledger in the same transaction.

#### What stays stored

- Evidence stays stored while a candidate names it as a root.
- Evidence no candidate names waits in a bounded ring and leaves oldest first.
- Candidates that ended before any attempt wait in their own bounded ring and leave oldest first.

The rings mean rejected traffic cannot allocate rows without bound. Report links stay readable after a policy change.

#### History allowances

A candidate's details become history at its first reservation. Each reservation charges its lane's allowance for any growth in the largest size those details can reach. A fifth of the fixed history budget is reserved for direct compromise and corroborated work.

- Each allowance admits history at a rate that spreads its size over the seven-day review window. It saves at most ten minutes of that rate, so a flood cannot fill a week of history in an hour.
- Scopes earn history turns in fixed quanta, so large records cannot take more than their share.
- A record that has earned its turn holds its lane until the credit covers it.

#### How long history is kept

An ended candidate's details are kept through the review window. Unless the candidate was only previewed, they are also kept for as long as the firewall row its attempt may have written can last. A failed attempt's row can outlive a failed restore write, and startup must still know its action while the row could be restored. Endings written before this rule keep their earlier time.

The details are retired after thirty days, or earlier when an allowance needs the room, oldest first.

An unresolved outcome is pinned in a separate recovery reserve until recovery settles it. New work waits while that reserve is full.

#### Ticks and wakes

Tick refills the allowances and retires history at its target in the clock's transaction. The next wake runs the scheduler read-only. Unassessed or overdue queue entries wake immediately for a sweep.

### The outbox (schema 5)

Schema 5 adds the outbox, which holds audit rows and notices until they are delivered. The first open upgrades a schema 1 to 4 ledger in the same transaction.

#### Audit rows

Every admitted step of an attempt (reservation, execution, outcome) writes an audit row in its own transaction. The reservation holds room for all three rows in the recovery reserve, which the outbox shares. Ended history is retired only after its rows are acknowledged.

Queue events and attempt outcomes are also counted into five-minute, hourly and daily buckets.

#### Notices

A response gap is an automatic response that was withheld. Gaps are recorded in the transaction that causes them, as coalesced notices:

- There is one record per reason, check and action family, with a bounded count of examples.
- There is a fixed overflow record per kind.
- There is a fixed Critical summary that no flood can refuse.

Records may use only a fixed share of the reserve. A key is due for delivery at most once an hour, and a summary once a minute, after acknowledged delivery.

Two cases have their own rules:

An applied block whose root is a Critical outbound destination (`c2_connection`) raises a Critical partial-containment record, reason `unsupported_containment` with outcome `applied`. The input-chain drop stops replies from the address, but outbound-only traffic to it still leaves. Its response ran, so it is not counted in the Critical summary or the doctor's gap row.

A protected or allowlisted address keeps its withheld notice when the firewall refuses it before reservation or at the final attempt to apply the block. Neither refusal advances the Critical summary. The attempted block still follows the usual failure accounting and retry limit.

#### Preview and live notice modes

Where a notice goes depends on what the owner is doing:

| The owner | Ledger notices | The stopped-admission notice |
|-----------|----------------|------------------------------|
| Previews or forecasts | Go to findings history only, as Warnings starting "Admission preview:". | Still reaches alert channels, as a Warning saying existing blocking is unaffected. |
| Executes | Go to the alert channels with their kind's severity and no preview prefix. | Is Critical. |

While the owner executes, a gap is an outage of automatic blocking, which is why its notices go to the alert channels.

A ledger notice keeps the mode it was raised in:

- A record with an event from while the owner executed, or from a real attempt's outcome, is delivered live after a dry run starts.
- A record raised only in a dry run stays a preview after execution returns.
- Other records from before a restart take the mode the owner starts in.

The stopped-admission notice is independent of the ledger. It uses the mode at delivery, including for a retried delivery. Stop retries retain their original timestamp, cause and stop identity.

Live and preview groups back off separately, so failing previews never delay a live notice.

If the startup clock fails, these rules apply:

- Later notice mode boundaries use the first valid clock reading.
- Restored notices keep the initial startup mode.
- Deliveries before that reading use the saved ledger time, to retain the mode of events raised during delivery.

#### Acknowledgements

Acknowledgements carry the count and first-event time of the record read, so a repeated acknowledgement cannot consume a later record under a reused key.

An audit row's acknowledgement carries the row's time as well. An acknowledgement held past the row's retirement then cannot remove the row a re-minted attempt writes later.

#### Handing applied blocks to consumers

After the action log write and before the acknowledgement, the owner hands the applied `block_ip` rows of each batch to `Options.Applied`. No other row reaches it.

- A failed call acknowledges nothing, so its consumers see the same row again. Consumers must be idempotent by action and transition.
- A row this process already wrote to the action log is not written again while its consumer or acknowledgement fails, even if new rows sort ahead of it into another batch.
- Each row's successful acknowledgement clears only that row's write receipt. A restart writes pending rows once more.
- Delivery errors remain visible in `admission.owner.audit_error` until a pass succeeds. The independent audit queue reports a stall if a pending batch cannot advance.

#### The threat and attack databases

The daemon opens the threat and attack databases before the owner starts. The consumer refuses rows while either is missing.

For each applied block the daemon does two things:

- It marks the address blocked in the attack database, as the legacy path marks a block that applied.
- While the action's verified firewall row still stands, it records a threat database row that ends at the block's absolute expiry.

One durable transaction per delivery batch precedes threat memory publication. Read or write errors leave delivery pending and threat memory unchanged. Repeats preserve the stored timestamp, counters and undo entries, including after restart.

Local evidence survives feed withdrawal. Permanent local evidence and longer temporary rows remain unchanged.

Locking rules for the threat database:

- Local threat writers serialize separately from lookups.
- The consumer reads the firewall state under the threat writer lock. Unblocks and flush cleanup remove the stored row under that lock, after the firewall row. An unblock that lands during delivery therefore removes what the batch wrote.
- An applied batch does not hold the lookup mutex during its durable write, so reputation reads and whitelist reload continue while that batch waits.
- Store transaction callbacks do not call back into threat mutations.
- Loaders finish reading the store before publishing an instance. Reload changes the existing instance's config whitelist only.

#### Recording blocks where legacy blocks are recorded

After the threat database write, a daemon goroutine records those standing blocks where a legacy block is recorded (`checks.RecordAdmissionBlocks`). It records three things:

- a tracker row that netblock escalation counts;
- a permanent-block strike;
- the Critical `auto_block` finding that reaches history, alerts and the block digest.

The strike promotes nothing, since a permanent block is not an admission response.

- A block already tracked at its expiry is skipped, so a repeated delivery changes nothing.
- The tracker batch is saved before strikes and notices. A crash can lose those best-effort side effects but cannot repeat them on replay.
- An unreadable tracker is left untouched. A failed tracker save emits no strike or notice.
- That goroutine waits for the tracker lock a scan holds. The owner never does.
- The in-memory backlog uses the existing audit delivery bound. A full consumer leaves the durable audit delivery pending for retry.

Blocks already queued when the daemon stops are not recorded there. A delivery after the consumer stops is refused and stays pending in the audit outbox, so the next start records it.

#### Status

`Status` reads every section in one read transaction, without the ledger's lock or a current clock. Each section has its own error. The doctor rules read nothing else: they turn the status and the ingress's own health into a fixed set of rows.

- Missing buckets fail the sections that read them. An unreadable database fails every section.
- Quiet notice indexes are checked with their records.
- Health snapshots own copies of the admission view.
- A clean ingress generation clears the interruption marker.

### Offense episodes (schema 6)

Schema 6 adds offense episodes. The first open upgrades a schema 1 to 5 ledger in the same transaction, without inventing episodes for candidates queued before.

An episode is the ledger's record of the current offense at one target. Responses of every kind at one target share its episode.

#### Episode identity and storage

- Each ledger draws episode IDs from its own random nonce and a counter. IDs never repeat, even in a ledger created again after loss.
- Opening the ledger proves every episode row against the candidates it names.
- The ledger, not the caller, assigns each arrival its episode and generation when it persists the arrival. An arrival that names either is refused.
- An episode that cannot be encoded is ledger damage.

History entries written before episode accounting keep their charges and encoding at upgrade. New entries require the episode allowance. An older entry is exempt only while it has no row for its episode.

An episode row lives only as long as a candidate it names:

- Ring eviction and history retirement clear that candidate reference. While another candidate holds the row, they retain the candidate's generation and whether its effect answers its kind.
- The last retained candidate takes the row with it.
- Each admitted candidate's history charge covers a row.
- A target without a row opens a new episode, so a retired candidate's ID is never minted again.

#### Which episode an observation joins

| The observation | Result |
|-----------------|--------|
| Was made within an hour of the episode's last one, or while the episode's work is queued or in flight | It joins the episode. |
| Was made later than that | It opens the next episode. |
| Is older than the previous episode's end | It is refused as stale. |
| Was already accepted by that episode while its work held it open | It is refused as stale. |
| Is dated after the ledger's current reading, even within assessment's clock-skew tolerance | It is refused. |

The last rule keeps future times out of observation frontiers and prevents an early episode boundary.

#### When an episode ends

An episode's quiet end is an hour after its last observation. Two clocks must both pass the end: admission time and the ceiling's elapsed time.

- A degraded clock reading never ends an episode.
- A forward wall step cannot end an episode early, and a reboot grants it no time.
- Each row records its elapsed end. Its quiet hour runs on elapsed time from the reading that places the observation, so a report processed late after a step cannot end it early either.
- A row written before the elapsed end existed ends on wall time alone until its next write. That next write includes maintenance that leaves its last observation unchanged.
- Existing elapsed ends survive maintenance.

The first row with a positive elapsed end moves the ledger to schema 13 on every host, which older builds refuse. Schema 13 records nothing of the live start or the effect records, so a schema 13 ledger proves them from their own markers.

#### How a verified block closes an episode

A verified block ends its episode at the block's original expiry, not an hour after the last observation. This holds even while work of another kind is queued or in flight. An unknown outcome or a response of another kind does not end the episode.

- Verified closing replaces the quiet end with the block's remaining lifetime, read at the block's execute reading. A wall step between execution and its outcome then cannot shorten it.
- Execution readings are released when an outcome commits, including startup settlement.
- A verified episode keeps that boundary. A later verified block of the same episode moves neither end.
- A legacy verified row gains its missing elapsed end from the original expiry when closed again.

The expiry is set on the engine's lease clock, which after a wall clock step back leads admission time. The owner passes that lead to `FinishOnLease` or, with a victim, `FinishEviction`. The episode then ends when the kernel element expires in admission time. Its elapsed end is the time left until then, so a forward wall step does not end the episode while the kernel element remains. An isolated member's isolation ends the same way.

Verified outcomes use the wall and elapsed values of the last committed clock reading. The ledger handle retains the two together and restores them at open. An unreadable ceiling or a failed later tick does not prevent recording a result for work that already ran. New work still requires a successful reading.

Retirement and retry staleness stay on the lease frame. Late retirement only holds an address longer, and the engine refuses an expired member.

#### Retained boundaries and history

An answered block frontier without candidate references retains its episode's verified boundary on both clocks, using schema 15. Earlier readers refuse it. Its verified predecessor's retirement collects it after both ends pass.

Address and subnet block histories remain charged while their episode boundary is still active on either clock. Scheduling and wake times count that retained history as unavailable. Bounded cleanup continues past retained histories across ticks, so they cannot hide later expired history.

#### Later observations in the same episode

What a later observation does depends on the state of the candidate of its kind:

| State of the candidate | A later observation of its kind |
|------------------------|---------------------------------|
| Queued, before its first attempt | Is coalesced into the candidate. |
| A queued retry | Is answered without coalescing. The retry remains live. |
| Ended before any attempt | May queue the next generation. Nothing else follows the ended candidate. |
| Effect verified or previewed | Is refused as an existing effect, which raises no notice. It still extends the episode. |
| Unknown outcome | Is refused the same way, but never extends the episode. The episode stays open until recovery retires the outcome. |
| Final failure, or a retired unknown outcome | Can start the next generation. |

#### Targets held by an unresolved attempt

After an unknown outcome, other kinds may queue at that target. Scheduling and admission defer them as `pending_recovery` until the unknown is retired.

An attempt still recorded as running holds its target the same way until its outcome is recorded. Such an attempt is left by a crash before settlement, or by an outcome that failed to commit. The hold also covers candidates from earlier episodes.

Each handle keeps the held targets as an index. It builds the index at open from the proven intents, and changes it only when a transaction that writes or deletes an intent commits. Scheduling and reservation then look a target up and do not read every intent. A missing intent bucket refuses the operation without changing the ledger.

#### A verified block that was removed early

On a live ledger, a verified block whose record is gone stops answering its kind before the episode's original verified end. A later observation of that kind queues a charged new generation in the same episode, when it was made after the removal and every one of its roots was observed after the removal too. This is a re-admission.

- An observation or root at or before the removal is answered or stale.
- The episode earns no equal-tier rotation.
- Past the original end, as when a reboot keeps the episode open on elapsed time, the block keeps answering until the episode ends on both clocks.
- Forgetting a refused return keeps the verified boundary until both ends pass.

On a live ledger the block line records the generation of its latest verified block, whose history outlives later generations. Queued, ended and forgotten returns then keep that evidence gate against the latest removal. Such lines also need schema 15.

- Older lines recover that generation from an unbroken chain of retained predecessors on their next arrival, and persist it with the next episode write. A gap leaves the line answered.
- Opening a ledger does not rewrite older lines. It rejects a reference to an unverified candidate, or to a block older than another retained verified block of the same kind and episode.

The owner caps a re-admission's first attempt at the episode's original verified end: the time left in admission time, added to the lease clock. A retry keeps its first expiry. A re-admission with no time left, or whose episode row has been replaced or lost, is refused as expired, or as invalid in a preview.

A forecast applies a similar cap. When the session has replaced its forecast block at an address, a block that later returns to that address is capped at the replaced block's expiry.

- The forecast applies the cap before the firewall snapshot, and again before deciding each pick, since an earlier pick can replace that address in the same turn.
- A shortened expiry must still leave the firewall's minimum timeout. Otherwise the return ends uncharged, without changing forecast occupancy or retaining an example.

### Execution intents (schema 7)

Schema 7 adds execution intents. An intent records what an attempt may apply, before it applies anything, so a restart knows which effects are unproven. The first open upgrades a schema 1 to 6 ledger in the same transaction.

#### Marking a batch as running

Execution marks a batch of up to 64 reserved attempts as running. In the same transaction, and before any host change, it records what each member may apply: its kind, its target and its absolute expiry.

| Call | Result |
|------|--------|
| The same members are executed again | They are read back. A batch readback requires every member to be running. |
| A member runs in another batch | The call is refused. |
| The batch mixes reserved and running members | It is refused as a transition conflict, regardless of member order or target overlap. Nothing is written. |

Direct queue requests can reserve a retired action ID again. If another member of that batch still runs, execution refuses the mixed batch.

#### What happens to an intent

- An applied or failed outcome removes the member's intent. An unknown outcome keeps it.
- A reservation holds room in the recovery reserve for its intent.
- An unknown outcome pins the intent with its history. It also holds the slot of the row that will retire it.
- The schema upgrade records an intent for any attempt that ran without an outcome or ended unknown. It holds each pinned outcome's intent in the reserve.
- Opening the ledger proves every intent against its attempt.

Startup reads the unresolved intents directly, without opening the ledger. A ledger older than intents has none. A ledger it cannot read is an error.

#### Retiring an unknown outcome

Recovery retires the uncertainty of an unknown outcome once all three of these hold:

1. Its absolute expiry has passed on a current, trusted clock.
2. Its outcome rows are delivered.
3. The engine finds nothing of it remaining.

Retirement does this:

- The outcome stays unknown and counts as nothing new.
- Nothing is dispatched again.
- The intent goes. The history and intent leave the recovery reserve.
- An `expired_unproven` audit row records the event.

Status counts the attempts that run and the unknown ones not yet retired, with the earliest expiry after which one can be retired. A missing or inconsistent intent marks only that section unreadable.

Opening the ledger checks retired attempts against the stored clock, even after their retirement events have been acknowledged.

### Endings without a new attempt

Queued work can end without running. It can be refused as an existing effect, linked to the block that already enforces it. It can be refused as `verdict_allow` or `disabled`. Or it can move to `dry_run`, which is an ending of its own and not a refusal. The last three differ in what they count and record:

| Ending | Counts | Notice | Minimum schema |
|--------|--------|--------|----------------|
| `verdict_allow` | One ended count | The notice that Critical or C3 work raises when it is refused | 9 |
| `disabled` | One ended count | None, since the operator turned the response off | 10 |
| `dry_run` | One `dry_run` outcome in the windows and no queue event | None | 9 |

None of the three makes an attempt, a charge or a history allocation, and none of them answers the episode. A later observation can therefore queue the next generation. Each required schema keeps the same buckets, and a later schema is retained.

#### Existing effect

A candidate refused as an existing effect can name the block that enforces it, with its expiry. The block is named in one of two ways:

- as the admission action that wrote it;
- by the firewall's `eff_` name of an operator or earlier block.

Two calls end a pick that way:

- `TerminateExisting` ends a queued pick, including a retry whose earlier attempt never ran.
- `FinishExisting` fails the current attempt, keeping its charge, and ends the pick linked in the same transaction. On the pick's last attempt it leaves the pick failed.

A historical result cannot end a later retry. A repeated linked ending must name the same block and expiry instant.

A linked record is candidate version 2, and an admitted candidate's history pays for its bytes. Without room the transaction changes nothing. A linked record requires at least schema 8, with the same buckets.

#### Verdict allow

A panel verdict that allows a queued candidate ends it refused as `verdict_allow`, like any other refusal. A retry keeps the charge of its failed attempt. Such a record requires at least schema 9. Older readers refuse unknown schemas.

#### Disabled

Queued work whose response the configuration has stopped allowing ends refused as `disabled`. The first such record moves the ledger to schema 10, which older builds refuse. An ingress checkpoint carrying disabled refusal counts also requires schema 10, even without a stored candidate.

A full outcome bucket, with every key at its largest count, is 32872 bytes against a bound of 33 KiB.

#### Dry run

`EndDryRun` ends queued work that dry-run mode forecast and did not run. The candidate moves to `dry_run` without an attempt, ceiling charge, history allocation, audit row or notice.

- A retry keeps its failed attempts, their charges and the history they paid for. That history ends with the candidate.
- Roots the work gained while it waited are dropped, as on other endings.
- The same ending again changes nothing.

The work must be ready as a reservation requires:

- A retry waits out its backoff.
- An unresolved attempt still holds the target.
- Stale work is refused.

### Dry-run forecast primitives

These ledger calls support the dry-run forecast. They do not activate owner execution or replace the comparison-only challenge path. [Dry-run forecast by the owner](#dry-run-forecast-by-the-owner) describes how the owner uses them.

#### `SchedulePreview`

`SchedulePreview` selects queued work for a dry-run forecast. It is not admission:

- Spent live ceiling and history budgets do not stop it.
- It reserves, charges and defers nothing for capacity.
- Every candidate, a challenge included, weighs one fair unit and no history.

Service order inside a selection:

- Direct and corroborated work alternates within a bounded reserved share of each batch.
- The general lane serves the rest by class and severity, where reserved-eligible work competes too.

The selection shares these rules with a schedule:

- Revalidation, age-out, retry backoff and recovery holds gate it as they gate a schedule.
- A held target is deferred as `pending_recovery`.
- A stale live `ceiling` or `storage_share` wait clears as a schedule clears it.
- Pending work is passed over.
- The live schedule and the selection share one fair position, which advances once per selection.

Challenges depend on whether the ledger has started live:

| Ledger | How a challenge is selected |
|--------|-----------------------------|
| Not started live | A challenge's comparison preview still spends live history. While the live history budget cannot pay for it, the selection passes it over with no wait or fair turn, as a schedule does. It serves the challenge on a lane that can pay. |
| Started live | A challenge preview spends no history and is selected as other work is. |

Before the live start, challenge picks share that live allowance within a selection. An earlier pick leaves less for the next.

#### `PreviewWake` and `CeilingSnapshot`

`PreviewWake` is the matching wake. It is now while selectable work waits. Otherwise it is the earliest of these:

- a backoff end;
- a queued deadline;
- until the ledger starts live, the time when the live history budget can pay for a passed-over challenge, whatever the other live budgets.

`CeilingSnapshot` reads the committed ceiling and its retained charges in one read transaction, proven against each other, for a forecast to start from.

Preview selection and wake calculations check saved ceiling, storage and live candidate history, even though live budgets do not limit them. Damaged accounting refuses the operation without advancing the fair position.

#### `RecordDryRunBlocks`

`RecordDryRunBlocks` writes one turn's forecast examples, at most one batch, into the `dry_run_blocks` bucket the legacy writer also uses.

- A record keeps the legacy `ip`, `reason` (the registered check) and `timeout_sec`. It adds `candidate_id`, `session_id`, `kind` and `expires_at`.
- Its key is a fixed-width UTC time with nanoseconds, the canonical address and the candidate. Two decisions for one target therefore never overwrite each other.
- The writer validates every record, and the encoded key and value bounds, before writing. One bad record refuses the batch.
- A full bucket makes room by evicting earlier sessions' first keys in key order, in the same transaction.
- The writer refuses a batch when no room can be made without evicting its active session, or while the bucket remains above its cap.

#### `MaintainDryRunBlocks`

`MaintainDryRunBlocks` runs one bounded step of a pass over the bucket. A pass does up to three things:

- It trims an oversized bucket without evicting the active session.
- It removes records whose key time is strictly older than a cutoff.
- For a purge, it removes every record of a session other than the one it keeps, legacy records included.

A purge with no active session removes everything. A purge with an active session preserves that session regardless of time.

A step resumes after the last key the pass visited, including protected keys. It writes nothing when nothing is due, and a failed step changes nothing.

#### The forecast model

The forecast model keeps charges in admission-time order, including when imported legacy spend is dated in the future. Earlier simulated charges can leave their window while that spend remains.

Only `block_ip` consumes simulated ceiling credit and temporary address space. Other kinds return `not_modelled` without changing capacity.

### The firewall lease clock

Kernel timeouts come from a lease clock that never runs backward. It is the later of the wall clock and its own last reading advanced by the time elapsed since.

Firewall startup restores temporary blocks only for their remaining lifetime. Reapplying the rules after the wall clock is set back restores each timed block for the time it had left, never for the step on top.

#### What reads the lease clock

- Batch checks and sends read it.
- Fresh legacy blocks record their deadline on it.
- Durable action planning, verification, sends, and whole-set retries use it for timed blocks.
- Allow and subnet expiry still use wall time.

Timeouts are refreshed at these points:

- Operator undo retains the original deadline. It refreshes its remaining timeout after persistence and before each bounded retry.
- Fresh legacy sends also refresh after persistence.
- Ruleset installation ages precomputed block timeouts after table discovery and rule construction.

#### Encoding timed elements

- Timed elements use the same millisecond encoder in legacy and durable state.
- Rows with less than a millisecond left, or an unrepresentable lifetime, are skipped.
- Blocks, operator allows and subnets use one startup clock reading.
- Durable updates compare absolute expiries before encoding timeouts, so millisecond rounding does not replace unchanged timed blocks.

#### The checkpoint

After every ruleset it installs, the engine saves the lease clock with the boot it was read in and the time since boot. The checkpoint is `lease.json` beside the state file.

A timed block saves the checkpoint before the legacy or durable state intent too. A new deadline created during a forward clock step then cannot gain time after correction and restart.

| Save failure | Result |
|--------------|--------|
| Before a new timed block | The new block is refused before state or kernel mutation. |
| After ruleset installation | A warning. The installed rules are not undone, and the next Apply retries the save. |

Separate clock samples are ordered so sampling latency can only shorten restoration.

#### Resuming from the checkpoint

A new engine resumes from the checkpoint before restoring timed blocks:

- Within the same boot, it resumes at the checkpoint plus the time elapsed since it, whatever the wall clock did meanwhile.
- On a new boot, it resumes at the checkpoint itself, crediting no downtime.

The first Apply resumes the checkpoint before durable planning, so its evidence and the installed timeouts share one clock.

Before the first Apply the daemon also moves the clock forward to the time the admission clock proves has passed. That time is the admission clock's saved high-water mark or, within the same boot, its checkpoint plus the time elapsed since.

- A valid but degraded admission clock still supplies that bound, and the discrepancy is logged.
- A damaged checkpoint or an unreadable ledger logs the missing coverage.
- With neither a usable lease checkpoint nor a readable ledger, the engine starts from the wall clock.

#### When the lease clock leads the wall clock

Forward steps can shorten restored leases. After a step back the lease clock stays ahead, unless wall time catches up through a later correction. Elapsed time alone does not close the lead.

- New rows record expiries that far ahead.
- The engine logs the first lead beyond the readback slack once per engine.
- The admission owner reads the engine's lease clock once per batch and sets a first attempt's expiry on it. The lead is then not lost from the block's lifetime, and a short block is not refused as already expired. A retry keeps the first expiry.
- The owner already defers while the admission clock is degraded, the only time the lease could trail it.

### Engine batch entry points

The engine also provides internal batch entry points for up to 64 timed full-address blocks. The admission owner runs them only when the daemon gives it an engine, and production gives none until cutover.

#### Checking members

Each member is checked against one state and kernel snapshot over bounded fresh sockets. Unreadable state refuses the whole call.

- Rejected members consume no slot and cannot exclude a valid member.
- Expired rows remain available for kernel cleanup in both the intent and restored state.
- Capacity is checked only at apply. A check before reservation never answers set_full.

#### When an address counts as already blocked

An address counts as already blocked only when a verified row and its kernel element agree. The element must be untimed for a permanent row. For a timed row it must have the time the row has left, accounting for elapsed time across both set reads and all member checks.

- Apply results also age existing-block proofs through the batch's writes.
- A timed proof that can already have expired is not coverage, even if its row has time left within the readback slack.
- The row must also last as long as the member, within the readback slack. A shorter block holds the address until it ends.
- Any other row or element holding the address refuses the member as pending recovery.

An existing-effect refusal, at check or apply time, names the block that holds the address, with its expiry. The name is the admission action that wrote the row, or `eff_` and a digest of an operator or earlier row's identity. The same row gets the same name on every check and after a restart.

#### Proving that the drop rules are in place

Set readback proves membership, not enforcement. A batch, a member check and a state probe therefore each read the input chain's rule handles before the set snapshot, up to the last source-address drop of a filtered blocked set.

- A missing or altered family guard, source load, register flow, lookup or drop verdict refuses them.
- The check decodes the raw expression list, so an expression unknown to the nftables decoder cannot disappear from it.
- Other rules contribute their handles without their expressions being understood.
- The namespace generation is not read, because any other nftables user changes it.

The batch reads the handles again just before its write and refuses when they changed, as after a ruleset reload or a rule inserted ahead of the drops. That refusal writes and sends nothing. It holds execution until a probe finds the drops again, without an apply fault.

#### Applying a batch

The batch does this, in order:

1. It rechecks its members.
2. It writes one intent, with expiry instants stored in UTC.
3. It refreshes timeouts after the write.
4. It uses one atomic transaction on a fresh socket with a two-second deadline.
5. Exact-family readback proves each applied member's key and timed lifetime.

| Result of the exchange | What the engine does |
|------------------------|----------------------|
| Definitive kernel rejection | Restores state. The retry marker for a kernel rejection requires a successful state restore. |
| Uncertain exchange | Retains unknown rows. |
| Failed state write | Returns a state-integrity error and retains live suppression until a successful state write. Later batches refuse while that error is held. |

Unknown rows are marked unverified and excluded from counts and seeding. They stay in state after their expiry passes, until the owner retires the matching attempt. Marking with no action IDs still writes the safe state, to release a state hold.

The admission owner must reconcile action-linked rows before startup, or before any downgrade to a build that ignores their verification fields.

#### Imports in the admission snapshot

The admission snapshot lists at most 256 imports, soonest expiry first, then by name. An import is a timed, verified row that a legacy automatic block stamped. It must be alone at its kernel address with a proven element. It is named by its raw row's `eff_` name.

- Mapped addresses share the canonical address.
- A retained zoned alias also disqualifies an import.
- A lone zoned row stays unlisted and unclaimed.
- The imported occupancy count still includes unlisted stamped occupants, so a bounded victim list cannot free capacity.

#### Taking a victim's slot

The victim of a member is the admission block or import that the ledger claimed for it. Victim checks require retained rows at the address to agree on action, expiry and verification. An unreadable startup ledger disqualifies all victims. Members can still use free slots.

A member takes its victim's slot when the victim still has that row, name, expiry and proven element, and the resulting set fits the current limit. The same transaction deletes the victim's element. Only a readback of the victim's set proves it removed. A member whose removal is unproven is unknown, even with its own add read back.

| Case | Result |
|------|--------|
| The victim does not qualify any more | The victim is spared and its member needs a free slot. |
| The victim has no more than the batch's minimum lifetime left at the send | The victim is spared and its member fails set_full alone. Its expiry in the kernel would otherwise reject the whole transaction. |
| The victim was removed by other means before the send | The kernel rejects the whole transaction with ENOENT, which fails its members like any rejection. |

The victim's row stays until the owner retires it after the ledger records the outcome, so a restart before then restores the victim.

Retirement removes an evicted import's row by its `eff_` name only while the stamped row still matches it. An operator or unstamped row is never retired under an import name.

Until a restart proves the saved actions, the engine removes no block for a batch, and its admission snapshot says so. The owner then plans no eviction or rotation, a dry run forecasts none, and higher work waits for a free slot.

#### `RemoveBlockActionRows`

`RemoveBlockActionRows` removes, in one state write, the rows the ledger has settled: failed, retired after expiry, or evicted with proven removal. An error reports no completed removal, including a durability failure after rename.

Startup calls it after marking every unproven row, with the settled subset that `store.ReadSettledBlockActions` returns. A start that stops between the two steps leaves the rows held back, and the next start removes them. Startup asks the ledger about every saved action, including rows an earlier start held back and other actions sharing their addresses.

- An expired row no start marked is never restored and is left to expiry, so it holds back no other block at its address.
- The engine selects those rows on its lease clock. It retains that reading through Apply, so a backward wall-clock step cannot restore an unchecked action.
- Marking preserves those separate rows until cleanup can remove only the settled actions. Removing a hold therefore cannot restore an unchecked action or erase another block.
- An unconfirmed removal is written again on retry, even if its rows already appear absent.
- Cleanup preserves other actions' rows, including distinct actions sharing one address.

#### `RetireBlockActions`

`RetireBlockActions` checks the kernel for up to 64 unknown attempts under one engine lock.

| State of the attempt's address | Result |
|--------------------------------|--------|
| No element | The attempt is clear. Its own row goes in one write. |
| An element that matches a verified row of another action, remaining lifetime included | The attempt is clear. Its own row goes in one write. |
| An element still present otherwise | The attempt stays held. |

- Retirement requires a kernel snapshot of the target's address family. A missing or disabled IPv6 set cannot prove absence, so it holds that attempt while the rest of the batch is answered.
- Cleanup resumes and saves the lease checkpoint first. An unreadable clock or checkpoint authorizes no removal.
- Address matching for recovery accepts legacy mapped, uppercase and zoned spellings within the engine's namespace. This does not relax the admission parser.

#### Unverified rows

- Unverified rows cannot suppress alerts or reputation checks through stale legacy tracker entries.
- They do not count as enforced blocks or select threat evidence for operator flush cleanup.
- Live deny limits count their kernel elements using kernel timeouts, not the unresolved rows' requested lifetimes. This includes replacement accounting.
- Permanent promotion requires a verified block row.

#### Rows that belong to the owner

A row an admission action wrote belongs to the owner. For an automatic legacy block of its address, this means:

- The legacy block ends as already blocked, even when the row is unproven or its element is gone.
- The legacy block never evicts the row at the temporary cap.
- Permanent promotion refuses it (`ErrAdmissionOwnsBlock`).

Operator blocks, unblocks, allows, flushes and undo keep their authority over the row. The guard also protects action rows already present in restored state.

An executed admission block writes no legacy tracker (`blocked_ips.json`) entry. Reputation, alert suppression and its injected loader, flush cleanup, threat lookups and the blocked list read the verified firewall row, so the block counts without a tracker entry.

#### The read-only admission snapshot

A read-only admission snapshot answers the same local checks for a bounded batch. Each answer names its member. The temporary occupancy and limit come from the same snapshot.

- No member takes a slot and no repeat is a duplicate there. The caller checks only the members it is ready to run, in order, for repeats and capacity.
- The snapshot also counts which of the bounded forecast addresses the sets already hold as a timed or an untimed element.
- A malformed or repeated forecast address refuses the call before any read.
- Other platforms report the snapshot unavailable.

#### Kill-point tests of the engine

The engine's kill-point tests stop a batch around its intent write, kernel batch, readback, unknown marking and rejected-state restoration. They then start the ledger and a new engine over the same state, after a process restart or after a reboot that empties the kernel.

Around an eviction they also stop before the outcome and before the victim's row is retired:

- Until the ledger records the eviction, a restart restores the victim and holds the block back.
- After a committed eviction, an admission victim's row goes and only the block is restored.
- An import has no startup cleanup record. After a committed eviction, a restart before row retirement restores both blocks until the import's original expiry, including after a reboot.

What a restart does depends on the ledger:

- An unreadable ledger restores unexpired unmarked rows with degraded coverage.
- A readable ledger keeps a committed applied outcome and holds the rest.
- Attempts without a committed outcome are unknown. Their rows are held back, and a new block of an address a held row names waits. Once the expiry passes, retirement removes the rows and the ledger retires the attempts.
- A new boot retains the saved lease floor.

The test kernel reads emitted transactions, including set families, timeouts and base chains. It does not assume a successful send installed the requested effects. It rejects incomplete batches and wrong set destinations before modeling loss. Mapped IPv6 keys never become IPv4 blocks.

In a real kernel, a batch killed after the kernel took it leaves its element until a new engine's Apply replaces the table without the marked row.

### Owner turns with an engine

With an engine, each owner turn runs its `block_ip` picks as one batch. Every other kind is still previewed.

#### Checks before anything is reserved

The engine checks every member against one snapshot before anything is reserved. None of these results costs a charge:

| What the check finds | Result for the member |
|----------------------|-----------------------|
| A row or element holds the address without proof | The member is deferred. |
| A block the engine proves already holds the address | The member ends, linked to that block. |
| An invalid or protected address, or a spent lifetime | The member ends. |

If the ledger refuses that link, because there is no history budget for it, the pick stays queued with the deferral reason and the rest of the batch runs. The next check tries again.

The rest of the members are reserved, recorded as running with their intents, applied and finished by their own effect.

#### Victims in a turn

Each member carries the victim its reservation claimed, as its intent names it. The ledger records what the batch did to that victim with the member's outcome. Whole-batch failures, short replies and delayed outcome writes keep the victim and lease clock information.

Once a verified eviction is recorded, the owner marks an admission victim's row and retires it, as startup does. It rotates failed or held rows behind waiting rows and retries on later turns, including while waiting for an absent engine during dry run.

- Cleanup follows the retirement policy, respects state-repair probe waits and preserves independent apply faults.
- Cleanup errors remain visible alongside unknown-attempt retirement errors.
- A restart removes the row before the firewall restores its state.
- After an unknown outcome the victim's row stays until the victim expires.

#### Imports in a turn

The turn hands the ledger the imports the set read listed.

- Clearing that set also clears its imports. This covers a failed read, an idle turn and entry into dry run.
- Returning to previews reads a fresh set and import list.
- The dry-run forecast reads the list from its own snapshot. It may replace a listed import, which it remembers by name until the import's expiry. It never claims one.

Retiring an evicted import's row follows these rules:

- An import's row is retired by its `eff_` name without a mark.
- An import-only retirement still retries a shared state repair after its probe wait. It does so without marking any import or clearing an independent apply fault, including during dry run.
- An import still enforced at retirement, because a reload or restart restored its row, is forgotten.
- An error or a short retirement answer keeps the request for retry.
- No ledger record names an evicted import, so a restart before its retirement restores it until its own expiry.

#### A block that already holds the address at apply time

A proven block found only when the batch applies is checked again when the outcome is written.

| Case | Result |
|------|--------|
| There is a fresh proof | The pick ends refused as an existing effect, linked to the block, keeping its charge. |
| There is no fresh proof, or the link write fails | The attempt still records its failure. |

A member with a victim records its eviction outcome before attempting that link. A member without one records its failure and link in one write.

When the failure is saved without a link, the ordinary bounded retry or the next check decides what happens to the pick. On the last attempt the pick already ends failed.

#### Outcome writes that fail

- If the outcome cannot be saved, execution waits for the pending write. A crash before it is saved leaves an unknown attempt.
- Failed outcome writes retry before more work is selected and once at shutdown, even without a fresh clock reading. The effect is never dispatched again for that attempt.
- An outcome the ledger refuses for good (a damaged record or a conflicting state) is not retried. Its attempt stays unresolved until recovery.

#### Retiring unknown outcomes

Each turn, before scheduling, the owner retires unknown outcomes whose expiry has passed.

1. It asks the engine, for up to 64 at a time, whether anything of them remains (`RetireBlockActions`). Running attempts are never sent.
2. The engine removes each clear attempt's own row.
3. The ledger then retires the attempt (`RetireUnproven`).

Each checked batch advances through action order, wrapping around, even when its retries are due by the next turn. A stop between the row removal and the ledger retirement leaves a row-less unknown that the next pass retires.

How long the owner waits before it asks again depends on what went wrong:

| Case | Wait before the next try |
|------|--------------------------|
| An element is still present, as after a forward wall step | One minute, on that attempt's own wait. A held batch then cannot starve the intents behind it. |
| A degraded clock, a missing engine or an engine that cannot check | Nothing is retired. The next pass waits one second, doubling to a minute. |
| The ledger refuses the retirement: undelivered outcomes, or a ledger clock that cannot yet prove the expiry | One second, doubling to a minute, for that attempt. |
| A damaged record, or an attempt that ended another way | One minute. |
| Any other fault, such as a failed write | One second, doubling to a minute, for that attempt. |
| A missing or unreadable attempt | The waits of the two rows above: one minute for a missing attempt or a damaged record, otherwise one second, doubling to a minute. Other attempts still retire. |
| An unreadable intent list | The whole pass is delayed. |

Each fault is reported once, in `admission.owner.retirement_error` and the doctor row `admission retirement`, until no attempt, list read or engine retirement check is left faulted. No retirement fault fails a turn. A turn that fails after its retirement pass fails with its own step's error.

Timing of the retirement pass:

- The turn wakes for the earliest expiry or monotonic retry. While a wake time is noted, a turn does not read the intent list until that time is due. With no wake time noted, every turn reads the list.
- The pass never rebases a retry on admission time or adds time spent inside an engine call.
- Expiry conversion uses a monotonic sample taken before reading the admission clock, so a slow tick or a later call cannot postpone another expiry.
- Running attempts create no retirement wake. Retired attempts leave no retry entry.

#### When nothing can be retired

An owner without the firewall engine, or under a refused execution policy, retires nothing and keeps each unknown's address held past its expiry.

- `admission.owner.retirement_held_by` names that cause (`engine` or `policy`) while unknown outcomes remain.
- The doctor row `admission unresolved outcomes` names the cause with its fix, in place of a retire time.
- Policy changes publish the retirement cause with the execution hold, preserving the cached ledger sample and its age.
- Once the cause is gone, each unknown still retires only after its expiry and the engine's proof under a valid clock.

A configured engine that has not started names no cause. Retirement retries on its waits and the firewall reports its own startup error.

### Holds on automatic execution

A hold stops the owner from running block picks. Status (`admission.owner.execution_held`) and the `csm doctor` row `admission execution` name the cause. Hold changes copy the cached owner status without rereading the ledger.

#### What holds execution

Any of these holds automatic execution:

- a state write the engine could not make;
- a failed batch check or apply, including per-member transport and readback errors;
- a missing engine.

Block picks then wait, deferred as an unavailable engine, while one probe runs per wait, from one second doubling to a minute.

A degraded admission clock cannot bound a lease, so it defers block picks the same way.

A batch the kernel rejected is different: it fails every member, charged. Each member then retries alone, one per turn, until its next outcome or its expiry.

#### Probes

| Hold | How it is probed |
|------|------------------|
| A held state write | The engine writes the safe state again and checks its snapshot. |
| A failed apply | One member is applied. See below. |
| A missing engine | It has no probe of its own. Idle scheduling pauses and resumes on the first schedule check that finds an engine, without waiting for the old probe deadline. |

Other idle holds still probe on their waits. Successful snapshots cannot reset a failing member check's backoff.

A failed apply keeps its cause and backoff through state repair, ledger refusals and member refusals, until an applied effect proves recovery. Its probe is one member:

- Every pick is checked and refusals end.
- Only the first accepted pick is reserved and applied.
- The rest wait untouched for the batch after it applies.

An isolated retry does not narrow these probe checks. It still runs alone if selected.

#### Apply-confirmed firewall windows

An apply-confirmed firewall window holds the engine's member checks, batches, probes and retirements (`ErrConfirmPending`). The hold lasts from before the window's snapshot until the window is confirmed or rolled back, so its rollback cannot erase a block the owner wrote inside it. A batch in flight finishes first and lands in the snapshot. The read-only admission snapshot of a forecast still answers.

A rollback with saved block state restores it and then gates the rows on the ledger again, as startup does, before the hold ends. A mark or removal the ledger asked for inside the window is then not lost with the restore. The restored ruleset also gives each timed block the time it had left when the window opened.

Normal rollback restores configuration first. Explicit confirmation accepts the current configuration.

When the hold ends, `RetimeBlocks` uses one strictly read row image and replaces the blocked sets in one transaction.

- If startup with IPv6 disabled left no blocked-set reference, retiming binds the restored IPv6 set after a successful transaction.
- An unreadable image sends nothing, even with a cache or a successfully preserved corrupt state file.
- A retiming failure warns and releases the hold.

Special cases:

- A restart with a window pending holds the same checks and batches before the owner sees the engine, until startup recovery settles the window.
- A window opened between member checks and apply also holds execution, but is not an apply fault. After it ends, a successful snapshot probe clears that hold even on an idle turn. Any earlier apply fault still needs a successful one-member apply.
- A kernel rollback alone does not release the hold when the saved engine configuration is unreadable. The confirmation remains pending until recovery succeeds or the operator confirms it.
- Keep the window's state snapshot through partial recovery, so another rollback restores the same state even after intervening legacy writes.
- Failed marker removal keeps the hold. Once the marker is gone, the hold and recovery fault clear even if snapshot cleanup fails. That error is still reported.

#### What an executing owner publishes

An owner publishes `admission.owner.executing` only while it runs block picks: it has `Options.Blocks` and its policy is not a dry run.

`admission.DoctorImpact` then closes every admission row with `ExecutionAffected`, not `PreviewUnaffected`. It turns the outages that stop automatic blocks, held execution included, from warnings into failures.

### Turn cadence

At most one batch starts per second. With an engine, a drain that queues new work runs the schedule at once and does not wait for its timer.

An owner with an engine also selects, checks or forecasts work once a second at most, including turns that dispatch nothing. Work that falls due sooner, from a drain or a panel answer, stays due for the next second. Retirement of earlier attempts keeps its own waits.

| Situation | What the turn selects |
|-----------|-----------------------|
| Before the next live batch may start | Nothing. It leaves the next selection due. |
| Execution is held and the probe is not yet due | Nothing, so held work keeps its place in the rotation. |
| A probe turn | It still selects. |
| A missing engine, which has no probe | It selects once per wait, from one second doubling to a minute, including during a clock outage. Work that needs no engine is then still previewed. |
| An engine returns | It selects immediately, even after a recent missing-engine preview. Batch starts still keep their spacing, and an earlier apply fault still requires a one-member probe. |

These rules also apply:

- Clock or engine outages still defer waiting blocks without spending fair turns or running early probes. Work already deferred for capacity keeps its reason.
- Dry-run forecasts and previews without an engine keep their own cadence.
- The policy installed at the turn boundary decides whether the batch wait applies. Changing between live execution and dry run does not spend a turn that cannot select work.
- During a batch wait, opt-outs end silently before any outage is reported.
- Outage deferrals check waiting work again first, so expired evidence and changed ownership keep their own terminal reasons.

### The live start

The first time an owner executes, its live start runs. It runs once per ledger, in one transaction, before anything is drained or served under the installed policy. Every drain and turn reads the clock first, and the reading runs the live start.

#### What the live start does

The live start hands the hour's spend over from legacy blocking:

- It charges the legacy hour as the greater of its count and the charges the ledger already retains in that hour, since previews and legacy blocking count the same responses.
- Earlier preview charges stay as handover charges with their lane, cost and release times, so a later forecast cannot refund them.
- Pending legacy entries stay legacy's to retry and count nothing. A finding that admission takes never enters the legacy pending queue.
- It leaves `blocked_ips.json` in place.
- A legacy state file it cannot read keeps no saved credit, and `admission.owner.import.error` names the error.

It settles the work the preview period left:

- Block work the preview period left queued, deferred or not, ends as `disabled` with no new attempt, charge or notice. Legacy blocking answered it.
- Work still in the ingress drains as live work. If legacy blocking already applied the block for an address, that work ends as an existing effect, because the engine keeps one row per address.
- It ends the episode answers of earlier observe previews. The next observation of a previewed address then queues a new generation, or a new episode when no other candidate kept the old one. Challenge previews and verified blocks keep their answers.
- It makes the previews' history eligible at once.

It resets notices:

- It clears the notice records raised while admission previewed, so none goes out as a live alert or delays a key's first live notice.
- The sender discards the preview delivery retry delay once it sees that committed start. Later live delivery failures keep their own backoff.
- Until the live start runs, an executing owner delivers no ledger notice.
- With execution enabled the sender reads the mode and the due notices together. An acknowledgement taken before the live start never covers a record raised after it.

#### Schema 11 and rollback

The live start raises the schema to 11, which every-host schemas 13 and later already exceed. It records the live feature bit in the ledger's meta bucket.

Every earlier build refuses that unknown key. A binary rolled back across the live start therefore does not open the ledger and keeps legacy-only blocking. A feature bit this build does not know is refused as a newer schema.

#### A failed live start

- A failed live start fails the turn, reload or drain that ran it.
- A failed tick or drain closes admission.
- A failed live-start tick reports its cause through `tick_error` and the stopped-admission notice until a later tick succeeds.
- The import error describes a committed handover. An aborted transaction does not replace it, and later startup retries do not erase it.

#### Previews after the live start

After the live start a preview takes nothing from the budgets that live work needs: no slot, no ceiling charge and no history allowance. The owner previews what it does not run: every kind but `block_ip`, and every pick of an owner without an engine.

- Such a preview ends as a dry run does, with no attempt, slot, ceiling charge or history.
- It leaves its episode open, so the next observation is previewed again. The comparison still counts it as observed.
- The schedule serves those kinds as uncharged picks, so they take no lane's ceiling budget or history allowance from the blocks that run.
- A dry-run selection on a started ledger does not wait for history a challenge preview does not spend.
- An owner without an engine selects its previews as a dry run does, outside the lanes, and wakes for them at once.

The hourly comparison counts refusals this way:

- A refused preview counts only after its terminal ending commits, in the hour of that ending.
- Deferrals and failed endings add no refusal count.
- A live pick the engine's check or its reservation refuses is counted the same way.
- A pick an existing block answers is not a refusal.
- A forecast's picks keep the rows a dry run already writes.

### The execution policy

An owner with an engine binds to one execution policy. The policy is the dry-run mode, the verdict callback and its timeout, the hourly ceiling and the response lifetimes, read together from one config publication. A comparison-only owner never reads the policy.

#### Epochs

Every publication that changes `auto_response` or the mode gets a new epoch.

- The owner does not start without a valid policy. It names the refusal, even with the callback off. `mode: observe` is refused.
- Each turn and reload installs a newer epoch before it selects work, and the turn uses that policy for every pick.
- A reload returns once the policy is installed, after any turn already running.
- An older epoch is ignored.
- The schedule checks for newer epochs even while idle. A publication without a reload therefore resumes held work and any probes suspended by dry-run.

#### A refused policy

Three things hold execution until a valid newer epoch arrives:

- changed settings under an installed epoch;
- missing required dependencies under an installed epoch;
- an invalid newer policy.

The refusal is in `execution_held`. The daemon reports a refusal at reload as a `config_reload_error` finding.

While a refusal holds execution:

- A selected pick of any firewall kind is deferred as `engine_unavailable`, with nothing previewed, reserved or charged.
- The schedule then passes the pick over, as it passes over work waiting for the panel, until a valid policy is installed.
- Engine probes and repairs are suspended.
- A challenge keeps its comparison preview.

#### Responses the configuration has turned off

The policy also carries whether the configuration still allows each queued response. The test is `checks.AutomaticResponseAllowed`, the switches the legacy funnels test before they act:

- `auto_response.enabled` and `block_ips` for every firewall kind;
- `block_cpanel_logins` for the checks that need it;
- each derived entry's own opt-in;
- challenge routing, for challenges.

Under a valid policy, a pick the configuration has stopped allowing ends refused as `disabled`. This happens before any panel ask, engine check, forecast, preview or reservation, live or dry run.

The test reads the configuration live at each turn, not the epoch's. Challenge, incident, central and per-check settings can change without a new epoch, and a saved change applies from the next turn.

A queued block also ends as `disabled` when the mint would refuse its address under the live configuration:

- The live configuration names the address as a trusted proxy.
- The address is a known CDN or website-firewall edge that one of the block's roots may have seen relaying. Roots are read only for an edge address.

Disabled responses end together before capacity selection, including challenge previews.

- Spent ceiling or history budgets, retry backoff and another attempt's recovery hold do not delay their refusal or generate capacity notices.
- The check visits only the bounded durable queue. It leaves allowed work's scheduling turns and capacity checks intact.
- Refusing queued work never releases an earlier attempt's charge or recovery hold.
- Startup and ceiling reload also refuse disabled work before inventory or queue revalidation can report expired evidence as a withheld response.

### Dry-run forecast by the owner

Under a dry-run policy the owner forecasts and does not run. It selects work with `SchedulePreview`, whatever the live budgets. It ends each pick as a dry run with a prediction: no attempt, charge, history, audit row or mutating engine call.

A forecast neither probes nor repairs the engine. A hold from live work stays in `execution_held` until the next live turn.

#### Forecast sessions

A forecast session starts at startup, or on entry into dry-run, from the committed ceiling and its retained charges (`ForecastSeed`). It then lives in memory apart from the committed ceiling:

- The same committed clock meters it.
- A new limit applies without new credit.
- Live credit is never copied over it.

The seed leaves out the charges of observe previews, which are comparison work, not responses. Their units leave the window, and their credit returns to its lane up to the bucket's cap (`Uncharge`). Legacy and genuine charges stay.

Ceiling, charges and keyed attempts come from one read-only transaction. Each retained attempt's charge must match its reservation time, lane and response cost. Damaged records refuse the seed without changing committed state.

A session ends in two ways:

- A live policy ends the session and never replays a dry-run ending. A later observation of the target is a new generation.
- A session whose model cannot be metered by a committed clock reading or a new limit ends too. The forecast error is `model_error` until the next session starts, and that session names `model_error` as its reset, not a mode change.

#### Previews stop answering during a forecast

While the owner forecasts, the ledger stops counting a preview as the answer of its block line (`PreviewsAnswer`). An address previewed before the session then queues its next generation on a new observation, and is forecast.

- A verified block, or its remembered answer, still answers until its expiry.
- Challenge lines keep following their previews.
- Leaving dry run turns previews back on.

#### How a pick gets its prediction

One read-only admission snapshot answers a turn's `block_ip` picks, with the real temporary occupancy and the real blocks of forecast addresses. A refused target ends or waits as a live check has it.

Picks that need no capacity decision:

| Case | Prediction |
|------|------------|
| A real block covers the address | `existing_actual`, unlinked |
| A forecast block covers the address and lasts as long, within the readback slack a real block is allowed | `existing_shadow` |
| A forecast block covers the address but is shorter | `pending_recovery` |
| The pick is of another firewall kind | `not_modelled`, with no verdict call |
| There is no engine or snapshot, or the clock is degraded | The pick waits as `engine_unavailable` and the forecast does not change. |

Neither kind of forecast block is renewed. A challenge keeps its comparison preview.

Other picks are checked against the modelled temporary capacity, the bound on forecast blocks and the modelled ceiling:

| Case | Prediction |
|------|------------|
| The pick passes the modelled ceiling and temporary-capacity checks | `capacity_admit` |
| No slot is free, and the pick takes the first strictly lower-tier forecast block or listed import in eviction order | `capacity_evict` |
| A fresh pick rotates out a forecast block of exactly its tier | `capacity_rotate` |
| The pick is otherwise funded, but the modelling bound is full | `forecast_limited` |
| There is no room, and a lane's partition holds a scoped block of exactly the pick's tier at another address | `equal_tier_wait` |
| Any other full set | `set_full` |

Only `capacity_admit`, `capacity_evict` and `capacity_rotate` add a forecast block and a simulated charge.

A decision is installed only once its ending commits. Only then is it counted in the hourly comparison summaries, as a `dry_run` decision with its prediction, a field apart from the refusal reason. The prediction names live in the admission package, which the finding stream tool reads too.

#### The capacity model

The model budgets slots with the ledger's rule (`SetOccupancy.Limits`).

- Forecast blocks rank by their pick's tier and next attempt. A forecast block without a tier is never replaced.
- Each forecast block records its pick's scope, and the admission time and session elapsed time of its decision.
- Real admission blocks count in occupancy but in no scope.
- A replaced import is remembered by name until its expiry and subtracted only while the engine still lists it.

Once the general partition is full, the session shares each partition as a live ledger does. The scopes that share it are:

- the scopes of its forecast blocks that the real sets do not hold;
- the scopes of the turn's block picks;
- the requester's scope.

The shares come from session cursors, which each such turn moves once before its first pick.

A fresh pick may then rotate out a forecast block of exactly its tier, by the same rule as the ledger. The block's hold must have passed on the admission clock and on the session's metered elapsed time. A pick is fresh when both of these hold:

- The ledger's episode row says so (`AdmissionLedger.Fresh`, which needs no live start).
- No forecast block of the address left the model before that block's expiry.

A replaced or rotated forecast block leaves the model and answers its address until its expiry (spec 5.2). Active forecast blocks and retained answers share the existing modelling bound. Answers expire only at their recorded boundary, never to free space for new predictions.

#### The verdict callback in a forecast

With the verdict callback on, a pick the model would judge is asked about first. It waits for its answer with no forecast change.

- A usable allow ends the pick as `verdict_allow` before any modelled capacity is judged.
- A covering forecast block ends the pick without a call.
- A full modelled set with nothing lower to replace and nothing to rotate also ends the pick without a call.

#### Forecast examples

Each committed `capacity_admit`, `capacity_evict` or `capacity_rotate` leaves one example in `dry_run_blocks`.

A turn writes its examples in one batch after its endings, also when a later pick stops the turn. A failed write loses them without undoing the endings or the forecast, and nothing retries it.

An owner that runs blocks is the only component that maintains the bucket:

- One bounded maintenance step a second trims the bucket to its cap and removes examples older than a week.
- Installing a live policy after a dry run, or at startup, asks for a purge of every example but the active session's.
- The purge pass starts over whenever the active session changes, so a dry run that resumes keeps its own examples whatever their times.
- The examples are stale until a purge pass completes.
- The daemon's legacy prune and live purge leave the bucket to such an owner.

#### Forecast status

Such an owner reports its forecast as `owner.dry_run` in status. The object holds:

- whether the owner forecasts;
- the session and why it started;
- the model's coverage;
- real against predicted temporary occupancy from the turn's snapshot;
- the forecast's own ceiling;
- each prediction's session and last-hour counts;
- lost examples and summaries, and failed writes;
- a pending purge;
- a fixed code for why forecasting last failed.

A turn that succeeds clears the code. A new session also clears the time of the last failure. Leaving dry run clears the forecast and keeps the last session's identity. A dry run whose session has not started shows none. The loss counters cover the process.

`csm doctor` renders the forecast in three rows that warn and never fail. The status getter returns a deep copy of its cached snapshot.

#### Forecast summaries in history

The forecast's committed predictions are also summarized in history, and never sent to an alert channel. A summary is one `auto_block` Warning, "Dry-run capacity forecast: N responses passed modelled capacity checks". It also carries:

- the other predictions' counts;
- its interval;
- a session count;
- a bounded list of distinct examples in committed order, each naming its candidate, finding, target and check.

The first summary is due a minute after the first prediction it counts. Each later one is due a minute after the previous attempt, a failed one included.

One summary is pending at a time:

- The sender takes it whole, and later predictions start the next one.
- A failed delivery goes back in front of them as one summary. It is retried with the notice backoff and counted in the notice queue while it waits.
- A mode change never flushes or relabels a pending summary.
- On Stop, a pending summary that is already due is sent. One that is not yet due is counted as lost: Stop never sends a summary early.
- Failed or cancelled summaries remain counted until delivered or reported lost.

Executable owners supply a cancellation-aware, history-only summary sink, separately from legacy notice delivery. An error must mean the summary was not committed. Stop cancels an active delivery, settles its receipt, and bounds the final attempt outside the owner goroutine.

### The verdict callback in live execution

With the policy's verdict callback on, a live owner asks the panel about each `block_ip` pick before anything is reserved, as a dry run does before it forecasts one.

#### Which picks are asked about

One read-only admission snapshot answers the turn's local checks without giving any pick a slot. A refused, protected or already enforced target ends or waits as a batch check would have it, all without a call.

The ledger decides whether there is room. It schedules a pick only when a slot is free or when there is a victim whose slot it can claim.

Any other pick is asked about, as `CSM auto-block: <check>` for its canonical address, and stays queued. The schedule passes it over until the answer arrives.

#### Answers

| Answer | Result |
|--------|--------|
| A valid allow | The pick ends as one `verdict_allow` refusal with no attempt or charge, even with the ceiling spent. The schedule picks it as uncharged work. |
| Block, an empty verdict or a failed exchange | The local path continues, and the reservation consumes the answer. |

- Each answer is keyed by candidate, attempt and policy epoch. It expires from completion, including time awaiting receipt.
- Local checks run again before an answer is used.
- A pick that stops being eligible has its call cancelled.
- A cancellation is never an answer.
- Admission uses the configured signature and replay validation, including explicit signing exceptions, through the same client as legacy blocking.

#### Workers

- Workers, outstanding jobs and cached answers are bounded. A full stage leaves picks queued and is never read as an answer.
- A new epoch, a mode change included, cancels every call, drops every answer and starts new workers only after the old ones return.
- Stop cancels the calls and joins the workers.
- Workers count completed calls before delivery. Late or duplicate results cannot count another call or consume a different job.

The owner status carries a `verdict` object for an owner with an engine provider. It holds stage gauges, process counters and the last failure as a fixed class, never response text. Its outstanding jobs are also the `admission.verdicts` queue row.

### Row-recovery reads

The admission ledger exposes two row-recovery reads, which take a list of action IDs:

| Read | What it names among the supplied action IDs |
|------|---------------------------------------------|
| `ReadSettledBlockActions` | Failed attempts, retired unknown outcomes, and verified blocks later evicted by a proven removal. |
| `ReadUnprovenBlockActions` | Every non-verified attempt, and those evicted blocks. |

`UnresolvedIntents` gives the owner the same ordered intents as the handle-free startup reader. Callers must inspect each attempt's outcome: an executing intent is unresolved but cannot be retired as unknown.

### Admission preview ledger

Admission previews reserve, charge history and capacity, and end observed in one transaction.

- They write both audit steps.
- They never execute a response and never count as applied.
- They do not end the evidence episode or raise a notice.
- Repeated evidence is answered until its quiet window closes.

Imported legacy usage retains its accounting-window charge after an attempt is retired. Retirement of old attempt history cannot create new admission capacity before that window closes.

#### Deferrals the scheduler records

The scheduler records only ceiling, history-budget and recovery-reserve deferrals, once per changed reason.

- Fair turns, member bounds and retry backoff produce no deferral.
- A cleared budget reason produces no new gap notice.
- Selected work also clears a stale budget reason without another count or notice.
- The scheduler preserves deferrals owned by other components.

Challenges spend fair turns and history without spending block credit. Bounded durable holds preserve the earned turn of charged work while challenges proceed.

Wake times consider both the next charged turn and the history needed by challenges. Independent history holds retain their earned credit through a ceiling wait.

#### How the owner serves previews

The owner schedules queued preview work on its timer and uses the next ledger wake even when no new arrival appears. Reloads recompute that wake under the current ceiling. The owner observes each pick transactionally and continues delivery retries independently of scheduling.

| Failure | Result |
|---------|--------|
| A preview is refused | Only its own queued work ends, so an invalid expiry cannot starve other picks. |
| A storage failure | The turn is retried: twice immediately, then after waits that double up to one minute. A held probe's waits double the same way. |

A storage failure shows as `admission.owner.turn_error` and the doctor row `admission turns`, not as a stopped owner.

#### How long a first attempt lasts

A first attempt lasts the legacy-selected lifetime, or the configured response's, never longer than `auto_response.block_expiry` (spec 5.6).

- An executable owner reads that limit from the policy of the epoch.
- An owner without an engine reads it from the current configuration.
- A policy whose `auto_response.block_expiry` is not positive is refused.
- Retries keep that absolute expiry.

The first selected temporary lifetime is durable and cannot be extended by a later report of the same candidate. Absent metadata retains the configuration-selected lifetime.

#### Coalescing and entry bindings

- Held responses coalesce by evidence, kind and effective entry, whether the root entry is named explicitly or omitted.
- Derived entries validate their producer binding before fresh placement, coalescing and answered results, including direct queue requests.
- Retained queued work also checks its entry binding again before scheduling or coalescing.
- Ingress placement on an ended or in-flight candidate is a counted invalid refusal.

#### Minting

- Root preparation and selected submission use the cached admission view and do not wait for ledger writes.
- Missing observation is an attribution refusal. Malformed input remains invalid.
- Unminted Critical responses refused while the ingress is stopped count in its stopped status.
- Minting accepts canonical IPv6 evidence, while the selected kind checks containment support. HTTP challenges do not depend on the firewall family setting.

### Response funnels

The funnels are the legacy code paths that select an automatic response. Each kind of funnel hands its selection to admission in its own way.

#### Per-address funnels

Per-address funnels hand every selected block or challenge to admission before the existing responder runs.

- A process-local finding flag skips only the second evaluation of the same finding, including its queued block retry. Unrelated pending work and fresh observations still run.
- Admission uses the canonical address selected by the legacy extractor, including its message fallback, without changing the finding or its audit identity.
- Distinct observations still submit even when their address is already challenged.
- Previews and challenges never change a responder decision.

#### When admission replaces the legacy block

While admission executes blocks, the legacy block is skipped in two cases:

- Admission accepts the block.
- Admission refuses the block because the client is behind a trusted proxy or is a CDN edge.

A skipped legacy block makes no engine call, tracker row, queued retry or hourly charge.

For a block admission accepts, the scan also drops every other legacy block of that address in the same pass: its queued retry, findings admission could not take, and mail spray findings.

Every other mint or synchronous ingress refusal keeps the legacy block.

Acceptance is not application. A later hold, dry-run change or queue displacement never returns that request to legacy.

When admission takes a derived block, the request ends before it reaches the firewall engine, as an expected refusal. Timeout escalation and central intel log nothing, and the incident correlator counts it as requested.

#### Blocks that stay legacy

Mail spray blocks stay legacy. So do derived blocks asked to last longer than `auto_response.block_expiry`. Admission would cut both to that expiry.

The funnel reads `auto_response.block_expiry` the same way the scan loop does, with a 24-hour fallback for an empty, unparsable or nonpositive value. The daemon passes a nonpositive value to the policy unchanged, and the policy refuses it. The owner then executes nothing, so legacy keeps every block.

#### Subnet funnels

Subnet funnels submit every selected response before the existing responder evaluates its available execution budget. Constituent evidence follows the selected mail response. Paths without eligible observations retain their designed refusal and do not mint a replacement root.

#### Challenge escalation

A challenge entry retains its routed root until timeout escalation hands the selected response to admission. Escalation never creates new root evidence, and permanent selections take the designed rootless policy refusal.

#### Central selections

Central selections use the locally corroborating finding as their root and carry its original attribution if preparation refuses. They do not adopt a remote report as local evidence, and they preserve the selected temporary lifetime.

#### Incident responses

- Incident event preparation retains the attesting finding's check and severity, its evidence or its preparation error until a block is actually selected.
- Roots use the canonical address the legacy block selects while retaining the original finding.
- Only that selection counts an admission decision. Generic and spray paths preserve the original check and cause.
- A derived response never mints a second root.

#### Hourly summaries

Hourly summaries count committed arrivals, memory-coalesced reports, mint refusals, displaced submissions and both observed and terminally refused picks.

- The displacement callback runs under the ingress mutex on the submitting goroutine and uses the funnel's clock. Drain callbacks use the owner's fresh clock.
- Summary time never regresses. Event hours are clamped to the latest admission-clock or funnel hour after a backward wall step, including clock readings from an incomplete startup.
- Immutable write acknowledgments cannot consume newer rows.
- Summaries continue during ledger or clock outages, and shutdown flushes completed decisions even when a final drain fails.
- Failed writes retain a bounded chronological set of completed hours, so missing recordings remain explicit lower bounds.

#### Shutdown

- Shutdown closes ingress before returning new blocks to legacy, even while an owner turn is still running.
- Work accepted earlier is drained for restart. New legacy-owned blocks cannot enter that queue.
- Incident background response loops stop before the owner.

An owner that executes blocks ends, as `disabled`, the incident and spray blocks an earlier process queued. The correlator reads its selectors at start, so that work may not be selected any more.

## Details

This section is reference material on three smaller pieces of state.

### Content-bound dismissal state

A dismissal of a finding is bound to the content it was made for. The rules below decide when new content ends a dismissal.

`state.Store.SetBaseline` handles content hashes this way:

- It retains a known content hash when a result for the same finding has no hash, including duplicate results and baseline resets.
- An explicit new hash replaces the earlier one.
- Findings absent from the new baseline are still removed.

`ReconcileDismissedContent` accepts fresh content evidence only. Empty hashes and `ScanCarryForward` snapshots neither adopt content nor revoke a dismissal.

Revocation deletes the entry, which invalidates pending delivery and resolution callbacks tied to it. Finding keys and fingerprints stay unchanged.

The daemon calls `ReconcileDismissedContent` in two places:

- in `dispatchBatch`, before deduplication, `FilterNew` and delivery;
- in `respondToInitialScan`, before filtering and delivery.

Every observation in the batch contributes content evidence, even when notification deduplication keeps only one finding.

For an ended dismissal, the call returns the batch without that key's hashless, carried or already dismissed observations, so deduplication keeps the new content. It logs the ended dismissal with the key quoted, so file names cannot inject log lines or terminal controls.

The initial scan retains the full batch in history and audit, including the observations omitted from notification and response. Pending shutdown findings retain `ScanCarryForward` in their private storage format, so replay cannot treat stale content as fresh.

Undo restores the earlier content hash only when the dismissal created the baseline or changed its content. Content adopted after a dismissal that left it alone survives the undo.

### Mail login standing index

The login standing index holds trusted clean logins per address and mailbox. An address has login standing on a mailbox when its trusted logins there began at least 24 hours before an attack, fall on two UTC dates before it, and the latest of them is within 14 days of it. The index keeps exact IPv6 addresses, folds mapped IPv4, and uses the normalized mailbox spelling, including names containing spaces.

#### What the index stores

Each retained UTC date keeps its first and last trusted success.

- The first proves that the date precedes the decision.
- The last determines recency when it also precedes the decision.
- Later successes cannot excuse earlier failures.

The stored `lasts` array preserves the last-success timestamps. When it is absent, only the recorded first success of each date is known.

#### Compromises and standing

The IMAP/POP/Sieve tracker classifies a login as a compromise before it updates login trust. A compromise softened by prior standing neither earns nor refreshes trust or standing, and revokes neither. Spray verdicts still apply.

Standing compromise advisories have separate suppression clocks from cracks, for both trusted and untrusted logins.

#### When a login earns no standing

Both trackers withhold standing from a login that follows failures in the address's active episode, under any spelling. The failures that count are failures on the login's own mailbox, or failures naming none. The exception is an address that had standing when that episode began.

Each tracker sees the other protocol's failures through the shared spray memory. That memory works like this:

- It keeps the current tracker episode separately from the first spray failure, and preserves it across saves.
- It retains failures for the longer of the spray and tracker windows.
- Overflow cannot move a known episode's start forward.

Shared IPv6 /64 evidence gates earning standing only.

#### Standing in block decisions

Fast and slow block decisions and IMAP compromise severity use the tracker's earliest active exact-address episode, so a later address spelling cannot move the cutoff.

Those decisions also drop standing for a mailbox whose failures in the tracker's fast window exceed `standingFailureCap` times its per-address threshold. The two trackers count those failures differently:

- The mail tracker counts them from its per-mailbox window lists.
- The SMTP tracker keeps the newest of them per mailbox in `fastAccounts`. That list is bounded by at least `slowBruteMaxTimesPerIP`, so every validated fast threshold can be applied on reload without losing relevant counts.

Both counters combine address aliases and exclude expired timestamps, even on entries not yet purged.

#### Loading and saving

The daemon loads the index before log readers start and saves it on the known-customer cycle. Mailbox response revokes the mailbox it acts on.

Rules for callers:

- Load the startup snapshot before recording or revoking logins.
- A later load cannot merge old history into live state. It schedules current rows or deletions for the supplied keys.
- The saver must serialize each `Changes`, store write, and `requeue` on failure.
- A retry uses current rows, never the failed snapshot.
- Pending deletions have their own budget. Overflow requests a full bucket replacement.
- Store I/O and logging remain outside the index mutex.

#### Memory

The index owns mailbox strings, so log-line slices cannot retain oversized buffers. Address lists per mailbox, per-row dirty flags, and bounded date-array growth keep retained memory near its budget at the row caps.

Tests cover maximum-length mailbox names, same-day renewal, historical decisions, eviction, revocation, snapshot validation, and persistence round trips.

### Attack event storage

Attack events live in `attacks:events`. The index bucket `attacks:events:ip` stores empty values under `<ip>/<TimeKey>` keys.

- The writer chooses an unused primary key inside the write transaction, because batch counters can repeat for the same timestamp.
- Primary rows, index entries and the event count are updated atomically, including count-cap pruning.

Address queries walk the index newest-first and resolve primary rows until the requested limit is met.

Older index entries can still contain a full event copy. The reader falls back to that copy if the primary row is missing, malformed or belongs to another address. Both forms must match the requested address. The UTC time-key migration preserves index values verbatim, so readers must keep handling both forms until older entries age out.
