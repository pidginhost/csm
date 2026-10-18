# Building & Testing

## Toolchain and prerequisites

Use the Go version required by `go.mod` (currently 1.27.2), including its
formatter. A newer local formatter can disagree with the pinned CI linter.
For an installed Go launcher that supports toolchain selection:

```bash
export GOTOOLCHAIN=go1.27.2
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

Some tests keep scratch folders under their package directory, because system
temporary directories change the behavior they test. Source inventories skip a
folder removed during their walk; a missing root or failed read still fails.

Process-context unit tests stub start times for synthetic PIDs so unrelated
processes cannot supply cache identity evidence. UID and command mismatches
are checked separately. Atomic replacement fixtures require newer birth times
only when testing WAF log replacement; plugin-copy tests also work without
filesystem birth-time support.

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

`internal/admission` is a standard-library-only package that live responses
reach only as a preview. Its persisted enum values are fixed by golden tests.
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
must contain only decimal digits and be recorded exactly once. Missing,
empty, overlong or overflowing values fail the snapshot. cPanel records
zero for its own system entries; recreating one between observations keeps
its generation when the token stays the same. An observed absence retires
the generation even for a zero-dated entry. Tenant edits do not change the
token.

The admission ledger (`store.AdmissionLedger`) keeps this state durably in
the daemon's state database, in `adm:` buckets it creates the first time it
is opened. The daemon's admission owner (`internal/admissionowner`) opens it
at startup, settles what a previous process left outstanding after its first
clock reading and ceiling, before ingress or admission, and holds the only handle: one goroutine makes every change,
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
The daemon wires the owner into the response funnels
(`checks.SetResponseAdmission`) while it runs: each automatic response the
legacy funnels select is minted as evidence and submitted to the ingress, and
derived responses (challenge timeout, central, incident, mail subnet, ASN
crawl, netblock, permanent block) carry the root evidence that caused them.
Legacy blocking never waits for admission and its outcome never changes a
legacy decision. The owner serves its queue as observe previews: a schedule
reserves and charges each pick and ends it observed in one transaction, so a
crash cannot leave a preview reserved. Each hour it appends counts of its
decisions to the action log. One owner serializes every write, and each call
is one transaction, so a failed call changes nothing. Admission time
comes only from recorded clock readings: a wall clock that steps back never
lowers it, a new boot credits no elapsed time, and a reopened ledger admits
no new work until it records a fresh reading. Evidence is immutable once
published, and later reports of the same observation are kept as bounded
links. A later mint that differs only in its owner, because the inventory
changed between the two mints, is refused as a stale identity. If the owner
and any other field differ, including the finding, the record is invalid.
A candidate takes its entry, check and finding link from its primary
evidence, coalesces repeated requests without refreshing its queue age, and
moves from queued through reserved and executing to one outcome. A proven
failure may requeue after a backoff, with at most three attempts in total;
an unknown outcome never retries. Reserve and Execute report whether the
call granted the step; reading back an attempt that is already reserved or
running grants nothing. A new process settles what the previous one left
outstanding before it reserves anything: a reservation, which recorded no
intent and so dispatched nothing, fails and may retry; a running attempt
ends unknown. Nothing is dispatched again. A handle that has granted a
reservation refuses to settle, and an unknown outcome needs the intent its
attempt recorded until that uncertainty is retired, including when reading
the outcome back. A missing intent or intent bucket returns a corrupt-record
error without changing the ledger.
An empty ledger settles without a clock reading.
The owner's kill-point tests stop it at each step of a block turn and of
audit delivery, then start a new owner on the same ledger. After the
restart a reservation has failed and retries as its next attempt, a running
attempt is unknown and holds its address until it retires, the startup
reads hold back every row not finished applied, the consumers see only
outcomes finished applied, and no attempt reaches the engine twice.
Original attempts keep their charges, and retries consume new charges
without renewing the original expiry. Synthetic clocks keep the scenarios
independent of runner load.

Candidate records without an existing-effect link keep version 1 and their
original encoding. A refused existing-effect candidate can carry the block
name and expiry in version 2. Its maximum encoded size includes the link
only when present; attempts and audit rows keep their existing formats.

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
returned. A schedule passes over candidates the caller names as pending,
such as one waiting for the panel's verdict: they are never picked or
deferred, their scopes keep their turns, and the next wake waits only for
their deadlines. A candidate the caller names as allowed ends without a
charge, so it is picked as uncharged work at no ceiling or history cost,
even with both spent, and wakes the owner at once. Detectors hand work to a nonblocking ingress that applies the same
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
gains budget. Challenge work spends fair-turn and history budgets without
spending ceiling units.

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
window and, unless the candidate was only previewed, for as long as the
firewall row its attempt may have written can last: a failed attempt's row
can outlive a failed restore write, and startup must still know its action
while the row could be restored. Endings written before this rule keep
their earlier time. They
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
row's retirement cannot remove the row a re-minted attempt writes later.
After the action log write and before the acknowledgement, the owner hands
the applied `block_ip` rows of each batch to `Options.Applied`; no other
row reaches it. A failed call acknowledges nothing, so its consumers see the
same row again and must be idempotent by action and transition. A row this
process already wrote to the action log is not written again while its
consumer or acknowledgement fails, even if new rows sort ahead of it into
another batch. Each row's successful acknowledgement clears only that row's
write receipt; a restart writes pending rows once more. The daemon opens the
threat and attack databases before the owner starts, and the consumer refuses
rows while either is missing. Delivery
errors remain visible in `admission.owner.audit_error` until a pass succeeds;
the independent audit queue reports a stall if a pending batch cannot advance.
The daemon marks the address blocked in the attack database, as the legacy
path marks a block that applied, and, while the action's verified firewall
row still stands, records a threat database row that ends at the block's
absolute expiry. One durable transaction per delivery batch precedes threat
memory publication; read or write errors leave delivery pending and threat
memory unchanged. Local evidence survives feed withdrawal;
permanent local evidence and longer temporary rows remain unchanged.
Local threat writers serialize separately from lookups. The consumer reads
the firewall state under the threat writer lock, and unblocks and flush
cleanup remove the stored row under that lock after the firewall row, so an
unblock that lands during delivery removes what the batch wrote. An applied batch
does not hold the lookup mutex during its durable write, so reputation reads
and whitelist reload continue while that batch waits. Store transaction callbacks do not call back
into threat mutations; loaders finish reading the store before publishing an
instance, and reload changes the existing instance's config whitelist only.
Repeats preserve the stored timestamp, counters and undo entries, including
after restart. Queue
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
attempt is followed only by a later observation of that kind. Once a
candidate's effect is verified or previewed, later observations of its kind
in the episode are refused as an existing effect, which raises no notice,
and still extend the episode. After an unknown outcome they are refused the
same way but never extend the episode, which stays open until recovery
retires the outcome. Other kinds may queue at that target, but scheduling
and admission defer them as `pending_recovery` until the unknown is retired.
An attempt still recorded as running, left by a crash before settlement or
by an outcome that failed to commit, holds its target the same way until
its outcome is recorded.
The hold also covers candidates from earlier episodes. A missing intent
bucket refuses the operation without changing the ledger. Each handle keeps
the held targets as an index it builds at open from the proven intents and
changes only when a transaction that writes or deletes an intent commits, so
scheduling and reservation look a target up instead of reading every intent.
A final failure or a retired unknown outcome lets a later
observation start the next generation. An episode row lives only as long as a
candidate it names: ring eviction and history retirement clear that
candidate reference but retain its generation, and whether its effect
answers its kind, while another candidate holds the row. The last retained candidate takes the
row, and each admitted
candidate's history charge covers a row. A target without a row opens a
new episode, so a retired candidate's ID is never minted again. A
verified block ends its episode at the block's original expiry instead of
an hour after the last observation, even while work of another kind is
queued or in flight; an unknown outcome or a response of another kind does
not end it.

A candidate refused as an existing effect can name the block that enforces
it: the admission action that wrote it, or the firewall's `eff_` name of an
operator or earlier block, with its expiry. `TerminateExisting` ends a
queued pick that way, including a retry whose earlier attempt never ran;
`FinishExisting` fails the current attempt, keeping its charge, and ends
the pick linked in the same transaction, or leaves it
failed on its last attempt. A historical result cannot end a later retry;
a repeated linked ending must name the same block and expiry instant. A linked record is candidate version 2 and an
admitted candidate's history pays for its bytes; without room the
transaction changes nothing. A linked record requires at least schema 8,
with the same buckets; this build opens schemas 7 to 10 without rewriting
them, and older builds refuse an unknown schema rather than misread it.
An unchanged schema-7 ledger stays readable by older builds until a write
needs a newer format. A write never lowers the schema.

A panel verdict that allows a queued candidate ends it refused as
`verdict_allow`, like any other refusal: no attempt, charge or history
allocation, one ended count, and the notice that Critical or C3 work raises
when it is refused. A retry keeps the charge of its failed attempt. The
episode is not answered, so a later observation can queue the next
generation. Such a record requires at least schema 9, with the same
buckets; a later schema is retained and older readers refuse unknown schemas.

Queued work whose response the configuration no longer allows ends refused
as `disabled`: no attempt, charge or history allocation, one ended count and
no notice, since the operator turned the response off. The episode is not
answered. The first such record moves the ledger to schema 10, with the same
buckets; older builds refuse it. A full outcome bucket, every key at its
largest count, is now 32872 bytes against a bound of 33 KiB.

`EndDryRun` ends queued work that dry-run mode forecast instead of running:
the candidate moves to `dry_run` without an attempt, ceiling charge,
history allocation, audit row or notice. The ending counts one `dry_run`
outcome in the windows and no queue event. A retry keeps its failed
attempts, their charges and the history they paid for, which ends; roots it
gained while it waited are dropped as on other endings. The work must be
ready as a reservation requires: a retry waits out its backoff, an
unresolved attempt still holds the target, and stale work is refused. The
same ending again changes nothing. The episode is not answered. A dry-run
ending requires at least schema 9 and retains any later schema.

`SchedulePreview` selects queued work for a dry-run forecast. It is not
admission: spent live ceiling and history budgets do not stop it, and it
reserves, charges and defers nothing for capacity. Every candidate, a
challenge included, weighs one fair unit and no history. A challenge's
comparison preview still spends live history, so the selection passes one
over, with no wait or fair turn, while the live history budget cannot pay
for it, as a schedule does, and serves it on a lane that can. Challenge
picks share that live allowance within a selection; an earlier pick leaves
less for the next. Direct and
corroborated work alternates within a bounded reserved share of each batch,
and the general lane serves the rest by class and severity, where
reserved-eligible work competes too. Revalidation, age-out, retry backoff
and recovery holds gate it as they gate a schedule, a held target is
deferred as `pending_recovery`, a stale live `ceiling` or `storage_share`
wait clears as a schedule clears it, pending work is passed over, and the
live schedule and the selection share one fair position, which advances
once per selection. `PreviewWake` is the matching
wake: now while selectable work waits, otherwise a backoff end, a queued
deadline or when the live history budget can pay for a passed-over
challenge, whatever the other live budgets. `CeilingSnapshot` reads the committed
ceiling and its retained charges in one read transaction, proven against
each other, for a forecast to start from.

Preview selection and wake calculations check saved ceiling, storage and
live candidate history even though live budgets do not limit them. Damaged
accounting refuses the operation without advancing the fair position.

`RecordDryRunBlocks` writes one turn's forecast examples, at most one batch,
into the `dry_run_blocks` bucket the legacy writer also uses. A record keeps
the legacy `ip`, `reason` (the registered check) and `timeout_sec`, and adds
`candidate_id`, `session_id`, `kind` and `expires_at`; its key is a
fixed-width UTC time with nanoseconds, the canonical address and the
candidate, so two decisions for one target never overwrite each other. The
writer validates every record and the encoded key and value bounds before
writing; one bad record refuses the batch. A full bucket makes room by
evicting earlier sessions' first keys in key order in the same transaction.
It refuses a batch when no room can be made without evicting its active
session, or while the bucket remains above its cap.
`MaintainDryRunBlocks` runs one bounded step of a pass over the bucket,
trimming an oversized bucket without evicting the active session,
removing records whose key time is strictly older than a cutoff,
and, for a purge, every record of a session other than the one it keeps,
legacy records included. A purge with no active session removes everything;
a purge with an active session preserves that session regardless of time.
It resumes after the last key it visited, including protected keys, writes
nothing when nothing is due, and a failed step changes nothing.

The forecast model keeps charges in admission-time order, including when
imported legacy spend is dated in the future. Earlier simulated charges can
leave their window while that spend remains. Only `block_ip` consumes
simulated ceiling credit and temporary address space; other kinds return
`not_modelled` without changing capacity. These primitives do not activate
owner execution or replace the comparison-only challenge path.

Schema 7 adds execution intents; the first open upgrades a schema 1 to 6
ledger in the same transaction. Execution marks a batch of up to 64
reserved attempts as running and records, in the same transaction and
before any host change, what each member may apply: its kind, its target
and its absolute expiry. Executing the same members again reads them back;
a member that runs in another batch refuses the call. A batch mixing
reserved and running members refuses as a transition conflict, regardless
of member order or target overlap. An applied or failed
outcome removes the member's intent, while an unknown one keeps it, so a
restart knows which effects are unproven. A reservation holds room in the
recovery reserve for its intent, and an unknown outcome pins the intent
with its history. The upgrade records an intent for any attempt that ran
without an outcome or ended unknown and holds each pinned outcome's intent
in the reserve, and opening proves every intent against its attempt.
Startup reads the unresolved intents directly, without opening the ledger;
a ledger older than intents has none, and one it cannot read is an error.
Ledger buckets without schema metadata are an error, including unfamiliar
buckets.
An unknown outcome also holds the slot of the row that will retire it.
Once its absolute expiry has passed on a current, trusted clock, its
outcome rows are delivered and the engine finds nothing of it remaining,
recovery retires the uncertainty: the outcome stays unknown and counts as
nothing new, nothing is dispatched again, the intent goes, the history and
intent leave the recovery reserve, and an `expired_unproven` audit row
records the event. Status counts the attempts that run and the unknown ones
not yet retired, with the earliest expiry after which one can be retired.
A missing or inconsistent intent marks only that section unreadable.
Opening checks retired attempts against the stored clock even after their
retirement events have been acknowledged.

Firewall startup restores temporary blocks only for their remaining lifetime.
Timed elements use the same millisecond encoder in legacy and durable state;
rows with less than a millisecond left or an unrepresentable lifetime are
skipped. Blocks, operator allows and subnets use one startup clock reading.
Durable updates compare absolute expiries before encoding timeouts, so
millisecond rounding does not replace unchanged timed blocks.
Kernel timeouts come from a lease clock that never runs backward: the later
of the wall clock and its last reading advanced by the time elapsed since.
Reapplying the rules after the wall clock is set back restores each timed
block for the time it had left, never for the step on top. Batch checks and
sends read the same clock. Fresh legacy blocks record their deadline on
that clock too. Operator undo retains the original deadline and refreshes
its remaining timeout after persistence and before each bounded retry.
Fresh legacy sends also refresh after persistence. Ruleset installation ages
precomputed block timeouts after table discovery and rule construction.
Durable action planning, verification, sends, and whole-set retries use the
same lease clock for timed blocks. Allow and subnet expiry still use wall
time. The first Apply resumes the checkpoint before durable planning, so
its evidence and the installed timeouts share one clock.
After every ruleset it installs, the engine saves that clock with the boot
it was read in and the time since boot (`lease.json` beside the state file).
A timed block saves it before the legacy or durable state intent too, so a
new deadline created during a forward clock step cannot gain time after
correction and restart. If that save fails, the new block is refused before
state or kernel mutation. A save failure after ruleset installation warns
without undoing the installed rules; the next Apply retries it. Separate clock samples are
ordered so sampling latency can only shorten restoration.
A new engine resumes from it before restoring timed blocks: within the same
boot at the checkpoint plus the time elapsed since it, whatever the wall
clock did meanwhile; on a new boot at the checkpoint itself, crediting no
downtime. Before the first Apply the daemon also moves the clock forward to
the time the admission clock proves has passed: its saved high-water mark
or, within the same boot, its checkpoint plus the time elapsed since. A
valid but degraded admission clock still supplies that bound and logs the
discrepancy; a damaged checkpoint or an unreadable ledger logs the missing
coverage, and without either the engine starts from the wall clock. Forward
steps can shorten restored leases. After a step back the lease clock stays
ahead unless wall time catches up through a later correction; elapsed time
alone does not close the lead. New rows record expiries that far ahead; the
engine logs the first lead beyond the readback slack once per engine. The
admission owner reads the engine's lease clock once per batch and sets a
first attempt's expiry on it, so the lead is not lost from the block's
lifetime and a short block is not refused as already expired; a retry
keeps the first expiry. The owner already defers while the admission clock
is degraded, the only time the lease could trail it.

The engine also provides internal batch entry points for up to 64 timed
full-address blocks. The admission owner runs them only when the daemon gives
it an engine, and production gives none until cutover. Each member is
checked against one state and kernel snapshot over bounded fresh sockets;
unreadable state refuses the whole call. Expired rows remain available for
kernel cleanup in both the intent and restored state. Rejected members
consume no slot and cannot exclude a valid member. An address counts as
already blocked only when a verified row and its kernel element agree: an
untimed element for a permanent row, or one with the time a timed row has
left, accounting for elapsed time across both set reads and all member checks.
Apply results also age existing-block proofs through the batch's writes.
A timed proof that can already have expired is not coverage, even if its row
has time left within the readback slack. The row must also last as long as
the member, within the readback slack: a shorter block holds the address
until it ends. Any other row or element holding the address refuses the
member as pending recovery. An existing-effect refusal, at check or apply
time, names the block that holds the address: the admission action that
wrote its row, or `eff_` and a digest of an operator or earlier row's
identity, with its expiry. The same row gets the same name on every check
and after a restart. The batch rechecks, writes one
intent with expiry instants stored in UTC, refreshes timeouts after the
write, and uses one atomic transaction
on a fresh socket with a two-second deadline. Exact-family readback proves
each applied member's key and timed lifetime. Definitive kernel rejection
restores state; uncertain exchanges retain unknown rows. Unknown rows are
marked unverified and excluded from counts and seeding. Expiry retains them
until the owner retires the matching attempt. A failed state
write is returned as a state-integrity error and retains live suppression
until a successful state write; later batches refuse while that error is
held. The admission owner must reconcile action-linked rows before startup
or any downgrade to a build that ignores their verification fields.
The retry marker for a kernel rejection requires a successful state restore.
Marking with no action IDs still writes the safe state to release a state hold.
`RemoveBlockActionRows` removes, in one state write, the rows of attempts the
ledger has settled (failed, or retired after their expiry); an error reports
no completed removal, including a durability failure after rename. Startup
calls it after marking every unproven row, with the settled subset
`store.ReadSettledBlockActions` returns, so a start that stops between the two
leaves the rows held back and the next start removes them.
The engine's kill-point tests stop a batch around its intent write, kernel
batch, readback, unknown marking and rejected-state restoration, then start
the ledger and a new engine over the same state, after a process restart or
after a reboot that empties the kernel. An unreadable ledger restores
unexpired unmarked rows with degraded coverage; a readable ledger keeps a
committed applied outcome and holds the rest. Attempts without a committed
outcome are unknown. Their rows are held back, a new block of an address a
held row names waits, and once the expiry passes retirement removes the
rows and the ledger retires the attempts. A new boot retains the saved
lease floor. The test kernel reads emitted transactions, including set
families, timeouts and base chains, instead of assuming a successful send
installed the requested effects. It rejects incomplete batches and wrong
set destinations before modeling loss. Mapped IPv6 keys never become IPv4
blocks. In a real kernel, a batch killed after the kernel took it leaves
its element until a new engine's Apply replaces the table without the
marked row.
An unconfirmed removal is written again on retry even if its rows already
appear absent. Cleanup preserves other actions' rows, including distinct
actions sharing one address.
`RetireBlockActions` checks the kernel for up to 64 unknown attempts under one
engine lock: an attempt is clear when its address has no element, or the
element matches a verified row of another action, remaining lifetime included,
and its own row then goes in one write. An element still present keeps it
held. Retirement requires a kernel snapshot of the target's address family;
a missing or disabled IPv6 set cannot prove absence, so it holds that
attempt while the rest of the batch is answered. Cleanup resumes and
saves the lease checkpoint first; an unreadable clock or checkpoint
authorizes no removal. Address matching for recovery
accepts legacy mapped, uppercase and zoned spellings within the engine's
namespace; this does not relax the admission parser.
Unverified rows cannot suppress alerts or reputation checks through stale legacy
tracker entries. They do not count as enforced blocks or select threat evidence
for operator flush cleanup. Live deny limits count their kernel elements using
kernel timeouts rather than the unresolved rows' requested lifetimes, including
replacement accounting. Permanent promotion requires a verified block row.
An executed admission block writes no legacy tracker (`blocked_ips.json`)
entry. Reputation, alert suppression and its injected loader, flush cleanup,
threat lookups and the blocked list read the verified firewall row instead,
so it counts without one.

A read-only admission snapshot answers the same local checks for a bounded
batch, each answer naming its member, with the temporary occupancy and
limit from the same snapshot. No member takes a slot and no repeat is a
duplicate there: the caller checks only the members it is ready to run,
in order, for repeats and capacity. The snapshot also counts which of the
bounded forecast addresses the sets already hold as a timed or an untimed
element. A malformed or repeated forecast address refuses the call before
any read, and other platforms report the snapshot unavailable.

With an engine, each owner turn runs its `block_ip` picks as one batch. The
engine checks every member against one snapshot before anything is reserved. A
full set, or an address a row or element holds without proof, defers a member;
a block the engine proves already holds the address ends it linked to that
block, and an invalid or protected address or a spent lifetime ends it, all
without a charge. If the ledger refuses that link (no history budget for
it), the pick stays queued with the deferral reason and the rest of the
batch runs; the next check tries again. A proven block found only when the batch applies is
checked again when the outcome is written: with a fresh proof the attempt
fails, with its charge, and the pick ends refused as an existing effect,
linked to the block, in one ledger write, so nothing retries against it.
Without a fresh proof, or if that write fails, the failure alone is attempted
at once. If both writes fail transiently, execution waits for the pending
outcome; a crash before it is saved leaves an unknown attempt. After a successful
write the ordinary bounded retry or the next check decides. On the
last attempt the pick already ends failed. The rest are reserved,
recorded as running with their intents, applied and finished by their own
effect. Failed outcome writes retry before more work is selected and once at
shutdown, even without a fresh clock reading; the effect is never dispatched
again for that attempt. An outcome the ledger refuses for good (a damaged
record or a conflicting state) is not retried: its attempt stays unresolved
until recovery. Each turn, before scheduling, the owner retires unknown
outcomes whose expiry has passed: it asks the engine, for up to 64 at a time,
whether anything of them remains (`RetireBlockActions`); running attempts are
never sent. The engine removes each clear attempt's own row, and the ledger
then retires it (`RetireUnproven`). An element still present, as after a
forward wall step, keeps that attempt for a minute on its own wait, so a held
batch cannot starve the intents behind it. Each checked batch advances through
action order, wrapping around, even when its retries are due by the next turn.
A degraded clock, a missing engine or an engine that cannot check retires
nothing; the next pass waits one second, doubling to a minute. An attempt
whose retirement the ledger refuses (undelivered outcomes, or a ledger clock
that cannot yet prove the expiry) is asked again after one second, doubling
to a minute. A damaged record or an attempt that ended another way is asked
again a minute later and reported once, so it does not fail every turn. A
missing or unreadable attempt uses the same wait without preventing other
attempts from retiring. An unreadable intent list delays the whole pass;
damage is reported once until a readable list proves recovery. A stop
between the row removal and the ledger retirement leaves a
row-less unknown that the next pass retires. The turn wakes for the earliest
expiry or monotonic retry. With one noted, a turn lists no intents until it
is due; with none noted, every turn lists them. A turn that fails after its
retirement pass still reports that pass's error. It never rebases a retry on
admission time or adds time spent inside
an engine call. Expiry conversion uses a monotonic sample taken before reading
the admission clock, so a slow tick or later call cannot postpone another
expiry. Running attempts create no retirement wake; retired attempts leave no
retry entry.
Every other kind is still previewed. A batch the kernel
rejected fails every member, charged; each then retries alone, one per turn,
until its next outcome or its expiry. A state write the engine could not make,
a failed batch check or apply (including per-member transport and readback
errors), or a missing engine holds automatic execution: block picks wait,
deferred as an unavailable engine, while one probe runs per wait, from one
second doubling to a minute. A held state write is probed by writing the safe
state again and checking its snapshot. Without an engine, idle scheduling
pauses and resumes on the first schedule check that finds an engine, without
waiting for the old probe deadline. Other idle holds still probe on their
waits; successful snapshots cannot reset a failing member check's backoff. A
failed apply keeps its cause and backoff through state repair, ledger refusals
and member refusals until an applied effect proves recovery. Hold changes copy
the cached owner status without rereading the ledger. Status
(`admission.owner.execution_held`) and the `csm doctor` row `admission
execution` name the cause. An owner publishes `admission.owner.executing`
only while it runs block picks: it has `Options.Blocks`, `liveExecution` is
on and its policy is not a dry run. `admission.DoctorImpact` then closes every
admission row with `ExecutionAffected` instead of `PreviewUnaffected` and
turns the outages that stop automatic blocks, held execution included, from
warnings into failures. `liveExecution` is a package variable that stays false
until plan 1.4c-2b removes it: under a live policy an owner with an engine
then previews its block picks as one without an engine does, asks no panel
and holds a refused policy's picks; a dry-run policy still forecasts. No
configuration reaches it, an architecture test refuses any production write,
and the package's tests turn it on to exercise execution.
A degraded admission clock cannot bound a lease, so
it defers block picks the same way. One batch starts a second at most; with an
engine, a drain that queues new work runs the schedule at once instead of
waiting for its timer. An owner with an engine also selects, checks or
forecasts work once a second at most, including turns that dispatch
nothing: work that falls due sooner, from a drain or a panel answer, stays
due for the next second, while retirement of earlier attempts keeps its own
waits.

An owner with an engine binds to one execution policy: the dry-run mode,
the verdict callback and its timeout, the hourly ceiling and the response
lifetimes, read together from one config publication. Every publication
that changes `auto_response` or the mode gets a new epoch. The owner does
not start without a valid policy; it names the refusal instead, even with
the callback off, and `mode: observe` is refused. Each turn and reload
installs a newer epoch before it selects work, and the turn uses that
policy for every pick; a reload returns once the policy is installed, after
any turn already running. An older epoch is ignored. Changed settings or
missing required dependencies under an installed epoch hold execution, as
does an invalid newer policy, with the refusal in `execution_held`, until a
valid newer epoch arrives; the daemon reports a refusal at reload as a
`config_reload_error` finding. While a refusal holds execution, a selected
pick of any firewall kind is deferred as `engine_unavailable` with nothing
previewed, reserved or charged, and the schedule then passes it over, as it
passes over work waiting for the panel, until a valid policy is installed;
a refused policy also suspends engine probes and repairs. The schedule
checks for newer epochs even while idle, so a publication without a reload
resumes held work and any probes suspended by dry-run. A challenge keeps
its comparison preview. A comparison-only owner never reads the policy.

Under a dry-run policy the owner forecasts instead of running. It selects
work with `SchedulePreview`, whatever the live budgets, and ends each pick
as a dry run with a prediction: no attempt, charge, history, audit row or
mutating engine call. A forecast session starts at startup or on entry into
dry-run from the committed ceiling and its retained charges, then lives in
memory apart from it: the same committed clock meters it, a new limit
applies without new credit, and live credit is never copied over it. One
read-only admission snapshot answers a turn's `block_ip` picks, with the
real temporary occupancy and the real blocks of forecast addresses. A
refused target ends or waits as a live check has it. A real block that
covers the address predicts `existing_actual`, unlinked; a forecast block
that lasts as long, within the readback slack a real block is allowed,
predicts `existing_shadow` and a shorter one `pending_recovery`, and
neither is renewed. Other picks are checked against
the modelled temporary capacity, the bound on forecast blocks and the
modelled ceiling, and only `capacity_admit` adds a forecast block and a
simulated charge. With the verdict callback on, a pick the model would
judge is asked about first and waits for its answer with no forecast
change; a usable allow ends it as `verdict_allow` before any modelled
capacity is judged, and a covering forecast block or a full modelled set
ends it without a call. Other firewall kinds end as `not_modelled`, with no
call; a challenge keeps its comparison preview. Without an engine or
snapshot, or with a degraded clock, picks wait as `engine_unavailable` and
the forecast does not change. A decision is installed only once its ending
commits, and only then counted in the hourly comparison summaries as a
`dry_run` decision with its prediction, a field apart from the refusal
reason. The prediction names live in the admission package, which the
finding stream tool reads too. A forecast neither probes nor repairs the engine: a hold from live
work stays in `execution_held` until the next live turn. A live policy ends
the session and never replays a dry-run ending; a later observation of the
target is a new generation. A session whose model cannot be metered by a
committed clock reading or a new limit ends too: the forecast error is
`model_error` until the next session starts, and that session names
`model_error` as its reset rather than a mode change.

Each committed `capacity_admit` leaves one example in `dry_run_blocks`. A
turn writes its examples in one batch after its endings, also when a later
pick stops the turn; a failed write loses them without undoing the endings
or the forecast, and nothing retries it. An owner that runs blocks keeps the
bucket alone: one bounded maintenance step a second trims it to its cap and
removes examples older than a week. Installing a live policy after a dry run,
or at startup, asks for a purge of every example but the active session's;
the purge pass starts over whenever the active session changes, so a dry run
that resumes keeps its own examples whatever their times, and the examples
are stale until a purge pass completes. The daemon's legacy prune and live
purge leave the bucket to such an owner.

Such an owner reports its forecast as `owner.dry_run` in status: whether it
forecasts, the session and why it started, the model's coverage, real
against predicted temporary occupancy from the turn's snapshot, the
forecast's own ceiling, each prediction's session and last-hour counts, lost
examples and summaries, failed writes, a pending purge, and a fixed code
for why forecasting last failed. A turn that succeeds clears the code; a new
session clears its time too. Leaving dry run clears the forecast and keeps
the last session's identity; a dry run whose session has not started shows
none. The loss counters cover the process.
`csm doctor` renders it in three rows that warn and never fail.

The forecast's committed predictions are also summarized in history, never
sent to an alert channel: one `auto_block` Warning, "Dry-run capacity
forecast: N responses passed modelled capacity checks", with the other
predictions' counts, its interval, a session count and a bounded list of
distinct examples in committed order, each naming its candidate, finding,
target and check. The first summary is due a minute after the first
prediction it counts, and each later one a minute after the previous
attempt, a failed one included. One summary is pending at a time: the
sender takes it whole, later predictions start the next one, and a failed
delivery goes back in front of them as one summary, retried with the notice
backoff and counted in the notice queue while it waits. A mode change never
flushes or relabels a pending summary; Stop sends one its minute allows and
counts any other as lost. Executable owners supply a cancellation-aware,
history-only summary sink separately from legacy notice delivery. An error
must mean the summary was not committed. Stop cancels an active delivery,
settles its receipt, and bounds the final attempt outside the owner
goroutine. Failed or cancelled summaries remain counted until delivered or
reported lost. The status getter returns a deep copy of its cached snapshot.

With the policy's verdict callback on, a live owner asks the panel about
each `block_ip` pick before anything is reserved, as a dry run does before
it forecasts one. One read-only admission
snapshot answers the turn's local checks without giving any pick a slot:
a refused, protected or already enforced target ends or waits as a batch
check would have it, and a full set defers the pick, all without a call.
Any other pick is asked about, as `CSM auto-block: <check>` for its
canonical address, and stays queued; the schedule passes it over until
the answer arrives. Workers, outstanding jobs and cached answers are bounded;
a full stage leaves picks queued and is never read as an answer. Each answer
is keyed by candidate, attempt and policy epoch and expires from completion,
including time awaiting receipt. Admission requires a signed, request-bound
allow even when legacy callback signing exceptions are configured. A valid
allow ends the pick as one `verdict_allow` refusal with no attempt or charge,
even with the ceiling spent: the schedule picks it as uncharged work.
Block, an empty verdict or a failed exchange continues the local path,
and the reservation consumes the answer. Local checks run again before an
answer is used. A pick that stops being eligible has its call cancelled.
A new epoch, a mode change included, cancels every call, drops every
answer and starts new workers only after the old ones return; Stop
cancels the calls and joins the workers. A cancellation is never an
answer. The owner status carries a `verdict` object for an executing
owner: stage gauges, process counters and the last failure as a fixed
class, never response text. Its outstanding jobs are also the
`admission.verdicts` queue row. Workers count completed calls before delivery;
late or duplicate results cannot count another call or consume a different job.

The admission ledger exposes two row-recovery reads. `ReadSettledBlockActions`
names failed attempts and retired unknown outcomes among the supplied action
IDs; `ReadUnprovenBlockActions` continues to include every non-verified
attempt. `UnresolvedIntents` gives the owner the same ordered intents as the
handle-free startup reader. Callers must inspect each attempt's outcome:
an executing intent is unresolved but cannot be retired as unknown.

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
name the file and line, never the matched text. Filenames are checked too;
a matching filename is reported with its path redacted. The
[fixture sanitisation rules](https://github.com/pidginhost/csm/blob/main/internal/daemon/testdata/php_relay/SANITISE.md)
describe the additional manual privacy review.

### Admission preview ledger

Admission previews reserve, charge history and capacity, and end observed in one transaction. They write both audit steps, never execute a response, never count as applied, and do not end the evidence episode or raise a notice. Repeated evidence is answered until its quiet window closes.

Imported legacy usage retains its accounting-window charge after an attempt is retired. Retirement of old attempt history cannot create new admission capacity before that window closes.

The scheduler records only ceiling, history-budget and recovery-reserve deferrals, once per changed reason. Fair turns, member bounds and retry backoff produce no deferral; a cleared budget reason produces no new gap notice. Challenges spend fair turns and history without spending block credit, and bounded durable holds preserve the earned turn of charged work while challenges proceed.

The owner schedules queued preview work on its timer and uses the next ledger wake even when no new arrival appears. Reloads recompute that wake under the current ceiling. It preserves the legacy-selected absolute expiry, including on retries, observes each pick transactionally and continues delivery retries independently of scheduling. A refused preview ends only its own queued work, so an invalid expiry cannot starve other picks; a storage failure retries the turn, twice at once and then after waits that double up to an hour, as a failing notice delivery is retried.

Held responses coalesce by evidence, kind and effective entry, whether the root entry is named explicitly or omitted. Derived entries validate their producer binding before fresh placement, coalescing and answered results, including direct queue requests. Retained queued work also revalidates its entry binding before scheduling or coalescing. The first selected temporary lifetime is durable and cannot be extended by a later report of the same candidate; absent metadata retains the configuration-selected lifetime.

Root preparation and selected submission use the cached admission view and do not wait for ledger writes. Missing observation is an attribution refusal; malformed input remains invalid. Unminted Critical responses refused while the ingress is stopped count in its stopped status. Minting accepts canonical IPv6 evidence, while the selected kind checks containment support: HTTP challenges do not depend on the firewall family setting.

Per-address funnels hand every selected block or challenge to admission before
the existing responder runs. A process-local finding flag skips only the
second evaluation of the same finding, including its queued block retry;
unrelated pending work and fresh observations still run. Admission uses the
canonical address selected by the legacy extractor, including its message
fallback, without changing the finding or its audit identity. Distinct
observations still submit even when their address is already challenged.
Admission outcomes do not change, delay or skip any existing responder decision.

Subnet funnels submit every selected response before the existing responder evaluates its available execution budget. Constituent evidence follows the selected mail response; paths without eligible observations retain their designed refusal rather than minting a replacement root.

A challenge entry retains its routed root until timeout escalation hands the selected response to admission. Escalation never creates new root evidence, and permanent selections take the designed rootless policy refusal.

Central selections use the locally corroborating finding as their root and carry its original attribution if preparation refuses. They do not adopt a remote report as local evidence, and preserve the selected temporary lifetime.

Incident event preparation retains the attesting finding's check and severity, its evidence or its preparation error until a block is actually selected. Roots use the canonical address the legacy block selects while retaining the original finding. Only that selection counts an admission decision; generic and spray paths preserve the original check and cause. A derived response never mints a second root.

Hourly summaries count committed arrivals, memory-coalesced reports, mint refusals, displaced submissions and both observed and terminally refused picks. The displacement callback runs under the ingress mutex on the submitting goroutine and uses the funnel's clock; drain callbacks use the owner's fresh clock. Summary time never regresses: event hours are clamped to the latest admission-clock or funnel hour after a backward wall step, including clock readings from an incomplete startup. Immutable write acknowledgments cannot consume newer rows. Summaries continue during ledger or clock outages, and shutdown flushes completed decisions even when a final drain fails. Failed writes retain a bounded chronological set of completed hours, so missing recordings remain explicit lower bounds.

Ingress placement on an ended or in-flight candidate is a counted invalid refusal. An episode that cannot be encoded is ledger damage. Shutdown closes ingress before final drains and stops incident background response loops before stopping the owner.

Selected work also clears a stale budget reason without another count or notice. The scheduler preserves deferrals owned by other components. Wake times consider both the next charged turn and the history needed by challenges, while independent history holds retain their earned credit through a ceiling wait.

A batch readback requires every member to be running. Direct queue requests
can reserve a retired action ID again. If another member of that batch still
runs, execution refuses the mixed batch without writes.
