# Building & Testing

## Toolchain and prerequisites

Use the Go version required by `go.mod` (currently 1.27.4), including its
formatter. A newer local formatter can disagree with the pinned CI linter.
For an installed Go launcher that supports toolchain selection:

```bash
export GOTOOLCHAIN=go1.27.4
export PATH="$(go env GOROOT)/bin:$PATH"
go version
```

Linux tests need PHP CLI and python3-cryptography for the shipped PHP runtime
and release verification regressions. The release-verifier tests skip when the
module is absent and fail when `CSM_REQUIRE_PYTHON_VERIFIER=1`, which the CI
test jobs set so a missing module cannot pass as a silent skip. The Web UI
JavaScript tests need Node 24 or newer the same way: they skip without it and
fail when `CSM_REQUIRE_NODE=1`, which the CI test job sets. Builds with `yara,journal,bpf` also need
CGO, pkg-config, YARA-X 1.23.0 and the systemd
development library. Use the release builder or the documented test images.
CI images ship the module toolchain and run with `GOTOOLCHAIN=local`, so a
stale image fails instead of downloading another toolchain in every job.

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

Admission retry tests repeat evidence with its original observation timestamp
and check the refusal reason. Changing that timestamp creates conflicting
evidence and bypasses episode placement. Forged-account flood tests keep the
host and real account backlogged in each evidence class and check repeated
alternating turns. A single account pick can pass through sort order alone.

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

### Antispam learning benchmarks

Run the learning benchmarks on Linux with repeated iterations:

```bash
TMPDIR=/var/tmp/csm-gotest go test ./internal/antispam/learn ./internal/antispam/learnwatch -run '^$' -bench . -benchtime=3x -count=3
```

Each publication iteration starts with one live anchor and adds one new
contributor. Each flood iteration starts from an empty baseline before new
messages arrive. Database state is reset between iterations; setup and cleanup
are excluded from timings. The flood wait metric is the mean across iterations.
The benchmarks check that publication commits, discovery visits the corpus,
the second account submits before the flood finishes, and audit coverage completes.

Storage metrics count logical keys and values, including contribution charges,
account usage and pending-message indexes. They exclude bbolt page overhead and
anchor message bodies. These fixed workloads do not establish maximum database
sizes or production latency: message names, contributor mixes, filesystem
performance and native rspamd calls change the cost. Runtime allowances remain
unchanged.

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

The gosec pin includes the upstream module loader fix. Version 2.30.0 can
split large packages in deeply nested checkouts and report false type errors.
Keep this pin aligned in the Makefile and both build images until a tagged
release includes the fix.

Linter config in `.golangci.yml`: errcheck, govet, staticcheck, unused, ineffassign, gocritic, misspell, bodyclose, nilerr.

## CI/CD

GitLab CI (`.gitlab-ci.yml`) is the internal build pipeline. It runs lint/test/package jobs, publishes internal packages, mirrors to GitHub, and creates the public GitHub release artifacts.

| Stage | What it does |
|-------|-------------|
| **.pre** | Manual CI tools and builder image builds (amd64 and arm64) block dependent jobs when their definitions change on a branch. |
| **preflight** | Release preflight rejects version tags without a usable cPanel image, after required images are built. |
| **lint** | Pinned golangci-lint and formatter, vet, blocking gosec/govulncheck, fixture privacy, and Prometheus config validation. |
| **test** | Full default-tag race/coverage suite (30-minute package timeout), shipped-tag lint/security/race gate, required kernel/service gate, four pinned clean-application gates, and the attack replay corpus. |
| **build** | amd64 and arm64 release binaries with YARA-X CGO and the `yara journal bpf` build tags. arm64 builds run under QEMU in rootless BuildKit. |
| **package** | RPM + DEB via nFPM |
| **integration** | Spin up cloudv-1 AlmaLinux and Ubuntu hosts plus the configured clean cPanel image via phctl, install the pipeline-built amd64 packages, run the integration test binary, collect coverage, and confirm every test server was really deleted. `main` integration is manual and can omit cPanel; version tags require the cPanel image, baseline-to-candidate package upgrade, installer, WHM, mail watcher and forward guard checks. |
| **sign** | Detached signatures on release artifacts |
| **publish** | Internal GitLab Generic Package Registry (versioned + `latest`) |
| **repo** | Publish RPM/DEB to the public `mirrors.pidginhost.com` apt/dnf repos |
| **pages** | Docs + coverage HTML (GitLab Pages preview) |
| **cleanup** | Remove old package versions |
| **release** | GitLab release on tags matching `v*` |
| **github** | Mirror to GitHub + upload release artifacts (auto on tag push) |

Lint and test jobs use the shared Go cache runner. Compiled and analysis
caches rotate with the CI tools and builder image tags because Go does not
detect changes to installed C libraries. Module downloads remain shared.
The default suite executes on every pipeline even when compiled packages
are cached. Release build and package jobs stay on separate runners and do
not consume these caches.

Preflight, lint, test, build and package jobs retry up to twice when the
runner, registry, scheduler or API fails; a failing script is not retried. A
newer push to the same ref cancels the older pipeline's lint and test jobs.
Integration, kernel tests and publishing jobs neither retry nor get cancelled.
Integration retries the Ubuntu package index update while the mirror syncs;
the image repair and the CSM install run once.

The test job uses `gocover-cobertura -strict` so unresolved package information
fails coverage conversion. A successful test job must include every covered
package in its report.

When an image definition changes on a branch, run its blocking manual
image jobs: ci-tools, or both builder architectures. Preflight waits for
those builds, and both release builds wait for preflight while still
running alongside lint and tests.

Release builds and preflight run in branch and tag pipelines, including
scheduled and manually started runs. They are excluded from merge-request
pipelines; merge requests use the checks in the branch pipeline.

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

Tag-specific `publish` dependencies require preflight, unit tests,
fixtures, corpus, production tags, kernel tests, signed artifacts and
integration. Repository publication and the GitLab release depend on
`publish`; the GitHub release also directly requires integration and the
test gates. A missing `csm-kernel` runner leaves publication pending. A
missing cPanel image fails tag preflight.
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

### Content-bound dismissal state

`state.Store.SetBaseline` retains a known content hash when a result for the
same finding has no hash, including duplicate results and baseline resets.
An explicit new hash replaces the earlier one. Findings absent from the new
baseline are still removed.

`ReconcileDismissedContent` accepts fresh content evidence only. Empty hashes
and `ScanCarryForward` snapshots neither adopt content nor revoke a dismissal.
Revocation deletes the entry, invalidating pending delivery and resolution
callbacks tied to it. Finding keys and fingerprints stay unchanged. The daemon
calls it before `FilterNew` in `dispatchBatch` and `respondToInitialScan`.

Undo restores the previous content hash only when the dismissal created the
baseline or changed its content. Content adopted after a dismissal that left
it alone survives the undo.

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

`SlotLimits.Take` adds a scope holding only for one-unit `block_ip` work.
Zero-cost and multi-unit work do not add holdings, even when marked as
eviction-capable. Free slots still decrease by the granted cost.

Effect records use an expiry-ordered key followed by the action ID. Decoding
requires a canonical value that reproduces the key and all recorded fields.
Victim references accept either an admission attempt ID or an import's
`eff_` name followed by 32 lowercase hex digits. Record keys remain attempt
IDs; an import has no record key. Imports have the fixed tier (C2, High)
and occupy general slots. The codecs keep their existing versions: an
older build refuses a ledger containing import claims, so such a ledger
must stay on a compatible build. Preview-only hosts have no such claims.
The effect records' partition tally rejects negative counts, underflow and overflow;
failed additions return the original tally. Combining a tally with set
occupancy also returns an error and the original occupancy if either
partition's total is invalid or overflows. A full-set deferral raises the
capacity notice for any assessed tier in a live ledger. A preview ledger
raises it only for Critical work. A pending block that evicts names its
victim in its effect record and its intent; an admission victim's record
names the block that claimed it and stops holding a slot once that block's
application is verified with the victim's removal proven. A verified
block that never removed its victim releases the claim; an unproven
removal is an unknown outcome, never a verified one. A definite failure
releases the victim claim; unknown outcomes keep it through retirement
until the victim expires. An import, a stamped legacy block the firewall
lists each turn, is a (C2, High) victim with no record of its own: only
the claiming block's record and intent name it, by its `eff_` name, and
no other block claims it while that record does. Opening rejects duplicate
import claims and requires a general slot above the import tier. Execution
uses the current turn's list; a missing or changed import drops the claim.
Scheduling, reservations, observe previews and wake calculations share
that list and count at least as many general imports as it names, while
preserving a larger occupancy count. An overfull partition funds no
replacement until the complete state fits. Observe previews write no
claim or effect record; wake calculations write nothing. A preview
reports the block whose slot it took, so the owner counts previewed
replacements in status; a readback reports none.
A member's sweep also ends its import claim; a delayed outcome may still
name the import in its intent without looking for a victim record.
A verified eviction marks its victim's record gone at the evicting block's
outcome. A verified block that two consecutive firewall answers no longer
hold is gone from the first of them, whatever removed it: an operator
unblock, undo or flush, or a lost kernel element. A held answer in
between starts the count again; the count lives in memory, so a restart
only delays the mark. Failed answers keep all previous misses and count
nothing new. Bounded batches get two answered checks before advancing,
so a larger configured capacity cannot hide later records. A record that
changed in between is left to what changed it. A gone record holds no
slot, so waiting work can take it, and stays until its expiry sweep.
The first stored gone record moves the ledger to schema 14, which older
builds refuse. Schema 14 requires the live-start marker, effect bucket and
tally even after all records expire. A check that marks nothing leaves
the schema unchanged. Only a live ledger has effect records, so preview
and forecast hosts never write schema 14.

The owner asks at most once a minute, and only while the ledger counts a verified
block. The firewall answers with the retirement rule reversed and writes
nothing: an element still at the address that no other action's verified
row proves counts as held, even after a forward wall step makes the
block's own row look expired, and so does an address whose family the
firewall cannot read. A failed or short answer marks nothing and counts
as no miss.

Startup drops the state row of an admission-record victim whose eviction
the ledger verified, and of a block the ledger marked gone, so a restart
cannot restore an element whose slot the ledger no longer counts. A
running owner retires the row of a block it marks gone as it retires an
evicted victim's, so a firewall reload cannot restore it either. Imports have no durable cleanup record: a restart
before retirement restores the import only until its original expiry. Startup readers report an error if the
effects bucket disagrees with the schema or an effect is a nested bucket;
they do not treat damaged eviction storage as an absent record.
Expiry can remove either record first. A late definite outcome still ends
the claim using the retained intent. A reservation that expired without
running releases its claim. Only records still holding slots contribute
to occupancy and expiry wakes. Scheduling retains scope turns while a
lane has no usable slot or strictly lower victim. A live ledger on a
trusted clock may instead rotate an equal-tier record out of a full
partition for fresh work: work whose episode row has had no verified
response, never work queued without one. The victim is a verified
record of exactly the work's tier, in the partition of the work's own
lane, whose 30-minute hold passed on both the admission clock and the
ceiling's elapsed time since its verified application. A reboot grants
no elapsed time and a degraded reading allows no rotation. Each
partition is shared among its active scopes, using the queue's integer
share rule: the scopes whose unexpired, unclaimed records hold its
slots, the scopes of queued work that would hold one at the last
schedule cycle, and the requester's. Each live schedule cycle on a trusted
reading that reads the victim pool first moves each partition's remainder cursor to the next
active scope and stores it beside the queue cursors, so reservations
share the set as their cycle did; a preview ledger never moves it. A
zero-share requester waits for a later cursor turn. Work at or over a
positive share rotates only its own scope's records;
work below it reclaims only the scope with the greatest excess among those
holding a verified record of its tier in that partition at another
address, never taking that scope below its share, and waits if that scope
has no record whose hold passed. The oldest application, then the lowest action, goes
first. Imports never rotate. The claim and its outcome are those of an
eviction, opening accepts an equal-tier claim only inside the block's
own lane partition, and a live rotation raises the capacity notice.
Notice allocation preserves the new attempt's recovery hold; insufficient
room sends the notice to its fixed overflow record.
An older build refuses a ledger holding a rotation claim or a moved set
cursor. Saved ceiling turns
also keep their earned credits through slot pressure and restart;
backoff keeps its existing release behavior. Records and intents without
an eviction keep their version 1 encoding.

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
returned. Regression tests reopen the ledger during unfinished scope and
reserved sub-lane rotations, then check service order across the restart.
Overload recovery uses elapsed-time refill and verifies each reservation's
charge, so a fresh cursor or an uncharged pick cannot satisfy the test.
Free-slot rotation tests require a granted reservation, its stored effect,
and the expected occupancy and charge, including after a limit increase.
A missing effect must fail rather than count as proof that no victim was taken.
A schedule passes over candidates the caller names as pending,
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
and a summary once a minute after acknowledged delivery. While the owner
previews or forecasts, ledger notices go to findings history only, as
Warnings starting "Admission preview:". The independent stopped-admission
notice still reaches alert channels as a Warning saying existing blocking
is unaffected. While it executes (never in this build, see `liveExecution`),
a gap is an outage of automatic blocking: notices go to the alert channels
with their kind's severity and no preview prefix, and the stopped-admission
notice is Critical. The mode is read at each delivery, including a retried
stop notice, so a record raised before a mode change is delivered in the new
mode. Stop retries retain their original timestamp, cause and stop identity. Acknowledgements
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
degraded clock reading never ends an episode, and an episode ends only
once the ceiling's elapsed time has passed its end as well: a forward wall
step cannot end it early, and a reboot grants it no time. Each row records
that elapsed end, and its quiet hour runs on elapsed time from the reading
that places the observation, so a report processed late after a step
cannot end it early either; a row written before it existed ends on wall time alone
until its next write, including maintenance that leaves its last
observation unchanged. Existing elapsed ends survive maintenance, and
verified closing replaces the quiet end with the block's remaining
lifetime, read at the block's execute reading, so a wall step
between execution and its outcome cannot shorten it. Execution readings
are released when an outcome commits, including startup settlement.
A verified episode keeps that boundary: a later verified block of the
same episode moves neither end. A legacy verified row gains its missing elapsed end from
the original expiry when closed again. An answered block frontier without
candidate references retains that verified boundary on both clocks, using
schema 15; earlier readers refuse it. Its verified predecessor's retirement collects it
after both ends pass. Address and subnet block histories remain charged
while their episode boundary is still active on either clock. Scheduling
and wake times count that retained history as unavailable. Bounded
cleanup continues past retained histories across ticks, so they cannot
hide later expired history. The first row with a positive elapsed end moves
the ledger to schema 13 on every host, which older builds refuse. Schema 13
records nothing of the live start or the effect records, so a schema 13 ledger
proves them from their own markers. Episode placement refuses an
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
not end it. The expiry is set on the engine's lease clock, which after a
wall clock step back leads admission time; the owner passes that lead to
`FinishOnLease` or, with a victim, `FinishEviction`, so the episode ends when
the kernel element expires in admission time. Its elapsed end is the time
left until then, so a forward wall step does not end the episode while the
kernel element remains. Verified outcomes use the wall and elapsed values
of the last committed clock reading, retained together by the ledger
handle and restored at open. An unreadable ceiling or a failed later tick
does not prevent recording a result for work that already ran. New work
still requires a successful reading. An isolated member's isolation
ends the same way.
Retirement and retry staleness stay on the lease frame: late retirement
only holds an address longer, and the engine refuses an expired member.

On a live ledger, a verified block whose record
is gone stops answering its kind before the episode's original verified
end: a later observation of that kind, made after the removal and with
every root observed after it, queues a charged new generation in the same
episode. On a live ledger the block line records the generation of its
latest verified block, whose history outlives later generations, so
queued, ended and forgotten returns keep that evidence gate against the
latest removal; such lines also need schema 15. Older lines recover that
generation from an unbroken chain of retained predecessors on their next
arrival and persist it with the next episode write. A gap leaves the line
answered. Opening a ledger does not rewrite older lines, but rejects a
reference to an unverified candidate or a block older than another retained
verified block of the same kind and episode. Forgetting a refused
return keeps the verified boundary until both ends pass. The
episode earns no equal-tier rotation. An observation or root at or before the removal
is answered or stale. Past the original end, as when
a reboot keeps the episode open on elapsed time, the block keeps
answering until the episode ends on both clocks. The owner caps a
re-admission's first attempt at the episode's original verified end, the
time left in admission time added to the lease clock; a retry keeps its
first expiry. A re-admission with no time left, or whose episode row
has been replaced or lost, is refused as expired, or as invalid in a
preview.
A forecast caps a block returning to an address whose forecast block the
session replaced at that block's expiry. It applies the cap before the
firewall snapshot and again before deciding each pick, since an earlier
pick can replace that address in the same turn. A shortened expiry must
still leave the firewall's minimum timeout; otherwise the return ends
uncharged without changing forecast occupancy or retaining an example.

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
with the same buckets; this build opens schemas 7 to 14 without rewriting
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
buckets; older builds refuse it. An ingress checkpoint carrying disabled
refusal counts also requires schema 10, even without a stored candidate.
A full outcome bucket, every key at its largest count, is now 32872 bytes
against a bound of 33 KiB.

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
each applied member's key and timed lifetime. Capacity is checked only at
apply: a check before reservation never answers set_full. Victim checks require
retained rows at the address to agree on action, expiry and verification.
An unreadable startup ledger disqualifies all victims; members can still use
free slots. The admission snapshot lists at most 256 imports, soonest
expiry first, then name: timed, verified rows a legacy automatic block
stamped, each alone at its kernel address with a proven element and named
by its raw row's `eff_` name. Mapped addresses share the canonical address;
a retained zoned alias also disqualifies an import. A lone zoned row stays
unlisted and unclaimed. The imported occupancy count still includes
unlisted stamped occupants, so a bounded victim list cannot free capacity.
A member whose
victim, the admission block or import the ledger claimed, still has that row, name,
expiry and proven element takes the victim's slot if the resulting set fits the current limit: the same
transaction deletes the victim's element, and only a readback of the victim's set
proves it removed; a member whose removal is unproven is unknown, even
with its own add read back. A victim that no longer qualifies is spared
and its member needs a free slot. A victim with no more than the batch's
minimum lifetime left at the send is spared and its member fails set_full
alone, since its expiry in the kernel would reject the whole transaction.
A victim removed by other means before the send rejects the whole
transaction with ENOENT, which fails its members like any rejection. The victim's row stays until the owner retires it
after the ledger records the outcome, so a restart before then restores
the victim. Retirement removes an evicted import's row by its `eff_` name
only while the stamped row still matches it. An operator or unstamped row
is never retired under an import name. Definitive kernel rejection
restores state; uncertain exchanges retain unknown rows. Unknown rows are
marked unverified and excluded from counts and seeding. Expiry retains them
until the owner retires the matching attempt. A failed state
write is returned as a state-integrity error and retains live suppression
until a successful state write; later batches refuse while that error is
held. The admission owner must reconcile action-linked rows before startup
or any downgrade to a build that ignores their verification fields.
The retry marker for a kernel rejection requires a successful state restore.
Marking with no action IDs still writes the safe state to release a state hold.
`RemoveBlockActionRows` removes, in one state write, the rows the ledger has
settled (failed, retired after expiry, or evicted with proven removal).
An error reports no completed removal, including a durability failure after
rename. Startup calls it after marking every unproven row, with the settled subset
`store.ReadSettledBlockActions` returns, so a start that stops between the two
leaves the rows held back and the next start removes them: it asks the ledger
about every saved action, including rows an earlier start held back and
other actions sharing their addresses. An expired row no start marked is never
restored and is left to expiry, so it holds back no other block at its
address. The engine selects those rows on its lease clock, retaining that
reading through Apply so a backward wall-clock step cannot restore an
unchecked action. Marking preserves those separate rows until cleanup can
remove only the settled actions. Removing a hold therefore cannot restore
an unchecked action or erase another block.
The engine's kill-point tests stop a batch around its intent write, kernel
batch, readback, unknown marking and rejected-state restoration, then start
the ledger and a new engine over the same state, after a process restart or
after a reboot that empties the kernel. Around an eviction they also stop
before the outcome and before the victim's row is retired: until the ledger
records the eviction a restart restores the victim and holds the block
back. After a committed eviction an admission victim's row goes and only
the block is restored. An import has no startup cleanup record: after a
committed eviction, a restart before row retirement restores both blocks
until the import's original expiry, including after a reboot. An unreadable ledger restores
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
A row an admission action wrote belongs to the owner: an automatic legacy
block of its address ends as already blocked, even when the row is unproven
or its element is gone, never evicts it at the temporary cap, and permanent
promotion refuses it (`ErrAdmissionOwnsBlock`). Operator blocks, unblocks,
allows, flushes and undo keep their authority over it. This build does not execute admission batches; the guard also protects any
action rows already present in restored state.
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
engine checks every member against one snapshot before anything is reserved. An
address a row or element holds without proof defers a member;
a block the engine proves already holds the address ends it linked to that
block, and an invalid or protected address or a spent lifetime ends it, all
without a charge. If the ledger refuses that link (no history budget for
it), the pick stays queued with the deferral reason and the rest of the
batch runs; the next check tries again. Each member carries the victim its
reservation claimed, as its intent names it, and the ledger records what the
batch did to that victim with the member's outcome. Whole-batch failures,
short replies and delayed outcome writes keep the victim and lease clock
information. Once a verified eviction is recorded, the owner marks an
admission victim's row and retires it, as startup
does, rotating failed or held rows behind waiting rows and retrying on
later turns, including while waiting for an absent engine during dry run.
Cleanup follows the retirement policy, respects state-repair probe waits
and preserves independent apply faults. Its errors remain
visible alongside unknown-attempt retirement errors; a restart
removes the row before the firewall restores its state. The turn hands the
ledger the imports the set read listed. Clearing that set also clears its
imports, including a failed read, an idle turn or entry into dry run.
Returning to previews reads a fresh set and import list. The dry-run
forecast reads the list from its own snapshot and may replace a listed
import, which it remembers by name until the import's expiry; it never
claims one.
An import's row is retired by its
`eff_` name without a mark. An import-only retirement still retries a
shared state repair after its probe wait, without marking any import or
clearing an independent apply fault, including during dry run.
An import still enforced at retirement (a reload or restart restored its
row) is forgotten. An error or short retirement answer
keeps the request for retry; no ledger record names an evicted
import, so a restart before its retirement restores it until its own
expiry. After an unknown
outcome the victim's row stays until the victim expires. A proven block
found only when the batch applies is checked again when the outcome is written.
With a fresh proof the pick ends refused as an existing effect, linked to
the block, keeping its charge. A member with a victim records its eviction
outcome before attempting that link; a member without one records its
failure and link in one write. Without a fresh proof, or if the link write
fails, the attempt still records its failure. If the outcome cannot be
saved, execution waits for the pending write; a crash before it is saved
leaves an unknown attempt. After a successful write the ordinary bounded
retry or the next check decides. On the
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
again a minute later; any other fault, such as a failed write, retries that
attempt after one second, doubling to a minute. A
missing or unreadable attempt uses the same wait without preventing other
attempts from retiring. An unreadable intent list delays the whole pass.
Each fault is reported once, in `admission.owner.retirement_error` and the
doctor row `admission retirement`, until no attempt, list read or engine
retirement check is left faulted; no retirement fault fails a turn. A stop
between the row removal and the ledger retirement leaves a
row-less unknown that the next pass retires. The turn wakes for the earliest
expiry or monotonic retry. With one noted, a turn lists no intents until it
is due; with none noted, every turn lists them. A turn that fails after its
retirement pass fails with its own step's error. It never rebases a retry on
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
and member refusals until an applied effect proves recovery. Its probe is one
member: every pick is checked and refusals end, but only the first accepted
pick is reserved and applied, and the rest wait untouched for the batch after
it applies. An isolated retry does not narrow these probe checks; it still
runs alone if selected. An apply-confirmed firewall window holds the engine's member
checks, batches, probes and retirements (`ErrConfirmPending`) from before its
snapshot until it is confirmed or rolled back, so its rollback cannot erase a
block the owner wrote inside it; a batch in flight finishes first and lands in
the snapshot. A restart with a window pending holds them before the owner sees
the engine, until startup recovery settles the window. A window opened between
member checks and apply also holds execution, but is not an apply fault:
after it ends, a successful snapshot probe clears that hold even on an idle
turn. Any earlier apply fault still needs a successful one-member apply.
The read-only
admission snapshot of a forecast still answers. A kernel rollback alone
does not release the hold when the saved engine configuration is unreadable;
the confirmation remains pending until recovery succeeds or the operator
confirms it. Keep its state snapshot through partial recovery, so another
rollback restores the same state even after intervening legacy writes.
Failed marker removal keeps the hold. Once the marker is gone,
the hold and recovery fault clear even if snapshot cleanup fails; that error
is still reported. Hold changes copy
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
waits. Before the next live batch may start, a turn selects nothing and
leaves the next selection due. Clock or engine outages still defer waiting
blocks without spending fair turns or running early probes; work already
deferred for capacity keeps its reason. Dry-run
forecasts and previews without an engine keep their own cadence.
The policy installed at the turn boundary decides whether the batch wait
applies; changing between live execution and dry run does not spend a turn
that cannot select work. During a batch wait, opt-outs end silently before
any outage is reported. Outage deferrals revalidate waiting work first, so
expired evidence and changed ownership keep their own terminal reasons.

The first time an owner executes (only in tests while `liveExecution` is
false), its live start runs once per ledger, in one transaction, before
anything is drained or served under that policy: every drain and turn reads
the clock first, and the reading runs the live start. It charges the legacy
hour as the greater of its count and the charges the ledger already retains
in that hour, since previews and legacy blocking count the same responses;
earlier preview charges stay as handover charges with their lane, cost and
release times, so a later forecast cannot refund them. It counts each
pending entry legacy blocking would still retry as refused for attribution,
since none carries an observation. It ends the episode answers of earlier
observe previews, so the next observation of a previewed address queues a
new generation, or a new episode when no other candidate kept the old one;
challenge previews and verified blocks keep their answers. It clears the
notice records raised while admission previewed, so none goes out as a live
alert or delays a key's first live notice. The sender discards the preview
delivery retry delay once it sees that committed start; later live delivery
failures keep their own backoff. The start also makes the previews' history
eligible at once. Until it runs, an executing owner delivers no ledger
notice; with execution enabled the sender reads the mode and the due notices
together, and an acknowledgement taken before the live start never covers a
record raised after it. It writes schema 11, which earlier builds refuse,
and leaves `blocked_ips.json` in place. A legacy state file it cannot read
keeps no saved credit, and `admission.owner.import.error` names the error.
A failed live start fails the turn, reload or drain that ran it, and a
failed tick or drain closes admission. A failed live-start tick reports its
cause through `tick_error` and the stopped-admission notice until a later
tick succeeds. The import error describes a committed handover: an aborted
transaction does not replace it, and later startup retries do not erase it.

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

The policy also carries whether the configuration still allows each queued
response: `checks.AutomaticResponseAllowed`, the switches the legacy funnels
test before they act (`auto_response.enabled` and `block_ips` for every
firewall kind, `block_cpanel_logins` for the checks that need it, and each
derived entry's own opt-in; challenges follow challenge routing). Under a
valid policy, a pick it no longer allows ends refused as `disabled` before
any panel ask, engine check, forecast, preview or reservation, live or dry
run. Most of these switches change only with an epoch; challenge, incident
and central settings change only at a restart, which is why every pick is
tested rather than every epoch.

Disabled responses end together before capacity selection, including
challenge previews. Spent ceiling or history budgets, retry backoff and
another attempt's recovery hold do not delay their refusal or generate
capacity notices. The check visits only the bounded durable queue and
leaves allowed work's scheduling turns and capacity checks intact. Refusing
queued work never releases an earlier attempt's charge or recovery hold.
Startup and ceiling reload also refuse disabled work before inventory or
queue revalidation can report expired evidence as a withheld response.

Under a dry-run policy the owner forecasts instead of running. It selects
work with `SchedulePreview`, whatever the live budgets, and ends each pick
as a dry run with a prediction: no attempt, charge, history, audit row or
mutating engine call. A forecast session starts at startup or on entry into
dry-run from the committed ceiling and its retained charges
(`ForecastSeed`), then lives in memory apart from it: the same committed
clock meters it, a new limit applies without new credit, and live credit is
never copied over it. The seed leaves out the charges of observe previews,
which are comparison work, not responses: their units leave the window and
their credit returns to its lane up to the bucket's cap (`Uncharge`);
legacy and genuine charges stay. Ceiling, charges and keyed attempts come
from one read-only transaction. Each retained attempt's charge must match
its reservation time, lane and response cost; damaged records refuse the
seed without changing committed state. While the owner forecasts, the
ledger also stops counting a preview as the answer of its block line
(`PreviewsAnswer`), so an address previewed before the session queues its
next generation on a new observation and is forecast; a verified block,
or its remembered answer, still answers until its expiry, and challenge
lines keep following their previews. Leaving dry run turns previews back
on. One
read-only admission snapshot answers a turn's `block_ip` picks, with the
real temporary occupancy and the real blocks of forecast addresses. A
refused target ends or waits as a live check has it. A real block that
covers the address predicts `existing_actual`, unlinked; a forecast block
that lasts as long, within the readback slack a real block is allowed,
predicts `existing_shadow` and a shorter one `pending_recovery`, and
neither is renewed. Other picks are checked against
the modelled temporary capacity, the bound on forecast blocks and the
modelled ceiling, and only `capacity_admit`, `capacity_evict` and
`capacity_rotate` add a forecast block and a simulated charge. The model
budgets slots with the ledger's rule (`SetOccupancy.Limits`): with no free
slot a pick may take the first strictly lower-tier forecast block or listed
import in eviction order and predicts `capacity_evict`. Forecast blocks
rank by their pick's tier and next attempt; one without a tier is never
replaced. Each records its pick's scope and the admission time and session
elapsed time of its decision. Once the general partition is full, the
session shares each partition as a live ledger does: among the scopes of
its forecast blocks the real sets do not hold, the scopes of the turn's
block picks and the requester's, from session cursors that each such turn
moves once before its first pick. A fresh pick may then rotate out a
forecast block of exactly its tier by the same rule as the ledger, once
that block's hold passed on the admission clock and the session's metered
elapsed time, and predicts `capacity_rotate`. Fresh means the ledger's
episode row says so (`AdmissionLedger.Fresh`, which needs no live start)
and no forecast block of the address left the model before that block's
expiry: a replaced or rotated forecast block leaves the model and answers
its address until then (spec 5.2). Active forecast blocks and retained
answers share the existing modelling bound; when it fills, an otherwise
funded pick predicts `forecast_limited`. Answers expire only at their
recorded boundary, never to free space for new predictions. A pick that finds no room while a
lane's partition holds a scoped block of exactly its tier at another
address predicts `equal_tier_wait`; other full sets predict `set_full`.
Real admission blocks count in occupancy but in no scope. A replaced
import is remembered by name until its expiry and subtracted only while
the engine still lists it.
With the verdict callback on, a pick the model would
judge is asked about first and waits for its answer with no forecast
change; a usable allow ends it as `verdict_allow` before any modelled
capacity is judged, and a covering forecast block, or a full modelled set
with nothing lower to replace and nothing to rotate, ends it without a call. Other firewall kinds end as `not_modelled`, with no
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

Each committed `capacity_admit`, `capacity_evict` or `capacity_rotate` leaves one example in
`dry_run_blocks`. A
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
check would have it, all without a call. Room is the ledger's: it
schedules a pick only on a free slot or a victim it can claim.
Any other pick is asked about, as `CSM auto-block: <check>` for its
canonical address, and stays queued; the schedule passes it over until
the answer arrives. Workers, outstanding jobs and cached answers are bounded;
a full stage leaves picks queued and is never read as an answer. Each answer
is keyed by candidate, attempt and policy epoch and expires from completion,
including time awaiting receipt. Admission uses the configured signature
and replay validation, including explicit signing exceptions, through the
same client as legacy blocking. A valid allow ends the pick as one
`verdict_allow` refusal with no attempt or charge,
even with the ceiling spent: the schedule picks it as uncharged work.
Block, an empty verdict or a failed exchange continues the local path,
and the reservation consumes the answer. Local checks run again before an
answer is used. A pick that stops being eligible has its call cancelled.
A new epoch, a mode change included, cancels every call, drops every
answer and starts new workers only after the old ones return; Stop
cancels the calls and joins the workers. A cancellation is never an
answer. The owner status carries a `verdict` object for an owner with an
engine provider: stage gauges, process counters and the last failure as a fixed
class, never response text. Its outstanding jobs are also the
`admission.verdicts` queue row. Workers count completed calls before delivery;
late or duplicate results cannot count another call or consume a different job.

The admission ledger exposes two row-recovery reads. `ReadSettledBlockActions`
names failed attempts, retired unknown outcomes and verified blocks later
evicted by a proven removal among the supplied action IDs.
`ReadUnprovenBlockActions` includes every non-verified attempt and those
evicted blocks. `UnresolvedIntents` gives the owner the same ordered intents
as the handle-free startup reader. Callers must inspect each attempt's outcome:
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

Keys should be snake_case. Values should be machine-parseable (numbers, strings, booleans) -- avoid formatted strings when you can pass the raw value. Pass paths and errors as they are: the text handler quotes and escapes any value with whitespace, a quote or a control character, so a value quoted beforehand is escaped twice.

### Migrating legacy call sites

Migration is incremental and optional. The legacy format stays valid. Start with the hottest subsystems (alert dispatch, firewall operations, WAF handlers) where structured fields provide the most value, then work outward. Do not batch-convert -- each subsystem should get a dedicated commit with before/after log samples in the PR description.

Keep the `[TIMESTAMP]` prefix of journalctl lines readable by humans: slog's text handler uses `time=... level=... msg=...` which is also human-parseable, so journalctl viewers still work.

## Worker processes

Code that parses attacker-controlled input and can loop, crash or exhaust
memory runs in a child process under `internal/workerproc`. The daemon can
kill a child; it cannot stop a stuck goroutine.

The launcher gives the child one Unix socket as both fd 0 and fd 1. A frame
is a 4-byte big-endian length followed by a JSON envelope, and it may carry
descriptors. The length is checked against a cap before anything is
allocated. Passing a descriptor never calls `Fd()`, so the caller's pipe keeps
its nonblocking mode and deadlines. Request descriptors are duplicated before
launch, and the caller may close its files once a call returns.

A request that misses its deadline kills and reaps the worker, and that
worker is never used again. Any other round-trip failure does the same, and
its error matches `workerproc.ErrWorkerFailed` with its text unchanged. Three
failures in a row pause spawning for 60 seconds, then one trial request is
let through. Each supervisor publishes a `requests` queue-health row.

`workerproc.FailureReason` classifies counted failures as `timeout`,
`protocol`, `crash`, `oom`, or `spawn`, including through wrapped errors.
Malformed frames and rejected descriptors are protocol failures; a broken
socket is a crash unless the process reports an OOM kill. The daemon cannot
read a unit worker's kill from the unit's own cgroup: by the time it sees the
worker die, systemd has removed that cgroup and its counters. On cgroup
v2 each supervisor uses its own slice, and the slice's `memory.events`,
which counts its children's kills and outlives them, is compared with its
value at start. Before that snapshot, startup waits for any previous unit's
cgroup to disappear, bounded by `StartTimeout`: a reaped `systemd-run` client
alone does not prove its service has exited. Standalone CLI scans include
their process ID in the prefix to keep their slices distinct.
On v1 that counter is not hierarchical, so an eventfd on
`memory.oom_control` reports the kill as it happens; OOM and removal
notifications are counted together even when they arrive in separate reads,
and a single notification with the directory gone remains undecided until the
watch closes after the client's exit. Diagnostic text
and underlying errors remain unchanged. A failed start matches `ErrSpawn`,
not `ErrWorkerFailed`.

`Config.OnFailure` receives each counted failure while the supervisor lock
is held. The callback must return promptly and must not call back into the
supervisor. `Stats.Kills` counts these failures by reason, including failed
starts, and returns an independent snapshot. Cancellation, stopped or
breaker refusals, and local descriptor exhaustion before the round trip
do not reach the hook or these counters.

`Config.OnJob` receives one outcome for every request that reached the
breaker: `ok` with the worker's memory use after the job (0 when unknown),
a failure reason, or `refused` when the breaker turned the request away. It
runs under the same lock and rules as `OnFailure`. Cancellation, a stopped
supervisor and local descriptor exhaustion are not reported. The daemon
feeds it into the `csm_parse_worker_*` metrics.

Some errors are not worker failures and never count toward the breaker:

- caller cancellation, including during launch; a canceled trial restarts
  the breaker cooldown;
- the daemon running out of descriptors (EMFILE or ENFILE) while duplicating
  request descriptors or starting a child. The request counts as lost work,
  but the healthy worker stays. Outside load can push the daemon to its
  descriptor limit, and that must not switch a worker off;
- PHP parser panics reported in a valid reply, which count as lost requests
  but do not replace the worker.

`Config.BreakOnSpawnOnly` narrows the breaker to failed starts. The mail
parse workers set it: a refused extraction delivers mail unscanned under
`fail_mode: open`, so crafted mail that kills workers must not open the
breaker for unrelated messages. Each message then costs at most one spawn.
Every successful start resets the failed-start count, even if that worker
then fails on its input or the caller cancels the request.

A known limit: when the daemon is at its descriptor limit, the kernel drops
descriptors a reply carries. That looks the same as a worker sending too
many, so it counts as a worker failure, classified as a crash rather than a
protocol violation.

`Config.MaxJobs` retires a worker after that many requests, and
`Process.Retire` lets a launcher retire one after a request, for example over
a memory threshold. `Config.IdleTimeout` stops a worker left unused; the idle
countdown restarts only after a served request and never stops a worker in
the middle of one. Retirement keeps the reply and is not a failure. Both
settings default to zero; the PHP taint worker leaves them at those defaults.

`workerproc.Handshake` sends `hello` and checks the child's protocol version
before any real request. It honors cancellation and the context deadline,
refuses reply descriptors and clears the socket deadline before returning.

`workerproc.Strikes` remembers inputs that made a worker fail. Two failures
within 24 hours block an input, for at most 1,024 inputs; `NewStrikesWith`
sets another limit and window, each failure within the window of the one
before. The phishing check keys it by the zip's SHA-256 and reports a blocked
zip with the `phishing_kit_archive_unscannable` warning instead of retrying
it on every scan. The spool watcher keys it by Exim message ID, and counts
kills per message source with a limit of three in ten minutes.

Worker diagnostics must go to stderr; stdout carries the protocol socket. The
PHP taint worker (`csm phptaint-worker`) runs through `UnitLauncher` as
`csm-phptaint-worker-<generation>`, with the parse worker's lockdown and a
512 MiB memory cap. The YARA workers run through it too; the section below
describes them.

### Parse worker units

The archive parse worker (`csm parse-worker`) runs through `UnitLauncher`:
each worker is a transient systemd unit started with `systemd-run --pipe`,
named `csm-parse-worker-<slot>-<generation>`, with the properties listed in
[service confinement](service-confinement.md). There is no fallback to
running it directly. The daemon installs one lazy zip lister, using slot
`zip0`, before scans start. It publishes `archive_list.requests` and is
stopped during daemon shutdown. The worker retires after 1,000 requests or
ten idle minutes. Each archive RPC has a 30-second timeout; unit startup has
a separate ten-second timeout, and reaping can take another ten seconds.

After the hello exchange, before an archive request, the launcher checks
that the worker's main PID is in that unit's own memory cgroup, reads back
the RAM cap, caps swap, and reads current usage. On cgroup v1 it caps memory
and swap together, or sets swappiness to zero where there is no swap
accounting. On cgroup v2 it
disables swap; without swap accounting it requires a host with no active
swap. A missing cgroup, a cap that does not read back, unreadable counters,
or usage already over the cap fail the start. Process RSS polling cannot
replace this: it misses memfd pages and other processes in the unit.

A watchdog reads the cgroup counters every 500 ms and kills a worker over its
cap, or whose usage cannot be read. It skips a tick when the daemon itself
runs out of descriptors (EMFILE or ENFILE). Memory kills are identified by
the watchdog or the unit's cgroup OOM counter; a missing or unreadable
counter alone is not evidence of an OOM kill.

A worker over three quarters of its cap after a request is retired. Units
also retire at three quarters of their lifetime cap. The supervisor checks
retirement before reusing an idle
worker, as well as after a request, so expired workers get no new input.
Kill closes the socket at once and asks systemd
to kill the unit by name; it never signals a PID and never blocks. The daemon
attempts to kill leftover `csm-parse-worker-*` units at startup, with a
30-second timeout. Cleanup failures are logged; lister initialization still
proceeds. Disabling scheduled phishing checks does not disable cleanup or
archive listings for requested account scans.

The worker gets an open zip descriptor, never a path, and reads it with
positional reads, so the daemon's file offset stays put. It returns entry
names in a memfd it seals against writes, growth and shrinkage. The daemon
treats every reply byte as hostile: it checks the seals, then the size, every
record and the entry count, before the visitor sees one name. Records are
charged against the request's directory budget, never a size the worker
reports. A malformed reply kills the worker and matches
`workerproc.ErrWorkerFailed`. An archive the worker could not read reports
itself incomplete, without counting as lost work. A worker can still leave
names out; validating the reply does not verify the archive. Name
classification stays in `internal/checks`.

`workerproc.Pool` holds a fixed number of supervisors, one per slot, and
`Call` names the slot. The mail extractor (`parseworker.Extractor`, op
`extract_message`) sizes its pool from `email_av.scan_concurrency` and names
units `csm-parse-worker-mail<slot>-<generation>`. The worker writes each
non-empty attachment to a memfd sealed against writes, growth and shrinkage.
A reply carries at most 200 parts. Names, content types and archive names are
cut to 255 bytes, the partial reason to 512, and From, Subject and each of at
most 100 recipients to 998.

The mail extraction API accepts open spool header and body descriptors.
Spool event descriptors are close-on-exec so worker launch commands cannot
inherit queued messages.
Its reply must be one UTF-8 JSON object with a `parts` field, which may be
null for an empty result. Each part must have a readable, sealed descriptor
of the claimed size. Individual sizes and their total must fit the request's
limits without integer overflow. Invalid replies discard all parts and kill
the worker with reason `protocol`. The spool watcher extracts every message
through it: each scan goroutine owns one worker slot, because parts are
charged to the memory cgroup of the worker that wrote them. A failed
extraction becomes a partial result naming the failure, never an error.
Watcher replacement waits for the previous scan goroutines to finish before
reusing their slots. On shutdown, queued spool events release their
descriptors without starting extractions. The daemon waits for active scans
and watcher restarts to finish before stopping or clearing the parse pools.
If a panic unwinds the daemon before shutdown is signalled, cleanup skips
that wait so the process can exit. Extractor lookup and removal share the
watcher lifecycle lock because a replacement may still be starting.

Unit tests use temporary proc and cgroup trees, never the host's. The kernel
tests in `internal/workerproc/unit_kernel_test.go` run real units as root on
the CI kernel runner.

## YARA-X Worker Process

By default CSM never compiles or scans YARA rules in the root daemon. Two
kinds of `csm yara-worker` process run through `workerproc.UnitLauncher`
with the parse worker's lockdown: no root, no network, no account files, a
memory cap and a lifetime cap. Wiring lives in
`internal/daemon/yara_backend.go`; the daemon side is `yaraworker.Backend`
in `internal/yaraworker/backend.go` and the worker side `yaraworker.Serve`
in `internal/yaraworker/worker.go`.

- The compile unit, `csm-yara-compile-worker-<generation>`, runs for one
  compile: 1 GiB memory cap, files up to 256 MiB (its reply), five-minute
  unit lifetime. The daemon allows two minutes for the compile request.
  The daemon reads the rule files (trust check, disabled-rule stripping)
  and passes their text in one sealed memfd. The worker compiles with
  includes disabled, so rule text comes only from that memfd, and returns
  `Rules.WriteTo` output in a sealed memfd. The daemon copies it into its
  own sealed memfd and keeps it.
- The scan unit, `csm-yara-worker-<generation>`, is a single worker: memory
  cap 512 MiB plus the larger of `thresholds.full_scan_max_file_mb` and, with
  mail scanning on, `email_av.max_attachment_size`, read from the live config
  at each launch; no file writes, 24 hour lifetime. Before the supervisor may send it a scan, the launcher
  loads the kept rules into it. A restart loads them again and never
  recompiles: 55 ms for the shipped rules, about 3.4 s for Forge full.
- Both units run with `MemoryDenyWriteExecute=no`
  (`UnitConfig.AllowExecutableMemory`): wasmtime maps the compiled rules
  executable, and with the denial the load fails as "invalid YARA-X
  compiled rules file". No `RLIMIT_AS` is set; the cgroup cap is the limit.
- A reload compiles in a new compile unit. On success the new rules replace
  the kept ones, the scan worker on the old rules retires before its next
  request, and a background warm-up starts its replacement. On failure the
  current rules stay; with none loaded the failure is `CompileError()`.
  Compiles run one at a time; a canceled startup retry stops waiting even
  when a rule update is already compiling.
- Forge downloads are compile-tested in the compile unit before they are
  installed. If the merged reload afterwards fails because the compile unit
  could not run, the new tier stays on disk, its version is not recorded,
  and a Critical `yara_backend_unavailable` finding says so; only rules that
  do not compile, or a collapsed rule count, roll the tier back.
- At startup the daemon attempts to kill leftover units of both prefixes;
  cleanup failures are logged without preventing startup.

Failures and findings:

- The backend is active from boot, before the first compile. While no rules
  are loaded because a compile failed or could not run, every scan returns
  an error, never a clean result.
- The boot compile runs before the daemon reports ready to systemd, so it is
  bounded to 45 seconds. A compile that cannot start, crashes, times out or
  outlives that bound is retried in the background with backoff; when the
  boot attempt and three retries have failed, a Critical
  `yara_backend_unavailable` finding fires.
- Rules that do not compile raise Critical `yara_worker_compile_failed` and
  are not retried. So does a rule set the compile unit cannot fit: more than
  1024 rule files (refused before a unit starts), an out-of-memory kill under
  the 1 GiB cap, or compiled rules over 256 MiB. Each message names
  `signatures.yara_worker_enabled: false`, which compiles in the daemon.
- Any counted scan worker failure (failed start, timeout, crash, out of memory,
  protocol) marks `watcher: yara_worker` failed and raises Critical
  `yara_worker_crashed`, at most once a minute after the last alert; an
  attached worker is killed.
  The next request starts a replacement; a served request marks the watcher
  attached again.
- Only failed starts count toward the worker breaker (`BreakOnSpawnOnly`),
  so content that kills the worker costs one restart per scan and cannot
  switch YARA off for other files. The backend keeps `workerproc.Strikes`
  by SHA-256 of exactly the bytes sent for scanning. Content with two scan
  worker failures within a day is refused as a scan error without starting
  another worker. The check and failure recording run under the
  supervisor's request lock (`Supervisor.CallGuarded`), so queued copies
  see the failures ahead of them. A failure is recorded against the rules
  the worker actually loaded, even if a reload lands while it starts.
  Failed starts, cancellation, breaker refusals and descriptor pressure do
  not strike content. Hashing runs only while an unexpired strike is
  recorded or to record a new failure. Records expire a day after the last
  failure and a successful rule reload clears them. The list holds at most
  1024 content hashes, evicting the oldest failure when full.

`signatures.yara_worker_enabled: false` runs YARA-X inside the root daemon
instead; `csm validate` warns about it.

Wire contract (workerproc frames on the unit's socket pair):

| Op | Request descriptors | Reply |
|---|---|---|
| `hello` | 0 | protocol version |
| `compile` | 1: rule texts back to back, named and sized by `sources` | `rule_count` and a sealed memfd of compiled rules, or `compile_error` and no descriptor |
| `load` | 1: compiled rules | `rule_count` |
| `ping` | 0 | `rule_count` of the loaded rules |
| `scan_fd` | 1: content, read positionally up to `max_bytes` | `matches`, always an array |

Malformed requests get an error frame, which kills the worker. A rule compile
error is a result, never a worker failure, and its text is cut to fit the
frame. Scans need a regular descriptor and every requested byte; the worker
gets its own read-only open of a file. Byte scans travel as sealed memfds, so
the frame cap does not limit them. With no rules, or every rule disabled,
byte scans answer clean without a worker unless compilation failed, and
mail-part scans fail.

Testing: `internal/yaraworker` launches the test binary as the worker with a
fake engine (`helper_test.go`), including fault modes for crashes, hung loads
and bad compile replies. Tests tagged `yara` run the real engine, including
backend recovery from invalid rules with disabled rules still excluded. Unit
lockdown is verified on the CI kernel runner and on scratch hosts.

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

The [attack replay corpus](attack-corpus.md) gate runs the same way and gates the same jobs.

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

Attack replay payloads are decoded in memory before checking. Every data
file in a sample directory is decoded regardless of its suffix; `.b64`
files are decoded elsewhere in the attack corpus test data too. Manifests,
corpus-root notes and saved Go fuzz seeds are checked as plain text.
Invalid base64 fails the check, and diagnostics never print decoded content.

### Admission preview ledger

Admission previews reserve, charge history and capacity, and end observed in one transaction. They write both audit steps, never execute a response, never count as applied, and do not end the evidence episode or raise a notice. Repeated evidence is answered until its quiet window closes.

Imported legacy usage retains its accounting-window charge after an attempt is retired. Retirement of old attempt history cannot create new admission capacity before that window closes.

The scheduler records only ceiling, history-budget and recovery-reserve deferrals, once per changed reason. Fair turns, member bounds and retry backoff produce no deferral; a cleared budget reason produces no new gap notice. Challenges spend fair turns and history without spending block credit, and bounded durable holds preserve the earned turn of charged work while challenges proceed.

The owner schedules queued preview work on its timer and uses the next ledger wake even when no new arrival appears. Reloads recompute that wake under the current ceiling. A first attempt lasts the legacy-selected lifetime, or the configured response's, never longer than `auto_response.block_expiry` (spec 5.6): an executable owner reads it from the policy of the epoch, an owner without an engine from the current configuration, and a policy without a positive one is refused. Retries keep that absolute expiry. The owner observes each pick transactionally and continues delivery retries independently of scheduling. A refused preview ends only its own queued work, so an invalid expiry cannot starve other picks; a storage failure retries the turn, twice at once and then after waits that double up to a minute, as a held probe is, and shows as `admission.owner.turn_error` and the doctor row `admission turns` rather than a stopped owner.

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
