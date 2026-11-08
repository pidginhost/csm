# Attack replay corpus

The required `test:attack-corpus` job plants known attack samples and
near-miss controls in a temporary cPanel account and runs them through the
three production paths that read files: realtime analysis, the scheduled deep
tier and the operator full account scan. Each path applies its own production
responders. The job fails when a path stops catching a sample, catches it at a
lower severity, flags or changes a control, remediates differently, or starts
catching a recorded gap. Package publication and GitHub releases depend on it.

Unit tests prove that a detector works on the input it was written for. The
corpus proves that the whole path still works: admission, path scoping,
severity, quarantine eligibility and the responders. A change that breaks a
detector end to end fails here even when every unit test passes.

The corpus measures file content only. Log and event replay and expected
incidents are later stages.

## The three paths

Every sample runs alone, with its own account tree, cPanel domain map, state
store, quarantine directory and monitor. The platform is pinned to cPanel, the
layout the samples use. The config is the shipped `configs/csm.yaml` template
with auto-response and file quarantine turned on and observe mode off, and
nothing else changed. Both signature engines load the shipped rules from
`configs/`. A partial rule load, an empty rule set or a scan error fails the
gate.

- **Realtime.** The driver builds the file monitor without fanotify, opens
  each planted file and derives its event path the way the event loop does.
  The file then goes through the production admission filter and, when
  admitted, through `analyzeFile`. A file the filter drops counts as not
  detected. The driver drains the dropper tracker and the staged package queue
  at once instead of waiting for their timers. Remediation is the inline
  quarantine that `analyzeFile` performs.
- **Deep tier.** The driver runs the file checks of the deep tier through the
  production runner, `runParallelWithContext`, so the runner's responders act
  on the findings as they do in production. Every deep check is classified as
  a file check or a host check (network, database, mail, packages). Host
  checks do not run. A test fails when a new deep check has no
  classification, so it cannot stay out of the gate unnoticed. Before planting,
  the driver runs the tier once on the empty account tree with the same state
  store. Findings that name no planted file and also appeared in that empty run
  are dropped as host noise. No check or path is allowlisted.
- **Full scan.** The driver runs the account scan with the options that
  `csm scan <account> --full --quarantine` uses, then the scan job's
  quarantine loop. That loop ignores the auto-response settings, as it does in
  production.

The tier and the full scan run PHP taint analysis in-process. Production runs
it in a separate worker, which has its own tests.

## Offline

The run never reaches the network. Requests through the default HTTP
transport are refused. On the two scan paths, database queries get an empty,
successful answer for a synthetic site, and host commands fail as a missing
program would. The realtime WordPress checksum fetcher is stopped. Refused
requests, database queries and `wp` runs are counted per sample and appear in
the report as `network_attempts`. A sample whose verdict depends on such a
lookup says so in its description.

## Sample format

Samples live in `internal/attackcorpus/testdata/corpus/<category>/<name>/`.
Each directory holds a `sample.json` and the base64 content files it names.
Content is base64 at rest and decoded only in memory or under a test's
temporary directory, because endpoint antivirus deletes decoded web shells
from a checkout.

`sample.json` fields:

- `name`: unique across the corpus.
- `category`: one of `webshell`, `dropper`, `malicious_plugin`,
  `credential_stealer`, `injected_js`, `phishing_kit`, `spam_script`,
  `persistence`, `binary`, `archive`.
- `kind`: `malicious` or `control`.
- `source`: `synthetic`, `fixture` or `real`.
- `description`: one line on what the sample is. It also names any policy,
  shortfall or offline lookup that explains its expectations.
- `provenance`: where the content came from. For a fixture, the test it was
  taken from and how the planted shape differs; for a synthetic sample,
  `written for the corpus`.
- `files`: each with `path`, account-relative (`public_html/...`) or
  `@crontab` for the account's crontab; exactly one of `b64` (a file beside the
  manifest, ending in `.b64`) or `selftest` (a sample from the
  [self-test](self-test.md) bundle); and an optional `mode`. JSON has no
  octal, so `0755` is written `493`.
- `expect`: one entry for each of `realtime`, `tier` and `fullscan`:
  - `findings`: each with `check`, `file` (a planted path) and
    `min_severity` (`warning`, `high` or `critical`). Every listed finding
    must arrive at that severity or above. Extra findings are reported, not
    failed.
  - `gap`: why this path misses the sample. Exclusive with `findings`.
  - `remediation`: per planted file, `quarantined`, `cleaned` or `untouched`.
    A file left out is expected untouched. `cleaned` needs the SHA-256 of the
    cleaned bytes in `cleaned_sha256`. The deep tier and the full scan clean a
    WordPress core, plugin or theme file in place, instead of moving it, when
    a Critical quarantine-eligible finding names it. A plugin or theme file
    with a known web shell name is quarantined instead. Such a sample expects
    `cleaned` on those paths, or `untouched` when the cleaner finds nothing
    to remove.

A missing file counts as quarantined only when a quarantine entry names its
path, or a parent directory's, and the retained copy matches the original
bytes. A damaged entry is an error. A file that disappears with no entry is
reported as `removed`, which no manifest may expect. A file whose bytes
changed is `cleaned`.

All files of a sample are planted before the first one is replayed. Manifest
order is not write order, so a sample whose verdict depends on the order of
writes is judged on the final tree.

Every self-test bundle sample is referenced exactly once, so the bundle and
the corpus cannot drift apart.

## Adding a sample

1. Write or decode content only in a temporary directory that your
   antivirus excludes, never in the checkout. Commit only the `.b64` file.
2. Add files by explicit path. Never run `git add -A` or `git add .`: an
   antivirus that deletes a decoded file leaves a deletion for the next commit
   to pick up.
3. Public samples follow the public repository rules: documentation IP
   addresses only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
   `2001:db8::/32`), `example.com`, `example.net` or `example.org` hosts, and
   no real names, accounts, domains, mailboxes or credentials. This applies to
   names, descriptions and provenance as well as content.
4. `make check-fixtures` decodes every corpus data file and scans it for
   addresses and private names. It decodes one layer only. A payload nested
   inside the sample, such as base64 inside PHP, a compressed blob, an archive
   member or a `String.fromCharCode` list, needs a manual check of the same
   rules before commit.
5. Write the expectations from what the sample is (see below), then run the
   gate. `TestPublicCorpusLoads` in the default test job loads the public
   corpus and checks category coverage, so a malformed manifest fails there
   first.

## Expectation rules

Judge each expectation from what the sample does. A run may draft the
findings, but every expected finding and severity must match what the attack
deserves, not what the detector happens to report today, except a recorded
severity floor (below).

- **Gaps.** A malicious sample that a path misses records a gap with the
  specific reason: which check misses which shape. A gap is a measurement, not
  an exemption. When a detector starts catching a recorded gap, the gate fails
  with `gap closed:` until the manifest replaces the gap with the finding. A
  finding that names no planted file but quotes an admitted file in its text
  counts too. Files rejected by admission cannot close a gap.
  Closing a gap is a corpus edit in the same change as the detector fix.
- **Never weaken an expectation.** Do not delete a sample, lower a
  `min_severity`, turn a finding into a gap, or change an expected remediation
  to make the gate pass. A regression is fixed in the detector or the
  responder. Never allowlist a path or name to make a sample pass.
- **Explicit policy.** Where production deliberately leaves a detected file in
  place, because the check is not on an explicit quarantine list or the
  responder is off in the shipped config, the path expects `untouched` and the
  description names the policy. When the policy changes, the expectation
  becomes `quarantined` in the same change.
- **Severity floors.** When a path detects a sample below the severity the
  attack deserves, `min_severity` records the observed level and the
  description names the shortfall. The gate then stops the severity from
  dropping further, but does not raise it.
- **Remediation shortfalls.** When a detector heuristic, not an explicit
  policy, leaves a file in place that should move, the expectation records the
  observed remediation and the description names the shortfall.

## Controls

Every category needs at least one malicious sample and one control, or the run
fails. A control is the legitimate file a detector for that category is most
likely to confuse: a cPanel MultiPHP handler in `.htaccess`, an inline base64
image, a vendored phar, a capability-checked upload handler. A control expects
no findings and `untouched` on every path, and cannot carry a gap.

Any finding on a control's file fails the gate, including a file the realtime
admission filter dropped. A finding that names no planted file but quotes a
control's path is a false positive. Any other unattributed finding on a
control is an error.

## Failures

Each failure in the report and the test log starts with its kind:

| Prefix | Meaning |
|---|---|
| `missed:` | An expected finding did not arrive. |
| `severity:` | An expected finding arrived below its `min_severity`. |
| `false positive:` | A control drew a finding. |
| `remediation:` | A planted file ended quarantined, cleaned, untouched or removed other than expected. |
| `gap closed:` | A path caught a sample recorded as a gap on it. |
| `error:` | The driver did not complete for this sample, or a control drew a finding that names no planted file. |

A run also fails before its first sample when a corpus cannot load, a category
lacks a malicious sample or a control, a self-test sample is not referenced
exactly once, or an engine did not load. A test filter that excludes a sample,
a driver that stops early, a check that panics, times out or reports partial
coverage, and a failed quarantine all fail the sample.

Driver errors appear in the test log by type only, unless
`CSM_ATTACK_CORPUS_SHOW_ERRORS=1` is set (see below). Reports carry check
names, severities, planted paths and verdicts, never sample content or finding
text, because either can quote decoded bytes.

## Measurement limits

What the corpus does not measure yet:

- No driver replays program execution, so YARA scans of programs started from
  a document root (`docroot_binary_exec`) are not measured.
- No driver replays the critical tier, so the crontab check is not measured
  on the scheduled path.
- The daemon's batch responders (permission fix, database malware response,
  companion sweep queueing, WP-Cron fix) are not driven. Realtime remediation
  is the inline quarantine only, and the tier stops at the runner's
  responders. In production, realtime findings also reach the batch process
  kill and file quarantine. Verdicts agree today because the only realtime
  check on the batch quarantine list, `signature_match_realtime`, passes the
  same high-confidence gate there as inline. A realtime check added to that
  list would change production remediation without the gate seeing it.
- `supply_chain` cannot fire: a fresh install has no advisory file.
  `group_writable_php` cannot fire: planted files belong to the test user's
  group, not a web server group.
- `cleaned` is not exercised: the `.htaccess` cleaner is off by default, the
  full scan skips `.htaccess` and crontab findings, the crontab fix is
  operator-only, and no sample draws a Critical quarantine-eligible finding on
  a file both scan paths clean in place (see `remediation` above).
- The throttled performance file checks run once per sample, in the second
  tier run only. A tier run that skips any check fails the sample.
- The full scan quarantine step is a copy of the scan job's loop. A change to
  that loop must be mirrored in the driver.
- Realtime does not admit `.js` or `.phar` files, so those controls are not
  exercised on that path.

## Running it

Run the gate in the release builder image, the one `CSM_BUILDER_IMAGE` and
`CSM_BUILDER_TAG` name in `.gitlab-ci.yml`:

```bash
GO_LINUX_RUNTIME=docker GO_LINUX_IMAGE=<release-builder-image> \
  scripts/go-linux.sh bash scripts/attack-corpus-test.sh
```

The script checks that the YARA-X C library matches the Go module and the
active builder pin exactly, then runs every `TestAttackCorpus` test in the
harness, daemon and checks packages with `-tags yara`. It writes to
`attack-corpus-results/`, which the job keeps for one year, including on failure:

- `realtime.json`, `tier.json`, `fullscan.json`: per sample results and a
  per-category summary (detected, gaps, missed, false positives, closed gaps,
  remediation mismatches, errors). The script fails if any is empty.
- `engines.txt`: Go version, YARA-X version, commit and run time.
- `tests.jsonl`: the `go test -json` event stream.

The output directory and its report files are open only to their owner,
including when the script reuses an existing directory. The script does not
change the umask, so under the usual 022 the drivers create files with the
modes the daemon gives them. CI artifact access still follows the project's
artifact permissions.

Environment:

- `CSM_ATTACK_CORPUS_REPORT_DIR` requests a run and names the report
  directory. Without it the corpus tests skip.
- `CSM_ATTACK_CORPUS_REQUIRED=1` turns that skip into a failure. The script
  sets both.
- `CSM_ATTACK_CORPUS_PRIVATE` adds a second corpus in the same format. It must
  load and hold at least one sample.
- `CSM_ATTACK_CORPUS_SHOW_ERRORS=1` logs the full reason of a driver error
  instead of its type. Local runs only: a reason can quote decoded sample
  bytes, and CI keeps test logs as artifacts. The report script unsets it,
  including when inherited from the caller.

The other `TestAttackCorpus` tests check the drivers themselves, on their own
samples, and need no report directory.
