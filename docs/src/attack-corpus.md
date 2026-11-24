# Attack replay corpus

The attack replay corpus is a set of known attack samples and near-miss controls. The required `test:attack-corpus` job plants them in a temporary cPanel account and runs them through the three production paths that read files: realtime analysis, the scheduled deep tier and the operator full account scan. Each path applies its own production responders. Package publication and GitHub releases depend on the job.

The job fails when a path does any of these:

- It stops catching a sample.
- It catches a sample at a lower severity.
- It flags or changes a control.
- It remediates differently.
- It starts catching a recorded gap. A gap is a recorded reason why one path misses one sample.

Unit tests prove that a detector works on the input it was written for. The corpus proves that the whole path still works: admission, path scoping, severity, quarantine eligibility and the responders. A change that breaks a detector end to end fails here even when every unit test passes.

The corpus measures file content only. Log and event replay and expected incidents are later stages.

## Running it

Run the gate in the release builder image, the one `CSM_BUILDER_IMAGE` and `CSM_BUILDER_TAG` name in `.gitlab-ci.yml`:

```bash
GO_LINUX_RUNTIME=docker GO_LINUX_IMAGE=<release-builder-image> \
  scripts/go-linux.sh bash scripts/attack-corpus-test.sh
```

The script first checks that the YARA-X C library matches the Go module and the active builder pin exactly. It then runs every `TestAttackCorpus` test in the harness, daemon and checks packages with `-tags yara`.

### Reports

The script writes to `attack-corpus-results/`, which the job keeps for one year, including on failure:

- `realtime.json`, `tier.json` and `fullscan.json` hold per sample results and a per-category summary: detected, gaps, missed, false positives, closed gaps, remediation mismatches and errors. The script fails if any of the three is empty.
- `engines.txt` holds the Go version, YARA-X version, commit, the private corpus line (see [Private half](#private-half)) and run time.
- `tests.jsonl` holds the `go test -json` event stream.

Reports carry check names, severities, planted paths and verdicts. They never carry sample content or finding text, because either can quote decoded bytes.

The output directory and its report files are open only to their owner, including when the script reuses an existing directory. CI artifact access still follows the project's artifact permissions.

The script does not change the umask. Under the usual 022 the drivers therefore create files with the modes the daemon gives them.

### Environment

- `CSM_ATTACK_CORPUS_REPORT_DIR` requests a run and names the report directory. Without it the corpus tests skip.
- `CSM_ATTACK_CORPUS_REQUIRED=1` turns that skip into a failure. The script sets both.
- `CSM_ATTACK_CORPUS_PRIVATE` adds the private half, a corpus checkout in the same format. It must load and hold at least one sample.
- `CSM_ATTACK_CORPUS_PRIVATE_REQUIRED=1` fails the run when `CSM_ATTACK_CORPUS_PRIVATE` or `CSM_ATTACK_CORPUS_REPORT_DIR` is not set, instead of skipping. The script sets it in CI.
- `CSM_ATTACK_CORPUS_SHOW_ERRORS=1` logs the full reason of a driver error instead of its type. Use it for local runs only: a reason can quote decoded sample bytes, and CI keeps test logs as artifacts. The report script unsets it, including when inherited from the caller.

The `TestAttackCorpus` tests that do not replay the corpus check the drivers themselves, on their own samples, and need no report directory.

## The three paths

Every path uses the same setup:

- Every sample runs alone, with its own account tree, cPanel domain map, state store, quarantine directory and monitor.
- The platform is pinned to cPanel, the layout the samples use.
- The config is the shipped `configs/csm.yaml` template with auto-response and file quarantine turned on and observe mode off, and nothing else changed.
- Both signature engines load the shipped rules from `configs/`.

A partial rule load, an empty rule set or a scan error fails the gate.

### Realtime

The driver builds the file monitor without fanotify. It opens each planted file and derives its event path the way the event loop does. The file then goes through the production admission filter and, when admitted, through `analyzeFile`. A file the filter drops counts as not detected.

The driver drains the dropper tracker and the staged package queue at once instead of waiting for their timers.

Remediation is the inline quarantine that `analyzeFile` performs.

### Deep tier

The driver runs the file checks of the deep tier through the production runner, `runParallelWithContext`. The runner's responders therefore act on the findings as they do in production.

Every deep check is classified as a file check or a host check (network, database, mail, packages). Host checks do not run. A test fails when a new deep check has no classification, so it cannot stay out of the gate unnoticed.

Before planting, the driver runs the tier once on the empty account tree with the same state store. Findings that name no planted file and also appeared in that empty run are dropped as host noise. No check or path is allowlisted.

### Full scan

The driver runs the account scan with the options that `csm scan <account> --full --quarantine` uses, then the scan job's quarantine loop. That loop ignores the auto-response settings, as it does in production.

### PHP taint analysis

The tier and the full scan run PHP taint analysis in-process. Production runs it in a separate worker, which has its own tests.

## Offline

The run never reaches the network:

- Requests through the default HTTP transport are refused.
- On the two scan paths, database queries get an empty, successful answer for a synthetic site.
- On the two scan paths, host commands fail as a missing program would.
- The realtime WordPress checksum fetcher is stopped.

Refused requests, database queries and `wp` runs are counted per sample and appear in the report as `network_attempts`. A sample whose verdict depends on such a lookup says so in its description.

## Sample format

Samples live in `internal/attackcorpus/testdata/corpus/<category>/<name>/`. Each directory holds a `sample.json` and the base64 content files it names.

Content is base64 at rest. It is decoded only in memory or under a test's temporary directory, because endpoint antivirus deletes decoded web shells from a checkout.

### Manifest fields

`sample.json` fields:

| Field | Meaning |
|-------|---------|
| `name` | Unique across both halves of the corpus, public and private. |
| `category` | One of `webshell`, `dropper`, `malicious_plugin`, `credential_stealer`, `injected_js`, `phishing_kit`, `spam_script`, `persistence`, `binary`, `archive`. |
| `kind` | `malicious` or `control`. |
| `source` | `synthetic`, `fixture` or `real`. |
| `description` | One line on what the sample is. It also names any policy, shortfall or offline lookup that explains its expectations. |
| `provenance` | Where the content came from. For a fixture: the test it was taken from and how the planted shape differs. For a synthetic sample: `written for the corpus`. |
| `files` | The files to plant. See [Planted files](#planted-files). |
| `expect` | One entry for each of `realtime`, `tier` and `fullscan`. See [Expectations for a path](#expectations-for-a-path). |

### Planted files

Each entry in `files` has:

- a `path`, either account-relative (`public_html/...`) or `@crontab` for the account's crontab,
- exactly one of `b64` (a file beside the manifest, ending in `.b64`) or `selftest` (a sample from the [self-test](self-test.md) bundle),
- an optional `mode`. JSON has no octal, so `0755` is written `493`.

All files of a sample are planted before the first one is replayed. Manifest order is not write order, so a sample whose verdict depends on the order of writes is judged on the final tree.

Every self-test bundle sample is referenced exactly once, so the bundle and the corpus cannot drift apart.

### Expectations for a path

An `expect` entry never holds both `findings` and `gap`.

| Key | Meaning |
|-----|---------|
| `findings` | Each has `check`, `file` (a planted path) and `min_severity` (`warning`, `high` or `critical`). Every listed finding must arrive at that severity or above. Extra findings are reported, not failed. |
| `gap` | Why this path misses the sample. |
| `remediation` | Per planted file: `quarantined`, `cleaned` or `untouched`. A file left out is expected untouched. `cleaned` needs the SHA-256 of the cleaned bytes in `cleaned_sha256`. |

### Which remediation to expect

Whole-file malware expects `quarantined`. An injected site file expects `cleaned`, or `untouched` when the cleaner refuses the removal.

The deep tier and the full scan clean a WordPress core, plugin or theme file in place, instead of moving it, when a Critical quarantine-eligible finding names it. They quarantine the file instead in these cases:

- It is a plugin or theme file with a known web shell name.
- Cleaning would leave it empty with no page output.
- Its core or plugin release does not ship it.

### How the gate reads what happened to a file

A missing file counts as quarantined only when a quarantine entry names its path, or a parent directory's, and the retained copy matches the original bytes.

| What the driver finds | Verdict |
|-----------------------|---------|
| A damaged quarantine entry | An error. |
| A file that disappeared with no entry | `removed`, which no manifest may expect. |
| A file whose bytes changed | `cleaned` |

## Adding a sample

1. Write or decode content only in a temporary directory that your antivirus excludes, never in the checkout. Commit only the `.b64` file.
2. Add files by explicit path. Never run `git add -A` or `git add .`: an antivirus that deletes a decoded file leaves a deletion for the next commit to pick up.
3. Follow the public repository rules for public samples. See [Rules for public samples](#rules-for-public-samples).
4. Run `make check-fixtures`. It decodes every corpus data file and scans it for addresses and private names. Check nested payloads by hand, as described in [Nested payloads](#nested-payloads).
5. Write the expectations from what the sample is (see [Expectation rules](#expectation-rules)), then run the gate.

`TestPublicCorpusLoads` in the default test job loads the public corpus and checks category coverage, so a malformed manifest fails there first.

### Rules for public samples

Public samples follow the public repository rules:

- IP addresses come only from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).
- Hosts are `example.com`, `example.net` or `example.org`.
- No real names, accounts, domains, mailboxes or credentials appear.

This applies to names, descriptions and provenance as well as content.

### Nested payloads

`make check-fixtures` decodes one layer only. A payload nested inside the sample needs a manual check of the same rules before commit. Examples are base64 inside PHP, a compressed blob, an archive member or a `String.fromCharCode` list.

## Expectation rules

Judge each expectation from what the sample does. A run may draft the findings. Every expected finding and severity must still match what the attack deserves, not what the detector happens to report today. The one exception is a recorded [severity floor](#severity-floors).

### Gaps

A malicious sample that a path misses records a gap with the specific reason: which check misses which shape. A gap is a measurement, not an exemption.

When a detector starts catching a recorded gap, the gate fails with `gap closed:` until the manifest replaces the gap with the finding. Closing a gap is a corpus edit in the same change as the detector fix.

Whether a finding closes a gap depends on what it names. Only the first two kinds below close it:

| Finding | Effect on a gap |
|---------|-----------------|
| On a planted file | Closes the gap. |
| Names no file but quotes an admitted planted file in its text | Closes the gap. |
| On a directory or other path | Reported as an extra finding. |

Files rejected by admission cannot close a gap.

### Never weaken an expectation

Do not do any of these to make the gate pass:

- delete a sample,
- lower a `min_severity`,
- turn a finding into a gap,
- change an expected remediation.

A regression is fixed in the detector or the responder. Never allowlist a path or name to make a sample pass.

### Explicit policy

Production deliberately leaves some detected files in place, because the check is not on an explicit quarantine list or the responder is off in the shipped config. For such a file the path expects `untouched` and the description names the policy. When the policy changes, the expectation becomes `quarantined` in the same change.

### Severity floors

When a path detects a sample below the severity the attack deserves, `min_severity` records the observed level and the description names the shortfall. The gate then stops the severity from dropping further, but does not raise it.

### Remediation shortfalls

When a detector heuristic, not an explicit policy, leaves a file in place that should move, the expectation records the observed remediation and the description names the shortfall.

## Controls

A control is the legitimate file a detector for that category is most likely to confuse. Examples are a cPanel MultiPHP handler in `.htaccess`, an inline base64 image, a vendored phar and a capability-checked upload handler.

Every category needs at least one malicious sample and one control, or the run fails. A control expects no findings and `untouched` on every path, and cannot carry a gap.

| Finding during a control's run | Result |
|--------------------------------|--------|
| Any finding on the control's file, including a file the realtime admission filter dropped | Fails the gate. |
| A finding that names no planted file but quotes the control's path | A false positive. |
| Any other unattributed finding | An error. |

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

Driver errors appear in the test log by type only, unless `CSM_ATTACK_CORPUS_SHOW_ERRORS=1` is set (see [Environment](#environment)).

### Failures before the first sample

A run fails before its first sample in these cases:

- A corpus cannot load.
- A required private half is not set.
- A private sample reuses a public sample's name.
- A category lacks a malicious sample or a control.
- A self-test sample is not referenced exactly once.
- An engine did not load.

### What fails a single sample

- A test filter excludes the sample.
- A driver stops early.
- A check panics, times out or reports partial coverage.
- A quarantine fails.

## Private half

Real attack samples, scrubbed of customer data, live in a private GitLab project in the same format, with `<category>/<name>/` at the project root. The project comes from the `CSM_ATTACK_CORPUS_PROJECT` CI variable. It must allow this project's CI job token to read it.

This repository pins the private commit in `internal/attackcorpus/private.commit`: one line holding the full 40-character lowercase commit hash. Moving the pin is a reviewed public commit.

### What CI does before the tests

In CI the script does the following before any test runs. Any failure stops the job.

1. It fails when `CSM_ATTACK_CORPUS_PROJECT` is unset or the pin file is missing or malformed. The pin accepts one full lowercase hash, with or without a single final newline. This check runs before any clone or checkout.
2. It clones the project with the CI job token into a new temporary directory. See [The private clone](#the-private-clone).
3. It checks out the pinned commit and fails unless `HEAD` is exactly that commit, so a short hash or a ref name fails.
4. It runs `scripts/fixturecheck -corpus -require-terms` over the checkout. Every file is scanned for IPv4 addresses outside the documentation ranges and for the private terms in the `CSM_PRIVATE_TERMS` file variable. Sample data is decoded first, one layer deep, as in the public check.
5. It sets `CSM_ATTACK_CORPUS_PRIVATE` to the checkout and `CSM_ATTACK_CORPUS_PRIVATE_REQUIRED=1`, so the tests fail rather than run without the private half.

### The private clone

The temporary directory is open only to its owner and sits outside the checkout and its artifacts. A temporary directory inside the checkout or reports is rejected. The clone is removed on success or failure, including a failed clone.

A credential helper reads the token from the environment. The token therefore never appears in a command line, a URL or the clone's git config, and no configured helper can store it. The helper serves only the exact project on the CI server over HTTPS, and Git refuses redirects.

### Local runs

Outside CI nothing is cloned and the private half is not required. A local run uses the public half alone unless `CSM_ATTACK_CORPUS_PRIVATE` names a checkout.

`engines.txt` records which private half ran:

| Run | Line in `engines.txt` |
|-----|-----------------------|
| CI, pinned commit | `private corpus: <commit>` |
| Local, with `CSM_ATTACK_CORPUS_PRIVATE` | `private corpus: local, unpinned` |
| Local, public half alone | `private corpus: none` |

### Rules for the private half

The coverage rules apply to the public half alone. The private half must load without validation errors and hold at least one sample. Sample names are unique across both halves.

Reports and test logs print sample names and planted paths. Private samples therefore follow the public naming rules for both: no real names, accounts, domains or mailboxes.

## Details

This section is reference material.

### Measurement limits

What the corpus does not measure yet:

- No driver replays program execution, so YARA scans of programs started from a document root (`docroot_binary_exec`) are not measured.
- No driver replays the critical tier, so the crontab check is not measured on the scheduled path.
- `supply_chain` cannot fire, because a fresh install has no advisory file.
- `group_writable_php` cannot fire, because planted files belong to the test user's group, not a web server group.
- Realtime does not admit `.js` or `.phar` files, so those controls are not exercised on that path.
- The throttled performance file checks run once per sample, in the second tier run only. A tier run that skips any check fails the sample.
- The full scan quarantine step is a copy of the scan job's loop. A change to that loop must be mirrored in the driver.
- The daemon's batch responders are not driven. See [Batch responders are not driven](#batch-responders-are-not-driven).
- The `cleaned` remediation is not exercised. See [`cleaned` is not exercised](#cleaned-is-not-exercised).

### Batch responders are not driven

The daemon's batch responders are not driven: permission fix, database malware response, companion sweep queueing and WP-Cron fix. Realtime remediation is the inline quarantine only, and the tier stops at the runner's responders.

In production, realtime findings also reach the batch process kill and file quarantine. Verdicts agree today because the only realtime check on the batch quarantine list, `signature_match_realtime`, passes the same high-confidence gate there as inline. A realtime check added to that list would change production remediation without the gate seeing it.

### `cleaned` is not exercised

The `cleaned` remediation is not exercised, for these reasons:

- The `.htaccess` cleaner is off by default.
- The full scan skips `.htaccess` and crontab findings.
- The crontab fix is operator-only.
- No sample draws a Critical quarantine-eligible finding on a file both scan paths clean in place (see [Which remediation to expect](#which-remediation-to-expect)).
