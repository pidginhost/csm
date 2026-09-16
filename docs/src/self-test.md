# Self-test

`csm selftest` scans a bundle of samples whose verdicts are known and reports
what the installed rules catch. It reads no account data and writes nothing, so
it is safe to run on a production host, and it answers the question an
evaluator actually has before pointing a scanner at real sites.

```bash
csm selftest
csm selftest --json
```

Exit status is 0 when every sample matched what the bundle records for each
available engine, and 1 when anything needs attention. Incomplete or empty rule
loads, scan errors, invalid samples and an empty bundle fail the run. A build
without YARA-X can pass its realtime checks, but explicitly reports that YARA
coverage was not tested.

The command uses the configured rules directory and disabled-rule list for
both engines. Disabling a detection can turn a sample into `MISSED`. A missing
or unreadable configuration fails the command rather than measuring a full
packaged ruleset that the host may not run. Pass `--config` and `--config-dir`
when the daemon uses custom paths.

## What the bundle contains

Adversarial samples and benign controls, in one list. The controls are the half
that decides whether a rule set is usable: a scanner that flags an ordinary
WordPress plugin is worse than one that misses a shell.

Samples are stored base64-encoded and decoded only in memory. Endpoint
antivirus deletes files that look like web shells, and a decoded copy on disk
would make the bundle disappear from the machine it is meant to test.

The split-assert sample represents legacy PHP string assertions, not PHP 8
behaviour. The chr-built sample constructs a callable command-execution
function; the test suite checks that it is callable without running its payload.

## Reading the output

| Verdict | Meaning |
|---|---|
| `detected` | An adversarial sample the rules caught. |
| `clean` | A benign control the rules left alone. |
| `known gap` | An adversarial sample the shipped signature rules do not catch, recorded in the bundle. |
| `MISSED` | An adversarial sample that should have been caught and was not. A regression. |
| `FALSE POSITIVE` | A benign control the rules fired on. |
| `GAP CLOSED` | A recorded gap that now fires. Good news; the bundle needs updating. |
| `ERROR` | The sample could not be decoded or scanned. The error is printed below it. |

The summary counts missed samples, false positives, closed gaps and errors
separately. A skipped engine has no sample results; JSON reports the reason in
its `skipped` field.

If configuration disables every rule in an engine, the command still measures
its samples, reports zero loaded rules and the resulting misses, and exits with
failure. Missing or malformed rule files remain load errors.

## Known gaps are recorded, not hidden

A gap is a measurement, and the test suite fails when one closes as well as
when one opens. A rule change that starts catching a recorded gap breaks the
build until the bundle is updated, so no gap can quietly become permanent and
no improvement goes unnoticed.

A gap is a gap **in the signature engines**. CSM's other layers -- PHP taint
analysis, the behavioural checks, PHP Shield, and the correlation that turns
findings into incidents -- are not measured by this bundle. A sample listed as
a known gap may still be caught in production by one of them.

## Engines

CSM ships two rule sets, and the command reports each separately:

- `realtime`, the YAML rules the real-time watchers use.
- `yara`, the YARA-X rules used by scheduled and email scanning. Present only in
  builds compiled with YARA-X; a build without it reports `SKIPPED` with a reason.
  A compiled engine whose rules cannot load fails the command.

The regular CI test job runs the realtime gate. The required `test:production`
job runs `scripts/production-tests.sh portable`, which includes all packages
with the `yara,journal,bpf` tags and the pinned YARA-X library, so it runs the
YARA bundle gate too. Tagged builds and lint alone do not execute that test.

To measure the bundle locally, install PHP CLI for the fixture validity check,
then run:

```bash
go test -count=1 ./internal/selftest
go test -count=1 -tags yara ./internal/selftest
```

The second command requires the pinned YARA-X library. The untagged command
does not measure YARA detection.
