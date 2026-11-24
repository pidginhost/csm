# Self-test

`csm selftest` scans a bundle of samples whose verdicts are known and reports what the installed rules catch. It reads no account data and writes nothing, so it is safe to run on a production host. Run it to see what the rules detect before you point the scanner at real sites.

```bash
csm selftest
csm selftest --json
```

## Exit status

The exit status is 0 when every sample matched what the bundle records, for each available engine. It is 1 when anything needs attention. These fail the run:

- A rule load that is incomplete or empty.
- A scan error.
- An invalid sample.
- An empty bundle.

A build without YARA-X can pass its realtime checks. It then reports explicitly that YARA coverage was not tested.

## Which rules it measures

The command uses the configured rules directory and the disabled-rule list, for both engines. Disabling a detection can turn a sample into `MISSED`.

A missing or unreadable configuration fails the command. CSM does not fall back to the full packaged ruleset, because the host may not run it. Pass `--config` and `--config-dir` when the daemon uses custom paths.

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

The summary counts missed samples, false positives, closed gaps and errors separately. A skipped engine has no sample results. The JSON output gives the reason in its `skipped` field.

If the configuration disables every rule in an engine, the command still measures that engine's samples. It reports zero loaded rules and the misses that follow, and exits with failure. Missing or malformed rule files are still load errors.

## Engines

CSM ships two rule sets, and the command reports each separately:

- `realtime` is the set of YAML rules the real-time watchers use.
- `yara` is the set of YARA-X rules that scheduled and email scanning use.

The `yara` engine is present only in builds compiled with YARA-X. A build without it reports `SKIPPED` with a reason. A compiled engine whose rules cannot load fails the command.

## What the bundle contains

The bundle holds adversarial samples and benign controls in one list. The controls decide whether a rule set is usable: a scanner that flags an ordinary WordPress plugin is worse than one that misses a shell.

Samples are stored base64-encoded and decoded only in memory. Endpoint antivirus deletes files that look like web shells, so a decoded copy on disk would make the bundle disappear from the machine it is meant to test.

Two samples need a note:

- The split-assert sample represents legacy PHP string assertions, not PHP 8 behavior.
- The chr-built sample constructs a callable command-execution function. The test suite checks that it is callable without running its payload.

## Known gaps are recorded, not hidden

A known gap is an adversarial sample the shipped rules do not catch, written down in the bundle as a measurement. The test suite fails when a gap opens and also when one closes. A rule change that starts catching a recorded gap breaks the build until the bundle is updated. So no gap can quietly become permanent, and no improvement goes unnoticed.

A gap is a gap **in the signature engines**. This bundle does not measure CSM's other layers:

- PHP taint analysis.
- The behavioral checks.
- PHP Shield.
- The correlation that turns findings into incidents.

A sample listed as a known gap may still be caught in production by one of these layers.

## Details

This section is reference material for developers who change the rules or the bundle.

The regular CI test job runs the realtime gate. The required `test:production` job runs `scripts/production-tests.sh portable`. That script includes all packages with the `yara,journal,bpf` tags and the pinned YARA-X library, so it runs the YARA bundle gate too. Tagged builds and lint alone do not execute that test.

To measure the bundle locally, install PHP CLI for the fixture validity check, then run:

```bash
go test -count=1 ./internal/selftest
go test -count=1 -tags yara ./internal/selftest
```

The second command requires the pinned YARA-X library. The untagged command does not measure YARA detection.
