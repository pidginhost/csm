# Clean application corpus

The required `test:clean-corpus` job downloads the public vendor ZIP archives in
`scripts/clean-corpus/manifest.json`. The manifest pins the version, official
HTTPS source, SHA-256, license file, and exact regular-file count. Archives are
cached, rechecked before extraction, and unpacked into a new private directory
on every run. Missing input, checksum mismatch, missing license, empty or
incomplete inventory, unsafe archive entries, and read failures stop the job.
No downloaded PHP or JavaScript is executed.

The initial corpus contains 10,178 files: WordPress 6.8.2 (GPL-2.0-or-later),
WooCommerce 9.9.5 (GPL-3.0-or-later), and Elementor 3.29.2 (GPL-3.0-only).
The archives retain their license notices, including notices for bundled
components. These are fixed test versions, not installation recommendations.
Source URLs and license file locations are in the manifest.

Run the same gate locally with the Go toolchain from `go.mod` and the matching
YARA-X C library installed:

```bash
bash scripts/clean-corpus-test.sh
```

The script compares the installed C library version with both the Go binding
and production builder pins. It runs YARA, YAML signatures, PHP taint, and
JavaScript taint gates. Ordinary unit tests may omit external corpus inputs;
the required job sets `CSM_CORPUS_REQUIRED=1`, so missing input is fatal.
Package publication and GitHub releases explicitly depend on the job.

`corpus-results/` is retained for one year, including on failures:

- `manifest.json` identifies the authenticated archives and licenses.
- `inventory.json` lists every extracted file, its size and SHA-256.
- `engines.txt` records the commit, toolchain, YARA-X and parser versions.
- Engine JSON reports include counts, per-rule hits including zeroes,
  thresholds, and taint status counts. `tests.jsonl` records execution.

YARA and both taint engines require zero findings. YAML retains the existing
reviewed false-positive budgets in `internal/signatures/corpus_fp_gate_test.go`;
new rules default to zero. The pinned corpus currently produces 10 YAML hits
across five rules, all within those existing budgets. This is a regression
gate, not a claim that every engine has zero false positives.

The signature engines apply the production default 16 MiB bound and archive
admission policy; 10,157 inputs reach each engine. PHP taint reads 10,171 inputs
within its source limit, including 163 that complete analysis. JavaScript
admission receives all 10,178 files and completes analysis on 289; seven are
oversized and twelve have parse errors. These JavaScript gaps have explicit
ceilings in the required gate; canceled, resource-limited and panic outcomes
have a zero ceiling. Neither oversized nor unparsed inputs count as proof of
successful analysis. The required taint gates each need at least 100 completed
analyses as well as their corpus inventory checks.

To update the corpus, download a versioned archive from its official source,
review its license and file inventory, and commit the new manifest pin with
the measurements. Investigate new matches and narrow detectors using content
semantics. Do not add scan-path exclusions or raise budgets to pass a run.
The gate also compiles deliberately overbroad YARA and YAML rules and verifies
that their clean-file matches are rejected.
