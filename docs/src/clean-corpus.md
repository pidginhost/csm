# Clean application corpus

The clean application corpus is a pinned set of public vendor archives: WordPress, WooCommerce and Elementor. The required `test:clean-corpus` job downloads them and runs the detection engines over them. It is a regression gate for false positives on clean vendor code. Package publication and GitHub releases explicitly depend on the job.

No downloaded PHP or JavaScript is executed.

## Running the gate locally

Run the same gate locally with the Go toolchain from `go.mod` and the matching YARA-X C library installed:

```bash
bash scripts/clean-corpus-test.sh
```

The script compares the installed C library version with both the Go binding pin and the production builder pin. It then runs four gates: YARA, YAML signatures, PHP taint and JavaScript taint.

Ordinary unit tests can run without the downloaded corpus. The required job sets `CSM_CORPUS_REQUIRED=1`, so a missing corpus is fatal there.

## What the corpus contains

The initial corpus contains 10,178 files:

| Application | Version | License |
|-------------|---------|---------|
| WordPress | 6.8.2 | GPL-2.0-or-later |
| WooCommerce | 9.9.5 | GPL-3.0-or-later |
| Elementor | 3.29.2 | GPL-3.0-only |

The archives retain their license notices, including notices for bundled components. These are fixed test versions, not installation recommendations. Source URLs and license file locations are in the manifest.

## What the gate requires

| Engine | Requirement |
|--------|-------------|
| YARA | Zero findings. |
| PHP taint | Zero findings, and at least 100 completed analyses. |
| JavaScript taint | Zero findings, and at least 100 completed analyses. |
| YAML signatures | Hits stay inside the reviewed false-positive budgets in `internal/signatures/corpus_fp_gate_test.go`. New rules default to zero. |

The pinned corpus currently produces 10 YAML hits across five rules, all within those existing budgets. This is a regression gate, not a claim that every engine has zero false positives.

A second YAML check fails if any regex would be skipped on a corpus file it matches.

The gate also compiles deliberately overbroad YARA and YAML rules and verifies that their clean-file matches are rejected.

Both taint gates also need their corpus inventory checks to pass. [How many files each engine reads](#how-many-files-each-engine-reads) has the coverage numbers.

## Results the job keeps

`corpus-results/` is retained for one year, including on failures:

- `manifest.json` identifies the authenticated archives and licenses.
- `inventory.json` lists every extracted file, its size and SHA-256.
- `engines.txt` records the commit, toolchain, YARA-X and parser versions.
- Engine JSON reports include counts, per-rule hits including zeroes, thresholds, and taint status counts.
- `tests.jsonl` records execution.

## Updating the corpus

1. Download a versioned archive from its official source.
2. Review its license and file inventory.
3. Commit the new manifest pin with the measurements.
4. Investigate new matches and narrow detectors using content semantics.

Do not add scan-path exclusions or raise budgets to pass a run.

## The manifest

`scripts/clean-corpus/manifest.json` lists the archives. For each one it pins the version, the official HTTPS source, the SHA-256, the license file and the exact regular-file count.

Every source names the CMS it belongs to in a `cms` field. The manifest also lists each supported CMS that has no pinned source yet under `pending`, with the roadmap item that blocks it. The manifest, not this page, is the record of which CMS has a false-positive gate.

The manifest is version 2. The validator refuses:

- an older manifest version,
- a source without a CMS,
- a supported CMS that is neither sourced nor pending,
- a supported CMS that is both sourced and pending.

A database scanner for a new CMS therefore cannot ship without a corpus decision.

A pending entry only records that the corpus has no pinned source for that CMS yet. No scanner, admission rule, hit budget or result filter reads it, and files from that CMS are treated exactly as before on a server. When a source for a pending CMS lands, remove its pending entry in the same change.

## Details

This section is reference material for the download, the cache and the coverage numbers.

### Download and verification

Each archive is verified before it is extracted into a new private directory. The job stops on any of these:

- a failed download,
- a missing license,
- an empty or incomplete inventory,
- an unsafe archive entry,
- a read failure.

### The archive cache

Archives are cached under their checksum, so editing metadata or adding a source downloads only the new pins. A corrupt cache entry is replaced with a verified download. Unverified downloads never enter the reusable cache.

`CSM_CORPUS_ARCHIVE_CACHE` selects the cache directory. The tool reserves its `.csm-corpus-v1` subdirectory for checksum-named archives, temporary downloads and a persistent lock. Do not put other files in that subdirectory.

Cleanup only touches generated archive and temporary names in that subdirectory. It never touches ZIPs elsewhere in the configured directory, and never symlink targets. A symlinked managed directory is refused.

Concurrent preparations that share a cache fail with a busy error. Retry after the active run finishes.

Before fetching, the tool prunes interrupted downloads and managed archives whose pin is gone from the manifest. It does so even if preparation later fails. GitLab saves verified downloads and cleanup on failed jobs too, so retries retain progress without accumulating retired pins.

### Cache entries from older versions

Valid flat cache entries from older versions of the tool are verified and copied into the managed cache without downloading. Their originals are left untouched, because names alone cannot establish ownership. You may remove those old inputs once no older tool uses them.

### Offline manifest tests

Ordinary unit tests validate the manifest offline, including with `go test -trimpath`. Invalid metadata is rejected before cache, extraction or report files are created or changed.

Command tests check the full archived manifest and every inventory record. These checks do not replace the detector gate.

### How many files each engine reads

The signature engines apply the production default 16 MiB bound and archive admission policy. 10,157 inputs reach each signature engine.

PHP taint reads 10,171 inputs within its source limit, including 163 that complete analysis.

JavaScript admission receives all 10,178 files and completes analysis on 289. Seven are oversized and twelve have parse errors. These JavaScript gaps have explicit ceilings in the required gate. Canceled, resource-limited and panic outcomes have a zero ceiling.

Neither oversized nor unparsed inputs count as proof of successful analysis.
