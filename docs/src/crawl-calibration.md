# Crawl Detector Calibration

The distributed crawl detector judges each site and URL pattern over a window of minutes. It removes the heaviest clients, then asks whether the remaining traffic is both far above the pattern's usual rate and spread over enough distinct clients. Every one of those settings, and the memory bounds behind them, must come from what real hosts served, not from guesses.

Two tools turn copies of a host's access logs into that evidence without retaining raw visitor identities:

- `scripts/domlog-stream` converts log copies into an anonymized bundle.
- `scripts/crawl-calibrate` replays bundles through exact models of the detector and writes a report.

Pseudonymous recordings are still private.

## Status: synthetic data only

**The tools are for synthetic data only.** This revision validates bundles and certified coverage and replays them through chronological sessions. Bounded experiments with executable acceptance limits are not yet implemented.

Until those contracts pass their tests and independent review, do not:

- convert private recordings,
- delete preserved recordings on the strength of these outputs,
- use reports to choose detector settings.

Real-data collection and conversion then require separate operator approval.

## Converting logs

`scripts/domlog-stream` converts local copies of domlogs into an anonymized record stream. The following example is for synthetic fixtures only, from a clean committed checkout. Use absolute local log-copy paths in the inventory:

```bash
# RECORDING_DIR is a mode-0700 synthetic scratch directory outside the checkout.
# Set WINDOW_MINUTES from the synthetic grid; do not reuse a real recording salt.
go build -o "$RECORDING_DIR/domlog-stream" ./scripts/domlog-stream
"$RECORDING_DIR/domlog-stream" convert \
    --salt-file "$RECORDING_DIR/synthetic-salt" \
    --inventory "$RECORDING_DIR/inventory.json" --labels "$RECORDING_DIR/labels.json" \
    --bot-evidence "$RECORDING_DIR/bots.json" \
    --out "$RECORDING_DIR/host-a.records.jsonl.gz" \
    --volume-out "$RECORDING_DIR/host-a.volume.jsonl.gz" \
    --manifest "$RECORDING_DIR/host-a.manifest.json"
```

One conversion writes a bundle: a record stream, a volume stream and a manifest. The inputs are described below: the [inventory](#the-inventory), optional [bot evidence](#bot-evidence) and optional [labels](#labels).

Every line goes through the detector's own record parser and request identity rules, with the same canonicalization. Deployed log escaping and proxy semantics still need qualification before real recordings can be trusted.

### What a record keeps

A record keeps:

- the logged time and order,
- the status,
- whether the request is dynamic or an expensive query,
- the Referer class: none, malformed, cross-site or same-site,
- a claimed bot identity with its verified-bot proof class,
- an infrastructure flag,
- the operator's label.

No path, query value, address, user agent or Referer is written.

### What becomes a pseudonym

These become salted pseudonyms that keep equality and the site/pattern hierarchy:

- sites,
- accounts,
- client bindings (the full IPv4 address or the IPv6 /64),
- episode names,
- URL patterns.

Two distinct names that would share a pseudonym stop the conversion instead of being merged.

Sites and accounts use the same pseudonyms as [recorded finding streams](finding-streams.md) under the same salt, so the two can be joined.

### The volume stream

A volume stream counts lines and bytes per site and minute, including lines without a usable target or client.

## The inventory

The inventory names the recording period, each site's verified identity and its log copies:

```json
{
  "period": {"from": "2026-09-20T00:00:00Z", "to": "2026-09-27T00:00:00Z"},
  "sites": [
    {"name": "example.com", "account": "acct1",
     "aliases": ["example.com", "www.example.com"],
     "logs": ["/srv/crawl-recording/raw/example.com",
              "/srv/crawl-recording/raw/example.com-ssl_log.gz"]}
  ],
  "trusted_proxies": ["198.51.100.9"],
  "infrastructure": ["192.0.2.200"]
}
```

| Part | Rule |
|------|------|
| Period | Bounded by whole UTC minutes, `from` inclusive and `to` exclusive. It must have ended. |
| Site names and aliases | Lowercase DNS names without a terminal dot, at most 253 bytes each. |
| Hosts | One host belongs to one site. An alias listed twice or naming another site is refused. |
| Log paths | Use absolute paths. The tool also accepts a relative path, but resolves it against the directory it runs in, which ties the inventory to that directory. |

### File form

The inventory, labels and bot evidence files must be regular files, not symlinks, devices or FIFOs. They must be in their exact JSON form: every member spelled exactly and given once, no null values and nothing after the document.

### Aliases and Referers

Aliases decide which Referers count as same-site. A `www` host counts only when it is listed.

### Clients behind a trusted proxy

Behind a trusted proxy the client is the rightmost forwarded address only when the qualified proxy appends the original client there.

| Line | Counted as |
|------|------------|
| A proxied line without a usable forwarded address | Attribution loss. |
| A proxied line whose rightmost address is another trusted proxy (an unqualified second hop) | Attribution loss. |
| A line whose peer is not a plain address | An invalid client. |

None of these gets a client binding.

## Bot evidence

Verified-bot identity comes only from the host's own verified-bot list. The optional bot evidence file is an export of that list for the recording period. It holds the list's source revision and configuration digest, then published ranges and reverse-DNS verdicts. Each range or verdict is for one identity and valid from `from` (inclusive) to `to` (exclusive):

```json
{
  "format_version": 1,
  "d2_revision": "<40 or 64 hex digits>",
  "config_sha256": "<64 hex digits>",
  "proofs": [
    {"bot": "googlebot", "kind": "range", "prefix": "203.0.113.0/24",
     "from": "2026-09-20T00:00:00Z", "to": "2026-09-27T00:00:00Z"},
    {"bot": "googlebot", "kind": "dns", "addr": "192.0.2.60", "verdict": "positive",
     "from": "2026-09-20T00:00:00Z", "to": "2026-09-21T00:00:00Z"}
  ]
}
```

The `proofs` list is required. Use `[]` for an explicitly empty export.

### How a claimed identity is classed

The converter looks nothing up. It classes a claimed identity from the evidence file alone:

| Evidence | Proof class |
|----------|-------------|
| A range of that same identity held the client at the logged time | `range` |
| Otherwise, a verdict for that exact address | `dns` or `negative` |
| A user agent alone, another bot's range, an expired proof or contradictory verdicts | The claim stays unverified. |

The manifest records the evidence digest and its list revision. Bundle validation refuses a proof without that reference or a client binding.

### Bots verified by user agent only

A bot the host verifies only through operator-configured user-agent substrings (`reputation.verified_bots`) has no claimed identity here. Its requests are ordinary traffic in the bundle, and bot-label qualification must account for them separately.

## Labels

Labels are what the calibration measures detection delay and false positives against.

The optional labels file marks time ranges of a site as `attack` or `overload` (each with an episode name) or `healthy`. A rule can optionally apply only to a first path segment or a parameter-name prefix.

- Each rule requires nonzero RFC 3339 `from` (inclusive) and `to` (exclusive) timestamps.
- Matching preserves fractional seconds even though stream timestamps use whole Unix seconds.
- Prefixes match canonical query names, with ASCII letters lowercased and non-ASCII case preserved.
- The first matching rule wins, and anything else stays unlabeled.

## Handling real data

These rules are for later qualified real-data use. This prototype does not authorize it.

### Copying the logs

Nothing runs on the monitored host. The work follows this order:

1. After explicit collection approval, the operator copies the logs read-only into a private local directory (mode 0700).
2. Run the tool.
3. Review coverage against those copies and independently recorded handler/logging liveness.
4. Let the operator delete the approved copies.

Take each copy no earlier than the end of the recording period plus the lateness bound, so requests that complete after the last minute are already written. When a copy was taken earlier, exclude the minutes it cannot vouch for as `partial_minute`.

Streams, labels, inventories and reports stay outside the repository.

### The salt

The salt is created on first use with mode 0600 and must stay private. Reuse the finding-stream salt so the streams join.

### The identity registry

The identity registry records every site, account and episode pseudonym the salt has issued, as keyed digests. It refuses a later bundle whose different name would take one. It is locked while a conversion runs.

Keep one identity registry per salt, in the salt's directory. The tool derives its filename as `registry-<salt SHA-256>.json`, using the full lowercase hex digest of the salt bytes.

Optional `--registry FILE` must name that same file. Another filename or directory is refused, even with `--new-registry`. Directory symlink aliases are accepted.

| Situation | What to do |
|-----------|------------|
| The run creates the salt | Nothing. The run starts the registry. |
| The salt exists but never had a registry, such as the finding-stream salt | Pass `--new-registry` on the first conversion only. It is refused once a registry exists. |
| The registry is missing and you pass no flag | The run stops. It does not start an empty registry that would forget issued pseudonyms. |
| An earlier tool wrote a custom registry filename | Stop conversions. Move that registry and its lock to the derived names before reusing the salt. |

Do not start an empty registry to replace existing history.

Back up the salt, registry and persistent `.lock` file together, and restore them together. Never remove or replace the lock during conversion.

[Identity registry rules](#identity-registry-rules) has the remaining rules.

### What the converter refuses

- The tool refuses to run from an unknown or modified build.
- It refuses to replace an existing output.
- It publishes nothing unless every log was read.
- A second path or hard link to a copy already read is refused.
- A copy whose decompressed content repeats another is refused.

Each log copy must be a regular file that stays unchanged while it is read. Reads stop at its initial size. Size, modification time and change time must still match afterward, so restoring the modification time cannot hide a rewrite.

Snapshot checks support Linux and macOS. Other platforms refuse conversion.

### The manifest

The manifest is published last. It records:

- the digests of every input (as read and decompressed) and output,
- the tool revision,
- the period,
- per site, the observed extent and the bytes read.

Every line read is either a record or exactly one of:

- oversized,
- refused by the parser,
- invalid time,
- time in the future,
- time outside the period,
- a final line without a newline, which is incomplete and never a request.

Records without a usable target or client are counted too. Record bytes are in the volume stream, and every other byte is counted as unplaced.

For lines without a usable time, the manifest keeps the logged times of the timed lines around them. That bounds where the lost requests belong.

### Identity digests in the manifest

The manifest also lists every site, account and episode pseudonym of the bundle with the full keyed digest it is a prefix of. Bundles replayed together must agree on every digest. Bundles converted against a forked or restored registry therefore cannot merge two names unnoticed.

### Observed extent is not coverage

The first and last timed lines describe an observed extent, not proof of complete minutes. The manifest keeps them apart from coverage. Only a coverage proof certifies minutes. An idle log alone cannot certify zero traffic.

## Replaying an experiment

`scripts/crawl-calibrate` replays an experiment through exact models of the detector. Build it from a clean committed checkout as well:

```bash
go build -o "$RECORDING_DIR/crawl-calibrate" ./scripts/crawl-calibrate
"$RECORDING_DIR/crawl-calibrate" --experiment "$RECORDING_DIR/experiment.json" \
    --out "$RECORDING_DIR/experiment.report.json"
```

### The experiment file

The experiment file lists the bundles in chronological order, the parameter sets to replay and the truth of every scored episode. Paths are relative to the experiment file's directory unless absolute. Like the inventory, it must be a regular file in its exact JSON form:

```json
{
  "format_version": 1,
  "identity_version": 1,
  "window": 10,
  "runs": [
    {"params": {"w": 10, "r": 3, "f": 5, "k": 20, "d": 50, "c": 80,
                "baseline": {"alpha": 0.1, "min_obs": 1, "min_age": 10080, "floor_per_min": 1}},
     "sketch": {"m": 64, "h": 128, "seed": 7}}
  ],
  "fixtures": [],
  "bundles": [
    {"manifest": "week1.manifest.json", "records": "week1.records.jsonl.gz",
     "volume": "week1.volume.jsonl.gz", "coverage": "week1.coverage.json",
     "role": "training",
     "states": [{"from": 29840820, "to": 29850899, "state": "normal"}]},
    {"manifest": "day8.manifest.json", "records": "day8.records.jsonl.gz",
     "volume": "day8.volume.jsonl.gz", "coverage": "day8.coverage.json",
     "role": "scoring", "score": [{"from": 29850900, "to": 29852339}],
     "states": [{"from": 29850900, "to": 29852339, "state": "normal"},
                {"site": "dom-0a1b2c.example", "key": {"level": 2, "key": "k-0123456789abcdef"},
                 "from": 29851500, "to": 29851560, "state": "protected"}]}
  ],
  "truth": [
    {"episode": "e-0123456789abcdef", "label": "attack", "site": "dom-0a1b2c.example",
     "keys": [{"level": 1, "key": "k-1111111111111111", "parent": "k-0123456789abcdef"}]}
  ]
}
```

Without parameter sets the report holds only volume, silence and shape diagnostics. State declarations and truth definitions are validated even without runs.

### Rules for bundles

Bundles in one experiment must:

- share one salt and identity contract,
- follow one another in time without overlap,
- agree on every identity digest.

A digest disagreement means their identity registries forked or one was restored from an older copy. The experiment is refused.

Each bundle is read once. It is refused in any of these cases:

- Its manifest is not exactly what domlog-stream wrote.
- A site is not a unique pseudonym.
- Any row, digest or total disagrees with the manifest.

### The coverage proof

Replaying needs a coverage proof for every bundle. The operator builds it from evidence independent of the logs:

- the collection record,
- handler and logging liveness,
- a measured bound on how long after its logged time a request can be written.

The proof names the manifest by digest. For every site, certified spans and reasoned exclusions (`partial_minute`, `collection_gap`, `liveness_unknown`, `topology_change`) must together cover every minute of the recording period exactly once. It cites evidence only by digest:

```json
{
  "format_version": 1,
  "manifest_sha256": "<SHA-256 of the manifest file>",
  "lateness_seconds": <measured completion-delay bound>,
  "evidence": [
    {"kind": "collection", "sha256": "<digest>"},
    {"kind": "logging_liveness", "sha256": "<digest>"},
    {"kind": "lateness", "sha256": "<digest>"},
    {"kind": "pre_application", "sha256": "<digest>"}
  ],
  "sites": [
    {"site": "dom-0a1b2c.example",
     "spans": [{"from": 29840821, "to": 29840838}],
     "excluded": [{"from": 29840820, "to": 29840820, "reason": "partial_minute"},
                  {"from": 29840839, "to": 29840839, "reason": "partial_minute"}],
     "rejects": [{"from": 29840827, "to": 29840827, "category": "no_target",
                  "lines": 1, "evidence": "<digest of the pre_application entry>"}]}
  ]
}
```

| Case | Result |
|------|--------|
| A bundle has no proof | It contributes diagnostics over each site's observed extent only. The report says its coverage is unqualified. |
| A site has no independently certified minutes | It remains in the bundle. Use an empty certified-span list and reasoned exclusions covering its whole period. It contributes no replay windows, while other qualified sites remain usable. |

### Which minutes a replay uses

A replay uses only certified minutes without unknown loss. Only covered records contribute to windows, baselines and detections.

The replay removes:

- a minute with a targetless or unattributed record,
- every minute a line without a usable time may belong to. Those are the minutes between the timed lines around it, widened by the lateness bound.

A `rejects` entry keeps those minutes only when independent evidence shows that exactly that many targetless or oversized lines were refused before the application ran. The HTTP status alone is not such evidence.

Removed minutes break windows like any unknown minute and never train a baseline.

### Lateness and log order

These bounds assume each copy lists requests in the order they completed. The manifest records, per copy, how far any logged time trails an earlier one. That disorder is a lower bound on completion delay, so a proof whose lateness bound is smaller is refused.

The declared disorder must also cover inversions between the timed neighbours of lost lines, including neighbours outside the recording period.

## How a replay runs

Each parameter set replays one session through all bundles in order. Every minute is judged against the history learned before it and only then learned, so held-out minutes never inform earlier ones.

Windows run on across adjacent bundles. A gap between bundles restarts every window.

The rules below speak of keys. A key is what the detector judges: a URL pattern, at a level such as L1 or L2, or the site as a whole.

### When a minute trains a baseline

A minute trains a baseline only when all of these hold:

- Its state is declared `normal`.
- No finding is active on the key.
- Either a complete window judged its traffic, or the minute was observed silent.

An idle key learns its silent minutes later, when it becomes active again. It learns the covered minutes declared `normal` in which it had no traffic, once only. Unknown minutes never become zeros.

A minute with no declared state is unknown and never trains.

Minutes declared `protected`, `degraded` or `recovery_hold` do not train a baseline either. That holds whether the protection was applied or only decided.

### Which state declaration applies

The most specific declaration applies, in this order:

1. The key's own declaration.
2. The declaration of its nearest ancestor. An L2 key's declaration covers its L1 keys, and the site key's covers every key.
3. The declaration made for the site.

### While a finding is active

When a finding starts, the key's hour-of-week profile and its trust are pinned until a complete window clears it. A coverage gap leaves the finding active but uncertain, and it never counts as a new finding.

## Findings and episodes

A High transition is the only finding event. Only transitions in a `scoring` bundle's scoring spans are reported. Findings still active from training appear as active when scoring began.

An episode is detected by the first transition that meets all of these:

- It happens in a scored minute.
- It is at a key the episode's truth entry names.
- Its window holds the episode's requests.

Ancestor findings that were already active are listed, never credited.

Every labeled episode in a scoring bundle needs a truth entry for its site. A window's majority label is only a suggested class for review.

### Undetected episodes

| Undetected episode | Reported as |
|--------------------|-------------|
| It began outside the scoring spans | `not_scored`, not a qualified detector miss. |
| None of its counted requests was replayed in a scored minute | `not_scored`, not a qualified detector miss. |
| Its later requests were replayed and scored | A miss. |

Relevant anomalous windows keep their margins even when an already active finding prevents a new detection.

[Episode onset](#episode-onset) explains where an episode starts.

## The report

### Provenance

The report records its provenance:

- the experiment and calibrator digests,
- the salt fingerprint,
- per bundle, its role and scoring spans, manifest and proof digests, converter revision, period and bot evidence.

### Diagnostics

Per bundle and site the report records certified and covered minutes, excluded minutes by reason and every line count. It also holds:

- host lines and bytes per minute over the observed extent within the recording periods. Gaps between bundles contribute no zero-traffic samples.
- line counts for nonempty site-minutes,
- in-file timestamp disorder across all validated records, including excluded minutes,
- how many patterns and clients are active per window.

Diagnostic windows continue across adjacent bundles and restart at coverage gaps. Key churn counts each site key only once across the experiment and combines samples in the same UTC hour.

The silence diagnostic joins adjacent spans but stops at an unknown gap. A silent run alone does not certify zero traffic.

### Results for each parameter set

For every parameter set the report lists:

- each scored transition with its margins, scope, window labels, suggested class and credited episodes,
- per site and UTC day: the scored and judged minutes, requests by label, transitions and credited transitions,
- each truth episode's outcome, detection delay, margins and scope match,
- key and client peaks over scored minutes.

With a sketch, the report also lists an independent exact session's outcomes, lost or extra decisions and lost findings. Beside them it shows how far the bounds fall below the exact values of the same window. These sketch comparisons use only scored minutes. Both sessions still learn from training and other unscored minutes.

Fixtures add synthetic attacks from clients that send one, three or twenty requests each, with optional padding and churn. Each fixture is replayed on its own, without the history learned from the bundles, and is scored by the suggested class, not by a truth entry.

## What a replay does not prove

A replay is a hypothesis about the detector, not a record of what the host did. Logs hold completed requests, not offered load, backend harm or queued work. The parser is only as good as the server's log escaping.

- Episode delays are offline event-time delays. They exclude request completion, log flush, lateness watermark and tick delay, so they are not correct-finding deadlines on their own.
- The packed footprint estimate is not measured memory or disk usage.
- Neither a model delay nor logged timestamp disorder measures request completion or log-flush delay. Disorder is only a lower bound on it.
- The tools model High findings only. Absence of Critical or actions here is not an end-to-end safety test.

## Qualification

Qualification must use:

- explicit complete-minute coverage,
- independently verified zero-traffic minutes,
- separate training and scoring intervals,
- held-out healthy, attack and legitimate-overload cohorts.

Warm seasonal profiles require history and observations for every enabled seasonal slot. A cold-start replay is a separate experiment.

Review every transition per site, key and day. Majority labels are a summary, not the definition of a correct finding or permission to ignore mixed traffic.

After qualification, chosen values and their evidence go to a private calibration ledger. Full-bound resource measurements and a private ledger approval are required before production implementation. The production components must repeat these measurements with their own allocations and I/O.

## Details

This section is reference material: exact rules for episode onset, session snapshots, cleanup failures and the identity registry.

### Episode onset

Episode onset remains the first labeled request across the experiment that the detector counts, even when its minute is excluded. Infrastructure and static requests inside a labeled range never move it.

If a later segment introduces the first counted request, findings active at onset are captured again at that request's minute.

An episode with no counted request keeps its first request as onset and is never scored.

### Session snapshots

The session snapshot API preserves findings across restores.

| Change | Effect on a restored session |
|--------|------------------------------|
| The identity contract | Drops old key declarations and non-finding keys. Requires a complete new window. |
| Baseline semantics | Resets history and learning watermarks and re-pins active findings without changing their start minute. Requires a complete new window. |
| The window, sketch mode, size, seed or hash version | Requires a complete new window. |
| Thresholds or shuffle | Keeps compatible evidence and pinned history. |

A snapshot made immediately after invalidation can be restored again with the same result.

### Cleanup failures

A cleanup failure returns a fixed error. If the filesystem refuses removal, private temporary or output files can remain. Retain them for operator-approved cleanup. Do not retry at those paths or consume them as accepted outputs.

### Identity registry rules

The identity registry reserves site, account and episode pseudonyms across all bundles under the same salt.

Key and binding pseudonyms are 64 bits and are checked within each bundle only. Registering every client and pattern would grow the registry with all traffic ever converted.

The registry and its lock must be private regular files. Inconsistent digest prefixes are refused.

Registry replacement is synced to its directory before bundle publication. Keep the registry and its lock file together.

A failed publication may leave conservative identity reservations. Keep those reservations on retry instead of rolling the registry back.
