# Crawl Detector Calibration

The distributed crawl detector judges each site and URL pattern over a
window of minutes: it removes the heaviest clients, then asks whether the
remaining traffic is both far above the pattern's usual rate and spread over
enough distinct clients. Every one of those settings, and the memory bounds
behind them, must come from what real hosts served, not from guesses. Two
tools turn copies of a host's access logs into that evidence without
retaining raw visitor identities. Pseudonymous recordings are still private.
This revision validates bundles and certified coverage and replays them
through chronological sessions, but bounded experiments with executable
acceptance limits are not yet implemented, so it is still for synthetic data
only. Do not convert private recordings, delete
preserved recordings on the strength of these outputs, or use reports to
choose detector settings until those contracts pass their tests and
independent review. Real-data collection and conversion then require
separate operator approval.

`scripts/domlog-stream` converts local copies of domlogs into an anonymized
record stream. The following example is for synthetic fixtures only, from a
clean committed checkout; use absolute local log-copy paths in the inventory:

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

Every line goes through the detector's own record parser and request
identity rules, with the same canonicalization. Deployed log escaping and
proxy semantics still need qualification before real recordings can be trusted.
A record keeps the logged time and order, status, whether the request is
dynamic or an expensive query, the Referer class (none, malformed,
cross-site or same-site), a claimed bot identity with its verified-bot proof
class, an infrastructure flag and the operator's label. Sites, accounts, client bindings (the full IPv4 address or the IPv6
/64), episode names and URL patterns become salted pseudonyms that keep
equality and the
site/pattern hierarchy. Two distinct names that would share a pseudonym stop
the conversion instead of being merged. No path, query value, address, user
agent or Referer is written. Sites and accounts use the same pseudonyms as
[recorded finding streams](finding-streams.md) under the same salt, so the
two can be joined. A volume stream counts lines and bytes per site and
minute, including lines without a usable target or client.

The inventory names the recording period, each site's verified identity and
its log copies. The period is bounded by whole UTC minutes, `from` inclusive and
`to` exclusive, and must have ended. Site names and aliases must be lowercase
DNS names without a terminal dot, at most 253 bytes each, and one host
belongs to one site: an alias listed twice or naming another site is
refused. Use absolute log paths: the tool also accepts a relative path, but
resolves it against the directory it runs in, which ties the inventory to
that directory:

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

The inventory, labels and bot evidence files must be regular files, not
symlinks, devices or FIFOs, in their exact JSON form: every member spelled
exactly and given once, no null values and nothing after the document.

Verified-bot identity comes only from the host's own verified-bot list. The
optional bot evidence file is an export of that list for the recording
period: the list's source revision and configuration digest, then published
ranges and reverse-DNS verdicts, each for one identity and valid from `from`
(inclusive) to `to` (exclusive):

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

The `proofs` list is required; use `[]` for an explicitly empty export.
The converter looks nothing up. A claimed identity is `range` when a range of
that same identity held the client at the logged time, else `dns` or
`negative` from a verdict for that exact address; a user agent alone, another
bot's range, an expired proof or contradictory verdicts leave the claim
unverified. The manifest records the evidence digest and its list revision.
Bundle validation refuses a proof without that reference or a client binding.
A bot the host verifies only through operator-configured user-agent
substrings (`reputation.verified_bots`) has no claimed identity here: its
requests are ordinary traffic in the bundle, and bot-label qualification
must account for them separately.

Aliases decide which Referers count as same-site; a `www` host counts only
when it is listed. Behind a trusted proxy the client is the rightmost
forwarded address only when the qualified proxy appends the original client
there. A proxied line without a usable forwarded address, or whose rightmost
address is another trusted proxy (an unqualified second hop), counts as
attribution loss; a peer that is not a plain address counts as an invalid
client. Neither gets a client binding. The optional labels file marks time ranges of a
site as `attack` or `overload` (each with an episode name) or `healthy`,
optionally only for a first path segment or parameter-name prefix. Each rule
requires nonzero RFC 3339 `from` (inclusive) and `to` (exclusive) timestamps;
matching preserves fractional seconds even though stream timestamps use
whole Unix seconds. Prefixes match canonical query names, with ASCII letters
lowercased and non-ASCII case preserved. The first matching rule wins and
anything else stays unlabeled. Labels are what the calibration measures
detection delay and false positives against.

Handling rules for later qualified real-data use (not authorized by this
prototype):

- The operator copies the logs read-only into a private local directory
  (mode 0700) after explicit collection approval. Take each copy no earlier
  than the end of the recording period plus the lateness bound, so requests
  that complete after the last minute are already written; when a copy was
  taken earlier, exclude the minutes it cannot vouch for as
  `partial_minute`. Run
  the tool, review coverage against those copies and independently recorded
  handler/logging liveness, then let the operator delete the approved copies.
  Nothing runs on the monitored host.
- The salt is created on first use with mode 0600 and must stay private;
  reuse the finding-stream salt so the streams join. Keep one identity
  registry per salt, in the salt's directory. The tool derives its filename
  as `registry-<salt SHA-256>.json`, using the full lowercase hex digest of
  the salt bytes. Optional `--registry FILE` must name that same file;
  another filename or directory is refused, even with `--new-registry`.
  Directory symlink aliases are accepted. It records every site, account and
  episode pseudonym the salt has issued, as keyed digests, and refuses a
  later bundle whose different name would take one; it is locked while a
  conversion runs.
- A run that creates the salt starts its registry. For a salt that already
  exists but never had a registry, such as the finding-stream salt, pass
  `--new-registry` on the first conversion only; it is refused once a
  registry exists. Without that flag, a missing registry stops the run
  instead of starting an empty one that would forget issued pseudonyms.
  Back up the salt, registry and persistent `.lock` file together, and
  restore them together. Never remove or replace the lock during conversion.
  If an earlier tool wrote a custom registry filename, stop conversions and
  move that registry and its lock to the derived names before reusing the
  salt. Do not start an empty registry to replace existing history.
- The tool refuses to run from an unknown or modified build, refuses to
  replace an existing output, and publishes nothing unless every log was
  read. Each log copy must be a regular file that stays unchanged while it
  is read. Reads stop at its initial size; size, modification time and
  change time must still match afterward, so restoring the modification
  time cannot hide a rewrite. Snapshot checks support Linux and macOS;
  other platforms refuse conversion. A second path or hard link to a copy
  already read, or a copy whose decompressed content repeats another, is refused.
- The manifest, published last, records the digests of every input (as read
  and decompressed) and output, the tool revision, the period and, per
  site, the observed extent and the bytes read. Every line read is either a
  record or exactly one of: oversized, refused by the parser, invalid time,
  time in the future, time outside the period, or a final line without a
  newline, which is incomplete and never a request. Records without a
  usable target or client are counted too. Record bytes are in the volume
  stream; every other byte is counted as unplaced. For lines without a
  usable time, the manifest keeps the logged times of the timed lines
  around them, which bounds where the lost requests belong.
- The manifest also lists every site, account and episode pseudonym of the
  bundle with the full keyed digest it is a prefix of. Bundles replayed
  together must agree on every digest, so bundles converted against a
  forked or restored registry cannot merge two names unnoticed.
- The first and last timed lines describe an observed extent, not proof of
  complete minutes, and the manifest keeps them apart from coverage. Only a
  coverage proof certifies minutes. An idle log alone cannot certify zero
  traffic.
- Streams, labels, inventories and reports stay outside the repository.

`scripts/crawl-calibrate` replays an experiment through exact models of the
detector. Build it from a clean committed checkout as well:

```bash
go build -o "$RECORDING_DIR/crawl-calibrate" ./scripts/crawl-calibrate
"$RECORDING_DIR/crawl-calibrate" --experiment "$RECORDING_DIR/experiment.json" \
    --out "$RECORDING_DIR/experiment.report.json"
```

The experiment file lists the bundles in chronological order, the parameter
sets to replay and the truth of every scored episode. Paths are relative to
the experiment file's directory unless absolute. Like the inventory, it must
be a regular file in its exact JSON form:

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

Bundles must share one salt and identity contract, follow one another in
time without overlap, and agree on every identity digest; a disagreement
means their identity registries forked or one was restored from an older
copy, and the experiment is refused. Each bundle is read once and refused
if its manifest is not exactly what domlog-stream wrote, a site is not a
unique pseudonym, or any row, digest or total disagrees with the manifest.
Without parameter sets the report holds only volume, silence and shape
diagnostics. State declarations and truth definitions are validated even
without runs. Replaying needs a coverage proof for every bundle, which the
operator builds from evidence independent of the logs: the collection record, handler and logging
liveness, and a measured bound on how long after its logged time a request
can be written. The proof names the manifest by digest and tiles the
recording period for every site with certified spans and reasoned
exclusions (`partial_minute`, `collection_gap`, `liveness_unknown`,
`topology_change`). It cites evidence only by digest:

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

A replay uses only certified minutes without unknown loss. A minute with a
targetless or unattributed record is removed, and so is every minute a line
without a usable time may belong to: the minutes between the timed lines
around it, widened by the lateness bound. A `rejects` entry keeps those
minutes only when independent evidence shows that exactly that many
targetless or oversized lines were refused before the application ran; the
HTTP status alone is not such evidence. Removed minutes break windows like
any unknown minute and never train a baseline. These bounds assume each copy
lists requests in the order they completed. The manifest records, per copy,
how far any logged time trails an earlier one; that disorder is a lower bound
on completion delay, so a proof whose lateness bound is smaller is refused.
The declared disorder must also cover inversions between the timed neighbours
of lost lines, including neighbours outside the recording period.
A bundle without a proof contributes diagnostics over each site's observed
extent only, and the report says its coverage is unqualified.

Each parameter set replays one session through all bundles in order. Every
minute is judged against the history learned before it and only then
learned, so held-out minutes never inform earlier ones; windows run on
across adjacent bundles, and a gap between them restarts every window. A
minute trains a baseline only when its state is declared `normal`, no
finding is active on the key, and either a complete window judged its traffic
or the minute was observed silent. Idle keys learn those covered normal zero
minutes on reactivation, once only; unknown minutes never become zeros. A
minute with no declared state is unknown and never trains. `protected`,
`degraded` and `recovery_hold` minutes are frozen the same way whether the
protection was applied or only decided. A key's own declaration wins; otherwise the nearest ancestor's applies
(an L2 key's covers its L1 keys, the site key's covers every key), and then
the site's. When a finding starts, the key's hour-of-week profile and its trust
are pinned until a complete window clears it; a coverage gap leaves the
finding active but uncertain, and it never counts as a new finding.

The session snapshot API preserves findings across restores. Changing the
identity contract also drops old key declarations and non-finding keys;
changing baseline semantics resets history and learning watermarks and
re-pins active findings without changing their start minute. Either change,
or a changed window, sketch mode, size, seed or hash version, requires a
complete new window. Threshold and shuffle changes keep compatible evidence
and pinned history. A snapshot made immediately after invalidation can be
restored again with the same result.

A High transition is the only finding event. Only transitions in a
`scoring` bundle's scoring spans are reported; findings still active from
training appear as active when scoring began. An episode is detected by the
first transition in a scored minute at a key its truth entry names, whose
window holds the episode's requests; ancestor findings that were already
active are listed, never credited. Every labeled episode in a scoring bundle
needs a truth entry for its site. A window's majority label is only a
suggested class for review.

The report records its provenance: the experiment and calibrator digests,
the salt fingerprint and, per bundle, its role and scoring spans, manifest
and proof digests, converter revision, period and bot evidence. Per bundle
and site it records certified and covered minutes, excluded minutes by
reason and every line count. It also holds host lines and bytes per minute
over the observed extent within the recording periods; gaps between bundles
contribute no zero-traffic samples. It also holds line counts for nonempty
site-minutes, in-file timestamp disorder across all validated records
(including excluded minutes) and how many patterns and
clients are active per window. Diagnostic windows continue across adjacent
bundles and restart at coverage gaps. Key churn counts each site key only
once across the experiment and combines samples in the same UTC hour.

For every parameter set it lists each scored transition with its margins,
scope, window labels, suggested class and
credited episodes; per site and UTC day the scored and judged minutes,
requests by label, transitions and credited transitions; each truth
episode's outcome, detection delay, margins and scope match; key and client
peaks over scored minutes; and, with a sketch, an independent exact session's
outcomes, lost or extra decisions and lost findings, beside how far the
bounds fall below the exact values of the same window. These sketch
comparisons use only scored minutes; both sessions still learn from training
and other unscored minutes. Fixtures add synthetic attacks from one-, three-
and twenty-request clients with optional padding and churn, replayed cold and
scored by suggestion.

Episode onset remains the first labeled request across the experiment that
the detector counts, even when its minute is excluded; infrastructure and
static requests inside a labeled range never move it. An undetected episode
that began outside the scoring spans, or none of whose counted requests was
replayed in a scored minute, is reported as `not_scored`, not as a qualified
detector miss; one whose later requests were replayed and scored is a miss. Relevant anomalous windows keep
their margins even when an already active finding prevents a new detection.
Only covered records contribute to windows, baselines and
detections.

The silence diagnostic joins adjacent spans but stops at an unknown gap. A
silent run alone does not certify zero traffic.

A replay is a hypothesis about the detector, not a record of what the host
did: logs hold completed requests, not offered load, backend harm or queued
work, and the parser is only as good as the server's log escaping. After
qualification, chosen values and their evidence go to a private calibration
ledger. Episode delays are offline event-time delays: they exclude request
completion, log flush, lateness watermark and tick delay, so they are not
correct-finding deadlines on their own. The packed footprint estimate is not
measured memory or disk usage.

Qualification must use explicit complete-minute coverage, independently
verified zero-traffic minutes, separate training and scoring intervals, and
held-out healthy, attack and legitimate-overload cohorts. Warm seasonal
profiles require history and observations for every enabled seasonal slot.
A cold-start replay is a separate experiment. Neither a model delay nor
logged timestamp disorder measures request completion or log-flush delay;
disorder is only a lower bound on it.

Review every transition per site, key and day. Majority labels are a summary,
not the definition of a correct finding or permission to ignore mixed traffic.
The tools model High findings only; absence of Critical or actions here is
not an end-to-end safety test. Full-bound resource measurements and a private
ledger approval are required before production implementation. The production
components must repeat these measurements with their own allocations and I/O.

A cleanup failure returns a fixed error. If the filesystem refuses removal,
private temporary or output files can remain; retain them for operator-approved
cleanup and do not retry at those paths or consume them as accepted outputs.

The identity registry reserves site, account and episode pseudonyms across
all bundles under the same salt. Key and binding pseudonyms are 64 bits and
are checked within each bundle only; registering every client and pattern
would grow the registry with all traffic ever converted. The registry and its
lock must be private regular files; inconsistent digest prefixes are refused.
Registry replacement is synced to its directory before bundle publication.
Keep the registry and its lock file together; never replace or remove the lock
while a conversion is running. A failed publication may leave conservative
identity reservations. Keep those reservations on retry instead of rolling
the registry back.

A site with no independently certified minutes remains in the bundle: use an
empty certified-span list and reasoned exclusions covering its whole period.
It contributes no replay windows, while other qualified sites remain usable.
