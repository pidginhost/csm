# Crawl Detector Calibration

The distributed crawl detector judges each site and URL pattern over a
window of minutes: it removes the heaviest clients, then asks whether the
remaining traffic is both far above the pattern's usual rate and spread over
enough distinct clients. Every one of those settings, and the memory bounds
behind them, must come from what real hosts served, not from guesses. Two
tools turn copies of a host's access logs into that evidence without
retaining raw visitor identities. Pseudonymous recordings are still private.
This revision validates bundles and certified coverage, but replay-session
state and bounded experiment acceptance are not yet implemented, so it is
still for synthetic data only. Do not convert private recordings, delete
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
refused. Log paths are absolute; a relative path resolves against the
working directory:

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
  (mode 0700) after explicit collection approval. Run
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
- The first and last timed lines describe an observed extent, not proof of
  complete minutes, and the manifest keeps them apart from coverage. Only a
  coverage proof certifies minutes. An idle log alone cannot certify zero
  traffic.
- Streams, labels, inventories and reports stay outside the repository.

`scripts/crawl-calibrate` validates a bundle and replays it through exact
models of the detector. Build it from a clean committed checkout as well:

```bash
go build -o "$RECORDING_DIR/crawl-calibrate" ./scripts/crawl-calibrate
"$RECORDING_DIR/crawl-calibrate" --manifest "$RECORDING_DIR/host-a.manifest.json" \
    --records "$RECORDING_DIR/host-a.records.jsonl.gz" --volume "$RECORDING_DIR/host-a.volume.jsonl.gz" \
    --coverage "$RECORDING_DIR/host-a.coverage.json" \
    --window "$WINDOW_MINUTES" --grid "$RECORDING_DIR/grid.json" --out "$RECORDING_DIR/host-a.report.json"
```

It reads each file once and refuses a manifest that is not exactly what
domlog-stream wrote, a site other than a unique pseudonym, and any row,
digest or total that disagrees with the manifest, whether or not a grid is
given. A grid replay needs `--coverage`, a proof the operator builds from
evidence independent of the logs: the collection record, handler and logging
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
Without `--coverage` the report holds only volume, silence and shape diagnostics
over each site's observed extent and says its coverage is unqualified.

The report records its provenance (the manifest and proof digests, both tool
revisions, the salt fingerprint, the period and the bot evidence) and, per
site, certified and covered minutes, excluded minutes by reason and every
line count. It also holds host lines and bytes per minute, line counts for
nonempty site-minutes,
in-file timestamp disorder across all validated records (including excluded
minutes), how many patterns and clients are active per
window, and, for every parameter set in the grid, each labeled episode's detection delay and margins, healthy
false positives per site and day, the scope level chosen, key and client
peaks, and, when a sketch is configured, how far the bounded estimates fall
below the exact values, lost or extra decisions against an independent
exact replay, and exact findings the sketch missed. Grid runs list the
window, rate multiple, rate floor, removed-client count, distinct-client count, coverage percent and
baseline settings, with optional sketch sizes; fixtures add synthetic
attacks from one-, three- and twenty-request clients with optional padding
and churn.

Episode onset remains the first labeled request in the bundle, even when
its minute is excluded. An undetected episode none of whose requests was
replayed in a scored minute is reported as `not_scored`, not a qualified
detector miss; one whose later requests were replayed is a miss. An
episode with no covered requests has no replay margins. Relevant anomalous
windows retain their margins even when an already active finding prevents
a new detection. Only covered records contribute to windows, baselines and
detections.

The silence diagnostic joins adjacent spans but stops at an unknown gap. A
silent run alone does not certify zero traffic.

A replay is a hypothesis about the detector, not a record of what the host
did: logs hold completed requests, not offered load, backend harm or queued
work, and the parser is only as good as the server's log escaping. After
qualification, chosen values and their evidence go to a private calibration
ledger. Current episode delays and majority-label counts are
prototype diagnostics, not correct-finding deadlines or qualified false-positive
rates. The packed footprint estimate is not measured memory or disk usage.

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
