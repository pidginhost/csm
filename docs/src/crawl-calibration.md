# Crawl Detector Calibration

The distributed crawl detector judges each site and URL pattern over a
window of minutes: it removes the heaviest clients, then asks whether the
remaining traffic is both far above the pattern's usual rate and spread over
enough distinct clients. Every one of those settings, and the memory bounds
behind them, must come from what real hosts served, not from guesses. Two
tools turn copies of a host's access logs into that evidence without
retaining raw visitor identities. Pseudonymous recordings are still private.
This revision is a construction prototype for synthetic data only. Certified
coverage, replay-session state and bounded experiment acceptance are not yet
implemented. Do not convert private recordings, delete preserved recordings
on the strength of these outputs, or use reports to choose detector settings
until those contracts pass their tests and independent review. Real-data
collection and conversion then require separate operator approval.

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
    --out "$RECORDING_DIR/host-a.records.jsonl.gz" \
    --volume-out "$RECORDING_DIR/host-a.volume.jsonl.gz" \
    --manifest "$RECORDING_DIR/host-a.manifest.json"
```

Every line goes through the detector's own record parser and request
identity rules, with the same canonicalization. Deployed log escaping and
proxy semantics still need qualification before real recordings can be trusted.
A record keeps the logged time and order, status, whether the request is
dynamic or an expensive query, the Referer class (none, malformed,
cross-site or same-site), a claimed bot identity and whether the client sits
in that bot's configured ranges, an infrastructure flag and the operator's
label. Sites, accounts, client bindings (the full IPv4 address or the IPv6
/64), episode names and URL patterns become salted pseudonyms that keep
equality and the
site/pattern hierarchy. No path, query value, address, user agent or
Referer is written. Sites and accounts use the same pseudonyms as
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
  "infrastructure": ["192.0.2.200"],
  "bot_ranges": {"googlebot": ["203.0.113.0/24"]}
}
```

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
  reuse the finding-stream salt so the streams join.
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
- The prototype's first/last timed lines describe an observed extent, not
  proof of complete minutes. Partial boundary minutes, internal gaps and
  stalled logging must be excluded before replay. An idle log alone cannot
  certify zero traffic. Do not qualify settings from an inferred extent.
- Streams, labels, inventories and reports stay outside the repository.

`scripts/crawl-calibrate` replays a bundle through exact models of the
detector:

```bash
go run ./scripts/crawl-calibrate --manifest "$RECORDING_DIR/host-a.manifest.json" \
    --records "$RECORDING_DIR/host-a.records.jsonl.gz" --volume "$RECORDING_DIR/host-a.volume.jsonl.gz" \
    --window "$WINDOW_MINUTES" --grid "$RECORDING_DIR/grid.json" --out "$RECORDING_DIR/host-a.report.json"
```

It refuses a bundle whose files do not match the manifest, and a manifest
that lists a site other than a unique pseudonym. The report holds
host lines and bytes per minute, line counts for nonempty site-minutes,
in-file timestamp disorder, how many patterns and clients are active per
window, and, for every parameter set in the grid, each labeled episode's detection delay and margins, healthy
false positives per site and day, the scope level chosen, key and client
peaks, and, when a sketch is configured, how far the bounded estimates fall
below the exact values. Grid runs list the window, rate multiple, rate
floor, removed-client count, distinct-client count, coverage percent and
baseline settings, with optional sketch sizes; fixtures add synthetic
attacks from one-, three- and twenty-request clients with optional padding
and churn.

The silence diagnostic joins adjacent observed spans but stops at an
unknown gap. A silent run alone does not certify zero traffic.

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
logged timestamp disorder measures request completion or log-flush delay.

Review every transition per site, key and day. Majority labels are a summary,
not the definition of a correct finding or permission to ignore mixed traffic.
The tools model High findings only; absence of Critical or actions here is
not an end-to-end safety test. Full-bound resource measurements and a private
ledger approval are required before production implementation. The production
components must repeat these measurements with their own allocations and I/O.
