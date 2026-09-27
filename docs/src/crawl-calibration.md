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

The inventory names each site's verified identity and its log copies. Site
names and aliases must be lowercase DNS names without a terminal dot, at
most 253 bytes each:

```json
{
  "sites": [
    {"name": "example.com", "account": "acct1",
     "aliases": ["example.com", "www.example.com"],
     "logs": ["raw/example.com", "raw/example.com-ssl_log.gz"]}
  ],
  "trusted_proxies": ["198.51.100.9"],
  "infrastructure": ["192.0.2.200"],
  "bot_ranges": {"googlebot": ["203.0.113.0/24"]}
}
```

Aliases decide which Referers count as same-site. Behind a trusted proxy the
client is the rightmost forwarded address only when the qualified proxy
appends the original client there; multi-hop chains need separate qualification; a proxied line without one is
counted as attribution loss. The optional labels file marks time ranges of a
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
  read. The manifest, published last, records the digests of every input
  and output, the tool revision and, per site, the observed extent and
  counts of refused, oversized, untimed, targetless and unattributed lines.
- The prototype's first/last timed lines describe an observed extent, not
  proof of complete minutes. Partial boundary minutes, internal gaps and
  stalled logging must be excluded before replay. An idle log alone cannot
  certify zero traffic. Do not qualify settings from an inferred extent.
- Streams, labels, inventories and reports stay outside the repository.
