# Recorded finding streams

Calibrating correlation (the coordinated-attack threshold, corroboration
grading, sequence rules) needs what a real host produced over days: every
finding with its check, severity, timestamp, owner and text, including the
false-positive floods and the long-lived rows that never clear. CSM already
writes that stream: every dispatched finding lands in
`/var/log/csm/audit.jsonl` (rotated copies are gzip files beside it). A
recorded stream is a copy of those files with every identity removed.

`scripts/finding-stream` turns the raw files into an anonymized stream:

```bash
# On the operator machine, after copying the files read-only from the host:
go run ./scripts/finding-stream anonymize \
    --salt-file ~/.local/share/csm/finding-streams/salt \
    --out ~/.local/share/csm/finding-streams/host-a.jsonl.gz \
    raw/audit.jsonl raw/audit.jsonl-*.gz
```

What the tool replaces, in every structured field and in free text:

- Host names become `host-<id>`, account names `acct-<id>`, domains
  `dom-<id>.example`, mailboxes `user-<id>@dom-<id>.example` (a mailbox
  truncated after the `@` keeps the same `user-<id>`). The `<id>` is
  derived from an HMAC of the value under a private salt, so the same salt
  maps one account to one pseudonym on every host and streams can be joined
  without knowing who is who. Names are replaced wherever they sit: in
  `/home/<account>/` paths, `Account:` lines, process context, LiteSpeed
  vhost tokens, and inside longer tokens such as `example.com-ssl_log` or
  `cp1.log`. The host's short name (its first label, when it carries a
  digit) maps to the same pseudonym as the full name. Any other token that
  looks like a domain (two or more labels, alphabetic last label that is
  not a file extension) is mapped too, even if no field named it; that
  over-reaches on a few dotted names like `options.option` and is accepted.
  Domain-shaped names inside filenames are replaced even when no structured
  field named them. Only pseudonyms actually emitted by this run are exempt;
  a raw name beginning with `host-` or `acct-` is still scrubbed.
- IPv4 addresses map into 198.18.0.0/15 and IPv6 addresses into
  2001:db8::/32, both reserved and never routed, one address per raw value.
  Loopback addresses, system users such as `root` or `nobody`, and bare
  numeric uids are kept: they identify nobody and carry meaning.
  Equivalent IPv6 spellings share one pseudonym across all streams; IPv4
  addresses written in IPv6 form use the IPv4 pseudonym.
  Addresses inside filenames and before numeric rotation suffixes are also
  replaced. This can replace address-shaped version numbers; privacy takes
  priority over preserving ambiguous numeric text.
- The details of a credential-leak finding are dropped entirely, and generic
  `password=`, `secret:` and `token=` material is blanked anywhere, including
  quoted keys and values containing spaces.
- Finding ids become `fid-<id>`, a salted id of at least 128 bits that keeps
  case, so an action row can name its finding without exposing the raw id.
- Timestamps, check names, severities, path structure below the account,
  plugin and file names, and process names are kept unless they contain an
  identity: they are what calibration reads. Paths and mailboxes in process
  command lines and parent processes also teach the scrubber which
  identities to remove elsewhere.

Before writing, the tool scans its own output for every identity it learned
from structured fields, paths and mail addresses, for domain-shaped names,
for raw ids (including inside longer tokens), and for any mailbox or address
outside the reserved ranges. It refuses to write if it finds one. The raw-id
scan includes check names and severity labels; these fields otherwise keep
their original vocabulary. Structured finding ids must be ids this run
emitted. A name glued to underscores or file extensions is still found. The summary prints
row counts, the number of distinct checks, replacement counts, the time span
and a salt fingerprint, never identities, check names, paths or the salt
itself. An error names only the stream, the file's position on the command
line, the line number and a fixed reason.

Every row must parse as exactly one JSON object of the known schema, with a
supported version and a timestamp. Unknown or repeated fields, nulls, data
after the object and values over the size limits refuse the whole run.
Malformed Unicode, non-JSON whitespace and timestamps that cannot be written
back as JSON also refuse the run before a salt is created. Typed rows accept
only the exact pseudonym spellings emitted during that run.

Handling rules:

- Copy the audit files read-only (`tar` over `ssh`, or `scp`) into a local
  directory with mode 0700, run the tool, then delete the raw copies. Nothing
  runs on the monitored host.
- The salt file is created exclusively on first use with mode 0600. Existing
  salts must be regular files without group or other access; symlinks are
  refused. A concurrent run that reads an unfinished salt fails without
  replacing it; retry after the creator finishes. Keep it private and
  reuse it for every host whose stream should be joinable with the others;
  losing it makes new recordings unjoinable with old ones.
- Outputs cannot replace an input, the salt, the input manifest or each
  other, whether named by path, through a symlinked directory or as a hard
  link, and an existing output must be a regular file. These checks run
  before the salt is created, including for missing directories and paths
  containing `..`. Case-only and Unicode-equivalent path variants are
  refused on every platform, as are paths that would need a file to also
  serve as a directory. Every output is written to a private temporary
  file beside its destination, and all are complete before any is renamed
  into place; if publishing fails partway, the outputs already replaced are
  restored. New directories have mode 0700 and outputs mode 0600, even when
  replacing a less restricted file.
- Filesystem cleanup failures are reported without claiming success. If
  rollback fails, remaining recovery copies are retained. If every output
  was published but backup cleanup fails, the error explicitly says the
  outputs were published; check the manifest and remove the leftover backups
  before sharing the directory. Other cleanup errors report unchanged outputs
  with temporary files left to remove.
- Recorded streams stay outside the repository entirely, in a private
  directory such as `~/.local/share/csm/finding-streams/` with mode 0700. A
  pseudonymized stream still describes real incidents on a real host, and this
  repository is public. Do not keep them in an ignored directory inside the
  checkout: `git clean -fdx` removes ignored files too, and a recording that
  took a host weeks to accumulate is not reproducible from anywhere else.

## Joining actions and firewall entries

The action log (`actions.jsonl`) and the firewall audit log
(`<state>/firewall/audit.jsonl`) say what CSM did about the findings. The same
run can anonymize both next to the findings, so the three streams share
pseudonyms. A joined run needs a manifest, and a manifest needs a build of a
known commit without local changes, so build the tool from a clean checkout
first:

```bash
go build -o /tmp/finding-stream ./scripts/finding-stream
/tmp/finding-stream anonymize \
    --salt-file ~/.local/share/csm/finding-streams/salt \
    --out host-a/findings.jsonl.gz \
    --actions raw/actions.jsonl --actions-out host-a/actions.jsonl.gz \
    --firewall-audit raw/firewall-audit.jsonl --firewall-out host-a/firewall.jsonl.gz \
    --manifest host-a/manifest.json \
    raw/audit.jsonl raw/audit.jsonl-*.gz
```

Action and firewall rows are rebuilt from a closed list of fields rather than
scrubbed:

- An action row keeps its time, operation and action, actor kind, result, a
  reason category, whether an error occurred, whether the file existed before
  and after, a block lease, and salted ids for the finding, incident, action
  and the action it undoes. Addresses map as in findings, networks keep their
  prefix length and endpoints their port and protocol. File paths, process ids
  and other targets become `tid-<id>`. Command lines, error and reason text,
  undo commands, recovery paths, digests, sizes, modes and owners are dropped.
  Account names are always mapped, system users included.
- A firewall row keeps its time, action, target, reason category, source and
  lease. Firewall entries carry no ids, so nothing joins them to actions or
  findings; the manifest says so rather than guessing from times or addresses.
- An operation, action, actor, result or source the tool has not been
  reviewed against refuses the run instead of passing through.

The manifest is written last and is the bundle's completion marker. It lists
every input and output with its stream kind, position, SHA-256 of the exact
bytes, record count and time span, the tool's source revision, the salt
fingerprint, join counts, counts of discarded fields, action results by value,
and coverage for each stream. Check every output's digest against it; a bundle
without a manifest, or with a digest that does not match, is incomplete.

- An action is matched when it names a finding id present in the recording,
  and nothing more. Actions naming a finding the recording lacks, and actions
  naming none, are counted apart.
- Repeated finding rows are kept and counted. A durable action row repeated
  exactly is a retransmission and does not count as another outcome; rows that
  share an action id and version but differ are reported as conflicting, never
  resolved by taking the latest.
- A result is what the writer recorded. An applied block or a firewall entry
  is an observation, not a verified effect or a reviewed correct action.

`--input-manifest` takes the collector's inventory of what the host has:

```json
{"v": 1, "streams": [
  {"kind": "findings", "availability": "present", "sha256": "<digest of the copied file>", "records": 1200},
  {"kind": "actions", "availability": "not_recorded"},
  {"kind": "firewall_audit", "availability": "absent"}
]}
```

Every supplied file must appear as a present entry with its digest and record
count, and every present entry must be supplied. `absent` means the collector
looked and found none; `not_recorded` means the host does not keep that
stream. Ledger and review streams can only be stated absent or not recorded.
Without an inventory, a stream that was not supplied is reported as not
supplied.

## What a recording does and does not contain

The audit log is the dispatch record: it holds findings that were alerted,
after deduplication. It is not the persisted latest-state set, which is larger
because every scan re-emits the findings it still sees and the merge refreshes
their timestamps. On one production host a single sweep dispatched 49 critical
findings while the active set carried 157 refreshed critical rows.

A replay therefore understates how full the persisted correlation window gets.
Compare windows against each other, and treat an absolute rate from a replay as
a property of the replay, not of the live host.

## Replaying a stream through correlation

`scripts/correlation-calibrate` replays a recording through the production
cross-account correlation so its thresholds can be re-derived from what hosts
produced rather than from an assumption:

```bash
go run ./scripts/correlation-calibrate \
    ~/.local/share/csm/finding-streams/host-a.jsonl.gz
```

It reports how often account-and-check pairs repeat, which checks dominate
the input, and what the aggregates did under both derivations:
per dispatch batch, and over the persisted latest-state set. For each it prints
a threshold sweep using the same eligible, windowed accounts as the aggregate.
`--window` selects the persisted correlation bound: it defaults to
one hour, and `--window 0` reproduces the original unbounded correlation.
Longer windows are applied directly, without the production default limiting
them. The source set keeps the store's retention and size limit. Batch
correlation counts all qualifying rows grouped into that dispatch batch.
Repeated pairs can include distinct findings on the same account; this metric
does not establish how many rows are re-reports of the same finding.

Batch boundaries are inferred from timestamp gaps. Persisted correlation is
recomputed at every recorded arrival, including ignored checks that only
advance time. Raised duration is measured between those observations, not
against an invented scan schedule. Recordings do not contain empty scans,
purges or dismissals, so this replay models latest-state accumulation rather
than reconstructing every store transition. Rows with no timestamp are counted
and skipped because they have no replay position; runtime correlation still
counts unstamped stored rows.

The tool needs no host access and reads nothing but the recording. It uses
cPanel account roots supplied directly to correlation, without platform
discovery on the replay machine.

## Replaying scan admission

`scripts/response-replay` replays a recording through a model of how
automatic scan blocks are admitted today: the hourly block limit, the retry
queue and its age limit, and eviction at the temporary deny limit. It reports
what the model would have done with the recorded findings, not what the host
did, and not whether any block was right.

```bash
go build -o /tmp/response-replay ./scripts/response-replay
/tmp/response-replay --findings host-a/findings.jsonl.gz --out replay/host-a.json \
    --max-blocks-per-hour 200 --deny-temp-ip-limit 500 --seed 1 --hour-zone UTC \
    --manifest host-a/manifest.json
```

- The live path tries queued candidates in Go map order. The model tries them
  in a reproducible random order chosen by `--seed`, so compare several seeds
  rather than reading one run as the order the host used.
- `--hour-zone` is the zone the host's clock runs in: the hourly limit resets
  when that zone's hour changes. `Local` is refused because it would depend
  on the machine running the replay.
- A recorded block from a challenge timeout, central intel, a credential
  spray or an incident is applied as recorded: it takes a firewall slot but
  not the hourly budget. A permanent one is counted, not modelled.
- Batches are inferred from equal timestamps. Recordings hold no empty scans,
  so queued work drains only when another finding arrives. Rows without a
  timestamp are counted and left out.
- The report lists the effective policy with every default it applied, the
  counts, queue delay and eviction residence distributions, blocks per
  elapsed hour, what was still queued when the recording ended, and the
  assumptions and mechanisms the model leaves out: infrastructure and
  allowlist protection, verdict callbacks, subnet blocks, permanent
  escalation, retries and failures, and manual unblocks. It carries no
  address, id, name or text from the recording.
- With `--manifest`, the report checks that the manifest describes this exact
  recording and carries its coverage and recorded outcomes beside the
  replay. Without one, the report says the recording has no statement of
  what was collected with it.
- Like a manifest, a report needs a build of a known commit without local
  changes.
