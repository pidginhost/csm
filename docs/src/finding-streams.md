# Recorded finding streams

A recorded stream is a copy of a host's finding audit files with recognized identities replaced by pseudonyms. CSM already writes the stream: every dispatched finding lands in `/var/log/csm/audit.jsonl`, and rotated copies are gzip files beside it. `scripts/finding-stream` turns those raw files into an anonymized stream.

Recordings exist for calibrating correlation: the coordinated-attack threshold, corroboration grading and sequence rules. That work needs what a real host produced over days. It needs every finding with its check, severity, timestamp, owner and text, including the false-positive floods and the long-lived rows that never clear.

This page covers five tasks:

- [Recording a stream](#recording-a-stream)
- [Joining actions and firewall entries](#joining-actions-and-firewall-entries)
- [Comparing the admission preview](#comparing-the-admission-preview)
- [Replaying a stream through correlation](#replaying-a-stream-through-correlation)
- [Replaying scan admission](#replaying-scan-admission)

## Recording a stream

Nothing runs on the monitored host. Copy the audit files read-only (`tar` over `ssh`, or `scp`) into a local directory with mode 0700. Then run the tool:

```bash
# On the operator machine, after copying the files read-only from the host:
go run ./scripts/finding-stream anonymize \
    --salt-file ~/.local/share/csm/finding-streams/salt \
    --out ~/.local/share/csm/finding-streams/host-a.jsonl.gz \
    raw/audit.jsonl raw/audit.jsonl-*.gz
```

Delete the raw copies after the run. [How outputs are written](#how-outputs-are-written) lists the protections on the output files.

### Keep recordings outside the repository

Recorded streams stay outside the repository entirely, in a private directory such as `~/.local/share/csm/finding-streams/` with mode 0700. A pseudonymized stream still describes real incidents on a real host, and this repository is public.

Do not keep recordings in an ignored directory inside the checkout. `git clean -fdx` removes ignored files too, and a recording that took a host weeks to accumulate is not reproducible from anywhere else.

### The salt file

The `<id>` in a host, account, domain or mailbox pseudonym is derived from an HMAC of the value under a private salt. The same salt therefore maps one account to one pseudonym on every host, and streams can be joined without knowing who is who.

- The salt file is created exclusively on first use with mode 0600.
- An existing salt must be a regular file without group or other access. Symlinks are refused.
- A concurrent run that reads an unfinished salt fails without replacing it. Retry after the creator finishes.
- Keep the salt private, and reuse it for every host whose stream should be joinable with the others. Losing it makes new recordings unjoinable with old ones.

## What the tool replaces

The tool replaces identities in every structured field and in free text.

| Identity | Replacement |
|----------|-------------|
| Host name | `host-<id>` |
| Account name | `acct-<id>` |
| Domain | `dom-<id>.example` |
| Mailbox | `user-<id>@dom-<id>.example`. A mailbox truncated after the `@` keeps the same `user-<id>`. |
| IPv4 address | An address in 198.18.0.0/15. |
| IPv6 address | An address in 2001:db8::/32. |
| Finding id | `fid-<id>`, a salted id of at least 128 bits that keeps case. An action row can name its finding without exposing the raw id. |

[The salt file](#the-salt-file) explains where `<id>` comes from. Both address ranges are reserved and never routed, and a raw value always maps to the same pseudonym.

The tool also removes secrets:

- The details of a credential-leak finding are dropped entirely.
- Generic `password=`, `secret:` and `token=` material is blanked anywhere, including quoted keys and values containing spaces.

The exact rules are under [How names are replaced](#how-names-are-replaced) and [How addresses are replaced](#how-addresses-are-replaced).

### What the tool keeps

Calibration reads these fields, so the tool keeps them unless they contain an identity:

- timestamps,
- check names,
- severities,
- path structure below the account,
- plugin and file names,
- process names.

Loopback addresses, system users such as `root` or `nobody`, and bare numeric uids are kept too. They identify nobody and carry meaning.

Paths and mailboxes in process command lines and parent processes also teach the scrubber which identities to remove elsewhere.

### The leak check before writing

Before writing, the tool scans its own output for:

- every identity it learned from structured fields, paths and mail addresses,
- domain-shaped names,
- raw ids, including inside longer tokens,
- any mailbox or address outside the reserved ranges.

It refuses to write if it finds one. A name glued to underscores or file extensions is still found.

The raw-id scan includes check names and severity labels. These fields otherwise keep their original vocabulary. Structured finding ids must be ids this run emitted.

### What the tool prints

The summary prints row counts, the number of distinct checks, replacement counts, the time span and a salt fingerprint. It never prints identities, check names, paths or the salt itself.

An error names only the stream, the file's position on the command line, the line number and a fixed reason.

### Input the tool refuses

Every row must parse as exactly one JSON object of the known schema, with a supported version and a timestamp field. Typed rows accept only the exact pseudonym spellings emitted during that run.

These refuse the whole run:

- unknown or repeated fields,
- nulls,
- data after the object,
- values over the size limits.

These also refuse the run, before a salt is created:

- malformed Unicode,
- non-JSON whitespace,
- timestamps that cannot be written back as JSON.

Rows that older CSM versions wrote with a zero time are kept, counted in the manifest and left out of time spans.

## Joining actions and firewall entries

The action log (`actions.jsonl`) and the firewall audit log (`<state>/firewall/audit.jsonl`) say what CSM did about the findings. The same run can anonymize both next to the findings, so the three streams share pseudonyms.

A joined run needs a manifest, and a manifest needs a build of a known commit without local changes. Build the tool from a clean checkout first:

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

Action and firewall rows are rebuilt from a closed list of fields rather than scrubbed. An operation, action, actor, result or source the tool has not been reviewed against refuses the run instead of passing through.

### Action rows

| Treatment | Fields |
|-----------|--------|
| Kept | Time, operation and action, actor kind, result, a reason category, whether an error occurred, whether the file existed before and after, and a block lease. |
| Kept as salted ids | The finding, the incident, the action and the action it undoes. |
| Mapped | Addresses map as in findings. Networks keep their prefix length and endpoints their port and protocol. Account names are always mapped, system users included. |
| Replaced by `tid-<id>` | File paths, process ids and other targets. |
| Dropped | Command lines, error and reason text, undo commands, recovery paths, digests, sizes, modes and owners. |

### Firewall rows

A firewall row keeps its time, action, target, reason category, source and lease.

Firewall entries carry no ids, so nothing joins them to actions or findings. The manifest says so rather than guessing from times or addresses.

### Admission rows

Admission is the CSM path that decides whether an automatic IP block goes ahead. Its rows keep their kind and step, including the retirement of an unknown outcome (`expired_unproven`).

Admission writes two kinds of row: one audit row for each step of an attempt, and an hourly summary. The target of an admission audit row is mapped the same way as a firewall row's target, so it joins the legacy row for the same address. Its reason category names the lane the attempt was reserved in.

An hourly summary is a row that sets `count`. It names no target and keeps these fields:

- check,
- entry,
- decision,
- refusal reason and attribution cause,
- dry-run prediction,
- count,
- `epoch`.

In admission rows, these also refuse the run:

- A summary's check matches a learned account, host or domain.
- An action inspection row carries an attribution cause. An attribution cause belongs only on a refusal summary.
- A row that is not a summary carries an `epoch`. An `epoch` belongs only on a summary.

### The manifest

The manifest is written last and is the bundle's completion marker. Check every output's digest against it. A bundle without a manifest, or with a digest that does not match, is incomplete.

The manifest lists:

- every input and output with its stream kind, position, SHA-256 of the exact bytes, record count and time span,
- the tool's source revision,
- the salt fingerprint,
- join counts,
- counts of discarded fields,
- action results by value, with admission steps and decisions included, at zero when absent,
- coverage for each stream.

### How joins and results are counted

- An action is matched when it names a finding id present in the recording, and nothing more. Actions naming a finding the recording lacks, and actions naming none, are counted apart.
- Repeated finding rows are kept and counted.
- A durable action row repeated exactly is a retransmission and does not count as another outcome.
- Rows that share an action id and version but differ are reported as conflicting. They are never resolved by taking the latest.
- A result is what the writer recorded. An applied block or a firewall entry is an observation, not a verified effect or a reviewed correct action.

### Saying what the host has

`--input-manifest` takes the collector's inventory of what the host has:

```json
{"v": 1, "streams": [
  {"kind": "findings", "availability": "present", "sha256": "<digest of the copied file>", "records": 1200},
  {"kind": "actions", "availability": "not_recorded"},
  {"kind": "firewall_audit", "availability": "absent"}
]}
```

Every supplied file must appear as a present entry with its digest and record count, and every present entry must be supplied.

| Availability | Meaning |
|--------------|---------|
| `absent` | The collector looked and found none. |
| `not_recorded` | The host does not keep that stream. |

Ledger and review streams can only be stated absent or not recorded. Without an inventory, a stream that was not supplied is reported as not supplied.

## Comparing the admission preview

`compare` sets the admission preview against the automatic blocks that the legacy path, the older blocking code, applied. Admission hands each automatic response to its ledger. While the ledger only previews or forecasts, the legacy path decides every automatic block and the ledger sees the same responses.

Compare a dry-run window. Once admission executes, the legacy path does not apply the blocks that admission owns.

`compare` reads the outputs of one joined run. For each legacy automatic block in the preview window, it looks up what the preview did with the block's finding:

```bash
/tmp/finding-stream compare --findings host-a/findings.jsonl.gz --actions host-a/actions.jsonl.gz --status host-a/status.json
```

Older unstamped finding rows still supply their identifiers and checks for joins.

### The status file

`--status` takes the host's `csm status --json` output, taken at the end of the run being judged. Compare reads only two things from it:

- the ledger's ingress `generation`, which names that run,
- the admission owner's `block_entries`.

### Runs and windows

Each hourly summary names the daemon run that counted it (`epoch`). Compare reports each run apart, since a restart loses the hour in progress. Summaries recorded before they named their run are reported as one unmarked run.

A run's window spans its first to its last hourly admission summary. The hour the first one counts may have begun before the run, so it is not counted.

### The gate

Each run's part of the report ends with a gate verdict. Only the run that the status file names is judged. The gate passes once all of these hold:

- The run's window spans at least 48 hours.
- Nothing is unexplained.
- The totals of Invalid refusals and of queue overflow refusals are both zero.
- Three blocks are matched for every entry the status lists.
- Three blocks are matched for every scan check that blocked, even if a later configuration change removes scan blocking from the status.

The two three-block conditions have a time limit, and two cases never pass:

| Case | Gate |
|------|------|
| An entry is short of three matches, or is listed but never blocking | Held until the run spans seven days. If the other conditions hold, the gate then passes and names the entry unproven. |
| The run is unmarked | Never passes. |
| The comparison ran without `--status` | Never passes. |

The report ends with the verdict on the run that the status names. A pass by an earlier run does not make that run pass.

### What you must still verify

A passing gate is not the whole acceptance:

- Verify the status and metric criteria the report names. Only `csm status` and the metrics show Critical deferrals, queue evictions and the handoff latency.
- Prove collector coverage and an undamaged ledger through status and doctor before accepting the comparison as passed.
- Keep the report private. It describes one host's responses.

Give `compare` only the outputs of one joined `anonymize` run. That run already passed its leak check. `compare` checks the shape of every row, but a shape check cannot prove the rows came from that run.

### What the report lists

Anything `compare` cannot match is listed as unexplained. The report also totals Invalid and queue overflow refusals.

Output errors never repeat file paths or host data.

The matching rules are under Details:

- [How compare matches a block](#how-compare-matches-a-block)
- [Blocks around a restart](#blocks-around-a-restart)
- [Which refusals count as explained](#which-refusals-count-as-explained)
- [Summary rules and clock steps](#summary-rules-and-clock-steps)
- [What missing summaries mean](#what-missing-summaries-mean)

## What a recording does and does not contain

The audit log is the dispatch record: it holds findings that were alerted, after deduplication. It is not the persisted latest-state set. That set is larger, because every scan re-emits the findings it still sees and the merge refreshes their timestamps.

On one production host a single sweep dispatched 49 critical findings while the active set carried 157 refreshed critical rows.

A replay therefore understates how full the persisted correlation window gets. Compare windows against each other, and treat an absolute rate from a replay as a property of the replay, not of the live host.

## Replaying a stream through correlation

`scripts/correlation-calibrate` replays a recording through the production cross-account correlation. Its thresholds can then be re-derived from what hosts produced rather than from an assumption:

```bash
go run ./scripts/correlation-calibrate \
    ~/.local/share/csm/finding-streams/host-a.jsonl.gz
```

The tool needs no host access and reads nothing but the recording. It uses cPanel account roots supplied directly to correlation, without platform discovery on the replay machine.

### What it reports

The tool reports:

- how often account-and-check pairs repeat,
- which checks dominate the input,
- what the aggregates did under both derivations: per dispatch batch, and over the persisted latest-state set.

For each derivation it prints a threshold sweep using the same eligible, windowed accounts as the aggregate.

Batch correlation counts all qualifying rows grouped into that dispatch batch. Repeated pairs can include distinct findings on the same account. This metric does not establish how many rows are re-reports of the same finding.

### The window

`--window` selects the persisted correlation bound. It defaults to one hour, and `--window 0` reproduces the original unbounded correlation. Longer windows are applied directly, without the production default limiting them.

`--window` bounds only the correlation. The latest-state set that the correlation reads keeps the store's own retention and size limit.

### What the replay models

- Batch boundaries are inferred from timestamp gaps.
- Persisted correlation is recomputed at every recorded arrival, including ignored checks that only advance time.
- Raised duration is measured between those observations, not against an invented scan schedule.
- Recordings do not contain empty scans, purges or dismissals. The replay therefore models latest-state accumulation rather than reconstructing every store transition.
- Rows with no timestamp are counted and skipped because they have no replay position. Runtime correlation still counts unstamped stored rows.

## Replaying scan admission

`scripts/response-replay` replays a recording through a model of how automatic scan blocks are admitted today: the hourly block limit, the retry queue and its age limit, and eviction at the temporary deny limit.

It reports what the model would have done with the recorded findings. It does not report what the host did, or whether any block was right.

```bash
go build -o /tmp/response-replay ./scripts/response-replay
/tmp/response-replay --findings host-a/findings.jsonl.gz --out replay/host-a.json \
    --max-blocks-per-hour 200 --deny-temp-ip-limit 500 --seed 1 --hour-zone UTC \
    --manifest host-a/manifest.json
```

Like a manifest, a report needs a build of a known commit without local changes.

### Options

`--seed` chooses the order in which the model tries queued candidates. The live path tries them in Go map order. The model tries them in a reproducible random order, so compare several seeds rather than reading one run as the order the host used.

`--hour-zone` is the zone the host's clock runs in. The hourly limit resets when that zone's hour changes. `Local` is refused because it would depend on the machine running the replay.

`--php-relay-ip-recipient-mode` mirrors `email_protection.php_relay.ip_recipient_mode` and defaults to `observe`. Use `enforce` to model form-relay client responses. Observed findings never drive a response in either mode. The report records the selected mode.

`--reconstruct-reputation-source` recovers the source address of a reputation finding. See [Reputation findings](#reputation-findings).

`--manifest` makes the report check that the manifest describes this exact recording. The report then carries the manifest's coverage and recorded outcomes beside the replay. Without a manifest, the report says the recording has no statement of what was collected with it. Negative outcome and join counts are refused.

### How the model treats recorded rows

| Recorded row | What the model does |
|--------------|---------------------|
| A block from a challenge timeout, central intel, a credential spray or an incident | Applies it as recorded. It takes a firewall slot but not the hourly budget. |
| A recorded block with a malformed target | Counts it as an unclassified row. Only a single IP address is accepted as the block target. |
| A permanent block | Counts it, does not model it. |
| A row without a timestamp | Counts it and leaves it out. |

A finding keeps the severity it was recorded with. A later change in how a check grades severity is not applied. An older recording can therefore replay as blockable a finding the current build would only challenge. Every report lists this among its assumptions.

Batches are inferred from equal timestamps. Recordings hold no empty scans, so queued work drains only when another finding arrives.

The demand is the audit log's record of dispatched findings, not every finding the admission path was called with.

The first stamped row establishes the replay clock, including dates before year one.

### Reputation findings

The audit log does not record a finding's structured source address. A reputation finding names its address only in that field and in its message. By default it therefore has no address in a replay and is counted as missing one.

`--reconstruct-reputation-source` recovers the address from that message's fixed form. The report then counts the recovered rows and lists the reconstruction among its assumptions.

### What the report contains

The report lists:

- the effective policy with every default it applied,
- the counts,
- queue delay and eviction residence distributions,
- blocks per elapsed hour,
- the assumptions,
- the mechanisms the model leaves out: infrastructure and allowlist protection, verdict callbacks, subnet blocks, permanent escalation, retries and failures, and manual unblocks.

It carries no address, id, name or text from the recording.

Candidates the queue dropped (aged out or overflowed) are reported apart from work still queued when the recording ended. The end of the recording cut that work off, not the queue.

The report counts the recorded subnet, ASN-crawl, netblock, permanent and dry-run block rows the model leaves out, and the findings that feed the subnet paths. ASN-crawl subnets spend the same hourly budget the model gives single addresses, so free scan slots in a replay are an upper bound.

Hourly distributions include empty elapsed hours across the full recorded time span, without allocating a sample for each empty hour.

### How the report is written

A report is written only to a new path. It never replaces an existing file. It cannot alias its recording or manifest through symbolic links, parent-directory traversal or hard links.

The report is staged beside the resolved destination and published as a private file. If another writer creates the destination in the meantime, the run is refused. A temporary file cleanup failure is reported with whether the report was published.

## Details

This section is reference material: the exact replacement rules, the output file rules, and how `compare` matches blocks.

### How names are replaced

Names are replaced wherever they sit:

- in `/home/<account>/` paths,
- in `Account:` lines,
- in process context,
- in LiteSpeed vhost tokens,
- inside longer tokens such as `example.com-ssl_log` or `web1.log`.

| Case | What the tool does |
|------|--------------------|
| A name holding an underscore or starting with a dot, such as a bare mail login | Replaces it as a whole wherever it is not glued to a letter or digit, ignoring case. |
| Identities overlap | The leftmost complete one wins. A full mailbox or home path keeps its usual mapping. |
| A learned name made only of punctuation | Does not replace it, so it cannot turn separators into identities. The final check refuses the run if one appears. |
| The host's short name (its first label, when it carries a digit) | Maps it to the same pseudonym as the full name. |
| A raw name beginning with `host-` or `acct-` | Still scrubs it. Only pseudonyms actually emitted by this run are exempt. |

A replacement is never rewritten again.

Any other token that looks like a domain is mapped too, even if no field named it. A token looks like a domain when it has two or more labels and an alphabetic last label that is not a file extension. That over-reaches on a few dotted names like `options.option` and is accepted.

Domain-shaped names inside filenames are replaced even when no structured field named them.

### How addresses are replaced

The IPv4 range holds 131,072 addresses, so distinct addresses can share a pseudonym. A manifest counts distinct addresses and distinct pseudonyms per family. A replay cannot tell merged addresses apart.

Equivalent IPv6 spellings share one pseudonym across all streams. IPv4 addresses written in IPv6 form use the IPv4 pseudonym.

Addresses inside filenames and before numeric rotation suffixes are also replaced. This can replace address-shaped version numbers. Privacy takes priority over preserving ambiguous numeric text.

New audit rows can carry a `cidrs` list. Those addresses use the same pseudonyms as addresses in text, keep their prefix lengths, and participate in the output leak check. Older audit rows remain readable without the list.

### How outputs are written

Outputs cannot replace an input, the salt, the input manifest or each other. This holds whether the file is named by path, through a symlinked directory or as a hard link. An existing output must be a regular file.

These checks run before the salt is created, including for missing directories and paths containing `..`. Two more kinds of path are refused on every platform:

- case-only and Unicode-equivalent path variants,
- paths that would need a file to also serve as a directory.

Every output is written to a private temporary file beside its destination. All are complete before any is renamed into place. If publishing fails partway, the outputs already replaced are restored.

New directories have mode 0700 and outputs mode 0600, even when replacing a less restricted file.

### When cleanup fails

Filesystem cleanup failures are reported without claiming success.

| Failure | What happens |
|---------|--------------|
| Rollback fails | The remaining recovery copies are retained. |
| Every output was published but backup cleanup fails | The error explicitly says the outputs were published. Check the manifest and remove the leftover backups before sharing the directory. |
| Any other cleanup error | The error reports unchanged outputs, with temporary files left to remove. |

### How compare matches a block

A block is matched by one observed attempt for the same finding, response kind and typed target within an hour. A scan block retried from the pending queue may land later, until its retry ages out two hours after it was queued.

A step is one admission audit row. A decision is what an hourly summary counts.

Spray blocks match through their own entries:

- the incident spray block of one address through `incident_spray`,
- the mail spray subnet block through `mail_subnet`.

Matching can reassign compatible decisions when their windows overlap. Each step explains at most one legacy row across all runs.

Observed steps and coalesced decisions are matched before designed refusals. Designed refusals are the attribution and policy refusals listed under [Which refusals count as explained](#which-refusals-count-as-explained). They explain discrepancies but do not satisfy coverage.

Coalesced decisions and designed refusals each spend one summary count from their own run for the same entry, kind and check in the same or an adjacent hour. Summary matches are aggregate lower bounds, not proof about one finding.

### Blocks around a restart

An unused step from before a restart may still explain a pending retry.

The same legacy row in a shared boundary hour needs only one step, even when both run reports include it.

A block the old process made in the hour of a restart also falls in the next run's window. When the earlier run's own summaries explain it, the next run reports it as explained by another run, and it adds no coverage there.

When both runs can explain several boundary blocks, matching assigns distinct rows before spending spare counts on rows already explained by the other run. Each run still spends only its own counts and earns coverage only from its own matches.

### Which refusals count as explained

| Refusal | Explains only |
|---------|---------------|
| Attribution | Scan-pass provenance gaps for checks served through the matching entry. |
| Policy | Netblock, permanent-block escalation, challenge timeout, incident or incident spray paths without a retained root. |

A rootless derived path may spend its fixed unknown-check policy count without a finding link. Rootless designed-refusal matches consume aggregate counts and provide no finding join.

Other policy and attribution refusals stay unexplained.

### Summary rules and clock steps

Summaries must be stamped at an hour boundary, and only refused decisions may carry a refusal reason. Counts that overflow refuse the comparison.

Hourly aggregation cannot prove the exact event delay. A backward wall step clamps counts to the admission hour floor. Larger clock disagreement stays unexplained and must be checked through clock status.

### What missing summaries mean

Summary retention discards whole oldest hours after failed writes exceed its bound. Missing summaries may mean idle hours, failed writes or a crash. They cannot certify coverage.
