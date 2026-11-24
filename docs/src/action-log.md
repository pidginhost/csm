# Action log

The [audit log](audit-log.md) records what CSM found. The action log records what CSM did. Every action gets one record, in one file with one schema, whether it came from the daemon, an operator command or the Web UI.

```
/var/log/csm/actions.jsonl
```

## Reading the log

```bash
csm actions                      # recent actions, one line each
csm actions --since 24h          # RFC 3339 timestamp or a duration
csm actions --op respond.block_ip
csm actions --json               # the raw records
csm action show <action_id>      # one admission response and its attempts
```

`csm actions` lists what was recorded. `csm action show` looks up one automatic response; see [Looking up one response](#looking-up-one-response).

## Schema

Each line of the file is one JSON record.

```json
{
  "v": 1,
  "ts": "2026-09-09T10:32:14.512938Z",
  "hostname": "host.example.com",
  "op": "respond.quarantine_file",
  "actor": "daemon",
  "finding_id": "8e3f1c204c1d8b95",
  "target": "/home/alice/public_html/uploads/x.php",
  "account": "alice",
  "reason": "webshell_realtime",
  "before": {"exists": true, "sha256": "5f2b...", "size": 1841, "mode": "-rw-r--r--", "uid": 1001, "gid": 1001},
  "after": {"exists": false},
  "result": "applied",
  "recovery_path": "/opt/csm/quarantine/2026-09-09T10-32-14-x.php"
}
```

| Field | Meaning |
|---|---|
| `op` | The privileged operation, using the IDs from the [capability matrix](capability-matrix.md). The matrix says what an operation may do; this says what it did. |
| `action` | The specific change within an operation, such as `block`, `unblock`, `apply` or `rollback`. |
| `actor` | `daemon`, `cli` or `webui`. `actor_detail` carries the operator's source address or the command name. |
| `finding_id` | The finding that caused the action, using the same ID the audit log emits, so the two streams join. |
| `command` | The exact argv when CSM ran a program. Absent when the action used system calls only. |
| `before` / `after` | The target file's digest, size, mode and owner around the change. `"exists": false` after a quarantine is the record that the file is gone. |
| `result` | `applied`, `dry_run`, `failed` or `refused`. A dry-run record says what CSM would have done. |
| `undo` | A command that reverses the action, when an exact inverse is available. |
| `recovery_path` | Retained quarantine content or a pre-clean backup, with a `.meta` sidecar. Use the quarantine recovery workflow; `csm restore` accepts state archives, not these files. |

`v` is the schema version. It is bumped only on an incompatible change, so a parser can pin on `v: 1` and ignore unknown keys.

### Which attempts get a record

- Attempted operations are recorded, including failures and safety refusals.
- An already blocked address does not produce another applied record.
- A successful file replacement or quarantine with a later warning stays visible with its recovery path.

A refused action is recorded too. "The safety rules stopped this" and "CSM never looked" are different operational states, and only one of them is a reason to change the configuration.

### Who the actor is

`actor` uses the caller's attribution when available. Otherwise it identifies the process performing the action. Some Web UI requests therefore record as `daemon`. The Web UI's own action log retains the operator's source address.

### Truncated text

Long reasons and error messages are truncated with an explicit marker, so one action cannot make the history unreadable. Targets and command arguments are preserved.

### File digests

| Target | Digest |
|---|---|
| A file larger than 64 MiB | Recorded without a digest, so hashing does not stall the action. |
| A quarantined file | Taken from the captured copy, after the move. |
| A cleaned file | Describes the exact bytes CSM read and the exact bytes it installed. |
| A directory or symlink | No digest. |

## What is covered

The [capability matrix](capability-matrix.md) has an "Action record" column. That column is the authoritative list. These operations write here today:

- Firewall blocks and unblocks, both automatic and operator.
- Whole-ruleset changes.
- File quarantine.
- Surgical file cleaning.
- Process termination.
- Mailbox suspension and the account-wide outgoing mail hold. A hold record carries the quoted `whmapi1 release_outgoing_email` command that lifts it.
- An operator's release of a suspension or a hold (`operate.release_mailbox`), with one record per part undone.
- Lifting Stalwart's ban of an address unblocked in CSM (`operate.clear_stalwart_ban`), with one record per ban.
- Each undo of a Server Hardening fix that reaches the root worker (`operate.undo_hardening`), with one record per undo, refused ones included. Applying fixes does not write here.

Everything else appears in the daemon log only. Tests exercise the operation paths, including failures and concurrent blocks.

### Firewall records

The firewall keeps its own audit file because the Web UI and the API read it. Its entries also appear here. Dry-run decisions, failed attempts and whole ruleset apply/rollback records are recorded directly on this stream. Startup rollback records are written before the daemon requests a restart.

## Admission records

Admission is the part of CSM that decides whether an automatic response, such as an IP block, goes ahead. It keeps a ledger: a stored record of the responses it admitted and what happened to each. Admission records in the action log describe each step of one admitted response.

| Field | Value in an admission record |
|---|---|
| `op` | `respond.block_ip` |
| `action` | The kind of response: `block_ip`, `block_subnet`, `block_service`, `promote` or `challenge`. |
| `target` | The canonical target of the response. |
| `reason` | The lane and the absolute expiry. |
| `result` | The step: `reserved`, `executing`, then `applied`, `narrowed`, `failed` or `unknown`. |
| `action_id` | Names the attempt. |
| `action_version` | Names the step. |

A record is written durably before the ledger lets it go, so after a crash it can appear twice. Drop a copy whose `action_id`, `action_version` and `ts` match another.

### Which steps appear

Which steps a response takes depends on the mode the ledger runs in.

| Mode | What the ledger does |
|---|---|
| `auto_response.dry_run` false, the firewall on, outside observe mode | It executes. An admitted IP block takes the steps above. |
| Dry run, with the firewall on and outside observe mode | It forecasts block responses instead of previewing them. Their terminal outcomes are counted in the ledger without a new per-attempt action-log row. |
| Any other case | It previews each response it is handed. An admitted response is `reserved` and then `observe`, and is never executed. |

The bounded forecast examples and the summaries are separate from these records.

### Looking up one response

`csm action show <id>` asks the daemon what the ledger holds on one response. The ID is the `action_id` of an admission record or the response's candidate ID. The command needs a running daemon and never changes admission or firewall state.

It prints JSON with three parts:

- The candidate: its kind, target, check, state, reason, outcome and expiry.
- Each attempt, with its lane, reservation, finish and outcome.
- For a response refused because a block already enforced it, that block's action and end (`link`).

| Case | What the command reports |
|---|---|
| The response's history has retired, or the response was never admitted | Not recorded. |
| A retired attempt that is still retained | Its unknown outcome and `retired: true`. Retirement is not proof of success. |
| A retained candidate is missing an earlier attempt | Ledger damage. The command does not claim the missing part aged out, and does not return a truncated history. |

Retention removes a candidate and all its attempts together.

The command offers no resolve, retry or undo operation. Durable firewall actions remain under `csm firewall actions`. The `admission.action_show.v1` capability advertises this local read command. It does not indicate that automatic execution is on.

The exact output fields are in [Fields of `csm action show`](#fields-of-csm-action-show). Each lookup is itself recorded; see [How a lookup is recorded](#how-a-lookup-is-recorded).

### Hourly summaries

Once an hour the ledger owner, the part of the daemon that runs the ledger, appends `respond.block_ip` summary records. They count its decisions on the responses handed to it during the hour ending at `ts`. A summary names no target.

| Field | Meaning in a summary |
|---|---|
| `count` | How many responses the summary covers. |
| `action` | The kind of response. |
| `reason` | The check that asked for the response. |
| `actor_detail` | The entry the response came through: `scan`, or a derived entry such as `challenge_timeout` or `central`. |
| `result` | The decision: `queued`, `coalesced`, `observe` or `refused`. |
| `error` | The refusal reason. |
| `cause` | Why an `attribution` refusal happened. See [Attribution refusal causes](#attribution-refusal-causes). |
| `epoch` | The daemon run that counted the summary. The number rises at every start of the owner, so summaries of two runs never share one. |

A clean stop writes the open hour early, so one hour can have several summaries that add up. A crash loses the open hour, so the counts are lower bounds.

The exact counting rules are in [What the summaries count](#what-the-summaries-count).

### Dry-run predictions in summaries

An owner that runs automatic blocks and forecasts them in dry-run mode also counts `dry_run` decisions. Each one has a `prediction` of what live admission would have done:

`capacity_admit`, `existing_actual`, `existing_shadow`, `ceiling`, `set_full`, `pending_recovery`, `forecast_limited`, `not_modelled`, `capacity_evict`, `capacity_rotate` or `equal_tier_wait`.

A prediction is not a refusal reason.

### Attribution refusal causes

An `attribution` refusal also names its `cause`.

| `cause` | Meaning |
|---|---|
| `no_observation` | No reader stamped the finding. |
| `kind_not_allowed` | No parser vouched for the address in a way the check accepts. |
| `target_mismatch` | The response names an address its evidence does not attribute. |
| `unreachable` | The address is a client behind a trusted proxy, so it sends this host no packets of its own. This includes an address the web peer log shows behind a trusted proxy. |
| `proxy_peer` | The address is a known CDN or website-firewall edge, which carries many visitors. This applies even when a forwarded client header names it. |
| `rewritten_log` | The web server replaced the logged client address, or CSM could not read its configuration, so the connecting peer is unknown. |
| `forged_client` | The web peer log shows the request came from a peer that is neither the address nor a trusted proxy. That peer chose the address. |
| `writable_log` | The address came from an SSH, mail or FTP line read from a syslog file. Any local user can write such a file under any program name. |

For an HTTP finding, `proxy_peer` is named before `rewritten_log`, and `rewritten_log` before `no_observation`.

A `challenge_timeout` refusal names the check and cause that left its challenge without a root. A refusal keeps the same cause whether it happens when the evidence is created, at submission or at queue placement.

### Findings read from syslog files

A finding with the `writable_log` cause follows these rules:

- It remains alert-only, even while admission is unavailable or not applying blocks.
- A threat-feed match does not make its address blockable.
- A subnet block is refused when its summary finding, or any address counted in it, came from a syslog file.
- Incidents retain this refusal through storage and timeline trimming.
- Derived responses retain it at every block lifetime.

A line read from the journal can become evidence for a response. A line read from a syslog file cannot.

## Rotation

The file rotates to `actions.jsonl.1` at 10 MB. `csm actions` reads both files. Readers and writers coordinate rotation through `actions.jsonl.lock`, so rotation cannot hide records and a slow reader does not hold up a writer.

CSM handles this rotation itself. The installed logrotate configuration leaves the live file alone. It archives `actions.jsonl.1`, which CSM never writes to again, for 90 days. Older history is compressed there and `csm actions` does not read it. Ship the stream to a SIEM if you need it queryable.

## Recording is best effort

The stream is not a transactional guarantee that every host change survives a crash.

- Sink errors or panics do not change an action's outcome.
- A write waits at most 250 ms, with at most 64 writes outstanding. A stalled sink or saturation can lose records.
- Normal CLI writes finish before the command exits.

Keep this log on a local filesystem and monitor write-error warnings.

## Details

The sections below are reference material for parsers and edge cases. You do not need them to read the log day to day.

### Fields of `csm action show`

The command uses `candidate_id` for the candidate and `attempts[].action_id` for each attempt, matching the action log's `action_id`. It never uses the log's `action` operation field for an identifier. Times use RFC 3339.

| Top-level field | Present |
|---|---|
| `candidate_id`, `kind`, `target`, `state` | Always. |
| `check`, `finding_id`, `reason`, `disposition`, `link` | Optional. |
| `expires_at` | Optional. Omitted candidate expiry means no expiry was assigned. It is not a permanent block. |
| `attempts` | Always an array, including when empty. |

`link.effect` identifies the existing block. An omitted `link.expires_at` means that block is permanent.

| Attempt field | Present |
|---|---|
| `action_id`, `seq`, `state`, `reserved`, `expires_at` | Always. |
| `disposition`, `lane`, `finished` | Optional. |
| `retired` | Only when true. |

### How a lookup is recorded

Each `csm action show` read is audited in the action log:

- The record has `op: respond.block_ip`, `action: show`, `actor: cli` and `actor_detail: csm action show`.
- `target` is the requested ID.
- `result: read` means the lookup succeeded, never that a block was applied.
- A failed lookup uses `result: failed` and `error`.

These read records have no lifecycle `action_id` or transition version. They go through the ordinary bounded, best-effort action log, outside the admission outbox, so a sink failure does not disable the diagnostic read.

The finding-stream exporter accepts these records as reads. It salts their targets as opaque references and drops error text. They cannot claim a block was applied.

### What the summaries count

| Case | How the summaries count it |
|---|---|
| A queued response that a later check refuses | `refused`, with its reason and cause, in the hour the ledger ended it. |
| A displaced queued response | Also counts once. |
| A refused preview | `refused`, with its reason. |
| A submission displaced from the memory queue | `refused`, with its reason, including every report merged into the displaced submission. |
| A block the owner runs while it executes | Shows only in its attempt rows; see [Admission records](#admission-records). The summaries count a live block pick only when the ledger refuses it at its recheck or reservation. |
| A batch the firewall engine refuses while applying it | No `refused` row. It shows in its attempt's outcome. |
| A pick the panel verdict callback allows | No `refused` row. It shows in the log and in the `verdict` counters of status. |

The later checks that can refuse a queued response are:

- its revalidation,
- an inventory refresh,
- a configuration opt-out,
- a lost queue position after reassessment,
- the recheck of a pick before an attempt or a preview.

### Summary timing and outages

- A late refusal row retains the hour the ledger ended the response, even after a newer hour was reported.
- Hours discarded when a logging outage exhausts summary retention stay discarded. Later refusals for them never return as partial summaries.
- Summaries continue while the ledger or its clock is unavailable.
- Stopping flushes completed decisions even if the final drain fails.
- A summary's hour never precedes the latest recorded admission hour, including clock readings from an incomplete startup.
