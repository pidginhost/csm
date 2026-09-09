# Action log

The [audit log](audit-log.md) records what CSM *found*. The action log records
what CSM *did*: one record per action, one file, one schema, whether the action
came from the daemon, an operator command or the web UI.

```
/var/log/csm/actions.jsonl
```

```bash
csm actions                      # recent actions, one line each
csm actions --since 24h          # RFC 3339 timestamp or a duration
csm actions --op respond.block_ip
csm actions --json               # the raw records
```

## Schema

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

Attempted operations include failures and safety refusals. An already blocked
address does not produce another applied record. A successful file replacement
or quarantine with a later warning stays visible with its recovery path.

A refused action is recorded too. "The safety rules stopped this" and "CSM never
looked" are different operational states, and only one of them is a reason to
change the configuration.

`v` is the schema version. It is bumped only on an incompatible change, so a
parser can pin on `v: 1` and ignore unknown keys.

Long reasons and error messages are truncated with an explicit marker so one
action cannot make the history unreadable. Targets and command arguments are
preserved.

A file larger than 64 MiB is recorded without a digest rather than stalling the
action while it is hashed. Quarantine digests come from the captured copy,
after the move. Cleaning digests describe the exact bytes read and installed
through the pinned file handles. Directories and symlinks have no digest.

## What is covered

The [capability matrix](capability-matrix.md) has an "Action record" column.
Six operations write here today: firewall blocks and unblocks (automatic and
operator), whole-ruleset changes, file quarantine, surgical file cleaning, and
process termination. Everything else appears in the daemon log only. The column
is the authoritative list. Tests exercise the operation paths, including
failures and concurrent blocks.

The firewall keeps its own audit file because the web UI and the API read it.
Its entries also appear here; dry-run decisions, failed attempts and whole
ruleset apply/rollback records are recorded directly on this stream.
Startup rollback records are written before the daemon requests a restart.

`actor` uses the caller's attribution when available and otherwise identifies
the process performing the action. Some web UI requests therefore record as
`daemon`; the web UI's own action log retains the operator's source address.

## Rotation

The file rotates to `actions.jsonl.1` at 10 MB. `csm actions` reads both.
Readers and writers coordinate rotation through `actions.jsonl.lock`.
Readers pin both files before releasing the lock, so rotation cannot hide
records and a slow reader does not hold up a writer.
CSM handles this rotation itself; the installed logrotate configuration leaves
the action log alone.

Recording is best effort. Sink errors or panics do not change an action's
outcome. A write waits at most 250 ms, with at most 64 writes outstanding; a
stalled sink or saturation can lose records. Normal CLI writes finish before
the command exits. Keep this log on a local filesystem and monitor write-error
warnings. The stream is not a transactional guarantee that every host change
survives a crash.
