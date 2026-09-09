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
  "undo": "csm quarantine restore 2026-09-09T10-32-14-x.php"
}
```

| Field | Meaning |
|---|---|
| `op` | The privileged operation, using the IDs from the [capability matrix](capability-matrix.md). The matrix says what an operation may do; this says what it did. |
| `actor` | `daemon`, `cli` or `webui`. `actor_detail` carries the operator's source address or the command name. |
| `finding_id` | The finding that caused the action, using the same ID the audit log emits, so the two streams join. |
| `command` | The exact argv when CSM ran a program. Absent when the action used system calls only. |
| `before` / `after` | The target file's digest, size, mode and owner around the change. `"exists": false` after a quarantine is the record that the file is gone. |
| `result` | `applied`, `dry_run`, `failed` or `refused`. A dry-run record says what CSM would have done. |
| `undo` | The command that reverses the action, when one exists. |

A refused action is recorded too. "The safety rules stopped this" and "CSM never
looked" are different operational states, and only one of them is a reason to
change the configuration.

`v` is the schema version. It is bumped only on an incompatible change, so a
parser can pin on `v: 1` and ignore unknown keys.

A file larger than 64 MiB is recorded without a digest rather than stalling the
action while it is hashed.

## What is covered

The [capability matrix](capability-matrix.md) has an "Action record" column.
Six operations write here today: firewall blocks and unblocks (automatic and
operator), whole-ruleset changes, file quarantine, surgical file cleaning, and
process termination. Everything else appears in the daemon log only. The column
is the authoritative list, and a test pins it, so it cannot claim coverage that
was not wired.

The firewall keeps its own audit file because the web UI and the API read it.
Every entry it records also appears here.

`actor` says which process performed the action. Actions an operator starts in
the web UI run inside the daemon, so they record as `daemon` here and carry the
operator's source address in the web UI's own action log.

## Rotation

The file rotates to `actions.jsonl.1` at 10 MB. `csm actions` reads both.
