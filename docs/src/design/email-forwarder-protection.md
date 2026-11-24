# Email Forwarder Protection and Visibility: Design and Roadmap

Status: shipped. This page is the design that the forward guard, the held-copy quarantine and its retention prune were built from. The forward guard holds spam and bounces before a forwarder relays them to an external mail provider. The configuration keys below are documented in [configuration](../configuration.md).

Date: 2026-06-07. Owner: CSM mail subsystem.

## Problem

cPanel/exim servers run many account forwarders that blindly relay inbound mail to external free providers (Yahoo, Gmail, Outlook). That mail includes spam and null-sender bounces. The harm builds in steps:

1. Forwarding spam to those providers generates complaints and damages the sending IP reputation.
2. The provider then defers all mail from the IP. Observed: Yahoo `421 4.7.0 [TSS04] ... unexpected volume or user complaints`, thousands of deferrals/day.
3. The queue fills with retrying forwards and backscatter.
4. Legitimate mail is delayed.

Before this work, operators had no view of:

- Which forwarders exist.
- Where they point.
- How much each contributes to the queue.
- Which outbound IPs are being throttled by which providers.

They also had no control to stop relaying spam externally.

## Goal / non-goals

The design has two goals:

- Full operator visibility: every forwarder, its destination, owner, queue impact, and the outbound-IP reputation picture.
- Opt-in protection that holds spam and backscatter before it is relayed to an external provider. This protects outbound IP reputation, with no risk of losing legitimate mail.

The design leaves these out:

- It is not a general inbound spam filter. SpamAssassin owns local-delivery scoring.
- It is not an MTA replacement. CSM observes, supplies data, and manages the quarantine and the UI.
- It does not auto-delete or auto-disable forwarders without operator action.

## Approved decisions

### Enforcement action

The external-forward copy is held in a CSM-owned quarantine. The local copy is always kept or delivered. Held mail is recoverable through an operator release, so false positives mean review, not loss.

### What to hold

The signals are layered: any match holds the message. Each signal can be toggled on its own.

- SpamAssassin flagged the message as spam.
- ClamAV or YARA-X reported a malware hit.
- The message is a null-sender `<>` bounce (backscatter).
- The sender IP is present in the CSM attack DB or reputation data.
- SPF, DKIM and DMARC all fail.

### Rollout

- A single global toggle, default OFF.
- A dry-run mode that only logs and accounts, and holds nothing.
- The existing `known_forwarders` list, reused as a skip-list for trusted relays.

### Visibility surfaces

All of these are included:

- Forwarder table.
- Outbound-IP reputation panel.
- Per-provider deferral rollup.
- Queue composition breakdown.
- Per-forwarder spam/volume trend.

### Build phases

The build is phased: visibility first (read-only, low risk), enforcement second (opt-in), breadth third (postfix and non-cPanel).

## Core architectural decision: CSM is NOT in the live mail path

The MTA performs the hold natively. CSM only does three things:

- It generates the MTA config and a reputation lookup file.
- It watches the quarantine.
- It renders visibility and handles release and delete.

The reason is production safety. If CSM is down or crashes, mail must still flow. CSM must never be a delivery dependency.

The MTA evaluates the layered signals itself. exim has native SPF/DKIM/DMARC/spam variables, a null-sender test, and an `lsearch`/`cdb` lookup against a CSM-maintained bad-IP file. CSM generates the rule and the MTA enforces it.

The failure posture has three parts:

- Any error in the MTA rule path must `defer`, so exim retries. It must never silently drop.
- CSM-generated config is idempotent and reversible: `Remove()` restores normal forwarding.
- The config survives cPanel exim rebuilds by using the cPanel-preserved advanced-configuration include sections.

## Components (platform-abstracted, OSS-minded)

The components live in a new package tree, `internal/mailfwd/`.

### `inventory`

`inventory` enumerates forwarders cross-platform and returns a normalized `Forwarder` list. The source is selected via `internal/platform`.

- On cPanel the source is `/etc/valiases/*`. Reuse the existing `ParseValiasEntries` / `IsExternalDest` from `internal/checks/forwarder.go` and `internal/daemon/forwarder_parse.go`.
- On non-cPanel hosts the sources are `/etc/aliases`, `~/.forward` and postfix `virtual`.

### `intel`

`intel` parses `exim_mainlog` for:

- Per-destination-provider deferrals with reason codes (TSS04 etc.).
- Per outbound-IP reputation: who is deferring it.
- Queue composition: bounce vs real, per-recipient, oldest, frozen.

Reuse `eximQueueSize` / `eximQueueDetails` in `internal/webui/email_api.go`.

### `policy`

`policy` is the single source of truth for the layered verdict. It has one function:

`Verdict(msg MessageMeta, cfg ForwardGuardConfig) (hold bool, reasons []string)`

Both the dry-run accounting and the rendered MTA rule use it. The MTA rule is generated from the same policy definition, so the two cannot drift.

### `adapter`

`adapter` is the interface `ForwardGuard { Apply(Policy) error; Remove() error; Status() (GuardStatus, error) }`. Adapters are idempotent and reversible.

The exim adapter comes first. It renders the router, the transport and the bad-IP lookup, reloads exim, and writes to the cPanel-preserved include. The postfix adapter comes later.

### `quarantine`

`quarantine` is a CSM-owned maildir for held forwards. It offers release (re-inject via the platform sendmail), delete, and per-forwarder held counters. It mirrors the existing `internal/emailav` quarantine and webui pattern (`apiEmailQuarantineList` / `apiEmailQuarantineAction`).

### Web UI

The Web UI work extends the existing `/email` page (`handleEmail`, `internal/webui/email_api.go`, `email_groups.go`). New read endpoints go under `requireRead`. Mutating actions go under `requireAuth + requireCSRF`, the existing pattern.

## Config

The settings extend `EmailProtection` in `internal/config/config.go`. Two rules apply:

- Remember the three-places rule: `DefaultConfig`, the installer template and the packaging `csm.yaml.default`. A CI drift test enforces it.
- Use presence checks (`yamlPathExists`) where a literal 0/false must be distinguishable from unset.

```yaml
email_protection:
  forward_guard:
    enabled: false          # master switch, default off
    dry_run: true           # log/account only, hold nothing
    hold_signals:
      bounce_backscatter: true
      spam_flagged: true
      malware: true
      bad_sender_ip: true
      auth_fail: true
    quarantine_retention_days: 14
```

### When CSM applies the settings

On cPanel hosts in enforce mode, CSM applies these settings at startup and on config reload.

| Case | What CSM does |
|------|---------------|
| A change fails | CSM retries it on the next 15-minute lookup refresh, using the latest settings. |
| A change waits for another CSM change to the Exim configuration, such as an antispam one | CSM logs it as deferred, not as a failure, and retries it the same way. |

Every CSM change to the Exim configuration takes one lock, the Exim lock. CSM waits up to one second for that lock, both before it records a change and before a worker starts one. A brief hold of the lock by another change therefore does not defer a change.

### Reloads, shutdown and startup

- A reload never waits for a forward-guard change. The change runs in the background.
- Reloads that arrive while a change runs are applied right after it, with the latest settings.
- Shutdown lets the running change finish and discards queued reloads.
- Startup applies the saved settings.

### Removing the guard

- Disabled and dry-run settings start no removal worker when no guard is installed.
- While another CSM change to the Exim configuration runs, even one started before a daemon restart, the removal is deferred the same way.

### Workers and request records

- CSM records each change before its worker starts.
- A worker whose change has been superseded, such as one started before a restart, changes nothing.
- Each submission has a distinct identity, even when its settings and sender list match an earlier submission.
- A delayed worker cannot replace a sender list refreshed since the newer submission.
- If its request record is missing or unreadable, the worker leaves the installed guard untouched.
- Request records are readable by root only. The Exim configuration and the bad-IP lookup stay readable by the mail transport user.

### Observe mode and hosts without cPanel

- Observe mode and hosts without cPanel leave the installed guard untouched.
- In observe mode CSM only cancels pending changes.
- Cancellation does not wait for another Exim transaction to finish.
- A worker that has already checked its request under the Exim lock finishes its transaction. Later workers cannot apply canceled requests.

## Web UI surfaces (email page)

### Forwarder table

Each row shows:

- Source -> destination(s).
- A provider badge (yahoo/gmail/outlook/external/local).
- The owner (cPanel user).
- Keep-local vs forward-only.
- The queued/stuck count.
- The held-or-would-hold count.
- A status (e.g. "Yahoo throttling").

The row actions are: disable forwarder, add to skip-list, view held.

### Other surfaces

| Surface | What it shows |
|---------|---------------|
| Outbound-IP reputation panel | Per sending IP: provider deferrals, parsed reason codes and throttle state. |
| Per-provider deferral rollup | Per provider: queued, throttle and % of queue. |
| Queue composition | Bounce vs real, top stuck recipients, oldest/frozen, and a one-click flush of backscatter. |
| Held forwards | The quarantine list with release/delete (phase 2). |

## Safety / OSS

- The guard is off by default, starts in dry run, and has a skip-list for trusted relays.
- Enforcement is MTA-native, so it fails open: CSM being down never blocks mail.
- MTA rule errors `defer`, never drop.
- Platforms are covered through adapters, exim/cPanel first. The capability flag is `mail.forward_guard.v1` in `internal/health/capabilities.go`.
- All mutating actions are audit-logged and fully reversible.
- Committed code, tests and docs carry no private hostnames or IPs. Use RFC 5737/3849 addresses.

## Testing

| Area | Tests |
|------|-------|
| `policy.Verdict` | Table-driven over each signal, combinations, skip-list, and dry-run on/off. Real assertions. |
| inventory parsers | Fixtures per platform, plus a fuzz target for attacker-controlled valias/aliases/.forward content. |
| adapter | Render-to-golden exim config. Idempotent apply/remove. On a reload failure, a no-op rollback with no half-applied state. |
| intel parsers | Real-format exim deferral lines (TSS04, Gmail, Spamhaus), plus fuzz. |
| quarantine | Release re-injects correctly. Retention prune. Per-forwarder counts. |

No live-mail tests run on production. Cross-compile and vet locally, then verify on scratch hosts (fresh Ubuntu + AlmaLinux).

## Roadmap

Each item is its own spec slice, plan, TDD cycle, review and MR.

### Phase 1: visibility (read-only, ship first)

1. `mailfwd/inventory`: cross-platform forwarder enumeration + unit/fuzz tests.
2. Email-page forwarder table + API (source/dest/provider/owner/keep-local).
3. `mailfwd/intel`: outbound-IP reputation + per-provider deferral rollup (exim_mainlog parse) + the two panels.
4. Queue composition panel + one-click backscatter flush action.
5. Dry-run `policy` engine: per-forwarder "would-hold" accounting surfaced in the table (no enforcement yet).

### Phase 2: enforcement (opt-in)

6. Config schema + settings-page toggles + validation/defaults (three-places).
7. `policy` -> exim `adapter`: router + transport + bad-IP lookup; idempotent apply/remove; cPanel-rebuild survival.
8. `mailfwd/quarantine` for held forwards + release/delete + per-forwarder held counts.
9. Live enforcement wiring (dry-run -> enforce), audit log, findings, capability flag.

### Phase 3: breadth

10. postfix adapter (non-cPanel hosts).
11. Reputation aids: provider feedback-loop hints, SRS guidance, delisting checklist surfaced to the operator.

## Existing code to reuse (do not reinvent)

| Where | What to reuse |
|-------|---------------|
| `internal/checks/forwarder.go` | `ParseValiasEntries`, `IsExternalDest`, `IsPipeForwarder`, `parseLocalDomainsContent`. |
| `internal/daemon/forwarder_parse.go` | `parseValiasFileForFindings`, `checks.IsKnownForwarder`; the live `ForwarderWatcher`. |
| `internal/webui/email_api.go` | `apiEmailStats`, `eximQueueSize`, `eximQueueDetails`, `topMailSenders`, and the quarantine list/action handlers. |
| `internal/webui/email_groups.go` | Email-page grouping + sort. |
| `internal/config/config.go` | The `EmailProtection` struct and `KnownForwarders`. |
| `internal/emailav` | The quarantine model + spool watcher (ClamAV/YARA). |
| `internal/platform` | The OS/panel/path/MTA abstraction. |
| `internal/health/capabilities.go` | Capability flags. |

## Conventions

- Production-grade, no shortcuts.
- TDD for security-relevant logic: write the test first.
- `go test ./... -race`, `golangci-lint`, `go vet` and `govulncheck` are clean before a push.
- gosec annotations need a real reason.
- A CHANGELOG entry (1-2 sentences, plain English, no internals) goes in the same commit as a behavior change.
- One conventional-commit subject per commit, no Co-Authored-By.
- Branch off main. Never push or open an MR without explicit instruction.
- Each item gets a review, then a self-review: read each changed file end to end.
- Platform paths go only through `internal/platform`.
- Never allowlist scan paths.
