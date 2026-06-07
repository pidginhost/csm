# Email Forwarder Protection and Visibility -- Design and Roadmap

Status: approved design, ready to implement.
Date: 2026-06-07.
Owner: CSM mail subsystem.

## Problem

cPanel/exim servers run many account forwarders that blindly relay inbound
mail -- including spam and null-sender bounces -- to external free providers
(Yahoo, Gmail, Outlook). Forwarding spam to those providers generates
complaints and tanks the sending IP reputation. The provider then defers all
mail from the IP (observed: Yahoo `421 4.7.0 [TSS04] ... unexpected volume or
user complaints`, thousands of deferrals/day), the queue fills with retrying
forwards and backscatter, and legitimate mail is delayed.

Operators today have no view of which forwarders exist, where they point, how
much each contributes to the queue, or which outbound IPs are being throttled
by which providers -- and no control to stop relaying spam externally.

## Goal / non-goals

Goal:
- Full operator visibility: every forwarder, its destination, owner, queue
  impact, and the outbound-IP reputation picture.
- Opt-in protection that holds spam/backscatter before it is relayed to an
  external provider, protecting outbound IP reputation, with no risk of losing
  legitimate mail.

Non-goals:
- Not a general inbound spam filter (SpamAssassin owns local-delivery scoring).
- Not an MTA replacement. CSM observes, supplies data, manages quarantine + UI.
- Not auto-deleting or auto-disabling forwarders without operator action.

## Approved decisions (from brainstorming)

1. Enforcement action: hold the external-forward copy in a CSM-owned
   quarantine, always keep/deliver the local copy. Held mail is recoverable
   (operator release), so false positives mean review, not loss.
2. What to hold (layered signals, any match -> hold), each individually
   toggleable:
   - SpamAssassin spam-flagged,
   - ClamAV / YARA-X malware hit,
   - null-sender `<>` bounce (backscatter),
   - sender IP present in CSM attack DB / reputation,
   - SPF + DKIM + DMARC all fail.
3. Rollout: single global toggle, default OFF; dry-run mode (log/account only,
   hold nothing); reuse existing `known_forwarders` as a skip-list for trusted
   relays.
4. Visibility surfaces (all included): forwarder table, outbound-IP reputation
   panel, per-provider deferral rollup, queue composition breakdown,
   per-forwarder spam/volume trend.
5. Build phased: visibility first (read-only, low risk), enforcement second
   (opt-in), breadth (postfix/non-cPanel) third.

## Core architectural decision: CSM is NOT in the live mail path

The MTA performs the hold natively. CSM only (a) generates MTA config + a
reputation lookup file, (b) watches the quarantine, (c) renders visibility and
handles release/delete.

Rationale (production safety): if CSM is down or crashes, mail must still flow.
CSM must never be a delivery dependency. The MTA evaluates the layered signals
itself -- exim has native SPF/DKIM/DMARC/spam variables, a null-sender test,
and an `lsearch`/`cdb` lookup against a CSM-maintained bad-IP file. CSM
generates the rule; the MTA enforces it.

Failure posture: any error in the MTA rule path must `defer` (exim retries),
never silently drop. CSM-generated config is idempotent and reversible
(`Remove()` restores normal forwarding) and survives cPanel exim rebuilds by
using the cPanel-preserved advanced-configuration include sections.

## Components (platform-abstracted, OSS-minded)

New package tree `internal/mailfwd/`:

- `inventory` -- enumerate forwarders cross-platform. cPanel: `/etc/valiases/*`
  (reuse existing `parseValiasLine` / `isExternalDest` from
  `internal/checks/forwarder.go` and `internal/daemon/forwarder_parse.go`).
  Non-cPanel: `/etc/aliases`, `~/.forward`, postfix `virtual`. Source selected
  via `internal/platform`. Returns a normalized `Forwarder` list.
- `intel` -- parse `exim_mainlog` for: per-destination-provider deferrals with
  reason codes (TSS04 etc.); per outbound-IP reputation (who is deferring it);
  queue composition (bounce vs real, per-recipient, oldest, frozen). Reuse
  `eximQueueSize` / `eximQueueDetails` in `internal/webui/email_api.go`.
- `policy` -- the single source of truth for the layered verdict. One function
  `Verdict(msg MessageMeta, cfg ForwardGuardConfig) (hold bool, reasons []string)`
  used by BOTH the dry-run accounting and the rendered MTA rule (the MTA rule
  is generated from the same policy definition so they cannot drift).
- `adapter` -- interface `ForwardGuard { Apply(Policy) error; Remove() error;
  Status() (GuardStatus, error) }`. exim adapter first (renders router +
  transport + bad-IP lookup, reloads exim, writes to cPanel-preserved include).
  postfix adapter later. Idempotent, reversible.
- `quarantine` -- CSM-owned maildir for held forwards; release (re-inject via
  the platform sendmail) and delete; per-forwarder held counters. Mirror the
  existing `internal/emailav` quarantine + webui pattern
  (`apiEmailQuarantineList` / `apiEmailQuarantineAction`).

WebUI: extend the existing `/email` page (`handleEmail`, `internal/webui/
email_api.go`, `email_groups.go`). New read endpoints under `requireRead`;
mutating actions under `requireAuth + requireCSRF` (existing pattern).

## Config

Extends `EmailProtection` in `internal/config/config.go`. Remember the
three-places rule: `DefaultConfig` + installer template + packaging
`csm.yaml.default` (CI drift test enforces). Use presence checks
(`yamlPathExists`) where a literal 0/false must be distinguishable from unset.

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
    skip_forwarders: []     # reuse/share known_forwarders semantics
    quarantine_retention_days: 14
```

## WebUI surfaces (email page)

- Forwarder table: source -> destination(s); provider badge
  (yahoo/gmail/outlook/external/local); owner (cPanel user); keep-local vs
  forward-only; queued/stuck count; held-or-would-hold count; status (e.g.
  "Yahoo throttling"); row actions: disable forwarder, add to skip-list, view
  held.
- Outbound-IP reputation panel: per sending IP, provider deferrals + parsed
  reason codes + throttle state.
- Per-provider deferral rollup: provider -> queued + throttle + % of queue.
- Queue composition: bounce vs real, top stuck recipients, oldest/frozen,
  one-click flush backscatter.
- Held forwards: quarantine list with release/delete (phase 2).

## Safety / OSS

- Default off; dry-run first; skip-list for trusted relays.
- MTA-native enforcement -> fail-open (CSM down never blocks mail).
- MTA rule errors `defer`, never drop.
- Cross-platform via adapters; exim/cPanel first; capability flag
  `mail.forward_guard.v1` in `internal/health/capabilities.go`.
- All mutating actions audit-logged; fully reversible.
- No private hostnames/IPs in committed code/tests/docs (use RFC 5737/3849).

## Testing

- `policy.Verdict`: table-driven over each signal, combinations, skip-list,
  dry-run on/off. Real assertions.
- inventory parsers: fixtures per platform + fuzz target (attacker-controlled
  valias/aliases/.forward content).
- adapter: render-to-golden exim config; idempotent apply/remove; reload
  failure -> no-op rollback (no half-applied state).
- intel parsers: real-format exim deferral lines (TSS04, Gmail, Spamhaus) +
  fuzz.
- quarantine: release re-injects correctly; retention prune; per-forwarder
  counts.
- No live-mail tests on production. Cross-compile + vet locally; verify on
  phctl scratch hosts (fresh Ubuntu + AlmaLinux).

## Roadmap (each item = its own spec-slice / plan / TDD / codex review / MR)

Phase 1 -- Visibility (read-only, ship first):
1. `mailfwd/inventory`: cross-platform forwarder enumeration + unit/fuzz tests.
2. Email-page forwarder table + API (source/dest/provider/owner/keep-local).
3. `mailfwd/intel`: outbound-IP reputation + per-provider deferral rollup
   (exim_mainlog parse) + the two panels.
4. Queue composition panel + one-click backscatter flush action.
5. Dry-run `policy` engine: per-forwarder "would-hold" accounting surfaced in
   the table (no enforcement yet).

Phase 2 -- Enforcement (opt-in):
6. Config schema + settings-page toggles + validation/defaults (three-places).
7. `policy` -> exim `adapter`: router + transport + bad-IP lookup; idempotent
   apply/remove; cPanel-rebuild survival.
8. `mailfwd/quarantine` for held forwards + release/delete + per-forwarder
   held counts.
9. Live enforcement wiring (dry-run -> enforce), audit log, findings,
   capability flag.

Phase 3 -- Breadth:
10. postfix adapter (non-cPanel hosts).
11. Reputation aids: provider feedback-loop hints, SRS guidance, delisting
    checklist surfaced to the operator.

## Existing code to reuse (do not reinvent)

- `internal/checks/forwarder.go`: `parseValiasLine`, `isExternalDest`,
  `isPipeForwarder`, `parseLocalDomainsContent`.
- `internal/daemon/forwarder_parse.go`: `parseValiasFileForFindings`,
  `isKnownForwarderWatcher`; live `ForwarderWatcher`.
- `internal/webui/email_api.go`: `apiEmailStats`, `eximQueueSize`,
  `eximQueueDetails`, `topMailSenders`, quarantine list/action handlers.
- `internal/webui/email_groups.go`: email-page grouping + sort.
- `internal/config/config.go`: `EmailProtection` struct, `KnownForwarders`.
- `internal/emailav`: quarantine model + spool watcher (ClamAV/YARA).
- `internal/platform`: OS/panel/path/MTA abstraction.
- `internal/health/capabilities.go`: capability flags.

## Conventions (from AGENTS.md)

Production-grade, no shortcuts. TDD for security-relevant logic (test first).
`go test ./... -race`, `golangci-lint`, `go vet`, `govulncheck` clean before
push. gosec annotations need a real reason. CHANGELOG entry (1-2 sentences,
plain English, no internals) in the same commit as behaviour changes. One
conventional-commit subject per commit, no Co-Authored-By. Branch off main;
never push/MR without explicit instruction. codex review at each item, then
self-review (read each changed file end to end). Platform paths only via
`internal/platform`. Never allowlist scan paths.
