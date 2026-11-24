# Incidents

CSM groups related findings into incidents, so you see one escalating story per account, mailbox or process instead of a stream of unrelated findings. An incident is layered on top of its findings: CSM does not change or suppress the originals. Grouping needs no configuration. [Auto-close](#auto-close) is on by default, and [credential-spray suppression](#credential-spray-suppression) and [incident auto-block](#incident-auto-block) are off until you enable them.

## Working with incidents

1. Open **Incidents** under **Monitor** in the [Web UI](#web-ui), or run `csm incidents list`. See [Control socket](#control-socket) for the commands.
2. Review each incident and set its status to `contained`, `resolved` or `dismissed`. [Lifecycle](#lifecycle) says what each status means.
3. If more incidents stay open than you want to triage, shorten the idle time for the kind that fills the list. See [Auto-close](#auto-close).
4. To collapse a password spray from one address into a single incident, follow the [rollout](#rollout) for credential-spray suppression.
5. To have an incident block its source address, enable [incident auto-block](#incident-auto-block).

### Web UI

Open **Incidents** under **Monitor**. The page has three tabs:

| Tab | What it shows |
|-----|---------------|
| Correlated | The default tab: a flat list of incidents with a status filter, a page size and a detail panel. |
| Grouped | Incidents rolled up by `(kind, source)`, so a credential spray that produced thousands of mailbox_bruteforce incidents shows as one row per attacker IP. It pages with the same page-size selector as Correlated. |
| Timeline Search | The older IP and account history search across the audit log. |

When an IP is known, the detail panel shows the current firewall block state for the incident's source IP: permanent, temporary, cphulk, or not blocked.

On the Grouped tab, click a group to see its member incidents in the detail panel, which also shows the source IP's firewall block state. Clicking a sample id jumps back to the Correlated tab, focused on that incident.

Admin tokens can change an incident's status (open / contained / resolved / dismissed). Read-scope tokens can browse all three tabs.

### Control socket

```
csm incidents list [--status all|active|open|contained|resolved|dismissed] [--limit N] [--offset N] [--all]
csm incidents show <id>
csm incidents status <id> <open|contained|resolved|dismissed> [details]
csm incidents bulk-status --older-than 24h [--last-seen-before RFC3339] [--status active|open|contained] [--kind K] [--domain D] [--account A] [--mailbox M] [--limit N] [--to resolved|dismissed] [--apply --confirm]
```

`csm incidents list` returns the first 100 incidents by default. Use `--offset` for the next page, `--status active` for open and contained incidents, or `--all` for an explicit full dump.

`csm incidents bulk-status` is a dry run by default. It prints the total match count and a bounded preview of the incidents that would change. It needs at least one age guard: `--older-than`, `--last-seen-before`, or both. To change incidents, pass both `--apply` and `--confirm`.

### API

| Route | What it does |
|-------|--------------|
| `GET /api/v1/incidents` | Lists incidents, newest first. |
| `GET /api/v1/incidents/<id>` | Returns one incident. |
| `POST /api/v1/incidents/<id>/status` | Changes the status. |

A successful list request returns a JSON object: `{"items":[...], "total":N, "offset":N, "limit":N, "status":"...", "truncated":false}`. `truncated` is true when more matches follow this page. Use `?offset=` to fetch the next page.

`?status=` accepts the four statuses plus `active`, which means open and contained and is the default Web UI filter. Without it, the list holds every status. `?limit=` defaults to 50 and the server caps it at 500.

See [api.md](api.md) for endpoint detail.

## Lifecycle

Every incident has a correlation key: what its findings share, such as the attacker IP, the account, the mailbox or the process. A new finding with the same key joins the incident while the incident is active.

| Status      | Meaning                                                                |
|-------------|------------------------------------------------------------------------|
| `open`      | Active. New findings for the same correlation key keep merging in.     |
| `contained` | An operator marked it under control. Findings still merge in inside the window. |
| `resolved`  | Closed. Future findings start a new incident.                          |
| `dismissed` | False positive. Future findings start a new incident.                  |

### Open threshold

A non-Critical finding normally needs at least two correlated sightings inside the merge window before an incident opens. CSM holds the first sighting as pending and counts it toward the threshold. The second sighting promotes both into a new incident with a two-event timeline.

Two cases open an incident on the first hit:

- Critical findings (account compromise, cloud-relay abuse, modsec rule escalations) bypass the threshold, so escalations still page on the first hit.
- A mail-filter exfil finding opens an incident even when an uncorroborated copy-forward is graded Warning, so the operator review path is not lost.

The threshold suppresses one-shot scanner noise, such as a single modsec deny from a wandering scanner or an isolated mistyped password, without hiding sustained activity. The `csm_incidents_pending` gauge shows the current number of pending findings. The daily retention sweep prunes stale pending entries.

### Correlation window

The correlation window, which this page also calls the merge window, is 15 minutes. Findings for the same key that arrive outside the window start a new incident. The window is a named constant in the code and has no config key.

The stored incident includes the full correlation key, including the process PID/UID and the remote IP when those are the only available dimensions. Active incidents therefore keep merging after a daemon restart.

### Severity policy

Severity only goes up. Each incident keeps the highest severity any joined finding has carried. CSM never re-emits a finding at a higher severity. The audit trail records an `incident_severity_changed` action when an incident's severity rises.

### Retention

CSM prunes a resolved or dismissed incident a set time after its last update:

| Who closed it | Pruned after |
|---------------|--------------|
| An operator | 30 days |
| The daemon (`closed_by` starts with `auto:`) | 7 days |
| Unknown: an older record without close attribution | 30 days |

Each of these gives the decision 30 days of retention:

- You confirm an automatic closure.
- You change a closed status.
- A block is recorded on a closed incident.

Recorded operator decisions on older rows with stale automatic attribution also keep the 30-day period. Reopening an incident clears its close attribution, and the next closure decides retention again.

The retention sweep never prunes open and contained incidents, but [auto-close](#auto-close) can resolve them. Pruning frees space for reuse; it does not shrink the state file. Finding history has its own retention, so a retained incident can refer to findings already evicted from history.

## Kinds

Each incident gets a `kind` when it is created.

| Kind | What it groups |
|------|----------------|
| `web_account_compromise` | Findings attributable to a hosted account or script: PHP relay, webshell, account-scoped login bruteforce and similar. |
| `web_attack` | An inbound web attack, or a remote-IP reputation or threat-score signal not tied to failed mailbox logins. |
| `mailbox_bruteforce` | Failed mailbox authentication, mail brute-force bursts, account-spray signals, pre-auth SMTP probes, and remote-IP reputation matches on addresses seen failing IMAP or POP3 logins. |
| `mailbox_takeover` | Post-authentication mailbox abuse such as suspicious geo, credential leaks, cloud relay abuse, spam outbreaks, and confirmed compromised-account signals. |
| `post_exploit_process` | Process exec from `/tmp`, `/var/tmp`, `/dev/shm`. |
| `host_integrity_risk` | Daemon and kernel-level signals: sensitive file changes, fake kernel threads, binary and config tampering. |
| `host_takeover` | Any two of a new uid-0 account, a planted suid binary, and an outbound connection to a bad ASN, seen for the same host inside the merge window. |
| `credential_spray` | One source IP brute-forcing many distinct mailboxes or accounts inside the merge window. See [Credential-spray suppression](#credential-spray-suppression). |

Two notes on the host-level kinds:

- Periodic binary and config tamper findings join the local `host_integrity_risk` incident even without account or IP attribution. Startup verification still alerts and refuses to start before normal incident processing is available.
- `host_takeover` is a compound escalation: CSM raises it when it correlates any two of the three legs for the same host.

### Classification

CSM separates attacks from compromises. An inbound attack is keyed on the attacker source IP, not on the victim it names:

- `web_attack` covers a WAF block, a scanner probe or a login brute-force. A victim domain or account in the finding is the attack target, not evidence that the account is compromised. CSM records it as target context and keys the incident on the attacker IP, so one attacker's hits across many vhosts collapse into one incident.
- `mailbox_bruteforce` covers failed mailbox logins, mail brute-force bursts and pre-auth SMTP probes from one source. A failed login is an attack attempt, not a takeover, so the incident is keyed on the attacker IP and not on the targeted mailbox.
- `credential_spray` is keyed on the source IP and not per mailbox, so a scanner spraying thousands of usernames produces one super-incident instead of thousands of mailbox_bruteforce rows.

A threat-intelligence match on an address seen failing IMAP or POP3 logins also opens a `mailbox_bruteforce` incident. This includes alerts queued during shutdown and delivered after restart.

The compromise kinds are reserved for evidence that an attack succeeded:

- `web_account_compromise` needs on-disk or behavioral signals such as a webshell or suspicious PHP.
- `mailbox_takeover` needs post-authentication abuse such as outbound spam, cloud relay, or a compromised-account signal.

The inbound-attack kinds `web_attack` and `mailbox_bruteforce` carry short attacker-grade retention (default 24h), and compromise kinds get the longer review window. For `web_attack`, this keeps defended probes and attacker-IP reputation hits from inflating the account-compromise count or its longer review window. [Auto-close](#auto-close) lists the defaults.

### Findings that never open an incident

Two classes of finding never open an incident:

- Findings that record an action CSM took, or how well it can see. CSM excludes them so its own output cannot re-enter its decision path.
- Findings that report a standing weakness in installed software, such as a known-vulnerable or outdated plugin. CSM excludes them because nothing has happened yet and there is nothing to contain.

Known-vulnerable plugin findings remain alertable. Routine outdated-plugin notices remain informational. Both classes appear in the findings list.

## Auto-close

Auto-close stops the open-incident backlog from growing without bound on busy hosts. The daemon scans open and contained incidents shortly after startup and then once an hour. It resolves every incident that has been idle, counted from its `updated_at`, for longer than the threshold of its kind.

An auto-resolved incident carries `closed_by: "auto:stale"` and an `incident_auto_closed` action in its timeline, so reports can tell it from an operator close.

Defaults (configurable in `csm.yaml`):

```yaml
incidents:
  auto_close:
    enabled: true            # set false to disable
    dry_run: false           # set true to log decisions without writing back
    by_kind:
      mailbox_takeover: 24h
      mailbox_bruteforce: 24h
      credential_spray: 24h
      web_attack: 24h
      web_account_compromise: 168h
```

Omitting a kind from `by_kind` keeps its default. Set its value to an empty string to remove its idle threshold. The default map omits `host_integrity_risk`, `host_takeover`, and `post_exploit_process`, because those host-level incidents should stay open until an operator reviews them.

Auto-close does not block re-detection. If a fresh finding for the same correlation key arrives after the auto-close, CSM creates a new open incident. The closed record keeps its history.

A live sweep closes at most 1000 stale incidents at a time. If more stale incidents remain, follow-up sweeps run every 30 seconds until the backlog drains. A dry-run sweep still scans the full set, so the counters show every would-close decision. The counters are listed under [Metrics](#metrics).

### Tuning on high-volume hosts

Each `by_kind` threshold is the idle time before that kind auto-resolves. The thresholds are independent, and you set them.

A host under sustained brute-force keeps a large open set mostly from the longer-lived kinds; `web_account_compromise` defaults to 168h. If the open-incident count is higher than you want to triage, shorten the relevant `by_kind` entry, for example `web_account_compromise: 72h`. Do that rather than disabling auto-close.

CSM keeps an untouched auto-resolved record for 7 days, measured from when the incident resolves. Shortening the threshold therefore also moves the prune point earlier relative to the last finding. Auto-close keeps the resolved record for follow-up; it does not delete history at close time.

## Credential-spray suppression

Failed mailbox logins already collapse onto the attacker IP as a single `mailbox_bruteforce` incident (see [Classification](#classification)). Spray suppression extends that across protocols. It is off by default, and its own `dry_run` is on by default.

For each source IP, CSM counts the distinct targets that the `per_check` detectors report. With `enabled: true` and `dry_run: false`, reaching `distinct_mailboxes` triggers a `credential_spray` incident. If an active incident already uses that IP as its key, CSM promotes it and keeps its timeline. Otherwise CSM opens one. Later qualifying findings join the same incident. On a merge, CSM raises the severity to Critical if the target count reaches or exceeds `severity_escalate_at`.

Defaults (configurable in `csm.yaml`):

```yaml
incidents:
  spray_suppression:
    enabled: false           # default OFF; opt-in
    dry_run: true            # default ON; counters move, routing unchanged
    distinct_mailboxes: 10   # threshold to trip
    severity_escalate_at: 50 # bump severity to CRITICAL at this many
    per_check:
      - email_auth_failure_realtime
      - pam_bruteforce
      - credential_stuffing
    max_tracked_ips: 10000
    block_at_severity: ""    # "" detection-only, "high" block on open,
                             # "critical" block on escalation
```

If `per_check` includes `mail_subnet_spray` or `smtp_subnet_spray`, grouping uses their single `cidrs` subnet. Older findings that carry the subnet in `source_ip` keep the same grouping, including when they are replayed or join restored incidents.

### Rollout

1. Ship the daemon with `enabled: false, dry_run: true`. The detector tracks per-IP mailbox sets and increments `csm_credential_spray_dry_run_total` whenever the threshold would have tripped, but routing stays on the legacy per-mailbox path.
2. Validate the counter on your own infrastructure for 24h. If a trusted IP shows up in the dry-run trips, add it to `reputation.whitelist`.
3. Set `enabled: true, dry_run: false`. New attacker IPs route through the spray path. The existing per-mailbox backlog drains through auto-close.
4. After another 24h, set `block_at_severity: high`. The firewall hand-off runs on every spray decision, open and merge alike, so an incident opened before you armed the flag still blocks on the next finding from the same IP.

### Choosing `block_at_severity`

| Value | What CSM does | When to use it |
|-------|---------------|----------------|
| `""` (default) | Detection only. Spray incidents open, and nothing is handed to the firewall. | During dry-run validation, and on hosts where a separate system owns blocking. |
| `high` | Blocks at the `distinct_mailboxes` trip. | Recommended once the dry-run counter looks clean. |
| `critical` | Blocks only after severity escalates: one IP hits `severity_escalate_at` distinct mailboxes. | Only when you have strong shared-NAT exposure and accept that slow sprayers evade the gate. |

Before a spray incident opens, a gap longer than the merge window resets the target count. Once CSM binds the address to an open spray incident, an idle gap alone does not reset it. Later qualifying findings can still trigger Critical escalation.

### How the spray block is applied

Once `spray_suppression.dry_run` is false, setting `block_at_severity` hands the source IP to the firewall as soon as the spray detector trips at the chosen tier. The hand-off also requires `auto_response.enabled` and `auto_response.block_ips`. The firewall still honors `auto_response.dry_run`, so a dry-run host logs the would-be block without applying nftables rules.

To latch an incident is to record that a live block request was accepted. Later findings then request no further block while that block lasts.

| Case | What CSM does |
|------|---------------|
| A live request is accepted | Records a `credential_spray_block_requested` action on the incident timeline. |
| The outcome is not live (dry-run, verdict-allow, already blocked), or the attempt fails | Does not latch the incident, so a later finding can retry after blocking is live again. |
| Several findings arrive for the same incident at once | They share one in-flight firewall call. |
| The spray incident is resolved or dismissed | Makes no new block decision. |
| No finding attests the address | Does not block. See [Address evidence](#address-evidence). |

### Whitelisted IPs

Spray detection skips whitelisted IPs: the entries in `reputation.whitelist` and the live whitelist you update in the Web UI. Internal mail relays, NAT egresses and known-good infrastructure therefore never produce a spray incident. Changes to `reputation.whitelist` apply on config reload.

## Incident auto-block

`spray_suppression` handles only the `credential_spray` kind. Low-and-slow scanners that never trip a per-detector window (modsec escalation, mail brute-force, smtp probe) still produce `web_attack`, `mailbox_bruteforce`, `mailbox_takeover` or `web_account_compromise` incidents, but nothing firewalls them. The `incidents.auto_block` block adds a generic hand-off from an incident to the firewall. It is off by default.

```yaml
incidents:
  auto_block:
    enabled: false           # default OFF; opt-in
    block_at_severity: ""    # "" / "high" / "critical"
    kinds: []                # empty = any non-spray kind with one source IP
```

The gate trips when an incident of a kind listed in `kinds` (any non-spray kind when the list is empty) reaches the `block_at_severity` severity. CSM then hands the source IP to the firewall through the same `dry_run` and `block_ips` checks as the spray path.

| Case | What CSM does |
|------|---------------|
| A live request is accepted | Records `incident_block_requested`. |
| The outcome is not live (dry-run, verdict-allow, already blocked) | Does not latch the incident. |
| The incident has multiple source IPs | Leaves it for manual review. |
| A long-running incident's timeline was truncated and the source IP is not part of the incident key | Auto-block stays off, because the remaining visible timeline may not contain every source IP. |
| The incident is a `credential_spray` | Excluded. The dedicated spray hand-off owns it. |
| No finding attests the address | Does not block. See [Address evidence](#address-evidence). |

Because a non-live outcome does not latch, you can arm `auto_block` after an incident has already crossed the gate. The incident still blocks on the next finding while it is open or contained.

Set `kinds` to narrow the surface, for example to only `web_account_compromise`, if you do not want every CRITICAL mailbox_takeover incident to block its source IP.

### Pairing with ModSecurity escalation

Auto-block pairs naturally with the ModSecurity escalation thresholds `thresholds.modsec_escalation_hits` and `thresholds.modsec_escalation_window_min`. The shipped default window is 10 minutes. Raising it to, for example, 4 hours lets the modsec detector promote paced scanners to a Critical escalation finding, which then trips the generic auto_block gate.

### ModSecurity escalation confidence

ModSecurity escalation is confidence-gated. CSM classifies each deny:

| Confidence | Rules |
|------------|-------|
| High | A specific attack or probe rule: SQLi, RCE, traversal, URL-encoding abuse, CSM custom, or an OWASP CRS rule from an `APPLICATION-ATTACK` rule file. |
| Low | Policy and anomaly scoring rules, such as COMODO content-type `210710` or anomaly-points `214930`, and OWASP CRS anomaly-score rules. |
| Unknown | Any other rule. |

The rule file is how CSM classifies LiteSpeed denies, since LiteSpeed omits the rule message and tags from its log.

Message and tag evidence comes from the rule configuration CSM reads, with macro references removed. Text that a request puts into a logged message therefore cannot change confidence. Without that configuration, known rule IDs and the rule file decide, and other rules stay unknown.

What a burst of denies does depends on what it contains:

| Burst | What CSM does |
|-------|---------------|
| Contains a high-confidence deny or an unknown deny | Escalates to a firewall ban at the normal hit count. |
| Contains only low-confidence denies | Emits one non-actioned `modsec_low_confidence_burst` finding for visibility and does not ban. It then emits no second such finding until that source's counted denies have all aged out of the escalation window. |
| Contains only low-confidence denies and reaches `thresholds.modsec_low_confidence_escalation_hits` (default 30) | Bans the source. This backstop catches a determined source that floods only low-confidence rules. |

This stops false bans of legitimate traffic, such as an unusual checkout that only trips content-type and anomaly rules. CSM still sees real attacks, which trip the high-confidence rules.

Unknown blocking rules are eligible for escalation, which is the fail-secure choice. Each one raises a `modsec_classifier_gap` finding once per rule for the whole host, repeated daily while the rule stays unclassified. A new vendor rule pack is therefore noticed, not silently given a no-ban path.

A few CSM rules match one specific exploit's request shape, for example the PHP2Shell upload progress field or the wp2shell tool User-Agent. These rules escalate on their first deny, whatever the hit threshold. To opt out, turn firewall escalation off for that rule on the ModSecurity rules page. The opt-out also covers the rule's retained evidence in later decisions.

Upload progress requests that carry browser headers are denied by a separate rule whose escalation is off by default. Requests lacking those headers retain first-deny escalation. See [ModSecurity Integration](modsecurity.md) for the browser-header limitation and the behavior when saved exclusions cannot be read.

[ModSecurity escalation edge cases](#modsecurity-escalation-edge-cases) lists the remaining rules.

## Address evidence

An incident of any kind, spray or not, blocks an address only when a finding that names that address as an attacker has joined the incident. CSM calls this address evidence, and says that the finding attests the address. It does not matter what raised the incident's severity. See [Auto-Response](auto-response.md).

Automatic incident blocks use this gate without a separate exclusion list. An incident block names the finding that supplied the address evidence.

| Finding | Can it attest an address? |
|---------|---------------------------|
| `pam_bruteforce` or `credential_stuffing` | Yes. |
| A raw mailbox failure such as `email_auth_failure_realtime` | No. It counts mailboxes and opens a spray incident, but cannot block the source alone. |
| A visibility-only finding, including `mail_bruteforce_suspected` and the High `mail_account_compromised` advisory for an established multi-mailbox source | No. It never makes a spray incident blockable and is excluded from generic incident auto-blocking too. |
| An `ip_reputation` match | No. An incident it opens blocks only after a local attack finding from the same address joins it. |
| An outbound connection's remote end, or a customer login | No. |
| An advisory event | Not alone. It can raise an incident's severity after an earlier attestation, even when the attesting event has since been trimmed from the timeline. |
| A syslog-file finding | No. |
| Older SSH, mail and FTP evidence without a recorded producer | No. This includes SSH findings saved under their former check name. |

A trimmed timeline is the timeline of a long-running incident after CSM truncated it, so an older event can be missing from it.

Setting `block_at_severity: high` does not turn an established multi-mailbox `mail_account_compromised` advisory into firewall evidence. A Critical compromise finding remains blockable.

CSM retains qualifying address evidence when findings join an incident and across restarts, including for incidents saved by earlier versions. Reopening an incident keeps its evidence. A new incident starts with its own evidence. [Address evidence after a restart or upgrade](#address-evidence-after-a-restart-or-upgrade) has the exact rules.

## Metrics

Incidents:

- `csm_incidents_open` is a gauge of currently open and contained incidents.
- `csm_incidents_created_total`
- `csm_incidents_severity_changed_total`
- `csm_incidents_status_changed_total`
- `csm_incidents_findings_merged_total`
- `csm_incidents_compacted_total`
- `csm_incidents_pending` is a gauge of findings held in the threshold gate, awaiting a second correlated sighting.

Auto-close:

- `csm_incidents_auto_closed_total`
- `csm_incidents_auto_close_dry_run_total`

Credential-spray suppression:

- `csm_credential_spray_opened_total`
- `csm_credential_spray_suppressed_mailbox_takeover_total`
- `csm_credential_spray_dry_run_total`
- `csm_credential_spray_tracked_ips`

## Cross-account correlation of findings

Separately from incidents, CSM derives two findings from the findings it sees. Both are Critical.

| Finding | Raised when |
|---------|-------------|
| `coordinated_attack` | At least three distinct hosting accounts each carry at least one Critical finding from a check classified as a security event or malware artifact. |
| `cross_account_malware` | The same malware-artifact check (`webshell`, `new_webshell_file`, `backdoor_binary`, `new_executable_in_config`) is present on two or more accounts at any severity. |

These rules bound the counts:

- For `coordinated_attack`, the checks may differ between accounts. Repeated findings or several installs inside one account never raise the count.
- For `cross_account_malware`, different malware checks on different accounts do not combine.
- A dismissed finding counts toward neither aggregate while it stays unchanged. A fresh scan that observes different file content can count that finding again.
- Derived findings are never inputs.

Every registered check is classified as a security event, a malware artifact, ignored with a stated reason, or derived. The [Correlation policy table](#correlation-policy-table) lists the class of every check.

Class membership does not mean an emitter currently reaches Critical. The non-WordPress administrator checks emit High with a stored baseline and Warning without one, and the outbound backdoor-port and bad-ASN variants emit High. All of them are eligible but contribute nothing until a Critical variant exists.

### Where correlation runs

Three places derive these findings: the scan runner, the realtime dispatcher and the latest-state merge. The latest-state set is the stored set of active findings that each completed scan merges into.

| Place | What it sees | Time window |
|-------|--------------|-------------|
| Scan runner and realtime dispatcher | Only their own batch. They produce alerts. | None. They keep their batch grouping and count all qualifying rows in the batch. |
| Latest-state merge | The merged, deduplicated, capped persisted active set, so evidence from separate scans combines. | One hour, counted from when each condition was first observed. |

A scan can carry forward an older finding for a file it could not examine. Its original timestamp does not exclude it from batch correlation, and correlation does not refresh that timestamp.

### The one-hour window

Over the persisted latest-state set, both aggregates combine only findings whose condition was **first observed** in the last hour.

CSM does not judge by report time. A scan re-emits every finding it still sees and the merge refreshes its report time, so judging by report time would let a months-old condition re-enter the window on every cycle. The merge carries each finding's first observation across re-reports, including when a completed scan replaces its owned findings, and correlation reads that.

These rules apply to the window:

- A condition removed by a completed scan starts a new observation if it is found again later.
- The window is relative to the merge time, so the next completed scan clears expired aggregates even if it produces no findings.
- CSM retains the source rows when their aggregates expire.
- A finding that carries no first observation falls back to its report time.
- A finding that carries no timestamp at all still counts.
- Derived timestamps never affect the window.
- JSON output omits `first_seen` when no first observation was recorded.

[First observation after an upgrade](#first-observation-after-an-upgrade) covers findings stored by an older version.

### How the persisted aggregates change

Because the latest-state merge combines scans, three accounts compromised in three different scans inside the one-hour window still produce a persisted `coordinated_attack`. It clears only when fewer than three accounts still carry a qualifying Critical there.

A merge works like this:

- Each completed runner snapshot replaces only its own checks' rows.
- Rows kept for an unscanned owner or a file coverage gap stay as inputs.
- CSM drops the previous derived findings and recomputes them from the merged set.

Demotion, dismissal or re-verification of a contributing row takes effect at the next nonempty scan merge, and only if fewer qualifying accounts remain. There is no immediate recompute and no promise that every file is re-verified. Demoting a malware artifact below Critical cannot clear the all-severity malware aggregate by itself.

There is no shared-signature or causal requirement, and no precision multiplier. The Critical inputs accumulate across scans and can include unrelated events and false positives, which is why the threshold calibration stays open on the roadmap.

### How CSM finds the account

Correlation needs the hosting account that owns each finding. It tries three sources in order:

1. A nonempty `TenantID` wins verbatim, including case, over the file path and the text.
2. If `TenantID` is empty, CSM uses the account home that contains the cleaned absolute `FilePath`.
3. The final fallback scans Message, then Details, for an account-root path.

A qualifying row with no identity from any source does not count toward either aggregate. [Attribution health](#attribution-health) shows how many such rows there are. [Account identity rules](#account-identity-rules) under Details has the limits of each source.

### Attribution health

The health snapshot (`csm status --json`, `/api/v1/status`) carries a `correlation_attribution` block with two views:

| View | What it counts |
|------|----------------|
| `current` | Per check, the unattributed qualifying rows retained in the active set and inside [the one-hour window](#the-one-hour-window) at its latest merge, including any eviction caused by the size limit. |
| `cumulative` | Every unattributed row since the daemon started, across active-set merges and per-batch derivations. A producer that recovered stays visible as having failed. |

Unstamped legacy rows also count in `current`. It clears when a later merge attributes those rows or they age out of the window. Dismissed rows with no identifiable account still count toward attribution health.

CSM publishes the counters together, in merge order. The block is absent until the first merge.

`csm doctor` reports the same state as `correlation attribution`. The row is OK when `current` is empty, and WARN otherwise, naming the checks and their counts. It shows the history in both cases.

## Details

This section is reference material: exact rules, upgrade behavior and rare cases.

### Retention sweeps

A retention sweep uses bounded transactions, so a large backlog does not hold the store writer for the entire cleanup.

### Address evidence after a restart or upgrade

A long-running incident can have its timeline trimmed. These rules say what happens to [address evidence](#address-evidence) then, and after a restart or an upgrade:

- The attesting check, severity and producer survive trimming and restart. CSM checks them again at startup.
- Older SSH, mail and FTP evidence without a recorded producer cannot attest, as the [Address evidence](#address-evidence) table says. For all other older incidents, CSM migrates the retained active proof. Missing or retired proof cannot authorize another block until a fresh qualifying finding arrives.
- At startup, an older incident recovers the link to its attesting finding from an attesting event in its timeline. This also happens for an incident that was already marked as having address evidence.
- If an older timeline has no finding identity or already lost that event, the original link cannot be recovered. CSM never builds it from message text.
- When the link is missing, the next finding that attests the key's address records its own identity. The new link survives trimming and restart.
- Retained evidence in existing incidents follows the advisory and `ip_reputation` rules on the next finding after an upgrade.

None of this changes blocks that already exist: installed blocks keep their expiry. `incidents.auto_block` and `incidents.spray_suppression` still control the responses.

### ModSecurity escalation edge cases

These rules complete [ModSecurity escalation confidence](#modsecurity-escalation-confidence):

- A deny whose request text imitates the rule fields ModSecurity writes counts as an unknown rule. A request therefore cannot borrow another rule's confidence or escalation setting.
- Warnings remain non-blocking even when request fields contain text resembling a deny message.
- Existing bans keep their configured expiry.
- While qualifying evidence remains in the window, duplicate escalations stay suppressed until `auto_response.block_expiry` allows fresh activity to renew the ban.

### First observation after an upgrade

The first observation that [the one-hour window](#the-one-hour-window) reads is not retroactive. On upgrade, a stored finding adopts its existing report time, because nothing recorded when that condition actually started.

A long-lived finding with a recent report can therefore count once after upgrading. It ages out one hour after that saved report time. The next completed scan clears expired aggregates even if it reports the same conditions again.

### Account identity rules

[How CSM finds the account](#how-csm-finds-the-account) lists three sources of identity. Each has limits.

#### `TenantID`

- A nonempty `TenantID` must identify the host-local hosting account.
- Existing stored values and verdict callbacks use the same precedence. Callbacks must supply the same owner keys as producers.
- External identifiers can split one owner or combine distinct owners. Correlation does not validate them.

#### File path

- Relative paths, root-only or home-only paths, and paths that escape the home after cleaning do not identify that home.
- The mapping is lexical, through the platform's account roots, including Plesk roots. It does not resolve symlinks or prove that directory aliases are distinct owners.
- Nonstandard content roots need producer-supplied identity.

#### Message and Details text

- The scan recognizes `<account-root>/<user>/`, not `(account: user)` labels.
- Within each field it searches roots in configured order, can match an embedded root substring, and can select an incidental path.

These compatibility limits are why account-aware producers should supply identity.

#### Rows with no identity

CSM counts qualifying rows with no identity once per call, and logs them once per check name per process. The log uses only that call's row count and no finding text. Ignored, derived, unknown and below-threshold security-event rows produce no diagnostic count.

A check with a declared attribution gap is still eligible. When its producer does supply an authoritative owner, that Critical counts.

### How producers supply the owner

Eligible producers supply verified identity when available. The test inventory names the producer test for each check, including unresolved branches.

| Producer | Owner |
|----------|-------|
| Database and CMS scanners | The owner of the install's configuration path, resolved through the account roots. An install outside every root keeps its display label but no owner. |
| Mail producers | The account that owns the mailbox or domain. See [Mail producers](#mail-producers). |
| Process, login and crontab producers | A system user whose home directory sits directly under an account root. See [Process, login and crontab producers](#process-login-and-crontab-producers). |
| File families | The judged file's path, which resolves as [File path](#file-path) describes. The collapsed core-integrity finding has no single path and carries the install owner. |
| Socket checks | The kernel UID, resolved through the same passwd and direct account-home validation. Root, service and unknown UIDs stay unattributed. |

The file families are content, phishing, htaccess, file index, core integrity, realtime file events, PHP shield events and self-deleting droppers.

Bad-ASN events also retain the socket owner when realtime process enrichment misses. An attributed socket or mail finding includes its owner in the message, so different accounts retain separate dispatch and audit identities.

Any unattributed qualifying finding reaches the diagnostic count. It never contributes an invented account.

#### Mail producers

The mail producers are rate windows, mail holds, credential leaks, bulk-service logins, forwarders, filters, mail brute force, cloud relay, geo logins and PHP relay volume. They resolve a mailbox or domain to its owning account through the panel's domain ownership table.

- Without that table, which means on any panel other than cPanel, the owner stays empty and the row is reported, not counted.
- A bare account name must resolve to a passwd home directly under an account root.
- Credential and bulk-service findings use the authenticated identity, never the envelope sender.
- Mail hold and governor findings require a local mail-server permission decision.

A sender-domain volume aggregate carries an owner only when every counted arrival proves the same local account through authentication or local submission:

- Arrivals with a remote ident username after the connecting address stay unattributed. That unquoted text can imitate later authentication metadata.
- Records whose greeting hides the connecting address also remain unattributed and supply no address.
- Mixed or unverified aggregates stay unattributed without reducing the volume count. Such an aggregate remains a declared attribution gap.

CSM reads submission identities from the mail log under these rules:

- CSM reads identities only from the reception fields that come before the message size field in the mail log line. Message IDs, subjects, addresses and login names cannot supply, replace or remove an owner or connecting address.
- Address literals in message IDs and recipients remain message data. Local arrivals do not acquire a peer from later metadata.
- An optional MAIL AUTH value follows the authenticated identity and does not change that identity or the peer.
- TCP Fast Open connections retain the same peer and ownership checks.
- The submission boundary follows [Exim's reception log fields](https://www.exim.org/exim-html-current/doc/html/spec_html/ch-log_files.html) and assumes Exim's default greeting syntax check.

Subject credential alerts have their own rules:

- They read the arrival's subject, with Exim's quote and backslash escapes decoded. Escapes for non-printing characters stay as written, and literal tabs remain as logged.
- Sender addresses, greetings, message IDs and recipients cannot supply that subject.
- Records with remote ident or optional MAIL AUTH text are skipped, because those unquoted values can imitate later fields.
- Subject text remains sender-controlled and is not proof of authentication.

#### Process, login and crontab producers

These producers accept a system user as owner only when its home directory sits directly under an account root. Root, service users and unknown uids therefore never become an account.

- Direct SMTP findings apply this validation to both socket users and enriched process accounts.
- SSH logins from unknown addresses use this validated account as their tenant only when the sshd record confirms successful authentication.
- Root and service-user logins group by source address. Their findings carry no `tenant_id` and no attack database account.
- The attack database uses only this validated tenant for SSH attribution. Certificate text in the log cannot supply an account.

Incidents and attack records stored before an upgrade keep their attribution. No setting changes this behavior.

### Findings from retired checks

A check name that no version of CSM emits any more stays registered while older installations can still hold findings under it. The reason is that CSM clears a stored finding only when the scan that produced it still lists that finding name among the names it clears.

Two file-index names are in that state: `new_php_in_languages` and `new_php_in_upgrade`. Nothing emits them again. For findings written by releases before the content-first file index:

- The next completed `file_index` scan clears them.
- They are kept while that scan is incomplete.
- They are kept per file while the scan reports a coverage gap for that file.

`php_dropper` was never emitted by any release, is not registered, and no response table lists it. The manual, automatic and full-scan quarantine sets and the attack database mapping are each declared once and tested against the registry, so a response table cannot list a name that was renamed or never emitted, where it would silently do nothing.

The same guard keeps `modsec_block` and `waf_block` out of the attack database mapping. Neither was ever emitted, so WAF blocks have never fed local reputation scoring through that database. Whether the ModSecurity block findings that CSM does emit should feed that scoring is still an open decision. The guard does not settle it.

#### Incomplete file-index scans

Directory enumeration errors and PHP handler-configuration read errors make the file-index scan incomplete, including when only one account root is unreadable. In that case the scanner keeps its previous index and directory cache, preserves its active findings, and still reports new findings from readable directories.

A later completed scan clears the retired names. Absent optional directories do not prevent completion. The first scan after startup, and every retry after an incomplete or interrupted walk, enumerates directories again, even if their cached modification times still match.

### Classification tests

This part is for developers. Tests check the host-integrity set, all five compound sets, the kind selectors and the identity exclusions against the detector registry. The independent test fixture `internal/incident/testdata/check-policy.json` records an explicit classification role and selecting-set membership for every registered check, including checks with no named override.

The tests reject unknown names, missing eligible members, new tables without a contract and new checks without a policy decision. They also exercise each check with account, mailbox, process and source-IP attribution to test classification precedence.

The tests live in the external `incident_test` package, which can import the check registry without adding a production dependency from `incident` to `checks`. That dependency would cycle through `checks -> control -> incident`.

Changes to the fixture require a review of the detector's emitted evidence; do not regenerate it from the selecting tables. Classification coverage does not calibrate correlation weights or prove that broader compound membership is safe.

### Correlation policy table

The table below is generated from the check registry. It lists every registered check with its class, its ignore reason when it is excluded, and its declared attribution gap.

A class says how correlation treats a check when it fires. It does not say the check currently reaches Critical, that its owner is available on every panel, or how precise it is.

Do not edit rows by hand. A test compares the table with the registry byte for byte and fails when a row is stale, missing or duplicated. Regenerate it with `go test ./internal/checks -run '^TestCorrelationDocumentation$' -args -update-correlation-docs`.

Regeneration preserves the surrounding prose and marker line endings, even when they use CRLF. The generated block itself uses LF line endings.

<!-- correlation-table:begin -->
Ignore reasons:

- `account-aggregate`: already summarizes several accounts without a single victim identity
- `attacker-side`: attacker activity or attempted access, not evidence of compromise of the named victim
- `host-scope`: host-wide condition with no account to attribute; a cross-account count cannot use it even when it is a real compromise
- `informational`: audit trail or inventory event with no compromise claim
- `performance`: resource usage
- `posture`: static configuration, hardening or hygiene state; a Critical means a misconfiguration, not an attack on the account
- `response`: record of an automatic action already taken; feeding it back would double count
- `self-health`: CSM's own health, capacity or coverage state

Attribution gaps:

- `envelope-sender`: sender-domain volume aggregate is unattributed when contributing submissions are unverified or belong to different accounts

| Check | Class | Ignore reason | Attribution gap |
| --- | --- | --- | --- |
| `account_scan` | ignored | self-health |  |
| `account_scan_error` | ignored | self-health |  |
| `account_scan_truncated` | ignored | self-health |  |
| `admin_cross_account_overlap` | ignored | account-aggregate |  |
| `admin_panel_bruteforce` | ignored | attacker-side |  |
| `af_alg_enforcement_corrected` | ignored | self-health |  |
| `af_alg_socket_use` | security event |  |  |
| `antispam_apply_failed` | ignored | self-health |  |
| `antispam_controller_open` | ignored | self-health |  |
| `antispam_feed` | ignored | self-health |  |
| `antispam_file_replaced` | ignored | self-health |  |
| `antispam_ip_map` | ignored | self-health |  |
| `antispam_learning` | ignored | self-health |  |
| `antispam_precondition` | ignored | self-health |  |
| `antispam_rspamd_down` | ignored | self-health |  |
| `antispam_rspamd_recovered` | ignored | self-health |  |
| `antispam_scan_error` | ignored | self-health |  |
| `api_auth_failure` | ignored | attacker-side |  |
| `api_auth_failure_realtime` | ignored | attacker-side |  |
| `api_tokens` | ignored | informational |  |
| `auto_block` | ignored | response |  |
| `auto_response` | ignored | response |  |
| `auto_response_paused` | ignored | response |  |
| `auto_response_withheld` | ignored | self-health |  |
| `backdoor_binary` | malware artifact |  |  |
| `backdoor_port` | security event |  |  |
| `backdoor_port_outbound` | security event |  |  |
| `backup_export_failed` | ignored | self-health |  |
| `bad_asn_outbound` | security event |  |  |
| `bpf_ringbuf_error` | ignored | self-health |  |
| `bpf_unavailable` | ignored | self-health |  |
| `bulk_password_change` | ignored | account-aggregate |  |
| `c2_connection` | security event |  |  |
| `cgi_backdoor_realtime` | security event |  |  |
| `cgi_suspicious_location_realtime` | security event |  |  |
| `challenge_route` | ignored | response |  |
| `check_panic` | ignored | self-health |  |
| `check_timeout` | ignored | self-health |  |
| `config_reload_error` | ignored | self-health |  |
| `config_reload_restart_required` | ignored | self-health |  |
| `coordinated_attack` | derived |  |  |
| `cpanel_file_upload` | security event |  |  |
| `cpanel_file_upload_realtime` | security event |  |  |
| `cpanel_login` | ignored | informational |  |
| `cpanel_login_realtime` | ignored | informational |  |
| `cpanel_multi_ip_login` | security event |  |  |
| `cpanel_password_purge` | ignored | informational |  |
| `cpanel_password_purge_realtime` | ignored | informational |  |
| `credential_log_realtime` | security event |  |  |
| `credential_reuse` | ignored | posture |  |
| `credential_stuffing` | ignored | attacker-side |  |
| `crond_change` | ignored | host-scope |  |
| `crontab_change` | ignored | informational |  |
| `cross_account_malware` | derived |  |  |
| `csm_health` | ignored | self-health |  |
| `database_dump` | ignored | informational |  |
| `db_content_scan_incomplete` | ignored | self-health |  |
| `db_doorway_sitemap_routes` | security event |  |  |
| `db_hidden_link_injection` | security event |  |  |
| `db_hostname_keyed_option` | security event |  |  |
| `db_magic_token_user` | security event |  |  |
| `db_malicious_event` | security event |  |  |
| `db_malicious_function` | security event |  |  |
| `db_malicious_procedure` | security event |  |  |
| `db_malicious_trigger` | security event |  |  |
| `db_options_injection` | security event |  |  |
| `db_options_new_external_script` | security event |  |  |
| `db_options_plugin_notice_injection` | security event |  |  |
| `db_phantom_post_author` | security event |  |  |
| `db_post_injection` | security event |  |  |
| `db_post_volume_burst` | security event |  |  |
| `db_rogue_admin` | security event |  |  |
| `db_siteurl_foreign_host` | security event |  |  |
| `db_siteurl_hijack` | security event |  |  |
| `db_siteurl_invalid` | ignored | posture |  |
| `db_spam_injection` | security event |  |  |
| `db_spam_taxonomy` | security event |  |  |
| `db_stored_cloak_logic` | security event |  |  |
| `db_stored_code_execution` | security event |  |  |
| `db_suspicious_admin_email` | security event |  |  |
| `db_unexpected_event` | ignored | informational |  |
| `db_unexpected_function` | ignored | informational |  |
| `db_unexpected_procedure` | ignored | informational |  |
| `db_unexpected_trigger` | ignored | informational |  |
| `detached_web_process` | security event |  |  |
| `detached_web_process_respawn` | security event |  |  |
| `direct_smtp_egress` | security event |  |  |
| `dns_connection` | ignored | host-scope |  |
| `dns_zone_change` | ignored | informational |  |
| `docroot_binary_exec` | security event |  |  |
| `dpkg_integrity` | ignored | host-scope |  |
| `drupal_admin_injection` | security event |  |  |
| `drupal_content_injection` | security event |  |  |
| `drupal_settings_injection` | security event |  |  |
| `email_auth_failure_realtime` | ignored | attacker-side |  |
| `email_av_degraded` | ignored | self-health |  |
| `email_av_encrypted_archive` | ignored | self-health |  |
| `email_av_hold_bypass` | ignored | self-health |  |
| `email_av_isolation_unavailable` | ignored | self-health |  |
| `email_av_late_verdict` | ignored | self-health |  |
| `email_av_parse_error` | ignored | self-health |  |
| `email_av_parse_worker_failed` | ignored | self-health |  |
| `email_av_parse_worker_rejected` | ignored | self-health |  |
| `email_av_parse_worker_source` | ignored | attacker-side |  |
| `email_av_quarantine_error` | ignored | self-health |  |
| `email_av_queue_overflow` | ignored | self-health |  |
| `email_av_scan_error` | ignored | self-health |  |
| `email_av_scanner_panic` | ignored | self-health |  |
| `email_av_source_backlog` | ignored | self-health |  |
| `email_av_timeout` | ignored | self-health |  |
| `email_bulk_recipients` | security event |  |  |
| `email_cloud_relay_abuse` | security event |  |  |
| `email_compromised_account` | security event |  |  |
| `email_credential_leak` | security event |  |  |
| `email_defer_fail_governor` | ignored | informational |  |
| `email_dkim_failure` | ignored | posture |  |
| `email_filter_blackhole` | security event |  |  |
| `email_filter_exfil` | security event |  |  |
| `email_filter_forwarder` | security event |  |  |
| `email_filter_pipe` | security event |  |  |
| `email_forged_sender` | security event |  |  |
| `email_mail_filters` | ignored | self-health |  |
| `email_mailbox_compromise` | security event |  |  |
| `email_mailbox_response` | ignored | response |  |
| `email_mailbox_suspension_paused` | ignored | response |  |
| `email_malware` | ignored | attacker-side |  |
| `email_outbound_reputation` | security event |  |  |
| `email_password_audit_incomplete` | ignored | self-health |  |
| `email_phishing_content` | ignored | attacker-side |  |
| `email_php_form_relay` | ignored | attacker-side |  |
| `email_php_form_relay_observed` | ignored | attacker-side |  |
| `email_php_form_relay_script` | security event |  |  |
| `email_php_form_relay_table_full` | ignored | self-health |  |
| `email_php_relay_abuse` | security event |  |  |
| `email_php_relay_account_volume_capped` | ignored | self-health |  |
| `email_php_relay_action_dry_run` | ignored | response |  |
| `email_php_relay_action_failed` | ignored | response |  |
| `email_php_relay_action_skipped` | ignored | response |  |
| `email_php_relay_cpanel_limit_unreadable` | ignored | self-health |  |
| `email_php_relay_disabled` | ignored | self-health |  |
| `email_php_relay_inotify_overflow` | ignored | self-health |  |
| `email_php_relay_inotify_overflow_recovered` | ignored | self-health |  |
| `email_php_relay_msgindex_persist_failed` | ignored | self-health |  |
| `email_php_relay_no_exim` | ignored | self-health |  |
| `email_php_relay_overflow_scan_truncated` | ignored | self-health |  |
| `email_php_relay_path2b_disabled` | ignored | self-health |  |
| `email_php_relay_policies_reload` | ignored | self-health |  |
| `email_php_relay_rate_limit_hit` | ignored | response |  |
| `email_php_relay_sweep_failed` | ignored | self-health |  |
| `email_php_relay_watcher_failed` | ignored | self-health |  |
| `email_pipe_forwarder` | security event |  |  |
| `email_rate_critical` | security event |  |  |
| `email_rate_warning` | security event |  |  |
| `email_spam_outbreak` | security event |  |  |
| `email_spf_rejection` | ignored | posture |  |
| `email_suspicious_forwarder` | security event |  |  |
| `email_suspicious_geo` | security event |  |  |
| `email_weak_password` | ignored | posture |  |
| `executable_in_config_realtime` | security event |  |  |
| `executable_in_tmp_realtime` | security event |  |  |
| `exfiltration_paste_site` | security event |  |  |
| `exim_frozen_realtime` | ignored | host-scope |  |
| `fake_kernel_thread` | security event |  |  |
| `fanotify_kernel_overflow` | ignored | self-health |  |
| `fanotify_overflow` | ignored | self-health |  |
| `firewall` | ignored | host-scope |  |
| `firewall_ipv6_unmanaged` | ignored | host-scope |  |
| `firewall_ports` | ignored | host-scope |  |
| `firewall_state_unreadable` | ignored | self-health |  |
| `ftp_auth_failure_realtime` | ignored | attacker-side |  |
| `ftp_bruteforce` | ignored | attacker-side |  |
| `ftp_login` | ignored | informational |  |
| `ftp_login_after_bruteforce` | security event |  |  |
| `full_scan_file_too_large` | ignored | self-health |  |
| `group_writable_php` | ignored | posture |  |
| `htaccess_auto_prepend` | security event |  |  |
| `htaccess_cgi_handler_abuse` | security event |  |  |
| `htaccess_errordocument_hijack` | security event |  |  |
| `htaccess_filesmatch_shield` | security event |  |  |
| `htaccess_handler_abuse` | security event |  |  |
| `htaccess_header_injection` | security event |  |  |
| `htaccess_injection` | security event |  |  |
| `htaccess_injection_realtime` | security event |  |  |
| `htaccess_php_in_uploads` | security event |  |  |
| `htaccess_rewrite_off_shield` | security event |  |  |
| `htaccess_security_disabled` | security event |  |  |
| `htaccess_spam_redirect` | security event |  |  |
| `htaccess_user_agent_cloak` | security event |  |  |
| `http_asn_crawl` | ignored | attacker-side |  |
| `http_claimed_bot_unverified` | ignored | attacker-side |  |
| `http_client_forged` | ignored | attacker-side |  |
| `http_distributed_flood` | ignored | attacker-side |  |
| `http_request_flood` | ignored | attacker-side |  |
| `http_scanner_profile` | ignored | attacker-side |  |
| `http_ua_spoof` | ignored | attacker-side |  |
| `infra_ips_unresolvable` | ignored | self-health |  |
| `integrity` | ignored | host-scope |  |
| `ip_reputation` | ignored | attacker-side |  |
| `joomla_admin_injection` | security event |  |  |
| `joomla_content_injection` | security event |  |  |
| `joomla_extensions_injection` | security event |  |  |
| `js_keylogger_dataflow` | security event |  |  |
| `js_taint_scan_incomplete` | ignored | self-health |  |
| `kernel_module` | ignored | host-scope |  |
| `local_threat_score` | ignored | attacker-side |  |
| `magento_admin_injection` | security event |  |  |
| `magento_content_injection` | security event |  |  |
| `magento_settings_injection` | security event |  |  |
| `mail_account_compromised` | security event |  |  |
| `mail_account_spray` | ignored | attacker-side |  |
| `mail_auth_backend_degraded` | ignored | self-health |  |
| `mail_bruteforce` | ignored | attacker-side |  |
| `mail_bruteforce_suspected` | ignored | attacker-side |  |
| `mail_log_source_unavailable` | ignored | self-health |  |
| `mail_per_account` | security event |  | envelope-sender |
| `mail_queue` | ignored | host-scope |  |
| `mail_queue_unavailable` | ignored | self-health |  |
| `mail_spam_source` | ignored | attacker-side |  |
| `mail_subnet_spray` | ignored | attacker-side |  |
| `malware_companion_files` | security event |  |  |
| `malware_companion_scan_incomplete` | ignored | self-health |  |
| `modsec_block_escalation` | ignored | attacker-side |  |
| `modsec_block_realtime` | ignored | attacker-side |  |
| `modsec_classifier_gap` | ignored | self-health |  |
| `modsec_csm_block_escalation` | ignored | attacker-side |  |
| `modsec_disabled_vhost` | ignored | posture |  |
| `modsec_low_confidence_burst` | ignored | attacker-side |  |
| `modsec_warning_realtime` | ignored | attacker-side |  |
| `mysql_superuser` | ignored | host-scope |  |
| `new_executable_in_config` | malware artifact |  |  |
| `new_php_in_languages` | security event |  |  |
| `new_php_in_sensitive_dir` | security event |  |  |
| `new_php_in_sensitive_dir_clean` | ignored | informational |  |
| `new_php_in_upgrade` | security event |  |  |
| `new_php_in_uploads` | security event |  |  |
| `new_php_in_uploads_clean` | ignored | informational |  |
| `new_suspicious_php` | security event |  |  |
| `new_webshell_file` | malware artifact |  |  |
| `nulled_plugin` | ignored | posture |  |
| `obfuscated_php` | security event |  |  |
| `obfuscated_php_realtime` | security event |  |  |
| `open_basedir` | ignored | posture |  |
| `opencart_admin_injection` | security event |  |  |
| `opencart_content_injection` | security event |  |  |
| `opencart_settings_injection` | security event |  |  |
| `outdated_plugins` | ignored | posture |  |
| `pam_auth_failures` | ignored | informational |  |
| `pam_bruteforce` | ignored | attacker-side |  |
| `pam_login` | ignored | informational |  |
| `password_hijack_confirmed` | security event |  |  |
| `perf_error_logs` | ignored | performance |  |
| `perf_load` | ignored | performance |  |
| `perf_memory` | ignored | performance |  |
| `perf_mysql_config` | ignored | performance |  |
| `perf_php_handler` | ignored | performance |  |
| `perf_php_processes` | ignored | performance |  |
| `perf_redis_config` | ignored | performance |  |
| `perf_wp_config` | ignored | performance |  |
| `perf_wp_cron` | ignored | performance |  |
| `perf_wp_loopback` | ignored | performance |  |
| `perf_wp_myisam` | ignored | performance |  |
| `perf_wp_transients` | ignored | performance |  |
| `phishing_credential_log` | security event |  |  |
| `phishing_directory` | security event |  |  |
| `phishing_iframe` | security event |  |  |
| `phishing_kit_archive` | security event |  |  |
| `phishing_kit_archive_unscannable` | security event |  |  |
| `phishing_kit_realtime` | security event |  |  |
| `phishing_page` | security event |  |  |
| `phishing_php` | security event |  |  |
| `phishing_realtime` | security event |  |  |
| `phishing_redirector` | security event |  |  |
| `php_config_change` | ignored | posture |  |
| `php_config_realtime` | ignored | posture |  |
| `php_config_scan_incomplete` | ignored | self-health |  |
| `php_dropper_realtime` | security event |  |  |
| `php_in_image_realtime` | security event |  |  |
| `php_in_sensitive_dir_realtime` | security event |  |  |
| `php_in_uploads_realtime` | security event |  |  |
| `php_remote_taint` | security event |  |  |
| `php_shield_block` | security event |  |  |
| `php_shield_eval` | security event |  |  |
| `php_shield_webshell` | security event |  |  |
| `php_suspicious_execution` | security event |  |  |
| `php_taint_scan_incomplete` | ignored | self-health |  |
| `placed_dir_incomplete_realtime` | ignored | self-health |  |
| `placement_unresolved_realtime` | ignored | self-health |  |
| `prestashop_admin_injection` | security event |  |  |
| `prestashop_content_injection` | security event |  |  |
| `prestashop_settings_injection` | security event |  |  |
| `protection_queue_degraded` | ignored | self-health |  |
| `protection_queue_recovered` | ignored | self-health |  |
| `realtime_scanner_panic` | ignored | self-health |  |
| `removed_file_restored_realtime` | security event |  |  |
| `reputation_quota_exhausted` | ignored | self-health |  |
| `response_capacity_exhausted` | ignored | self-health |  |
| `root_password_change` | ignored | host-scope |  |
| `rpm_integrity` | ignored | host-scope |  |
| `self_deleting_dropper_overflow` | ignored | self-health |  |
| `self_deleting_dropper_realtime` | security event |  |  |
| `sensitive_file_modified` | ignored | host-scope |  |
| `shadow_change` | ignored | host-scope |  |
| `shared_senders_stale` | ignored | self-health |  |
| `signature_match_realtime` | security event |  |  |
| `signature_update_rescan_queued` | ignored | self-health |  |
| `signature_update_rollback` | ignored | self-health |  |
| `smtp_account_spray` | ignored | attacker-side |  |
| `smtp_bruteforce` | ignored | attacker-side |  |
| `smtp_probe_abuse` | ignored | attacker-side |  |
| `smtp_subnet_spray` | ignored | attacker-side |  |
| `spam_evidence_evicted` | ignored | self-health |  |
| `ssh_keys` | ignored | host-scope |  |
| `ssh_login_unknown_ip` | ignored | informational |  |
| `sshd_config_change` | ignored | host-scope |  |
| `ssl_cert_issued` | ignored | informational |  |
| `stalwart_address_list` | ignored | self-health |  |
| `stalwart_ban` | ignored | attacker-side |  |
| `stalwart_log_degraded` | ignored | self-health |  |
| `stalwart_spam_filter_off` | ignored | self-health |  |
| `stalwart_webmail_bruteforce` | ignored | attacker-side |  |
| `suid_binary` | security event |  |  |
| `supply_chain_vuln` | ignored | posture |  |
| `suspicious_crontab` | security event |  |  |
| `suspicious_file` | ignored | host-scope |  |
| `suspicious_php_content` | security event |  |  |
| `suspicious_process` | security event |  |  |
| `symlink_attack` | security event |  |  |
| `test_alert` | ignored | informational |  |
| `threat_feed_stale` | ignored | self-health |  |
| `trusted_proxy_unusable` | ignored | self-health |  |
| `uid0_account` | ignored | host-scope |  |
| `user_outbound_connection` | ignored | informational |  |
| `vulnerable_plugins` | ignored | posture |  |
| `vulnerable_timthumb` | ignored | posture |  |
| `waf_attack_blocked` | ignored | attacker-side |  |
| `waf_bypass` | ignored | posture |  |
| `waf_detection_only` | ignored | posture |  |
| `waf_rules` | ignored | posture |  |
| `waf_rules_stale` | ignored | posture |  |
| `waf_status` | ignored | posture |  |
| `web_exposed_backup_archive` | ignored | posture |  |
| `web_exposed_config_leak` | ignored | posture |  |
| `web_exposed_db_dump` | ignored | posture |  |
| `web_exposed_phpinfo` | ignored | posture |  |
| `web_exposed_repo_metadata` | ignored | posture |  |
| `web_exposed_sample_sql` | ignored | posture |  |
| `web_exposed_source_backup` | ignored | posture |  |
| `webmail_bruteforce` | ignored | attacker-side |  |
| `webmail_login_realtime` | ignored | informational |  |
| `webshell` | malware artifact |  |  |
| `webshell_caller` | ignored | attacker-side |  |
| `webshell_content_realtime` | security event |  |  |
| `webshell_path_public` | ignored | informational |  |
| `webshell_realtime` | security event |  |  |
| `whm_account_action` | ignored | informational |  |
| `whm_login_realtime` | ignored | informational |  |
| `whm_password_change` | ignored | informational |  |
| `whm_password_change_noninfra` | security event |  |  |
| `whm_unauth_scripts_realtime` | ignored | attacker-side |  |
| `world_writable_php` | ignored | posture |  |
| `wp_core_integrity` | security event |  |  |
| `wp_core_unverified` | ignored | self-health |  |
| `wp_login_bruteforce` | ignored | attacker-side |  |
| `wp_plugin_inventory_unverified` | ignored | self-health |  |
| `wp_user_enumeration` | ignored | attacker-side |  |
| `xmlrpc_abuse` | ignored | attacker-side |  |
| `yara_backend_unavailable` | ignored | self-health |  |
| `yara_forge_rollback` | ignored | self-health |  |
| `yara_match_realtime` | security event |  |  |
| `yara_match_scheduled` | security event |  |  |
| `yara_realtime_scan_error` | ignored | self-health |  |
| `yara_scan_incomplete` | ignored | self-health |  |
| `yara_worker_crashed` | ignored | self-health |  |
<!-- correlation-table:end -->
