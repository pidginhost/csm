# Incidents

CSM groups related findings into Incident objects so operators see one
escalating story per account, mailbox, or process instead of a stream
of unrelated findings. Original findings are not mutated or suppressed
-- the Incident is layered on top.

## Classification

Each incident is assigned a `kind` at create time. Inbound attacks are keyed
on the attacker source IP, not on the victim they name:

- `web_attack` -- a WAF block, scanner probe, or login brute-force. When the
  finding names a victim domain or account, that is the attack target, not
  evidence the account is compromised, so the incident keys on the attacker IP
  and one attacker's hits across many vhosts collapse into one incident.
- `mailbox_bruteforce` -- failed mailbox logins, mail brute-force bursts, and
  pre-auth SMTP probes from one source. A failed login is an attack attempt,
  not a takeover, so it keys on the attacker IP rather than the targeted
  mailbox.

Compromise kinds are reserved for evidence that an attack succeeded:
`web_account_compromise` (on-disk or behavioural signals such as a webshell or
suspicious PHP) and `mailbox_takeover` (post-authentication abuse such as
outbound spam, cloud relay, or a compromised-account signal). Inbound-attack
kinds carry short attacker-grade retention; compromise kinds get the longer
review window.

Two further classes of finding never open an incident at all. Findings that
record an action CSM took, or how well it can see, are excluded so CSM's own
output cannot re-enter its decision path. Findings that report a standing
weakness in installed software -- a known-vulnerable or outdated plugin -- are
excluded because nothing has happened yet and there is nothing to contain.
Known-vulnerable plugin findings remain alertable. Routine outdated-plugin
notices remain informational, and both classes appear in the findings list.

## Lifecycle

| Status      | Meaning                                                                |
|-------------|------------------------------------------------------------------------|
| `open`      | Active. New findings for the same correlation key keep merging in.     |
| `contained` | Operator marked under control. Findings still merge in window.         |
| `resolved`  | Closed. Future findings start a new incident.                          |
| `dismissed` | False positive. Future findings start a new incident.                  |

Resolved and dismissed incidents are pruned 30 days after their last
update. Open and contained incidents are never auto-pruned by the
retention loop, but they may be auto-resolved by the per-kind idle
threshold described under "Auto-close" below.

## Auto-close

To stop the open-incident backlog from growing without bound on busy
hosts, the daemon scans Open / Contained incidents shortly after startup
and then once an hour, auto-resolving any whose `updated_at` exceeds the
per-kind idle threshold. A live sweep closes at most 1000 stale incidents
at a time; if more stale incidents remain, follow-up sweeps run every 30
seconds until the backlog drains. Dry-run sweeps still scan the full set
so the counters show every would-close decision. Auto-resolved incidents
carry `closed_by: "auto:stale"` and an `incident_auto_closed` action in
their timeline so reporting can distinguish them from operator closes.

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

Kinds absent from `by_kind` are never auto-closed. The default map
omits `host_integrity_risk`, `host_takeover`, and `post_exploit_process`
because those host-level incidents should stay open until an operator
reviews them. `host_takeover` is the compound escalation raised when any
two of three host-takeover legs (a new uid-0 account, a planted suid
binary, an outbound connection to a bad ASN) are correlated for the same
host inside the merge window.

If a fresh finding for the same correlation key arrives after the
auto-close, the merge-window stale-binding logic creates a new open
incident -- nothing about auto-close blocks re-detection. History is
preserved on the closed record.

**Tuning on high-volume hosts.** Each `by_kind` threshold is the idle
time before a kind auto-resolves; they are independent and operator-set.
A host under sustained brute-force keeps a large open set mostly from the
longer-lived kinds (`web_account_compromise` defaults to 168h). If the
open-incident count is higher than you want to triage, shorten the
relevant `by_kind` entry (e.g. `web_account_compromise: 72h`) rather than
disabling auto-close. The closed records are retained 30 days regardless,
measured from when the incident resolves, so shortening the threshold also
moves the eventual prune point earlier relative to the last finding.
Auto-close still keeps a resolved record for follow-up instead of deleting
history at close time.

Metrics: `csm_incidents_auto_closed_total` and
`csm_incidents_auto_close_dry_run_total`.

## Credential-spray suppression

Failed mailbox logins already collapse onto the attacker IP as a single
`mailbox_bruteforce` incident (see "Classification"). Spray suppression
extends that across protocols: it tracks the distinct-mailbox/account set
per source IP for the configured `per_check` detectors (mail and PAM)
across the merge window and, once an IP exceeds `distinct_mailboxes`,
opens a single `credential_spray` super-incident keyed on the IP with
breadth-based severity escalation. Subsequent findings from that IP
attach to the spray incident's timeline.

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

Setting `block_at_severity` hands the source IP to the firewall as soon
as the spray detector trips at the chosen tier, once
`spray_suppression.dry_run` is false. The detector also requires
`auto_response.enabled` and `auto_response.block_ips`; the firewall still
honors `auto_response.dry_run`, so a dry-run host logs the would-be block
without applying nftables rules. Live accepted requests are recorded on
the incident timeline as a `credential_spray_block_requested` action.
Non-live outcomes (dry-run, verdict-allow, already blocked) and failed
attempts do not latch the incident, so a later finding can retry after
blocking is live again. Concurrent findings for the same incident share
one in-flight firewall call, and resolved or dismissed spray incidents do
not make new block decisions.

Visibility-only findings do not make a spray incident blockable by themselves.
This includes `mail_bruteforce_suspected` and the High
`mail_account_compromised` advisory for an established multi-mailbox source.
A separate blockable finding in the same spray incident can still trip the
configured severity gate.

Whitelisted IPs (entries in `reputation.whitelist` and the live bbolt
whitelist updated via the Web UI) are skipped from spray detection so
internal mail relays, NAT egresses, and known-good infrastructure
never produce a spray incident.

Choosing `block_at_severity`:

- `""` (default) -- detection-only. Spray incidents open, no firewall
  hand-off. Use during dry-run validation and on hosts where blocking
  is owned by a separate system.
- `high` -- block at the `distinct_mailboxes` trip. Recommended once
  the dry-run counter looks clean. Trips on the first sustained
  burst before the source IP goes idle for longer than the merge
  window.
- `critical` -- block only after severity escalates, i.e. one IP hits
  `severity_escalate_at` distinct mailboxes before the source IP is
  idle for more than the merge window. A low-and-slow attacker that
  stays below that count before each idle reset never escalates and
  never blocks. Pick this only when you have strong shared-NAT exposure
  and accept that slow sprayers evade the gate.

Rollout:

1. Ship the daemon with `enabled: false, dry_run: true`. The detector
   tracks per-IP mailbox sets and increments
   `csm_credential_spray_dry_run_total` whenever the threshold would
   have tripped, but routing stays on the legacy per-mailbox path.
2. Validate the counter on your own infrastructure for 24h. If a
   trusted IP shows up in the dry-run trips, add it to
   `reputation.whitelist`.
3. Flip `enabled: true, dry_run: false`. New attacker IPs route
   through the spray path; existing per-mailbox backlog drains via the
   auto-close path.
4. After another 24h, set `block_at_severity: high`. The firewall
   hand-off runs on every spray decision (open + merge), so an
   incident opened before the flag was armed still blocks on the
   next finding from the same IP.

Metrics: `csm_credential_spray_opened_total`,
`csm_credential_spray_suppressed_mailbox_takeover_total`,
`csm_credential_spray_dry_run_total`,
`csm_credential_spray_tracked_ips`.

## Incident auto-block

`spray_suppression` only handles the credential_spray super-incident
kind. Low-and-slow scanners that never trip a per-detector window
(modsec escalation, mail brute-force, smtp probe) still produce
web_attack, mailbox_bruteforce, mailbox_takeover, or
web_account_compromise incidents but never get firewalled. The
`incidents.auto_block` block adds a generic incident-driven firewall
hand-off:

```yaml
incidents:
  auto_block:
    enabled: false           # default OFF; opt-in
    block_at_severity: ""    # "" / "high" / "critical"
    kinds: []                # empty = any non-spray kind with one source IP
```

When the gate trips, the correlator hands the source IP to the firewall
through the same dry-run / block_ips gate as the spray path. A live
accepted request records `incident_block_requested`; non-live outcomes
(dry-run, verdict-allow, already blocked) do not latch the incident, so
an operator who arms `auto_block` AFTER an incident has already crossed
the gate still gets a block on the next finding while the incident is
open or contained. Incidents with multiple source IPs are left for manual
review.
If a long-running incident's timeline was truncated and the source IP is
not part of the incident key, auto-block also stays off because the
remaining visible timeline may not contain every source IP.

The same visibility-only findings are excluded from generic incident
auto-blocking. In particular, setting `block_at_severity: high` does not turn
an established multi-mailbox `mail_account_compromised` advisory into firewall
evidence. A Critical compromise finding remains blockable.

credential_spray is explicitly excluded from this path; the dedicated
spray hand-off owns it. Set `kinds` to narrow the surface (e.g. only
`web_account_compromise`) if you do not want every CRITICAL
mailbox_takeover incident to block its source IP.

This pairs naturally with the ModSecurity escalation thresholds
(`thresholds.modsec_escalation_hits`,
`thresholds.modsec_escalation_window_min`) -- raising the window from
the shipped default of 10 minutes to e.g. 4 hours lets the modsec
detector promote paced scanners to a Critical escalation finding,
which then trips the generic auto_block gate.

ModSecurity escalation is confidence-gated. Each deny is classified as
high-confidence (a specific attack/probe rule -- SQLi, RCE, traversal,
URL-encoding abuse, CSM custom), low-confidence (policy/anomaly scoring
rules such as COMODO content-type `210710` or anomaly-points `214930`,
and OWASP CRS anomaly-score rules), or unknown. A burst escalates to a
firewall ban at the normal hit count only when it contains a
high-confidence deny or an unknown deny; a low-confidence-only burst
emits one non-actioned `modsec_low_confidence_burst` finding for
visibility instead of banning, then stays quiet until that active
low-confidence window drains. This stops false bans of legitimate
traffic (e.g. an unusual checkout that only trips content-type/anomaly
rules) without blinding CSM to real attacks, which trip the
high-confidence rules. A determined source that floods only
low-confidence rules is still banned once it reaches the
`thresholds.modsec_low_confidence_escalation_hits` backstop (default
30). Unknown blocking rules are escalation-eligible (fail-secure) and
raise a one-time `modsec_classifier_gap` finding so a new vendor rule
pack is noticed rather than silently given a no-ban path.

## Kinds

- `web_account_compromise` -- findings attributable to a hosted account
  or script (PHP relay, webshell, account-scoped login bruteforce, etc.).
- `web_attack` -- an inbound web attack or remote-IP reputation/threat-score
  signal. When the finding includes a victim domain or account, that field is
  recorded as target context, not as the correlation key. Keyed on the source
  IP and given attacker-grade retention (default 24h) so defended probes and
  attacker-IP reputation hits do not inflate the account-compromise count or
  its longer review window.
- `mailbox_bruteforce` -- failed mailbox authentication, mail brute-force
  bursts, account-spray signals, and pre-auth SMTP probes. Keyed on the
  attacker source IP with attacker-grade retention (default 24h).
- `mailbox_takeover` -- post-authentication mailbox abuse such as suspicious
  geo, credential leaks, cloud relay abuse, spam outbreaks, and confirmed
  compromised-account signals.
- `post_exploit_process` -- process exec from `/tmp`, `/var/tmp`,
  `/dev/shm`.
- `host_integrity_risk` -- daemon/kernel-level signals (sensitive file
  changes, fake kernel threads, binary/config tampering). Periodic
  binary/config tamper findings join the local host incident even without
  account or IP attribution. Startup verification still alerts and refuses
  to start before normal incident processing is available.
- `host_takeover` -- any two of a new uid-0 account, a planted suid
  binary, and an outbound connection to a bad ASN, seen for the same host
  inside the merge window.
- `credential_spray` -- one source IP brute-forcing many distinct
  mailboxes/accounts inside the merge window. Keyed on the source IP
  rather than per-mailbox, so a scanner spraying thousands of usernames
  produces one super-incident instead of thousands of mailbox_bruteforce
  rows. Findings from the same IP after the trip attach to this
  incident's timeline. See "Credential-spray suppression" below.

The host-integrity set, all five compound sets, kind selectors and identity
exclusions are checked against the detector registry. The independent test
fixture `internal/incident/testdata/check-policy.json` records an explicit
classification role and selecting-set membership for every registered check,
including checks with no named override. Tests reject unknown names, missing
eligible members, new tables without a contract and new checks without a
policy decision. They also exercise each check with account, mailbox, process
and source-IP attribution to test classification precedence.

These tests live in the external `incident_test` package, which can import the
check registry without adding a production dependency from `incident` to
`checks`. That dependency would cycle through `checks -> control -> incident`.
Changes to the fixture require a review of the detector's emitted evidence;
do not regenerate it from the selecting tables. Classification coverage does
not calibrate correlation weights or prove that broader compound membership
is safe.

## Severity policy

Severity escalates only. Each incident keeps the highest severity any
joined finding has carried. Findings themselves are never re-emitted at
a higher severity. The audit trail records an
`incident_severity_changed` action when an incident's severity bumps.

## Correlation window

15 minutes by default. Findings outside the window for the same key
start a new incident. The window is a named constant in code; not yet
exposed via config.

## Open threshold

Non-Critical findings normally need at least two correlated sightings inside
the merge window before an incident opens. The first sighting is held in a
pending bucket and counted toward the threshold; the second promotes both into
a new incident with a two-event timeline. A mail-filter exfil finding remains a
first-hit incident even when an uncorroborated copy-forward is graded Warning,
so the operator review path is not lost. Stale pending entries are pruned by
the daily retention sweep.

Critical-severity findings (account compromise, cloud-relay abuse,
modsec rule escalations) bypass the threshold and open immediately
so escalations still page on first hit.

The threshold suppresses one-shot scanner noise (a single modsec
deny from a wandering scanner, an isolated mistyped password) without
hiding sustained activity. The current pending-bucket size is exposed
as the `csm_incidents_pending` gauge.

The stored incident includes the full correlation key, including process
PID/UID and remote IP when those are the only available dimensions, so
active incidents keep merging after daemon restart.

## Cross-account correlation of findings

Separately from incidents, the scan runner, the latest-state merge and the
realtime dispatcher derive two findings from the findings they see:

- `coordinated_attack` (Critical) when at least three distinct hosting
  accounts each carry at least one Critical finding from a check classified
  as a security event or malware artifact. The checks may differ between accounts. Repeated
  findings or several installs inside one account never raise the count.
- `cross_account_malware` (Critical) when the same malware-artifact check
  (`webshell`, `new_webshell_file`, `backdoor_binary`,
  `new_executable_in_config`) is present on two or more accounts at any
  severity. Different malware checks on different accounts do not combine.

Every registered check is classified as a security event, a malware
artifact, ignored with a stated reason, or derived. Derived findings are never
inputs. A nonempty `TenantID` wins verbatim, including case, over the file
path and text. It must identify the host-local hosting account. Existing
stored values and verdict callbacks use the same precedence; callbacks must
supply the same owner keys as producers. External identifiers can split one
owner or combine distinct owners, and correlation does not validate them.

If that field is empty, correlation uses the account home containing the
cleaned absolute `FilePath`. Relative paths, root/home-only paths and paths
that escape the home after cleaning do not identify that home. This is a
lexical mapping through the platform's account roots, including Plesk roots;
it does not resolve symlinks or prove that directory aliases are distinct
owners. Nonstandard content roots need producer-supplied identity.

The final fallback scans Message before Details for an account-root path.
It recognizes `<account-root>/<user>/`, not `(account: user)` labels. Within
each field it searches roots in configured order, can match an embedded root
substring, and can select an incidental path. These compatibility limits are
why account-aware producers should supply identity.

Qualifying rows with no identity from any source do not count toward either
aggregate. They are counted once per call and logged once per check name per
process, using only that call's row count and no finding text. Ignored,
derived, unknown and below-threshold security-event rows produce no
diagnostic count. A check with a declared attribution gap is still eligible:
when its producer does supply an authoritative owner, that Critical counts.

The health snapshot (`csm status --json`, `/api/v1/status`) carries a
`correlation_attribution` block with two views: `current` is the per-check
count of unattributed qualifying rows retained in the active set after its
latest merge, including any eviction caused by the size limit, and clears
when a later merge attributes them; `cumulative`
sums every unattributed row since the daemon started, across active-set
merges and per-batch derivations, so a producer that recovered stays visible
as having failed. Counters are published together in merge order. The block
is absent until the first merge. `csm doctor`
reports the same state as `correlation attribution`: OK when `current` is
empty, WARN naming the checks and their counts otherwise, with the history
in both cases.

The two per-batch derivations (scan runner, realtime dispatcher) see only
their batch and produce alerts. The latest-state merge derives from the
merged, deduplicated, capped persisted active set under the same lock as the purge,
so evidence from separate scans combines: three accounts compromised in three
different scans still produce a persisted `coordinated_attack`, and it clears
only when fewer than three accounts still carry a qualifying Critical there.
Each completed runner snapshot replaces only its own checks' rows; rows kept
for an unscanned owner or a file coverage gap stay as inputs; the previous
derived findings are dropped and recomputed from the merged set. Demotion,
dismissal or re-verification of a contributing row takes effect at the next
nonempty scan merge, and only if fewer qualifying accounts remain; there is
no immediate recompute and no promise that every file is re-verified.
Demoting a malware artifact below Critical cannot clear the all-severity
malware aggregate by itself. There is no time window, no shared-signature or
causal requirement, and no precision multiplier: the widened Critical inputs
accumulate across scans and can include unrelated events and false
positives, which is why the threshold calibration stays open on the roadmap.

Callers initialize platform detection before correlation; the latest-state
caller does so before taking the store lock. Correlation reads cached roots,
and attribution warnings are reported after the merge releases that lock.

Class membership does not mean an emitter currently reaches Critical: the
non-WordPress administrator checks emit High with a stored baseline and
Warning without one, and the outbound backdoor-port and bad-ASN variants emit
High, so all of them are eligible but contribute nothing until a Critical
variant exists.

Eligible producers supply verified identity when available. The test
inventory names the producer test for each check, including unresolved
branches:

- Database and CMS scanners stamp the owner of the install's configuration
  path, resolved through the account roots. An install outside every root
  keeps its display label but no owner.
- Mail producers (rate windows, mail holds, credential leaks, bulk-service
  logins, forwarders, filters, mail brute force, cloud relay, geo logins,
  PHP relay volume) resolve a mailbox or domain to its owning account through
  the panel's domain ownership table. Without that table (any panel other
  than cPanel) the owner stays empty and the row is reported, not counted. A
  bare account name must resolve to a passwd home directly under an account
  root. Credential and bulk-service findings use the authenticated identity,
  never the envelope sender. Sender-domain volume aggregates have no verified
  owner and stay unattributed. Owner lookups run after tracker locks are
  released. Mail hold and governor findings require a local mail-server
  permission decision.
- Process, login and crontab producers accept a system user as owner only
  when its home directory sits directly under an account root, so root,
  service users and unknown uids never become an account. Direct SMTP findings
  apply this validation to both socket users and enriched process accounts.
- File families (content, phishing, htaccess, file index, core integrity,
  realtime file events, PHP shield events, self-deleting droppers) carry the
  judged file's path, which resolves as described above. The collapsed
  core-integrity finding has no single path and carries the install owner.
- The periodic socket checks have no hosting owner, and the per-domain mail
  volume aggregate is keyed by the attacker-controlled envelope sender. Both
  are declared gaps in the registry; their unattributed Criticals reach only
  the diagnostic count.

### Correlation policy table

The table below is generated from the check registry: every registered
check with its class, its ignore reason when it is excluded, and its declared
attribution gap. A test compares it with the registry byte for byte and fails
when a row is stale, missing or duplicated; regenerate it with
`go test ./internal/checks -run '^TestCorrelationDocumentation$' -args -update-correlation-docs`
rather than editing rows by hand. A class says how correlation treats a check
when it fires; it does not say the check currently reaches Critical, that its
owner is available on every panel, or how precise it is.

Regeneration preserves the surrounding prose and marker line endings, even
when they use CRLF. The generated block itself uses LF line endings.

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

- `envelope-sender`: volume aggregate keyed by the attacker-controlled envelope sender; no verified owner exists
- `partial-socket-owner`: periodic evaluator supplies no tenant; realtime process enrichment can supply one but can miss
- `socket-owner`: periodic socket finding has no hosting owner; an unattributed Critical is counted in diagnostics only

| Check | Class | Ignore reason | Attribution gap |
| --- | --- | --- | --- |
| `account_scan` | ignored | self-health |  |
| `account_scan_error` | ignored | self-health |  |
| `account_scan_truncated` | ignored | self-health |  |
| `admin_cross_account_overlap` | ignored | account-aggregate |  |
| `admin_panel_bruteforce` | ignored | attacker-side |  |
| `af_alg_enforcement_corrected` | ignored | self-health |  |
| `af_alg_socket_use` | security event |  |  |
| `api_auth_failure` | ignored | attacker-side |  |
| `api_auth_failure_realtime` | ignored | attacker-side |  |
| `api_tokens` | ignored | informational |  |
| `auto_block` | ignored | response |  |
| `auto_response` | ignored | response |  |
| `backdoor_binary` | malware artifact |  |  |
| `backdoor_port` | security event |  | socket-owner |
| `backdoor_port_outbound` | security event |  | socket-owner |
| `bad_asn_outbound` | security event |  | partial-socket-owner |
| `bpf_ringbuf_error` | ignored | self-health |  |
| `bpf_unavailable` | ignored | self-health |  |
| `bulk_password_change` | ignored | account-aggregate |  |
| `c2_connection` | security event |  | socket-owner |
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
| `db_spam_cleaned` | ignored | response |  |
| `db_spam_found` | security event |  |  |
| `db_spam_injection` | security event |  |  |
| `db_spam_taxonomy` | security event |  |  |
| `db_stored_cloak_logic` | security event |  |  |
| `db_stored_code_execution` | security event |  |  |
| `db_suspicious_admin_email` | security event |  |  |
| `db_unexpected_event` | ignored | informational |  |
| `db_unexpected_function` | ignored | informational |  |
| `db_unexpected_procedure` | ignored | informational |  |
| `db_unexpected_trigger` | ignored | informational |  |
| `direct_smtp_egress` | security event |  |  |
| `dns_connection` | ignored | host-scope |  |
| `dns_zone_change` | ignored | informational |  |
| `dpkg_integrity` | ignored | host-scope |  |
| `drupal_admin_injection` | security event |  |  |
| `drupal_content_injection` | security event |  |  |
| `drupal_settings_injection` | security event |  |  |
| `email_auth_failure_realtime` | ignored | attacker-side |  |
| `email_av_degraded` | ignored | self-health |  |
| `email_av_encrypted_archive` | ignored | self-health |  |
| `email_av_parse_error` | ignored | self-health |  |
| `email_av_quarantine_error` | ignored | self-health |  |
| `email_av_queue_overflow` | ignored | self-health |  |
| `email_av_scan_error` | ignored | self-health |  |
| `email_av_scanner_panic` | ignored | self-health |  |
| `email_av_timeout` | ignored | self-health |  |
| `email_cloud_relay_abuse` | security event |  |  |
| `email_compromised_account` | security event |  |  |
| `email_credential_leak` | security event |  |  |
| `email_defer_fail_governor` | ignored | informational |  |
| `email_dkim_failure` | ignored | posture |  |
| `email_filter_blackhole` | security event |  |  |
| `email_filter_exfil` | security event |  |  |
| `email_filter_forwarder` | security event |  |  |
| `email_filter_pipe` | security event |  |  |
| `email_mail_filters` | ignored | self-health |  |
| `email_malware` | ignored | attacker-side |  |
| `email_password_audit_incomplete` | ignored | self-health |  |
| `email_phishing_content` | ignored | attacker-side |  |
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
| `ftp_auth_failure_realtime` | ignored | attacker-side |  |
| `ftp_bruteforce` | ignored | attacker-side |  |
| `ftp_login` | ignored | informational |  |
| `ftp_login_after_bruteforce` | security event |  |  |
| `ftp_login_realtime` | ignored | informational |  |
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
| `htaccess_security_disabled` | security event |  |  |
| `htaccess_spam_redirect` | security event |  |  |
| `htaccess_user_agent_cloak` | security event |  |  |
| `http_asn_crawl` | ignored | attacker-side |  |
| `http_claimed_bot_unverified` | ignored | attacker-side |  |
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
| `mail_subnet_spray` | ignored | attacker-side |  |
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
| `perf_wp_transients` | ignored | performance |  |
| `phishing_credential_log` | security event |  |  |
| `phishing_directory` | security event |  |  |
| `phishing_iframe` | security event |  |  |
| `phishing_kit_archive` | security event |  |  |
| `phishing_kit_realtime` | security event |  |  |
| `phishing_page` | security event |  |  |
| `phishing_php` | security event |  |  |
| `phishing_realtime` | security event |  |  |
| `phishing_redirector` | security event |  |  |
| `php_config_change` | ignored | posture |  |
| `php_config_realtime` | ignored | posture |  |
| `php_config_scan_incomplete` | ignored | self-health |  |
| `php_dropper_realtime` | security event |  |  |
| `php_in_sensitive_dir_realtime` | security event |  |  |
| `php_in_uploads_realtime` | security event |  |  |
| `php_remote_taint` | security event |  |  |
| `php_shield_block` | security event |  |  |
| `php_shield_eval` | security event |  |  |
| `php_shield_webshell` | security event |  |  |
| `php_suspicious_execution` | security event |  |  |
| `php_taint_scan_incomplete` | ignored | self-health |  |
| `protection_queue_degraded` | ignored | self-health |  |
| `protection_queue_recovered` | ignored | self-health |  |
| `realtime_scanner_panic` | ignored | self-health |  |
| `reputation_quota_exhausted` | ignored | self-health |  |
| `root_password_change` | ignored | host-scope |  |
| `rpm_integrity` | ignored | host-scope |  |
| `self_deleting_dropper_overflow` | ignored | self-health |  |
| `self_deleting_dropper_realtime` | security event |  |  |
| `sensitive_file_modified` | ignored | host-scope |  |
| `shadow_change` | ignored | host-scope |  |
| `signature_match_realtime` | security event |  |  |
| `signature_update_rescan_queued` | ignored | self-health |  |
| `signature_update_rollback` | ignored | self-health |  |
| `smtp_account_spray` | ignored | attacker-side |  |
| `smtp_bruteforce` | ignored | attacker-side |  |
| `smtp_probe_abuse` | ignored | attacker-side |  |
| `smtp_subnet_spray` | ignored | attacker-side |  |
| `ssh_keys` | ignored | host-scope |  |
| `ssh_login_realtime` | ignored | informational |  |
| `ssh_login_unknown_ip` | ignored | informational |  |
| `sshd_config_change` | ignored | host-scope |  |
| `ssl_cert_issued` | ignored | informational |  |
| `suid_binary` | security event |  |  |
| `supply_chain_vuln` | ignored | posture |  |
| `suspicious_crontab` | security event |  |  |
| `suspicious_file` | ignored | host-scope |  |
| `suspicious_php_content` | security event |  |  |
| `suspicious_process` | security event |  |  |
| `symlink_attack` | security event |  |  |
| `test_alert` | ignored | informational |  |
| `threat_feed_stale` | ignored | self-health |  |
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
| `webshell_content_realtime` | security event |  |  |
| `webshell_realtime` | security event |  |  |
| `whm_account_action` | ignored | informational |  |
| `whm_login_realtime` | ignored | informational |  |
| `whm_password_change` | ignored | informational |  |
| `whm_password_change_noninfra` | security event |  |  |
| `whm_unauth_scripts_realtime` | ignored | attacker-side |  |
| `world_writable_php` | ignored | posture |  |
| `wp_core_integrity` | security event |  |  |
| `wp_login_bruteforce` | ignored | attacker-side |  |
| `wp_user_enumeration` | ignored | attacker-side |  |
| `xmlrpc_abuse` | ignored | attacker-side |  |
| `yara_forge_rollback` | ignored | self-health |  |
| `yara_match_realtime` | security event |  |  |
| `yara_match_scheduled` | security event |  |  |
| `yara_scan_incomplete` | ignored | self-health |  |
| `yara_worker_crashed` | ignored | self-health |  |
<!-- correlation-table:end -->

## Findings from retired checks

A check name that no version of CSM emits any more stays registered while
older installations can still hold findings under it, because a finding is
only ever cleared when its name appears in the owning runner's purge list.
Two file-index names, `new_php_in_languages` and `new_php_in_upgrade`, are
in that state: findings written by releases before the content-first file
index are cleared by the next completed `file_index` scan, are kept while
that scan is incomplete, and are kept per file while the scan reports a
coverage gap for that file. Nothing emits them again. `php_dropper` was
never emitted by any release, is not registered, and no response table lists
it: the manual, automatic and full-scan quarantine sets and the attack
database mapping are each declared once and tested against the registry, so a
renamed or never-emitted name cannot sit inert in a response table. The same
guard removed `modsec_block` and `waf_block` from the attack database mapping;
neither was ever emitted, so WAF blocks have never fed local reputation
scoring through that database. Whether the emitted ModSecurity block names
should is an open scoring decision, not something the guard decides.

Directory enumeration and PHP handler-configuration read errors make the
file-index scan incomplete, including when only one account root is unreadable.
The scanner keeps its previous index and directory cache, preserves its active
findings, and still reports new findings from readable directories. A later
completed scan clears the retired names; absent optional directories do not
prevent completion. The first scan after startup and every retry after an
incomplete or interrupted walk enumerate directories again, even if their
cached modification times still match.

## API

- `GET /api/v1/incidents` -- list, newest first. Without query
  parameters the response is a bare JSON array (compat with the
  existing wire shape phpanel/SIEM consumers decode against).
  When `?limit=`, `?offset=`, or `?status=` is present the response
  switches to an envelope: `{"items":[...], "total":N, "offset":N,
  "limit":N, "status":"..."}`. Status accepts the four spec values
  plus `active` (open + contained, the default web UI filter).
  Limit is capped server-side at a safe maximum.
- `GET /api/v1/incidents/<id>` -- one incident.
- `POST /api/v1/incidents/<id>/status` -- transition status.

See [api.md](api.md) for endpoint detail.

## Web UI

Open **Monitor -> Incidents**. The page has three tabs:

- **Correlated** -- the default flat list of incidents with status
  filter, page size, and detail panel. The detail panel shows the
  current firewall block state for the incident's source IP (permanent,
  temporary, cphulk, or not blocked) when an IP is known.
- **Grouped** -- rolls up incidents by `(kind, source)` so a credential
  spray that produced thousands of mailbox_bruteforce incidents shows as
  one row per attacker IP. Pageable with the same page-size selector
  as Correlated. Click a group to see member incidents in the detail
  panel, which also surfaces the source IP's firewall block state;
  clicking a sample id jumps back to the Correlated tab focused on
  that incident.
- **Timeline Search** -- the older IP/account history search across
  the audit log.

Admin tokens can transition incident status (open / contained /
resolved / dismissed); read-scope tokens can browse all three tabs.

## Control socket

```
csm incidents list [--status all|active|open|contained|resolved|dismissed] [--limit N] [--offset N] [--all]
csm incidents show <id>
csm incidents status <id> <open|contained|resolved|dismissed> [details]
csm incidents bulk-status --older-than 24h [--last-seen-before RFC3339] [--status active|open|contained] [--kind K] [--domain D] [--account A] [--mailbox M] [--limit N] [--to resolved|dismissed] [--apply --confirm]
```

`csm incidents list` returns the first 100 incidents by default. Use
`--offset` for the next page, `--status active` for open + contained
incidents, or `--all` for an explicit full dump.

`csm incidents bulk-status` defaults to dry-run. It prints the total
match count and a bounded preview of the incidents that would change.
At least one age guard is required: `--older-than`, `--last-seen-before`,
or both. To mutate incidents, pass both `--apply` and `--confirm`.

## Metrics

- `csm_incidents_open` -- gauge of currently open + contained incidents.
- `csm_incidents_created_total`
- `csm_incidents_severity_changed_total`
- `csm_incidents_status_changed_total`
- `csm_incidents_findings_merged_total`
- `csm_incidents_compacted_total`
- `csm_incidents_pending` -- gauge of findings held in the threshold gate, awaiting a second correlated sighting.
