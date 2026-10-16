# Inbound spam filtering

CSM can filter inbound mail on cPanel hosts through rspamd, with each cPanel
account deciding for itself whether its mail is filtered. It is off by default.

The operator installs rspamd. CSM configures it, wires it into Exim, keeps the
integration current and reports when filtering is not working. CSM is never in
the live mail path: Exim talks to rspamd directly, and stopping CSM leaves the
installed filtering in place.

## What each account gets

The switch is cPanel's own **Spam Filters** page, "Process New Emails and Mark
them as Spam" (the `~/.spamassassinenable` file). New accounts start opted in.
Who may change the switch is controlled by the `spamassassin` feature in cPanel
feature lists; CSM adds no setting for it.

With `dry_run: false`, inbound mail is scored by rspamd and Exim applies the
account's choice. For an opted-in account, Exim:

- rejects it with 550 when the score is at or above `reject_score`;
- adds `X-Spam-Status: Yes` when the score is at or above `tag_score` and below
  `reject_score`. If the user turned on cPanel's spam box, the mail is filed in
  the Spam folder; otherwise it is delivered normally with the header.

Mail for an opted-out account is delivered with no CSM rejection and no spam
verdict header. Opting out never affects antivirus, outbound checks, SMTP-time
controls such as RBLs, rate limits and anti-spoofing, or CSM's detections.

A change to the switch applies from the next recipient Exim accepts. CSM does
nothing and Exim does not reload.

The Spam Filters page's own score threshold and allow and deny lists are not
used: `reject_score` and `tag_score` apply to every opted-in account.

### Who decides for a message

Policy follows the account that owns the addressed domain, including aliases,
forwarders and catch-alls. It is not re-evaluated for the mailbox a forwarder
finally delivers to:

- a forwarder in an opted-out account delivers unfiltered into an opted-in
  mailbox it points at;
- an address in an opted-in account can reject mail its forwarder would have
  passed to an opted-out mailbox.

When one message has recipients with different choices, Exim accepts the first
recipient and answers 452 for each later recipient whose choice differs. The
sending server retries those recipients in a separate delivery, which follows
their own choice.

If `/etc/global_spamassassin_enable` exists, cPanel treats every account as
opted in and no account can opt out. CSM reports this as a warning.

### Mail that is never scanned

Only unauthenticated mail from remote hosts to the host's local domains is
scanned. Authenticated submissions, local mail and these peers are not:
`127.0.0.0/8`, `::1`, `trustedmailhosts` and `cpanel_mail_netblocks`, the same
set cPanel exempts from its own spam scan.

cPanel also accepts some recipients before the scan hook runs, so they are
never filtered: mail to a domain from that domain's remote MX hosts, hosts in
`skipsmtpcheck_hosts`, always-relay and pop-before-SMTP hosts, Mailman
`-bounces` addresses and suspended recipients.

## Before you enable it

Install rspamd from the upstream [rspamd.com](https://rspamd.com/downloads.html)
repository and keep its systemd unit's `User=` setting (the upstream package
runs as `_rspamd`); CSM checks the scan socket's owner against it. CSM does not
install rspamd or Redis. A first install waits for the conditions below; a
definite failure after installation removes owned integration content when safe.

1. **SpamAssassin is off.** Disable spamd in WHM so `/etc/spamddisable` exists.
   Otherwise cPanel's own scan uses CSM's scanner and adds its own headers and
   subject tag whatever the account chose.
2. **A scan socket for Exim.** Add a Unix socket to rspamd's normal worker, in
   `/etc/rspamd/local.d/worker-normal.inc`:

   ```
   bind_socket = "/run/rspamd/csm-normal.sock mode=0666";
   ```

   This replaces the normal worker's TCP listener. The socket and every parent
   directory must be owned by root or the rspamd user. Parent directories must
   not be writable by group or others, so a hosting account cannot replace the
   listener. Extra ACL entries on the socket or any parent directory block
   installation. Exim's runtime user must be able to search every parent
   directory and write to the socket; `mode=0666` grants socket write access.
3. **rspamd accepts every message Exim accepts.** rspamd's default
   `max_message` (50 MiB) equals cPanel's default Exim limit, and Exim adds
   headers before scanning. Set `max_message` to Exim's `message_size_limit`
   plus at least 1 MiB in `/etc/rspamd/local.d/options.inc`, for example
   `max_message = 60mb;` with cPanel's 50M default.
4. **Validate and reload rspamd** (`rspamadm configtest`, then
   `systemctl reload rspamd`).
5. **Exim is running.** CSM probes an Exim listener before and after each
   change.

CSM also refuses to install while any of these hold, and names the cause:

- Exim settings, ACLs or filters that already act on spam scores, such as
  `deny_spam_score_over_*`, `ratelimit_spam_score_over_*` or automatic spam
  deletion and forwarded-spam restrictions;
- another `spamd_address` in `/etc/exim.conf.local`;
- cutthrough delivery, PRDR or CHUNKING enabled;
- an Exim main log other than the one CSM reads (`log_file_path`);
- an Exim or rspamd unit that cannot reload;
- disabled custom ACL hooks or invalid named lists used by the hooks;
- unsafe mutation targets, malformed CSM markers or foreign rspamd files in
  the locations CSM manages;
- an rspamd override that defeats CSM's settings below.

CSM does not change WHM options, account toggles, Redis or rspamd worker
settings to satisfy these conditions.

## Configuration

```yaml
email_protection:
  antispam:
    enabled: false
    dry_run: true
    rspamd_socket: /run/rspamd/csm-normal.sock
    reject_score: 15
    tag_score: 6
    feeds:
      enabled: []
      spamhaus_dqs_key_file: ""
```

- `enabled` turns the integration on. Setting it back to `false` requests
  removal of CSM's owned content; conflicts or failures can prevent removal
  and produce findings. On a host without cPanel it stays inactive; the
  daemon logs a warning at startup and whenever a configuration change is
  reloaded.
- `dry_run` scans and logs what would happen without rejecting, tagging or
  splitting recipients.
- `rspamd_socket` is the scan socket above: an absolute path of at most 107
  characters using letters, digits, `/`, `.`, `_` and `-`.
- `reject_score` and `tag_score` are whole rspamd scores with
  `0 < tag_score < reject_score <= 1000`.
- `feeds` selects optional blocklists; see [Feeds](#feeds).

All of these are hot-reloadable: after antispam starts, `systemctl reload csm` or a
Settings save updates health tracking and requests a reconcile pass before
forward-guard reconciliation. Settings saved before antispam starts are picked
up when it initializes, after the startup forward-guard reconciliation.
`enabled: true` is refused in [observe mode](observe-mode.md).

`rspamd_socket` is not the `reputation.rspamd` controller URL. That optional
setting reads rspamd's scan history for IP reputation and is unrelated to
filtering.

The capabilities API lists `mail.antispam.v1` when a build supports this
integration; it does not mean filtering is installed on the host.

## Feeds

Feeds and map redirects need rspamd 4 or later. On an older or unreadable
rspamd version CSM leaves rspamd's own lists and maps alone and reports it.

Every feed is off until you name it:

```yaml
email_protection:
  antispam:
    feeds:
      enabled: [psbl, mailspike]
      spamhaus_dqs_key_file: ""   # only for spamhaus_dqs
```

`enabled` is a list of feed names; an unknown or repeated name, or
`spamhaus_dqs` without a clean absolute `spamhaus_dqs_key_file`, makes the
configuration invalid. Check each list's terms against your use before you
enable it:

| Name | Terms |
|---|---|
| `mailspike` | Free for sites under 100,000 messages and 100,000 DNS queries a day; contact Mailspike above that. |
| `psbl` | Free for anyone. |
| `uceprotect1` | Free for private and commercial use; above 100,000 requests a day UCEPROTECT asks for its rsync feed. Level 1 also lists some forwarders that break SPF. |
| `nordspam` | Free for commercial and non-commercial use; contact Nordspam above 10,000 queries a day. |
| `sem` | Free; for scoring only, never to reject mail on its own. Tell Spam Eating Monkey before going above 100,000 queries a day. |
| `spamcop` | Free; SpamCop calls its list aggressive and recommends tagging, not rejecting. |
| `barracuda` | Free after registering the addresses of the resolvers that query it with Barracuda. |
| `dnswl` | Free through DNS under 100,000 queries a day; its pages conflict on non-commercial use. A listing lowers the score slightly. |
| `uribl` | Free for low-volume use only; URIBL blocks public and large shared resolvers. |
| `surbl` | Free only for organisations under 1,000 users or 250,000 messages a day, and never inside a product or service sold for a fee; other use needs SURBL's paid data service. See the [SURBL usage policy](https://www.surbl.org/usage-policy). |
| `spamhaus_dqs` | Needs a DQS key. The free key covers non-commercial use under 100,000 queries a day; commercial use needs a paid key. |
| `rspamd_maps` | Keeps rspamd's own map downloads from maps.rspamd.com; free use is non-commercial and under 5,000 queries a day, other use needs an agreement with rspamd. See [rspamd's usage policy](https://docs.rspamd.com/other/usage_policy/). |

### Maps without any feed

Without `rspamd_maps`, CSM redirects the rspamd.com maps it manages to
local files: the copies the rspamd package installs in `/etc/rspamd/maps.d`,
refreshed by package updates. The freemail and disposable-address rules stay
quiet until you put your own lists in
`/etc/rspamd/local.d/maps.d/freemail.map` and
`/etc/rspamd/local.d/maps.d/disposable.map`. Phishing exceptions read
`/etc/rspamd/local.d/maps.d/phishing_whitelist.inc` when it exists.

This does not block network access to rspamd.com. Operator-owned files and
additional maps can keep downloads active; CSM reports those it finds in
enabled modules after the integration is installed and current.

### DNS feeds need a local resolver

Some blocklists refuse queries from public resolvers. CSM enables a DNS feed
only when every nameserver rspamd uses is loopback or private. rspamd uses
`dns.nameserver` from its options, or `/etc/resolv.conf` when that is unset.
Run a recursive resolver on the host and add this line to
`/etc/rspamd/local.d/options.inc`:

```
dns { nameserver = ["127.0.0.1"]; }
```

cPanel's local BIND usually recurses for localhost; cPanel's PowerDNS and the
systemd-resolved stub do not. When PowerDNS holds port 53, run the resolver
on another port and name it with that port, for example
`dns { nameserver = ["127.0.0.1:5353"]; }`. A loopback or private address passes CSM's
address check, but a resolver that forwards to a public resolver can still
be refused. CSM never edits `options.inc`. After changing it, run
`rspamadm configtest`, reload rspamd, then reload CSM to request a check.

### Spamhaus DQS

Put the key alone in a root-owned file, mode 600, and name the file in
`spamhaus_dqs_key_file`. CSM reads it on every check, never logs it, and
writes it only into `/etc/rspamd/override.d/rbl.conf`, mode 640, owned by root
and rspamd's group. CSM must know that group: set `User=` (and optionally
`Group=`) in the rspamd unit. A root-started rspamd that changes user itself
leaves the group unknown, and the feed stays off.

rspamd writes the name of every failed lookup, which contains the key, to its
log. CSM keeps `spamhaus_dqs` off, with a feed warning, while that log file
can be read by other users, which is the rspamd package's default. Make it
private, for example `chmod 750 /var/log/rspamd` and `chmod 640` on the files
in it, and set rspamd's log rotation to create new files with mode 640. The
DQS rules also run without rspamd's own list monitoring. CSM probes ZEN's
test points and reports failures without stopping lookups. Turn the feed off
when a critical warning reports listings for a never-listed test point.

The log and its directories must be owned by root or rspamd, with no extra
ACLs or write access for other users. A private file or enclosing directory
must restrict readers to root and rspamd, including group access. Symlinks
and paths with dot components cannot establish privacy. CSM cannot verify
syslog or console routing; use `logging.type = file` with a private log.
The worker rechecks log privacy and rspamd version before applying feeds.

### Scores

No feed symbol weighs more than 5, and the symbols of one feed add up to at
most 14, so no feed alone reaches the default reject score of 15. Each symbol
counts once per message. SURBL's four scoring categories weigh 3.5 each;
Spamhaus DQS gives 5 for ZEN, 3 and 2 for the DBL categories and 3 and 1 for
newly seen domains.

### Files

CSM owns these files while a feed or map redirect needs them:

- `/etc/rspamd/override.d/rbl.conf` and `/etc/rspamd/override.d/rbl_group.conf`,
  with a DNS feed. They replace rspamd's own lists and their weights, so only
  the feeds you named run;
- `forged_recipients.conf`, `mid.conf`, `mime_types.conf`, `whitelist.conf`
  and `multimap.conf` in `/etc/rspamd/local.d`, without `rspamd_maps`.

An operator-owned file at one of these optional locations is left alone:
CSM omits DNS feeds or the affected map redirect. Its contents can still
conflict with required settings and block core filtering. In particular,
an `override.d/rbl.conf` that enables the RBL module defeats CSM's attempt
to turn it off when no DNS feeds are usable. Resolve that conflict before
enabling antispam.

### Feed findings

Each `antispam_feed` finding names the feed, `rspamd_maps` for maps, or
`rbl` for loaded-rule checks:

- feed off: the reason is in the details, such as a public resolver, a key
  file with the wrong owner or mode, or a file CSM cannot own. Fix it; the feed
  returns on the next check.
- map redirect skipped: CSM could not manage that optional file. Check the
  operator's map settings; they may already use local copies. Move those
  settings out of CSM's target file if CSM should manage the redirect.
- rspamd.com paths still loaded: rspamd still fetches those maps from
  rspamd.com. Redirect the named maps
  yourself, or enable `rspamd_maps` only if your use meets rspamd.com's terms.
- loaded rules differ during a routine check: rspamd runs a different set
  of blocklist rules from those CSM wrote, usually through an operator
  override. This is a warning only; CSM leaves the installed filtering in
  place. Correct the overrides, validate and reload rspamd, then reload CSM.
- refuses CSM's queries: the list answered with an error code, such as a
  refused resolver, a query limit or a rejected key. Those error-code answers
  add no score.
- does not answer: three checks in a row got no answer through rspamd's
  resolver. Check that the resolver recurses and can reach the list.
- unexpected answer: the test point returned an unrecognised answer. Check
  the provider and resolver; only the configured listing codes can score.
  A listed test point returning both listing and refusal codes also raises
  this warning; it does not prove that the list stopped scoring.
- answers for addresses it never lists (Critical): turn the feed off and
  reload CSM. CSM's probes only report findings; they do not disable feeds.
  A listing code still triggers this warning when the reply also contains
  a refusal code, since rspamd can score the listing code independently.
  rspamd stops querying a list only after its own monitoring detects it.
  DQS monitoring is disabled, so its lookups continue until you turn it off.

An apply that fails at `feeds_check` is reported as `antispam_apply_failed`
and attempts to roll back. CSM omits DNS feeds from subsequent applies until
the enabled feed names or DQS key-file path changes, or CSM restarts. Fix
the override before retrying. Reloading unchanged settings or replacing the
key's contents does not clear this hold.

CSM probes only while antispam is enabled outside observe mode and the
installed integration is current without blocking preconditions. It checks
two test names per supported zone through rspamd's first nameserver, on the
port rspamd uses, looking up A records. It does not probe SEM's IPv6 zone or
Spamhaus DBL and ZRD. A healthy probe result does not establish the health of
those zones or of other configured resolvers.

## What CSM writes

- three Exim ACL hooks under `/usr/local/cpanel/etc/exim/acls`
  (`custom_begin_spam_scan_check`, `custom_begin_spam_scan` and
  `custom_begin_check_message_post`), inside `# CSM-ANTISPAM BEGIN` and
  `# CSM-ANTISPAM END` markers;
- one `spamd_address` line in the `@CONFIG@` section of `/etc/exim.conf.local`;
- `actions.conf`, `greylist.conf`, `rbl.conf`, `emails.conf`, `asn.conf`,
  `fuzzy_check.conf` and `phishing.conf` in `/etc/rspamd/local.d`, each
  starting with `# csm-managed-version: 1`. Greylisting, the emails module,
  sender-IP lookups to rspamd.com, phishtank URL lookups to rspamd.com and
  public fuzzy storage are off. DNS block lists stay off unless a DNS feed is
  enabled;
- the map redirect files and, with a DNS feed, the blocklist files listed
  under [Feeds](#feeds);
- a completion record in `/var/lib/csm/antispam`.

Content outside CSM's markers, including forward-guard blocks, is preserved.
CSM regenerates its own blocks and files, so manual edits to them are
overwritten. A core file of the same name without CSM's header blocks the
install; removal leaves it alone. Optional feed and map files follow the
conflict handling described under [Files](#files).

The loaded `phishtank_enabled` setting must be the boolean `false`. Missing,
duplicate or non-boolean values are configuration conflicts, just like `true`.
CSM reports them and removes its integration when safe. Failed commands or
malformed command output leave the integration in place for a later check.

Each change runs as one transaction in a short-lived root helper started by
systemd outside CSM's sandbox, under the same lock as the forward guard. It
rebuilds the Exim configuration, checks it, reloads Exim and rspamd only when
needed, and restores the previous state if a step fails. If `systemd-run` is
not available, CSM changes nothing.

CSM checks the integration at startup, after each config reload and every 15
minutes, and repairs drift, such as a cPanel rebuild that dropped the hooks.
After fixing a condition that blocked it, run `systemctl reload csm` to request
another check, even when `csm.yaml` is unchanged. A check already running finishes
first; the reload does not wait for it.
When another CSM change holds the lock, it tries again 20 seconds later.

Before each check, CSM cancels antispam changes still waiting to run from an
earlier check or an earlier daemon, also while antispam is disabled or in
observe mode. A change that is already running finishes first.

If cancelling fails, CSM raises a warning and retries: after 20 seconds while
antispam is enabled, at the next regular check while it is disabled.

Existing Exim SMTP sessions retain their old hooks; new sessions use the
updated hooks. Account toggles are still read at each recipient. Reloading
rspamd can change scoring for scans from either generation of Exim hooks.

## Rolling it out

1. Meet the conditions above and enable with `dry_run: true`.
2. Leave dry run on for at least 7 days. Review each would-reject decision in
   the Exim main log (`CSM-ANTISPAM event=scan ... decision=reject`), and watch
   for scan-error findings. Do not enforce until all predicted rejects are
   classified, none rejects legitimate mail, and no scan or configuration
   failure finding remains.
3. Review which accounts are opted out today, and decide whether users may use
   the spam box (WHM Tweak Settings, `skipspambox`).
4. Set `dry_run: false`. Check every 550 for a week. Return to dry run on a
   confirmed false positive.

To roll back, set `enabled: false` while CSM is in enforce mode. Successful
removal reloads Exim, and new sessions no longer use CSM filtering. Check for
removal failures before assuming rollback completed. Observe mode leaves the
installed integration untouched.

Sessions opened before removal retain their old hooks and may still scan.
Those scans use operator or default rspamd settings after CSM's settings are
removed; scores can change and external lists can become active again.

## Findings

| Check | Severity | Meaning |
|---|---|---|
| `antispam_precondition` | Warning | A condition above is not met. The message names the cause, such as `rspamd_socket` or `spamassassin_enabled`. A temporary cause keeps an installed integration; a definite one removes it when that is safe. |
| `antispam_apply_failed` | Warning, or Critical when the previous state could not be confirmed | An install, update or removal failed at the named step, or pending changes could not be canceled. |
| `antispam_rspamd_down` | Warning | Three probes of the scan socket in a row failed. CSM probes every 20 seconds while antispam is enabled. |
| `antispam_rspamd_recovered` | Warning | Two probes in a row succeeded after an outage. |
| `antispam_scan_error` | Warning | Exim logged a failed scan. One finding covers every failure until a scan succeeds. |
| `antispam_feed` | Warning, or Critical when a list answers for everything | A feed or map redirect is off, loaded rules differ, a list misbehaves, or rspamd still fetches maps from rspamd.com. These findings alone do not disable filtering. See [Feeds](#feeds). |

While rspamd is down or scans fail, mail is delivered without spam filtering.
Exim adds no rejection for a scanner failure, and other mail checks keep
running. Disabling antispam clears the down and scan-error findings without
a recovery notice. Preconditions or removal failures can still be reported.

Dismissing a scan-error finding acknowledges the current episode. A successful
scan clears that dismissal immediately, even between health probes. Disabling
antispam or restarting CSM also resets it. Undismissed scan errors keep the
normal daily notification deduplication so intermittent failures do not send
one alert per message.

Rspamd outage and recovery notices do not consume the routine hourly alert
budget. They honor notification suppressions and email check exclusions.
Suppressed notices remain in history, the audit log and event streams.

In observe mode CSM changes no mail configuration; it only cancels changes
still waiting to run. An installed integration is reported as `observe_mode`.

## rspamd timeouts

When a scan reaches rspamd's `task_timeout`, rspamd answers with the score it
had so far. A slow rule that would have lowered the score is lost, so a
timed-out scan can tag or reject mail a complete scan would pass. Exim cannot
tell the difference; rspamd's log records the timeout. If it shows timeouts,
raise `task_timeout` or remove the slow rule.

## Tested versions

cPanel 11.138 with cPanel's Exim 4.100.1: on AlmaLinux 8 with rspamd 4.2.1 and
4.2.2, and on AlmaLinux 9 with rspamd 4.2.2. CSM needs Exim 4.97 or later with
content scanning and rspamd 3 or later.
