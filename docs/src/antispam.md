# Inbound spam filtering

CSM can filter inbound mail through rspamd on cPanel hosts, where each cPanel
account decides for itself whether its mail is filtered, and on Postfix hosts,
where every local domain is filtered. It is off by default.

The operator installs rspamd. CSM configures it, wires it into Exim on cPanel,
keeps the integration current and reports when filtering is not working. CSM is
never in the live mail path: Exim or Postfix talks to rspamd directly, and
stopping CSM leaves the installed filtering in place.

Most of this page describes cPanel hosts. [Postfix hosts](#postfix-hosts) lists
what differs there.

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
  the Spam folder; otherwise it is delivered normally with the header. When the
  [forward guard](configuration.md) enforces `spam_flagged`, a copy forwarded
  to an outside address is held instead of relayed.

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

This section is for cPanel hosts. Postfix hosts have their own
[requirements](#requirements).

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
- unsafe mutation targets or malformed CSM markers in the locations CSM
  manages;
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
    exempt: []
```

- `enabled` turns the integration on. Setting it back to `false` requests
  removal of CSM's owned content; conflicts or failures can prevent removal
  and produce findings. On a host that is neither a cPanel host running Exim
  nor a Postfix host it stays inactive; the daemon logs a warning at startup
  and whenever a configuration change is reloaded. Once such a host runs
  Postfix, for example after Postfix was installed or started after CSM, the
  next reload (`systemctl reload csm`) starts antispam without a restart.
- `dry_run` scans and logs what would happen without rejecting, tagging or
  splitting recipients. On a Postfix host CSM's rspamd files already apply in
  dry run, and the host's own action thresholds decide on CSM's scores; see
  [Dry run and enforce](#dry-run-and-enforce).
- `rspamd_socket` is the scan socket above: an absolute path of at most 107
  characters using letters, digits, `/`, `.`, `_` and `-`.
- `reject_score` and `tag_score` are whole rspamd scores with
  `0 < tag_score < reject_score <= 1000`.
- `feeds` selects optional blocklists; see [Feeds](#feeds).
- `exempt` lists recipient domains and mailboxes that are never filtered on a
  Postfix host, such as `example.com` or `postmaster@example.net`, and whose
  Junk folders are never learned from. Entries are
  lower-cased, and only plain domains and mailboxes are accepted. cPanel hosts
  ignore it: there each account's Spam Filters switch decides. See
  [Which mail is filtered](#which-mail-is-filtered).

All of these are hot-reloadable: after antispam starts, `systemctl reload csm` or a
Settings save updates health tracking and requests a reconcile pass before
forward-guard reconciliation. Settings saved before antispam starts are picked
up when it initializes, after the startup forward-guard reconciliation.
`enabled: true` is refused in [observe mode](observe-mode.md).

`rspamd_socket` is not the `reputation.rspamd` controller URL. That optional
setting reads rspamd's scan history for IP reputation and is unrelated to
filtering.

The capabilities API lists `mail.antispam.v1` when a build supports this
integration, and `mail.antispam.postfix.v1` when it also supports Postfix
hosts; neither means filtering is installed on the host.
`mail.antispam.learning.v1` means the build can learn from Spam folders,
and `mail.antispam.learning.postfix.v1` that it can also learn from Junk
folders on Postfix hosts; while learning runs, `csm status --json` carries
an `antispam_learning` block.

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
| `csm_ip_map` | Local data only: CSM's block history, its threat feeds and the spam evidence it records. |
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
only when every nameserver rspamd uses is loopback, private, or inside
the top-level `infra_ips`. rspamd uses `dns.nameserver` from its options, or
`/etc/resolv.conf` when that is unset.

When your own resolvers sit on public addresses and refuse other networks,
list their addresses or CIDRs in `infra_ips`; hostnames do not count for this
check. `infra_ips` changes need a CSM restart, not a reload. Otherwise run a
recursive resolver on the host and add this line to
`/etc/rspamd/local.d/options.inc`:

```
dns { nameserver = ["127.0.0.1"]; }
```

cPanel's local BIND usually recurses for localhost; cPanel's PowerDNS does
not. When rspamd uses the systemd-resolved stub (127.0.0.53 or 127.0.0.54
on port 53), CSM asks systemd-resolved for every server it can forward to,
including its fallback servers when no other server is configured, and
judges those. If CSM cannot read that list, DNS feeds stay off with a
warning. Other ports on the stub addresses count as separate local
resolvers. When PowerDNS holds port 53, run the resolver
on another port and name it with that port, for example
`dns { nameserver = ["127.0.0.1:5353"]; }`. A loopback or private address passes CSM's
address check, but a resolver that forwards to a public resolver can still
be refused. CSM never edits `options.inc`. After changing it, run
`rspamadm configtest`, reload rspamd, then reload CSM to request a check.

Resolver lists accept `master-slave:`, `round-robin:`, `random:`, and `hash:`
prefixes without regard to case. Rspamd 4.2.2 does not support `sequential:`;
CSM leaves DNS feeds off for that setting. A warning about an unreadable
`/etc/resolv.conf` applies only when no explicit nameserver setting exists;
invalid explicit settings get their own warning.

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

### CSM IP map

`csm_ip_map` gives rspamd CSM's own evidence about sender addresses. CSM
rebuilds the map at start and every 10 minutes into
`/var/lib/csm-rspamd/csm_ip.map`, and rspamd scores listed senders through
one rule, `CSM_IP`:

| Symbol | Listed when | Score |
|---|---|---|
| `CSM_IP_DROP` | the address is in a Spamhaus DROP network from CSM's threat feeds | 4 |
| `CSM_IP_BLOCKED` | CSM blocked the address permanently | 3 |
| `CSM_IP_MAIL_AUTH` | the address attacked SMTP or mail logins in the last 30 days | 3 |
| `CSM_IP_SPAM` | its spam evidence score is 50 or more, see [Spam evidence](#spam-evidence) | 3 |
| `CSM_IP_BLOCKLISTDE` | blocklist.de lists it in CSM's threat feeds | 2 |
| `CSM_IP_CINS` | CINS Army lists it in CSM's threat feeds | 2 |

Each address or network gets one line with its strongest symbol, so the map
adds at most 4 to a message. Whitelisted addresses (operator, temporary and
`reputation.whitelist`), `infra_ips`, private, loopback and link-local
addresses and the server's own addresses are never listed, and neither is a
network that contains one of them.

IPv4-mapped IPv6 addresses and CIDRs in `infra_ips` protect the same senders
as their IPv4 forms. Infrastructure hostnames use the last successful DNS
answers from CSM's firewall resolver. This requires a running CSM firewall;
without it, use literal addresses or CIDRs. DNS changes affect the map on
its next rebuild and spam evidence on the next scan record. Entries only in
`firewall.infra_ips` grant firewall access without suppressing spam evidence
or map listings.

The feed stays off with a warning until the map exists as a regular
root-owned file, mode 0640, in rspamd's service group, without extra ACLs. Every parent must be a root-owned directory with
no group or other write access or extra ACLs, and rspamd must be able to
traverse it. Symlinks cannot establish safe map access.

CSM must know rspamd's group, as for DQS above. The worker rechecks map
access and rspamd version before applying a queued request. A failed check
leaves the installed configuration intact. The next regular check retries
with the current host facts.

The feed needs CSM to own `/etc/rspamd/local.d/multimap.conf`, even with
`rspamd_maps` selected. CSM replaces an operator-owned file there, see
[Replaced files](#replaced-files); one that is not safe to replace leaves the
feed off.
Like the other feeds, it needs rspamd 4 or later.

CSM checks that rspamd uses the current map by scanning a canary message
from 192.0.2.255 every 30 seconds while the rule is in use. The scan stays
out of rspamd's history and statistics. `antispam_ip_map` reports a map CSM
could not write, or two consecutive probes showing rspamd still not using
the current map after its 5-minute load grace; a matching answer clears it.
Earlier probe failures are forgotten when the map is removed, monitoring is
disabled, observe mode is entered, or the scan socket changes.
Dismissing the warning acknowledges the current outage; recovery clears the
dismissal so a later failure can notify again.
A failed write keeps the previous map, which rspamd keeps using. A missing
map, a changed file mode or a changed
rspamd group makes CSM write the map again even when its content is the
same. Once no installed rule reads the map, CSM deletes it; a failed removal
raises `antispam_apply_failed` and is retried on the next pass.
If removal fails and a later apply reuses the surviving map, CSM resumes
monitoring it and subtracts its score from new spam evidence.

### Spam evidence

While antispam is enabled, CSM reads each scan result Exim logs and records
a verdict about the sending address: spam when the score reaches the reject
score, ham when it stays below the tag score, and nothing in between or when
the scan failed. The score the CSM IP map gave the sender is subtracted
first, so the map never feeds its own evidence. Dry run and enforce record
the same way, and so do recipients with filtering off: the verdict is about
the sender. Whitelisted, `infra_ips`, private and the server's own addresses
are skipped. Postfix hosts record no verdicts; see [Scan records](#scan-records).
This works with or without `csm_ip_map`, so you can review the data before
turning the map on. After a CSM restart with `csm_ip_map` enabled, verdicts
are not recorded until CSM has written the map again, because the map's
share of a score is unknown until then.

A spam verdict creates or updates the sender's record on the Threat page.
Ham only updates a record that already exists, so busy legitimate senders do
not fill the attack database. The spam score is the share of spam among
recent verdicts, each verdict losing half its weight every 7 days; two recent
spam verdicts and no ham reach 50, which lists the sender as `CSM_IP_SPAM`.
Spam evidence never blocks an address, never changes its threat score and is
never reported to AbuseIPDB.

With `spam` in `reputation.report.classes`, a sender that rspamd keeps
rejecting, and that has sent no clean mail recently, is reported to the
central abuse database. Senders of the shared mail services are never
reported. Dry-run nodes count their verdicts too. See
[Abuse Reporting](threat-intel.md#abuse-reporting).

The Threat page's Spam column shows spam and ham counts and the spam score,
with a badge once the score reaches the listing threshold of 50. The badge
does not confirm a listing: the feed may be off, and the map still skips
excluded addresses. The "Spam evidence only" filter lists
senders by spam score. The IP lookup shows mail login attacks and spam
verdicts.

### Scores

No feed symbol weighs more than 5, and the symbols of one feed add up to at
most 14, so no feed alone reaches the default reject score of 15. Each symbol
counts once per message. SURBL's four scoring categories weigh 3.5 each;
Spamhaus DQS gives 5 for ZEN, 3 and 2 for the DBL categories and 3 and 1 for
newly seen domains. URIBL's grey and red lists weigh 0.5 because they also
list domains that legitimate bulk senders use.

### Files

CSM owns these files while a feed or map redirect needs them:

- `/etc/rspamd/override.d/rbl.conf` and `/etc/rspamd/override.d/rbl_group.conf`,
  with a DNS feed. They replace rspamd's own lists and their weights, so only
  the feeds you named run;
- `forged_recipients.conf`, `mid.conf`, `mime_types.conf`, `whitelist.conf`
  and `multimap.conf` in `/etc/rspamd/local.d`, without `rspamd_maps`.
  The local IP feed also needs `multimap.conf` when `rspamd_maps` is selected.

CSM replaces an operator-owned file at one of these locations while it
needs the file, see [Replaced files](#replaced-files). A file that is not
safe to replace makes CSM omit the DNS feeds or the affected map redirect
instead. An operator file CSM does not need stays, and its contents can
still conflict with required settings and block core filtering. In
particular, an `override.d/rbl.conf` that enables the RBL module defeats
CSM's attempt to turn it off when no DNS feeds are usable. Resolve that
conflict before enabling antispam.

### Feed findings

Each `antispam_feed` finding names the feed, `rspamd_maps` for maps, or
`rbl` for loaded DNS-rule checks:

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
- IP-map rule differs or cannot be verified: with `csm_ip_map` enabled,
  CSM checks that multimap is enabled and that `CSM_IP` uses the managed
  map, expected score and complete symbol set. Symbol order does not matter.
  Extra rule options that can change matching or force an action are
  conflicts. Failed configuration dumps also produce a warning. Routine
  checks leave core filtering installed; correct the override or command
  failure before retrying an apply.
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
and attempts to roll back. CSM omits DNS feeds and `csm_ip_map` from subsequent
applies until the enabled feed names or DQS key-file path changes, or CSM
restarts, and does not rewrite the IP map meanwhile. Fix the override before
retrying. Reloading unchanged settings or replacing the key's contents does not
clear this hold.

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
  `fuzzy_check.conf`, `phishing.conf` and `regexp.conf` in
  `/etc/rspamd/local.d`, each starting with `# csm-managed-version: 1`.
  Greylisting, the emails module, sender-IP lookups to rspamd.com, phishtank
  URL lookups to rspamd.com and public fuzzy storage are off. DNS block lists
  stay off unless a DNS feed is enabled. `regexp.conf` holds the
  `CSM_INVISIBLE_CJK_SUBJECT` rule: a Subject with an invisible character,
  such as a zero-width space, next to a Chinese, Japanese or Korean letter.
  It checks the decoded Subject, including MIME-encoded ones, and covers
  kana, Han and Hangul letters with their half-width and supplementary
  forms. Punctuation does not trigger it. Spam uses invisible characters to
  split words so filters miss them. On its own the rule lifts a message
  above the default `tag_score` but not to the default `reject_score`.
  Keep your own regexp rules in `/etc/rspamd/override.d/regexp.conf`;
- the map redirect files and, with a DNS feed, the blocklist files listed
  under [Feeds](#feeds);
- `groups.conf` in `/etc/rspamd/local.d`, which lowers rspamd's
  `HIDDEN_TEXT` weight from 5 to 2. Newsletters hide their preview line, and
  at the default `tag_score` that rule plus one minor symbol tagged them. It
  also counts `URL_VERY_LONG` once per message instead of once per long
  link, so newsletters full of tracking links are not tagged for that. It
  raises `DMARC_POLICY_REJECT` from 2 to 3, so forged mail from a domain
  whose DMARC policy is reject reaches the tag score sooner. A symbol you
  define in any `*_group.conf` in `/etc/rspamd/local.d` keeps your weight:
  CSM leaves it out of its file. If one of those files cannot be read or
  uses includes, macros or multiline strings, CSM leaves all three weights
  to rspamd. Your `override.d` group files already take precedence.
  CSM replaces an operator-owned `groups.conf`.
  One that is not safe to replace is left alone: rspamd keeps its own
  weights and CSM reports an `rspamd_scores` warning;
- with learning on, the learning files listed under
  [Learning from Spam folders](#learning-from-spam-folders);
- a completion record in `/var/lib/csm/antispam`.

Content outside CSM's markers, including forward-guard blocks, is preserved.
CSM regenerates its own blocks and files, so manual edits to them are
overwritten. A file of the same name without CSM's header is replaced, see
[Replaced files](#replaced-files); removal leaves it alone.

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

### Replaced files

CSM owns its rspamd files and the Roundcube include outright. When antispam
is enabled and one of those paths holds your own file, CSM copies it to
`/var/lib/csm/antispam/replaced` before writing its own. Each copy is
readable by root only. Its name is the UTC time followed by the escaped
original path, for example
`20261101T120000Z_%2Fetc%2Frspamd%2Flocal.d%2Factions.conf`.

CSM replaces only a regular file owned by root, with no group or other write
access and no extra ACL entries, in directories protected the same way. Any
other file at one of these paths blocks the install, or leaves the optional
feature that needs it off. CSM repeats these checks before copying the file
and before replacing it. The Exim hook files and `/etc/exim.conf.local`
are shared: CSM edits its own block there and never replaces them.

Each retained copy raises one `antispam_file_replaced` warning naming the
file and the copy in the same check that runs the update. Move any settings
you still need into a file CSM does not manage, then delete the copy to clear
the warning.

When a change fails, CSM restores your file with its original owner, group
and permissions. It deletes that copy only after the restore is durable,
even if another file could not be restored. Copies made for replacements
that never happened are removed too. If a restore cannot be confirmed, its
copy remains for recovery.

On a cPanel host, disabling antispam deletes CSM's files and does not
restore the copies. On a Postfix host, disabling antispam puts the newest
copy of each file back over CSM's own file and deletes that copy, and
returning to dry run does the same for `actions.conf`, see
[Dry run and enforce](#dry-run-and-enforce). Older copies of the same file
stay, and CSM never restores over a file it did not write. Restores require
root-owned backups with mode 0600 in a root-only directory. A symlink,
unsafe backup or unsafe destination permissions stop the transaction
before mail configuration changes. Correct the permissions and retry.
If a backup changes before completion, CSM rolls back and keeps that edit.
Restores and their rollbacks never follow directory symlinks.
A restored file gets the owner and mode checked before the restore, which
after a takeover are your original ones. `/etc/rspamd/override.d/rbl.conf`
written while a DQS key is set is the exception: CSM's file is owned by root,
in rspamd's group, with mode 0640, and the restored file keeps that.
Each warning says what CSM will do with its copy. The warnings describe
past replacements, including
after antispam is disabled.

## Rolling it out

1. Meet the conditions above and enable with `dry_run: true`.
2. Leave dry run on for at least 7 days. Review each would-reject decision in
   the Exim main log (`CSM-ANTISPAM event=scan ... decision=reject`), and watch
   for scan-error findings. Do not enforce until all predicted rejects are
   classified, none rejects legitimate mail, and no scan or configuration
   failure finding remains.
3. Review which accounts are opted out today, and decide whether users may use
   the spam box (WHM Tweak Settings, `skipspambox`). That setting only shows or
   hides the choice: accounts that already have `~/.spamassassinboxenable`
   get tagged mail in their Spam folder either way, and turning the spam box
   off in WHM deletes that file from every account.
4. Set `dry_run: false`. Check every 550 for a week. Return to dry run on a
   confirmed false positive.

To roll back, set `enabled: false` while CSM is in enforce mode. Successful
removal reloads Exim, and new sessions no longer use CSM filtering. Check for
removal failures before assuming rollback completed. Observe mode leaves the
installed integration untouched.

Sessions opened before removal retain their old hooks and may still scan.
Those scans use operator or default rspamd settings after CSM's settings are
removed; scores can change and external lists can become active again.

## Postfix hosts

On a host without cPanel that runs Postfix, CSM manages rspamd only. Postfix
already passes mail to rspamd's proxy worker as a milter, and rspamd applies
the decision. CSM never edits Postfix's configuration. The sections above
about cPanel accounts, Exim and Roundcube do not apply.

### Requirements

1. **Postfix passes mail to rspamd's proxy worker.** `smtpd_milters` must
   name the address of an rspamd proxy worker that has `milter = yes`. CSM
   checks this read-only with `postconf` and rspamd's worker settings. When
   smtpd runs chrooted, a `unix:` milter path is resolved inside Postfix's
   queue directory, as Postfix does. Without this wiring CSM reports a
   definite `postfix_milter` precondition and installs nothing.
   `milter_mail_macros` must also include `{auth_authen}`, with the braces,
   as Postfix's default does: rspamd knows authenticated mail by it. Without
   it CSM reports the same precondition, because customers' outbound mail
   would be filtered as remote mail. CSM reads both settings from `main.cf`
   only; per-service `-o smtpd_milters` overrides in `master.cf` are not
   read.
2. **rspamd refuses the mail it rejects.** With `discard_on_reject` on the
   proxy worker, rspamd's milter drops a message it rejects; with
   `quarantine_on_reject` it accepts the message into Postfix's hold queue,
   where it stays until someone releases or deletes it. Either way the
   sender is never refused. CSM does not enforce while either is set on a
   proxy worker Postfix passes mail to, and removes an enforcing install,
   with a definite `milter_rejects` precondition. In dry run, where the
   host's own rejects go the same way, it is a warning. An option given
   more than once counts as set unless every value is false, and so does
   any value that is not a boolean, such as null. Set both to false, once
   each, for example in `/etc/rspamd/local.d/worker-proxy.inc`.
3. **rspamd 4.2 is recommended.** CSM accepts rspamd 3 or later, but its
   scope rule is tested with rspamd 4.2.3.
4. **`/etc/rspamd/lua.local.d` exists**, owned by root and not writable by
   group or others. CSM's scope rule goes there.
5. **A scan socket for CSM.** CSM uses it to check that rspamd answers. Add
   a Unix socket to rspamd's normal worker in
   `/etc/rspamd/local.d/worker-normal.inc`:

   ```
   bind_socket = "localhost:11333";
   bind_socket = "/run/rspamd/csm-normal.sock mode=0600";
   ```

   Only CSM uses this socket, as root, so mode 0600 is enough. Keep the
   first line if your proxy worker passes mail on to the normal worker
   instead of scanning it itself. The socket and every parent directory must
   be owned by root or the rspamd user and not writable by group or others.
   Run `rspamadm configtest`, then `systemctl reload rspamd`.
6. **rspamd logs to a file at `info` level.** CSM reads its scan records
   from rspamd's log file, for example `/var/log/rspamd/rspamd.log`. When
   rspamd logs to the journal or syslog, CSM warns and sees no scan records.
   `info` is rspamd's default. At `notice`, `warning` or `error` level rspamd
   does not write them, and CSM does not warn; set `level = "info";` in
   `/etc/rspamd/local.d/logging.inc`.
7. **rspamd accepts every message Postfix accepts.** CSM warns when rspamd's
   `max_message` is below Postfix's `message_size_limit`.
8. **Postfix and rspamd are running.**

### Which mail is filtered

All unauthenticated mail from remote hosts is filtered, whatever domain it
is addressed to. That includes mail Postfix relays for hosts in
`mynetworks` on public addresses; list those in `infra_ips`. CSM never
rejects or tags mail:

- from a sender who authenticated to Postfix;
- from rspamd's local networks (`local_addrs`), which include loopback and
  the private address ranges by default;
- from an address in `infra_ips`.

Mail whose every recipient is in `exempt` is scored and logged, but never
rejected or tagged. A domain entry matches that domain only, not its
subdomains. One recipient outside the list is enough: the whole message is
then filtered.

Your own rspamd settings rules, for example in
`/etc/rspamd/local.d/settings.conf`, keep working. For mail CSM does not
filter, CSM only raises the action thresholds on top of what your rule set.
A rule that limits which symbols run (`symbols_enabled` or `groups_enabled`)
also skips CSM's scope rule: mail it matches keeps the normal thresholds, even
when it is authenticated, local or exempt, and gets no scan record.

### Dry run and enforce

A dry run on Postfix already changes how rspamd scores mail. rspamd is in
the mail path, and CSM installs its scoring files from the first dry run, so
it can predict its own decisions. From then on:

- greylisting, the emails module and public fuzzy storage are off;
- rspamd's own DNS block lists are off, unless you name DNS feeds in
  `feeds.enabled`;
- sender-IP and phishtank lookups to rspamd.com are off, and without the
  `rspamd_maps` feed the rspamd.com maps CSM manages are read from local
  copies, so the freemail and disposable-address lists stay empty until you
  fill them, see [Maps without any feed](#maps-without-any-feed);
- CSM's symbol weights and its invisible-character Subject rule apply;
- CSM's `milter_headers.conf` replaces yours, so other header routines you
  enabled there stop;
- your own files at those paths are replaced, with a copy kept and an
  `antispam_file_replaced` warning, see [Replaced files](#replaced-files).

What CSM leaves to the host in dry run is `actions.conf`: rspamd keeps
rejecting and tagging at the host's own thresholds, now applied to CSM's
scores, for all mail, including authenticated, local and exempt mail. Mail
can therefore score differently than before CSM, in both directions. CSM
logs what it would have done with each scored message: `decision=reject`,
`tag` or `none`, and `unfiltered` for exempt mail.

When the host's own reject threshold is at or below `reject_score`, as with
rspamd's built-in actions when there is no `actions.conf`, the dry run still
rejects mail. CSM raises a `dry_run_rejects` precondition warning, for
example "dry run on this host still rejects: rspamd rejects at 15, at or
below CSM's reject score of 15".

With `dry_run: false` CSM takes over `/etc/rspamd/local.d/actions.conf`. An
existing file is copied first, see [Replaced files](#replaced-files). rspamd
then rejects at `reject_score` and adds headers at `tag_score`. CSM's
thresholds never reject or tag authenticated, local, `infra_ips` or exempt
mail; other rspamd modules, such as antivirus, can still reject it.

Going back to dry run puts your `actions.conf` back from its newest copy,
deletes that copy and clears its warning. The file gets the owner and mode
CSM's file had, which after a takeover are your original ones, or root
ownership and mode 0644 when CSM's file was loosened.
Your thresholds decide again. Without a copy CSM deletes its own file, and
rspamd's built-in actions apply, which reject too.

### Headers and the Junk folder

CSM owns `/etc/rspamd/local.d/milter_headers.conf`. rspamd removes any
`X-Spam-Status` header a message arrives with and adds its own:
`X-Spam-Status: Yes, score=...` at the add header threshold, `No` below it.
For authenticated and local mail, which rspamd's milter headers skip, CSM's
scope rule removes the inbound copy itself. In dry run the header follows
the host's own add header threshold.

rspamd also adds its own `Authentication-Results` header with the SPF, DKIM,
DMARC and ARC results, and removes any copy the message arrived with, since a
sender could forge one. Authenticated and local mail get no new
`Authentication-Results` header and keep any existing copies, so rspamd does
not add login names to outbound mail. Their inbound `X-Spam-Status` is still
removed. Other header routines, such as `X-Spam-Level` or rspamd's extended
headers, are off.

CSM leaves the `X-Spam: Yes` header of rspamd's proxy worker alone. Filing
tagged mail into the Junk folder stays your Sieve rule, for example one that
files `X-Spam: Yes` into Junk. CSM does not manage Sieve.

### Scan records

CSM's scope rule writes one `CSM-ANTISPAM event=scan` line per scored message
into rspamd's log, at `info` level: rspamd logging at `notice` or above
hides them. Authenticated, local and `infra_ips` mail get none. These
records count toward scan health and the Email Security page only. They do
not feed spam evidence, the CSM IP map, the Threat page or abuse reports:
any local process can make rspamd log such a line through its local scan and
milter listeners.

Failed scans come from Postfix's mail log: Postfix logs a warning each time
its milter call to rspamd fails, and CSM raises `antispam_scan_error`. What
happens to that mail depends on Postfix's `milter_default_action`: `accept`
delivers it unfiltered, `tempfail` defers it, `reject` rejects it and
`quarantine` holds it in Postfix's hold queue.

### Files and learning

CSM writes the rspamd files and the completion record listed under
[What CSM writes](#what-csm-writes), `actions.conf` only while it enforces,
plus `milter_headers.conf` in `/etc/rspamd/local.d` and `csm_scope.lua` in
`/etc/rspamd/lua.local.d`. It writes no Exim or Roundcube file. Each change
reloads rspamd only. Disabling antispam removes these files and puts back
the newest copy of each file CSM replaced, see
[Replaced files](#replaced-files).

Learning installs the same rspamd files as on cPanel, without the webmail
include; see [Learning from Junk folders](#learning-from-junk-folders).

If CSM cannot tell which mail server runs, for example while Postfix
restarts on a host that also has Exim installed, it leaves an installed
integration in place and reports a temporary `platform` precondition.

### Learning from Junk folders

With `learning.enabled: true` CSM learns from mail users move into their
Dovecot Junk folder. Scores, limits, retention, stored messages, operator
commands and findings work as described under
[Learning from Spam folders](#learning-from-spam-folders), with these
differences:

- Every mailbox Dovecot lists takes part. There is no per-mailbox switch
  and no opt-in file. Mailboxes and domains in `exempt` are not watched:
  CSM does not read their Junk folders.
- CSM reads the `new` and `cur` directories of each Junk folder. A report
  must be owned by the uid Dovecot stores that mailbox's mail as.
- Mail already in a Junk folder is never learned. The first pass records
  what is there, and only messages moved in later are reports.
- No webmail Junk-button include is installed.

#### Learning requirements

The [learning prerequisites](#prerequisites) apply, and also:

1. **Dovecot 2.3.** CSM lists users with `doveadm user '*'` and reads mail
   settings with `doveconf`. A userdb must be able to list its users. A
   passwd or passwd-file userdb can, but not a passwd-file whose path holds
   `%` variables, such as one file per domain. An SQL or LDAP userdb needs
   its iterate settings. A static, checkpassword or prefetch userdb cannot.
   When no userdb can list users, and on Dovecot 2.4, whose mail settings
   changed, CSM reports `unsupported` and leaves learning off. When a userdb
   that can list users fails, for example while its SQL database is down,
   CSM reports `backend_unavailable`: installed learning stays and new
   reports wait for a later check. A temporary failure looking up an
   individual user also pauses discovery, without cancelling reservations
   or pruning state. Unusable or case-colliding user names pause discovery
   because their identities and mail owners cannot be established safely.
2. **Junk marked as `\Junk`.** CSM finds Junk folders by
   `special_use = \Junk` in Dovecot's namespace mailbox settings, as
   Dovecot's example `15-mailboxes.conf` sets for `Junk`. A single configured
   mailbox is supported too. A folder named
   Junk without the flag is not watched, and with no `\Junk` mailbox at all
   every mailbox is skipped.
3. **Maildir in its default layout.** CSM skips a mailbox stored another
   way: another driver such as `mdbox` or `mbox`, `LAYOUT=fs`, or the `zlib`
   or `mail_crypt` plugin. It also skips a mailbox whose uid is 0, whose
   home or mail location it cannot use, such as a location with `DIRNAME`,
   `MAILBOXDIR` or a `%{if}` condition, or whose lookup confirms the user
   does not exist. A `%{if}` in `mail_location` or a private namespace
   location skips every mailbox; CSM still reads their mail owners for
   isolation checks. Known owners remain part of those checks even when
   their mailboxes are skipped for another reason.
   Two users whose mail directories are the same, including a symlink
   alias, or one inside the other, are both skipped: CSM cannot tell their
   moves apart. Private namespaces without Junk also count. An unresolved
   mail location holds other mailboxes sharing its uid until discovery can
   distinguish them. Skipped mailboxes are counted by reason in one
   `mailboxes_skipped` warning that names none of them; learning goes on
   for the others.
4. **A Redis of its own.** Learning never uses rspamd's Redis on Postfix,
   because other rspamd modules share it. Run a second Redis instance and
   set `learning.redis_socket` to its socket; without it CSM reports
   `unsupported`. On Debian and Ubuntu the packaged `redis-server@.service`
   template runs an instance from `/etc/redis/redis-<name>.conf`. For an
   instance named `csm`, create its data directory:

   ```
   install -d -o redis -g redis -m 0750 /var/lib/redis/csm
   ```

   Then write `/etc/redis/redis-csm.conf`:

   ```
   port 0
   unixsocket /run/redis-csm/redis.sock
   unixsocketperm 770
   pidfile /run/redis-csm/redis-server.pid
   dir /var/lib/redis/csm
   maxmemory 256mb
   maxmemory-policy noeviction
   appendonly yes
   ```

   and start it with `systemctl enable --now redis-server@csm`. The
   template's sandbox lets Redis write below `/var/lib/redis`,
   `/var/log/redis`, its run directory and, for cluster mode, `/etc/redis`;
   `systemctl cat redis-server@csm` shows the exact list on your system.
   `dir` must be in one of them for persistence to work. Use the data
   directory created above, not `/var/lib/redis` itself, where the main
   instance keeps its files. Size `maxmemory` for the hashes you expect to
   learn.

   Give rspamd's user access through the socket's group, for example with
   `usermod -aG redis _rspamd`; no other user may be in that group. Then
   restart rspamd: a reload keeps the groups it started with, and its fuzzy
   worker would be refused by the socket. The Redis checks of the
   prerequisites apply to this socket. rspamd's global `redis` settings
   must not use sentinels, TLS or a named user, because rspamd would apply
   them to the learning Redis too.
5. **A private controller socket for CSM**, as on cPanel; see
   [rspamd admin interface](#rspamd-admin-interface).
6. **A mail user that is not a service user.** Users' Sieve scripts and
   Dovecot's mail processes run as the uid Dovecot stores mail as, such as
   `vmail`, so CSM treats every name of that uid as a user that can run
   tenant code: none may be in the Redis socket's group. Mail stored as
   rspamd's or Redis's uid is refused with `unsafe_prerequisite`.

CSM checks these on every reconciliation pass while learning is requested.
The learner and its Junk folder watcher start only once none of them fails.

#### Reporters

`learning.reporter` decides who casts one learning vote:

- `domain`, the default: each mail domain is one reporter. Its mailboxes
  share one vote per cluster and one learning allowance. A domain that
  reaches its allowance pauses only its own new reports.
- `mailbox`: each mailbox is a reporter of its own, as each cPanel account
  is.

A user without a domain, such as a system user, reports under its own uid
in either mode.

Changing the mode, or `exempt`, restarts the Junk folder watcher. Votes
already cast stay until their cluster expires, so a cluster reported both
before and after a mode change can count the same domain or mailbox one
extra time. Reports the old reporters had not sent yet are dropped, and
the Junk folders of domain mailboxes start new baselines.

#### Enabling learning on Postfix

1. Set up the Redis instance and the private controller socket above, then
   run `rspamadm configtest` and restart rspamd. A reload is not enough
   after adding rspamd's user to the socket's group.
2. Set `learning.enabled: true` and `learning.redis_socket`, then run
   `csm validate` and `systemctl reload csm`.
3. Check `antispam_learning` findings and `csm doctor`. Once learning runs,
   `csm status --json` carries an `antispam_learning` block.
4. Move a test message into a Junk folder. The next pass, within five
   minutes, picks it up.

### Rolling it out on Postfix

1. Meet the requirements above. Choose `feeds.enabled` first: the dry run
   already turns off rspamd's own DNS block lists and greylisting. Enable
   with `dry_run: true`. Leave `exempt` empty unless a recipient must never
   be filtered.
2. Check that rspamd's loaded actions are still the host's
   (`rspamadm configdump actions`) and that no `dry_run_rejects` or
   `milter_rejects` warning appears. Review each `antispam_file_replaced` copy, and check that
   greylisting and DNS block lists are as you intend. Then check that
   `CSM-ANTISPAM` lines appear in rspamd's log and that mail at the host's
   add header threshold still carries `X-Spam: Yes`.
3. Leave dry run on for at least 7 days. Review each would-reject decision
   in rspamd's log (`CSM-ANTISPAM event=scan ... decision=reject`) and watch
   for scan-error findings.
4. Set `dry_run: false`. Check every reject for a week. On a confirmed false
   positive, return to dry run: CSM puts your own `actions.conf` back.

To roll back, set `enabled: false`. CSM removes its rspamd files, puts back
the files it replaced and reloads rspamd.

## rspamd admin interface

rspamd's controller answers admin and statistics requests. By default it
trusts every connection from `127.0.0.1` and `::1` without a password, and
every process on the server can connect there, including customer scripts.
Such a process could read rspamd's history, which lists senders and
recipients of scanned mail, or change scores and actions at runtime.

While antispam is enabled, CSM reports each controller listener that other
users may reach as an `antispam_controller_open` finding. The finding names
the listener and the reason, including cases where CSM cannot prove isolation:

- a trusted address that local processes can use (loopback, a wildcard, or
  one of the server's own addresses);
- a trust entry CSM cannot resolve, such as a map file or a hostname;
- no controller password at all, only an enable password, or an empty
  password;
- a controller configuration CSM cannot read in full, such as an unreadable
  worker type, an unsupported `enabled` or `count` value, a systemd socket,
  or a second controller worker;
- a Unix socket, or one of its parent directories, that other users can
  write to, or whose access CSM cannot verify.

For symlinked Unix sockets, a private directory protects only its own
descendants. CSM also checks the resolved socket path: a private directory
on a detour does not hide a socket reachable through its real path.

These warnings also update in observe mode and when an apply is busy. When
`rspamadm` cannot run, CSM keeps the previous warnings until it can.
Turning antispam off clears them even if CSM cannot cancel pending changes.

To close TCP access, keep a controller password set and put this in
`/etc/rspamd/override.d/worker-controller.inc`:

```
secure_ip = [];
```

rspamd ships with the placeholder password `q1`, which it rejects as client
authentication, so this also works without setting your own. With both
`password` and `enable_password` unset, an empty `secure_ip` opens every
command to everyone. Setting only `enable_password` leaves read-only access
open.

For local administration add a private Unix socket in the same file. Direct
Unix socket connections get admin access without a password. Forwarded
headers trigger additional trust and password checks, so local clients must
send no forwarded headers. Keep the socket and its parent directories owned
by root or rspamd, with no extended ACLs. Use socket mode 0600 and non-symlink
directories that other users cannot write to. Socket mode alone does not
protect a replaceable parent:

```
bind_socket = "/run/rspamd/csm-controller.sock mode=0600";
bind_socket = "localhost:11334";
secure_ip = [];
```

Reload rspamd after the change. CSM never edits the controller settings.

The Email Security page reads rspamd's counters through a Unix controller
socket owned by rspamd, such as the private socket above, or else a loopback
listener that `secure_ip` trusts, and shows "Stats unavailable" without
either; CSM never uses the controller password.

## Learning from Spam folders

`email_protection.antispam.learning.enabled: true` makes rspamd learn from
mail users move to their Spam folder. When several accounts report the same
content, later copies of it score higher. Learning is off by default and
requires antispam to be enabled. Enabling it is refused in
[observe mode](observe-mode.md). This section describes cPanel hosts; for
Postfix hosts see [Learning from Junk folders](#learning-from-junk-folders).

Enabling learning is consent to two things: CSM reads new messages in the
Spam folders of participating accounts, and it keeps one full message per
learned cluster. Clusters normally retire 90 days after their last report,
but pauses and cleanup failures can retain messages longer (see
[Stored messages](#stored-messages)).

### How reports are found

Every five minutes CSM checks the main mailbox and each domain mailbox of
every account whose Spam Filters switch is on, or of every account when
`/etc/global_spamassassin_enable` exists. It looks at the `new` and `cur`
directories of `.spam`, the folder spam-box delivery and the webmail Junk
button use, and `.Junk`, which many mail clients use. Folders are read
without following links; CSM never creates folders or changes permissions.
The exception is a `.spam` or `.Junk` that links to another folder of the
same mailbox, such as `.spambox` on some older cPanel accounts, by its bare
name or its exact path under the account's home. CSM reads that folder, and
pointing the link elsewhere starts a fresh baseline.

The first pass over a folder records what is already there without reading
it. Only messages that arrive after that are reports, so existing mail is
never learned retroactively. Moving a message within the folder or
changing its flags does not report it again. A pass reads at most 20
reports per account, takes turns between accounts, and stops before the
next one is due; the rest wait for the next pass.

### What counts as a report

A report is a regular file owned by the account, at most 10 MiB, that did
not change while CSM read it. A message still linked from another folder,
such as one delivery shared by several mailboxes, counts once it and its
links have stayed unchanged for a full pass, so a move into or out of Spam
can finish first. Messages are skipped when any `X-Spam-Status` header
says `Yes`, when that header cannot be parsed, and when the header block
is malformed or too large, linked or not. Only the text parts of a report
are learned, attached text included; images and other attachments never
are. A message whose MIME structure CSM cannot read is skipped as
`no_digest`, for operator requests too.

Reports are not authenticated. Tenants control their own mail: they can
move any message they received, or deliver one locally, and a forged
`X-Spam-Status: Yes` header keeps a message from being learned. In dry run
senders' headers are not removed, so forged headers have this effect on
any message.

### Scores and limits

Each reporting account adds a fixed weight to the cluster. One, two, three
and four accounts give `CSM_FUZZY_SPAM` scores of about 2.9, 5.4, 7.2 and
8.4, so with the default tag score of 6 a message needs reports from about
three accounts to be tagged on that evidence alone. An operator mark from
`csm antispam learn --spam` weighs as much as nine accounts.
Copies in multiple Spam folders or mailboxes of the same account still
contribute only once to that cluster.

Messages that share most of their text join the same cluster, so later
variants of a campaign score too. A new message whose plain text and HTML
versions differ starts its cluster from one of them, normally the larger;
attached messages are never used. Later copies score through that version.
Newsletters built from one template can also be close enough to join.
Lowering or correcting a learned value removes and re-adds it, which can
leave a short gap in which the message scores lower.

Learning writes scores with either value of antispam's `dry_run` setting.
In dry run they affect the measured score; what happens to the message
still follows the dry-run policy.

### Opt-out, disable and retention

Unless `/etc/global_spamassassin_enable` exists, turning an account's Spam
Filters switch off stops CSM reading its folders at the next check and
drops its unsent reports, including reports the learner accepted but has
not yet sent to rspamd. Each cluster of a report is handled on its own: a
part whose update rspamd may already have received still completes. If the
learner cannot cancel, CSM reports it and retries at the next check while
the account stays opted out. Turning the switch back on starts new
baselines.
The global override prevents per-account opt-out, including learning.
Removing a cPanel account drops its learner reports the same way, once its
UID belongs to no remaining account. An account whose home directory CSM
cannot use keeps them. While the account list is changing or cannot be
read, every account keeps them and CSM retries at the next check.
What the account already contributed stays until the cluster expires or an
operator forgets it; opting out or removal does not delete it sooner.

Turning learning off keeps stored messages, keys and the learning ledger,
but clears folder baselines and unsent reports; re-enabling starts new
baselines. Observe mode keeps everything and resumes where it stopped.

Folders absent for 90 days are forgotten with their pending reports.
Unresolved accounts, unreadable homes, incomplete mailbox lists and unsafe
or unreadable folders keep their state until they can be checked again.
Links in an account's `etc` directory, such as cPanel's Roundcube database
link, are not mail domains: CSM does not follow them and they do not hold
back this cleanup.

A backend error stops further submissions for that pass; the next pass
starts with the accounts after the one that failed. Reports stay pending
while rspamd's fuzzy storage answers no lookup, however long that lasts. A
failure counts against a message only when storage answered a lookup for
another report earlier in the same pass, or when rspamd cannot process the
message; such a message does not stop other accounts' reports. When rspamd
answers a message's inspection with an error, CSM inspects a fixed test
message: if storage answers it, the failure counts against the message and
the pass goes on with the next report. If storage does not answer it,
submissions stop and the report stays pending without a counted failure,
even if storage answered earlier in the pass. A message with three counted failures,
including unclassified learner errors, is skipped as `failed`. Canceled or
expired passes, reconciliation pauses, unsent controller requests, a wrong
controller peer and local state failures never count. Unreadable learning
state holds reports even when the learner cannot finish startup; the
reports resume once the state is available.

### Prerequisites

While learning is requested, CSM checks these during reconciliation.
Definite failures request removal of the learning configuration. Temporary
probe failures keep an existing installation. Learning findings do not
disable core filtering; `antispam_learning` names the reason.

- rspamd 4.2.x and Redis 5.0.x, 6.2.x or 7.x; other versions are refused;
- exactly one private controller Unix socket owned by rspamd, mode 0600, in
  directories only root and rspamd can write to, with no extended ACLs, and
  no other controller listener granting other users admin or read-only
  access (see
  [rspamd admin interface](#rspamd-admin-interface));
- rspamd's control socket private to root and rspamd, with protected
  directories and no extended ACLs. Check the effective `control_socket`
  path and its permissions as well as the controller socket;
- one Redis server for fuzzy storage, reached only through a Unix socket:
  `port 0` and `tls-port 0`, a socket owned by root, rspamd or the `redis`
  service user, no access for other users or extended ACLs, and any group
  access limited to `root`, `redis` and rspamd's service user. Service users
  must not be hosting accounts. Parent directories must protect the socket
  from replacement. Redis needs a positive `maxmemory` and
  `maxmemory-policy noeviction`. A Redis build without TLS needs no
  `tls-port` setting;
- with `learning.redis_socket` set, that Redis instead of rspamd's: CSM
  applies the checks above to it, refuses it while any other rspamd module
  or rspamd's global Redis settings name the same socket, or while those
  global settings use sentinels, TLS or a named user, and points the fuzzy
  worker at it with no password. Learning moves to a new socket only after
  it passes these checks; until then it keeps its current Redis;
- rspamd's uid used by rspamd alone: no cPanel account, and on Postfix no
  user but the service users, may share it. If CSM cannot read every
  account's uid, learning waits: an installation stays, and nothing new is
  published until a later pass can check;
- rspamd's log unreadable to other users, by file permissions or by CloudLinux
  CageFS. CageFS qualifies only for a file log under `/var/log/rspamd`, with
  every account confined and that directory absent from its skeleton;
- no local fuzzy rule and no enabled fuzzy worker of your own. CSM's files
  replace them, so CSM refuses instead. The stock rule for rspamd.com is
  replaced on purpose.

CSM sends the Redis password only to a socket it has verified, and only on a
connection served by that socket's owner.

A cPanel account record with no system user, such as cPanel's own `system`
record, does not count as an account sharing the Redis owner when
`/etc/passwd` does not list it either. If `/etc/passwd` cannot be read in
full, or an account lookup fails for another reason, CSM does not trust a
non-root Redis owner. On Postfix these account read failures pause learning
and retain its installed configuration. The worker rechecks Dovecot mail
owners before using a dedicated Redis, including owners of skipped mailboxes.

Redis persistence is recommended. CSM warns only when both append-only
persistence (`appendonly yes`) and snapshots (`save`) are disabled. While
learning is active, CSM rebuilds missing learned values from stored messages.

### What learning installs

- `fuzzy_check.conf` and `worker-fuzzy.inc` in `/etc/rspamd/override.d`, mode
  0640 for root and rspamd's group: local fuzzy scoring and storage;
- `fuzzy_group.conf` in `/etc/rspamd/local.d`: the `CSM_FUZZY_SPAM` score
  and its group cap;
- `csm_learning.lua` in `/etc/rspamd/lua.local.d`: a controller plugin for
  message inspection;
- `/usr/local/cpanel/base/3rdparty/roundcube/config/inc.d/zz-csm-antispam.inc.php`,
  which points Roundcube's Junk button at the Spam folder. This changes the
  Junk button for every webmail user on the server, regardless of the
  account's Spam Filters switch. CSM replaces an operator-owned file at that
  path, see [Replaced files](#replaced-files). The `markasjunk` plugin must
  already be enabled; CSM does not enable it.

CSM checks the include by loading Roundcube's configuration with cPanel's
PHP as the `nobody` user, never as root. If Roundcube does not load the Junk
settings, or the check fails, CSM restores the previous include and reports
`roundcube_unavailable`.
The rest of the learning configuration stays installed. Later passes omit
CSM's include until the learning configuration changes or CSM restarts.
A later include can override the settings.

After writing these files CSM checks what rspamd loaded, including the
effective `CSM_FUZZY_SPAM` weight the controller reports, which can differ
from the files after a runtime weight change. A failed learning check
attempts to roll back the change. Later passes omit learning until its
configuration changes or CSM restarts. Fix the reported cause before
restarting; reloading unchanged settings does not clear the hold.

On an otherwise current, completed installation, changing only learning
reloads rspamd without rebuilding Exim. Changing only the Roundcube include
reloads neither service. An incomplete installation or Exim configuration
drift can still require an Exim rebuild.

Keys live in `/var/lib/csm/antispam/learning/keys`, root only: directories
are mode 0700 and key files mode 0600. CSM creates a complete set when none
exists. It refuses a partial or invalid set with `state_mismatch`, leaving
learning off. Do not delete the surviving keys to start over: new keys
cannot match hashes made with the old ones.
The learning ledger is bound to the hash keys and hash settings. A changed
generation stops learning instead of reusing the previous learning state.

The Redis capacity warning starts at 75% of `maxmemory` and clears below
70%. It leaves installed learning configuration in place and pauses the
learner, including pending changes, until usage falls.

Turning learning off requests removal of CSM's learning files and Roundcube
include, while keeping the keys. Conflicts or transaction failures can
prevent removal. Check findings before assuming learned scoring is gone.
Disabling learning or entering observe mode stops native learning calls
before configuration reconciliation. Calls already in flight are canceled
and drained within their deadlines. Reconciliation pauses the learner until
a completed pass confirms that learning can resume.

### Stored messages

Each learned cluster keeps one message, the first one reported, so the
learner can restore its value if Redis loses it. CSM keeps its headers and
text parts, without images or other attachments, under
`/var/lib/csm/antispam/learning/anchors`, readable only by root. A cluster
started from one version of a message keeps only that version. CSM deletes
it when the cluster retires, 90 days after its last report, or when an
operator forgets it. Backups and file system snapshots can keep a copy
longer. Messages saved by older versions keep their attachments until
their cluster retires.
If deleting a retained message fails, CSM still removes its retired score
and reports the cleanup error. New reports wait until cleanup succeeds.
Disabling learning, observe mode or unmet prerequisites can delay retirement
and message deletion. Turning learning off keeps stored messages and state.
rspamd can hash the same message differently from one check to the next,
because the words it hashes depend on the language it detects. When a
stored message no longer gives its cluster's value, CSM retires that
cluster, removes its score and logs a warning; other clusters and new
reports are not affected. A failed inspection leaves the cluster intact.
CSM can still publish the message if its text-only form reproduces the
learned digest; otherwise publication waits for a later retry.
Reports joined to a retired cluster contribute no vote;
operator spam requests report `skipped:superseded`.

Retained messages consume their learning allowance until deletion succeeds.
The record that prevents a retired score from returning remains charged,
including when a new cluster retires before its first contribution completes.

CSM's state archive (`csm store export`) leaves learning state out;
`csm backup` includes it, see
[Backup, restore and a fresh namespace](#backup-restore-and-a-fresh-namespace).

### Teaching and correcting learning

Root can learn a saved message as spam, or remove what one taught:

```
csm antispam learn --spam <file>...
csm antispam learn --forget <file>...
csm antispam learn --status [<request-id>...]
csm antispam learn --fresh-namespace
```

The daemon must be running. `--spam` and `--forget` require learning enabled
and refuse observe mode. Each file must be regular with one link, at most
10 MiB, and unchanged during reading. Symlinks anywhere in its path are refused. The
snapshot is sent to the daemon as bytes. `--spam` gives each matching cluster one
operator mark, which weighs as much as nine reporting accounts. `--forget`
removes the clusters a file matches, with every account's contribution to
them, and deletes their stored message. Other learned messages may still
score similar mail.

Each file gets a request ID, printed before it is sent. If printing fails,
that file is not sent. A lost or truncated reply is retried once with the
same ID and snapshot. Refusals and completed replies are not retried.

A file reported as `pending` was reserved; the daemon keeps publishing it
in the background. A file reported as `deferred` changed nothing, because
learning was busy or waiting on another change; run the command again
later.

`csm antispam learn --status <request-id>` shows what the daemon recorded
for a request, including clusters still publishing and their phase.
Status only reads the ledger and works with learning disabled or in observe
mode. Without an ID it lists the requests that are not finished. If the
command is interrupted, look its ID up there, or in the action log with
`csm actions --op integrate.antispam_learn --json`, which records the
request ID, escaped basename, outcome and full digests, never message
content or headers. A missing record does not prove that no change
occurred. Running the command again makes a new request.

Forgetting works for the whole server: the clusters a file matches lose
every account's contribution. CSM keeps a zero-value record for each
forgotten value and keeps auditing it, so a late write cannot bring the
score back unnoticed. Forget is not a permanent allowlist; new reports of
the same content start a new cluster.

| Exit status | Meaning |
|---|---|
| 0 | Every file was learned, already learned, forgotten or matched nothing; `--status` and `--fresh-namespace` succeeded. |
| 1 | At least one file was refused, failed or is still pending, or the daemon could not complete the request. |
| 2 | The command line is not valid. |

### Backup, restore and a fresh namespace

`csm backup` stores the learning state as one bundle: the ledger in the
state database and `/var/lib/csm/antispam/learning`, which holds the hash
keys, transport keys and stored messages. `csm restore` brings the bundle
back and moves any learning directory it replaces to
`learning.old-<UTC time>-<suffix>`. Installation failures trigger rollback,
but rollback itself can fail. Cleanup errors can also occur after the new
bundle is installed. After any restore error, check the reported paths and
resolve it before restarting CSM.

Restored learning state holds new reports until the daemon has run with
learning disabled outside observe mode; enable learning again only when
the backup is the current bundle. CSM cannot tell an old backup from the
current one by comparing scores.

If the backup is older, or storage was lost along with the keys, start a
fresh namespace instead. With learning disabled, run:

```
csm antispam learn --fresh-namespace
```

It waits for an active reconciliation pass, moves
`/var/lib/csm/antispam/learning` to `learning.old-<UTC time>` and empties
the learning and Spam folder state. If emptying fails, CSM attempts to move
the directory back and reports any failure to do so. Resolve that failure
before enabling learning. After a successful reset, the next enable creates
new keys and a new storage prefix, and every folder starts a new baseline. Old
reports are not replayed. The old directory still holds full messages;
remove it once you no longer need it. CSM never flushes Redis; old hashes
stay under the old prefix until they expire.

### Learning findings

Each `antispam_learning` finding names one reason. Each reconcile pass
reports server readiness; the running learner adds the reasons from
`anchor_drift` on. On Postfix the learner also reports a Dovecot listing
that failed in its last pass, until a later pass reads it.

| Reason | Meaning |
|---|---|
| `unsupported` | An rspamd or Redis version is outside the supported versions above, a Postfix host has no `learning.redis_socket`, or Dovecot runs 2.4 or has no userdb that can list its users; learning is disabled. |
| `unsafe_prerequisite` | Required isolation or Redis settings are unsafe or cannot be established; learning is disabled. |
| `state_mismatch` | Learning keys could not be created or loaded safely, restored learning state awaits confirmation, or the learner found its state out of step with its storage; learning is disabled and nothing is adopted or deleted. The CSM log names the disagreeing fuzzy digests when the learner finds it. |
| `config_conflict` | Operator configuration conflicts with CSM's learning setup; learning is disabled. |
| `apply_failed` | A learning check failed during apply; subsequent passes hold learning off until its configuration changes or CSM restarts. |
| `backend_unavailable` | A probe failed temporarily, including a Dovecot listing that failed or timed out; existing learning configuration is retained unless a definite failure also requires removal. A first installation waits. |
| `worker_absent` | The installed fuzzy worker is not listening. Restart rspamd after fixing the cause; CSM leaves the configuration installed. |
| `redis_capacity` | Redis has reached the capacity guard above; CSM leaves the configuration installed. |
| `redis_persistence` | Redis has neither append-only persistence nor snapshots enabled; CSM warns without disabling learning. |
| `roundcube_unavailable` | The Junk-button include could not be installed, verified or removed cleanly. The other learning files are unaffected. |
| `removal_incomplete` | rspamd still loads CSM's learned scoring while learning is disabled; resolve the reported conflict or removal failure. |
| `anchor_drift` | A learned value moved away from its target more than once. CSM keeps correcting it; repeated drift means something else writes to the learning storage. |
| `mutation_uncertain` | A write to the learning storage got no answer. CSM reads the stored value before it sends anything else. |
| `anchor_body_invalid` | A stored message is missing or changed. That cluster's value is held until it is forgotten. |
| `state_io` | Learning state could not be written, for example on a full disk. Nothing unrecorded is sent and installed scores stay. |
| `audit_overdue` | The check of every learned value has not finished a round within 24 hours. |
| `request_errors` | Learning requests to rspamd failed three times in a row. |
| `backend_rebuilding` | Learned values are missing from storage, for example after Redis lost its data. CSM restores them from the stored messages and holds new clusters until it is done. |
| `mailboxes_skipped` | On Postfix, Dovecot mailboxes CSM does not watch, counted by reason; see [Learning requirements](#learning-requirements). Learning goes on for the others. |
| `account_capacity` | An account, or the operator, reached its learning allowance, or an account's Spam folder state reached its limit of 65536 messages. Its new reports are skipped or wait; existing learning stays. Confirmed absent folders are forgotten after 90 days, which frees their share. |

## Findings

| Check | Severity | Meaning |
|---|---|---|
| `antispam_precondition` | Warning | A condition above is not met. The message names the cause, such as `rspamd_socket` or `spamassassin_enabled`. A temporary cause keeps an installed integration; a definite one removes it when that is safe. |
| `antispam_apply_failed` | Warning, or Critical when the previous state could not be confirmed | An install, update or removal failed at the named step, or pending changes could not be canceled. |
| `antispam_file_replaced` | Warning | CSM replaced your own file at one of its paths and kept a copy. Deleting the copy clears it, and so does CSM putting the copy back on a Postfix host. See [Replaced files](#replaced-files). |
| `antispam_rspamd_down` | Warning | Three probes of the scan socket in a row failed. CSM probes every 20 seconds while antispam is enabled. |
| `antispam_rspamd_recovered` | Warning | Two probes in a row succeeded after an outage. |
| `antispam_scan_error` | Warning | The mail server logged a failed scan. One finding covers every failure until a scan succeeds. |
| `antispam_controller_open` | Warning | Other users may reach rspamd's admin or read-only interface, or CSM cannot verify isolation. See [rspamd admin interface](#rspamd-admin-interface). |
| `antispam_feed` | Warning, or Critical when a list answers for everything | A feed or map redirect is off, loaded rules differ, a list misbehaves, or rspamd still fetches maps from rspamd.com. These findings alone do not disable filtering. See [Feeds](#feeds). |
| `antispam_ip_map` | Warning | The IP map could not be written, or rspamd has not confirmed the current map 5 minutes after a write. Core filtering is unaffected. See [CSM IP map](#csm-ip-map). |
| `antispam_learning` | Warning | One finding per learning readiness or removal problem. Core filtering is unaffected. See [Learning findings](#learning-findings). |

While rspamd is down or scans fail on a cPanel host, mail is delivered
without spam filtering. Exim adds no rejection for a scanner failure, and
other mail checks keep running. On a Postfix host, Postfix's
`milter_default_action` decides, see [Scan records](#scan-records).
Disabling antispam clears the down and scan-error findings without a
recovery notice. Preconditions or removal failures can still be reported.

Scan records in the Exim main log include the connecting sender's address as
`ip=`. Scan health ignores records with a malformed non-empty address. Older
records without that field, and records with an empty address, still count.

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
