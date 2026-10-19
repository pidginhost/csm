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
`mail.antispam.learning.v1` means the build can learn from Spam folders;
while learning runs, `csm status --json` carries an `antispam_learning`
block.

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
only when every nameserver rspamd uses is loopback or private. rspamd uses
`dns.nameserver` from its options, or `/etc/resolv.conf` when that is unset.
Run a recursive resolver on the host and add this line to
`/etc/rspamd/local.d/options.inc`:

```
dns { nameserver = ["127.0.0.1"]; }
```

cPanel's local BIND usually recurses for localhost; cPanel's PowerDNS does
not, and the systemd-resolved stub forwards to its upstream resolvers, which
are usually public. When PowerDNS holds port 53, run the resolver
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
`rspamd_maps` selected. An operator-owned file there leaves the feed off.
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
are skipped.
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
newly seen domains.

### Files

CSM owns these files while a feed or map redirect needs them:

- `/etc/rspamd/override.d/rbl.conf` and `/etc/rspamd/override.d/rbl_group.conf`,
  with a DNS feed. They replace rspamd's own lists and their weights, so only
  the feeds you named run;
- `forged_recipients.conf`, `mid.conf`, `mime_types.conf`, `whitelist.conf`
  and `multimap.conf` in `/etc/rspamd/local.d`, without `rspamd_maps`.
  The local IP feed also needs `multimap.conf` when `rspamd_maps` is selected.

An operator-owned file at one of these optional locations is left alone:
CSM omits DNS feeds or the affected map redirect. Its contents can still
conflict with required settings and block core filtering. In particular,
an `override.d/rbl.conf` that enables the RBL module defeats CSM's attempt
to turn it off when no DNS feeds are usable. Resolve that conflict before
enabling antispam.

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
- with learning on, the learning files listed under
  [Learning from Spam folders](#learning-from-spam-folders);
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

## Learning from Spam folders

`email_protection.antispam.learning.enabled: true` makes rspamd learn from
mail users move to their Spam folder. When several accounts report the same
content, later copies of it score higher. Learning is off by default and
requires antispam to be enabled. Enabling it is refused in
[observe mode](observe-mode.md).

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

The first pass over a folder records what is already there without reading
it. Only messages that arrive after that are reports, so existing mail is
never learned retroactively. Moving a message within the folder or
changing its flags does not report it again. A pass reads at most 20
reports per account, takes turns between accounts, and stops before the
next one is due; the rest wait for the next pass.

### What counts as a report

A report is a regular file owned by the account, at most 10 MiB, that did
not change while CSM read it. A message still linked from another folder
waits for the next pass. Messages are skipped when any `X-Spam-Status`
header says `Yes`, when that header cannot be parsed, and when the header
block is malformed or too large.

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

Messages that share most of their text join the same cluster, so later
variants of a campaign score too. Newsletters built from one template can
also be close enough to join. Lowering or correcting a learned value
removes and re-adds it, which can leave a short gap in which the message
scores lower.

Learning writes scores with either value of antispam's `dry_run` setting.
In dry run they affect the measured score; what happens to the message
still follows the dry-run policy.

### Opt-out, disable and retention

Unless `/etc/global_spamassassin_enable` exists, turning an account's Spam
Filters switch off stops CSM reading its folders at the next check and
drops its unsent reports. Turning the switch back on starts new baselines.
The global override prevents per-account opt-out, including learning.
What the account already contributed stays until the cluster expires or an
operator forgets it; opting out does not delete it sooner.

Turning learning off keeps stored messages, keys and the learning ledger,
but clears folder baselines and unsent reports; re-enabling starts new
baselines. Observe mode keeps everything and resumes where it stopped.

### Prerequisites

While learning is requested, CSM checks these during reconciliation.
Definite failures request removal of the learning configuration. Temporary
probe failures keep an existing installation. Learning findings do not
disable core filtering; `antispam_learning` names the reason.

- rspamd 4.2.x and Redis 5.0.x or 6.2.x; other versions are refused;
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
- rspamd's log unreadable to other users, by file permissions or by CloudLinux
  CageFS. CageFS qualifies only for a file log under `/var/log/rspamd`, with
  every account confined and that directory absent from its skeleton;
- no local fuzzy rule and no enabled fuzzy worker of your own. CSM's files
  replace them, so CSM refuses instead. The stock rule for rspamd.com is
  replaced on purpose.

CSM sends the Redis password only to a socket it has verified, and only on a
connection served by that socket's owner.

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
  account's Spam Filters switch. CSM leaves an operator-owned file at that
  path alone. The `markasjunk` plugin must already be enabled; CSM does not
  enable it.

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
learner can restore its value if Redis loses it. The message is stored
whole, headers and attachments included, under
`/var/lib/csm/antispam/learning/anchors`, readable only by root. CSM
deletes it when the cluster retires, 90 days after its last report, or
when an operator forgets it. Backups and file system snapshots can keep a
copy longer.
If deleting a retained message fails, CSM still removes its retired score
and reports the cleanup error. New reports wait until cleanup succeeds.
Disabling learning, observe mode or unmet prerequisites can delay retirement
and message deletion. Turning learning off keeps stored messages and state.

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
`anchor_drift` on.

| Reason | Meaning |
|---|---|
| `unsupported` | An rspamd or Redis version is outside the supported versions above; learning is disabled. |
| `unsafe_prerequisite` | Required isolation or Redis settings are unsafe or cannot be established; learning is disabled. |
| `state_mismatch` | Learning keys could not be created or loaded safely, restored learning state awaits confirmation, or the learner found its state out of step with its storage; learning is disabled and nothing is adopted or deleted. |
| `config_conflict` | Operator configuration conflicts with CSM's learning setup; learning is disabled. |
| `apply_failed` | A learning check failed during apply; subsequent passes hold learning off until its configuration changes or CSM restarts. |
| `backend_unavailable` | A probe failed temporarily; existing learning configuration is retained unless a definite failure also requires removal. A first installation waits. |
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
| `account_capacity` | An account, or the operator, reached its learning allowance. Its new reports are skipped; existing learning stays. |

## Findings

| Check | Severity | Meaning |
|---|---|---|
| `antispam_precondition` | Warning | A condition above is not met. The message names the cause, such as `rspamd_socket` or `spamassassin_enabled`. A temporary cause keeps an installed integration; a definite one removes it when that is safe. |
| `antispam_apply_failed` | Warning, or Critical when the previous state could not be confirmed | An install, update or removal failed at the named step, or pending changes could not be canceled. |
| `antispam_rspamd_down` | Warning | Three probes of the scan socket in a row failed. CSM probes every 20 seconds while antispam is enabled. |
| `antispam_rspamd_recovered` | Warning | Two probes in a row succeeded after an outage. |
| `antispam_scan_error` | Warning | Exim logged a failed scan. One finding covers every failure until a scan succeeds. |
| `antispam_controller_open` | Warning | Other users may reach rspamd's admin or read-only interface, or CSM cannot verify isolation. See [rspamd admin interface](#rspamd-admin-interface). |
| `antispam_feed` | Warning, or Critical when a list answers for everything | A feed or map redirect is off, loaded rules differ, a list misbehaves, or rspamd still fetches maps from rspamd.com. These findings alone do not disable filtering. See [Feeds](#feeds). |
| `antispam_ip_map` | Warning | The IP map could not be written, or rspamd has not confirmed the current map 5 minutes after a write. Core filtering is unaffected. See [CSM IP map](#csm-ip-map). |
| `antispam_learning` | Warning | One finding per learning readiness or removal problem. Core filtering is unaffected. See [Learning findings](#learning-findings). |

While rspamd is down or scans fail, mail is delivered without spam filtering.
Exim adds no rejection for a scanner failure, and other mail checks keep
running. Disabling antispam clears the down and scan-error findings without
a recovery notice. Preconditions or removal failures can still be reported.

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
