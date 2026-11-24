# Inbound spam filtering

CSM can filter inbound mail through rspamd. On cPanel hosts each cPanel account decides for itself whether its mail is filtered. On Postfix hosts filtering is server-wide. You can exempt recipients or domains. Filtering is off by default.

You install rspamd. CSM configures it, wires it into Exim on cPanel, keeps the integration current and reports when filtering is not working. CSM is never in the live mail path: Exim or Postfix talks to rspamd directly, and stopping CSM leaves the installed filtering in place.

Most of this page describes cPanel hosts. [Postfix hosts](#postfix-hosts) lists what differs there. On [Stalwart hosts](#stalwart-hosts) CSM does not manage rspamd at all.

## What each account gets

Each account opts in or out with a switch on cPanel's own Spam Filters page, "Process New Emails and Mark them as Spam". cPanel stores it as the `~/.spamassassinenable` file. New accounts start opted in. The `spamassassin` feature in cPanel feature lists controls who may change the switch. CSM adds no setting for it.

With `dry_run: false`, rspamd scores inbound mail and Exim applies the account's choice:

| Account | Score | What Exim does |
|---|---|---|
| Opted in | At or above `reject_score` | Rejects the message with 550. |
| Opted in | At or above `tag_score` and below `reject_score` | Adds `X-Spam-Status: Yes`. |
| Opted out | Any | Delivers the message with no CSM rejection and no spam verdict header. |

What happens to tagged mail:

- If the user turned on cPanel's spam box, the mail is filed in the Spam folder.
- Otherwise it is delivered normally with the header.

In both cases, when the [forward guard](configuration.md) enforces `spam_flagged`, a copy forwarded to an outside address is held, not relayed.

Opting out never affects antivirus, outbound checks, SMTP-time controls such as RBLs, rate limits and anti-spoofing, or CSM's detections.

A change to the switch applies from the next recipient Exim accepts. CSM does nothing and Exim does not reload.

The Spam Filters page's own score threshold and its allow and deny lists are not used. `reject_score` and `tag_score` apply to every opted-in account.

### Who decides for a message

Policy follows the account that owns the addressed domain, including aliases, forwarders and catch-alls. It is not evaluated again for the mailbox a forwarder finally delivers to:

- A forwarder in an opted-out account delivers unfiltered into an opted-in mailbox it points at.
- An address in an opted-in account can reject mail its forwarder would have passed to an opted-out mailbox.

One message can have recipients with different choices. Exim then accepts the first recipient and answers 452 for each later recipient whose choice differs. The sending server retries those recipients in a separate delivery, which follows their own choice.

If `/etc/global_spamassassin_enable` exists, cPanel treats every account as opted in and no account can opt out. CSM reports this as a warning.

### Mail that is never scanned

Only unauthenticated mail from remote hosts to the host's local domains is scanned. These are not scanned:

- Authenticated submissions.
- Local mail.
- Mail from these peers: `127.0.0.0/8`, `::1`, `trustedmailhosts` and `cpanel_mail_netblocks`. This is the same set cPanel exempts from its own spam scan.

cPanel also accepts some recipients before the scan hook runs, so they are never filtered:

- Mail to a domain from that domain's remote MX hosts.
- Mail from hosts in `skipsmtpcheck_hosts`.
- Mail from always-relay and pop-before-SMTP hosts.
- Mail to Mailman `-bounces` addresses.
- Mail to suspended recipients.

## Before you enable it

This section is for cPanel hosts. Postfix hosts have their own [requirements](#requirements).

Install rspamd from the upstream [rspamd.com](https://rspamd.com/downloads.html) repository. Keep its systemd unit's `User=` setting (the upstream package runs as `_rspamd`), because CSM checks the scan socket's owner against it. CSM does not install rspamd or Redis.

Then meet these conditions:

1. Turn SpamAssassin off. Disable spamd in WHM so `/etc/spamddisable` exists. Otherwise cPanel's own scan uses CSM's scanner and adds its own headers and subject tag whatever the account chose.
2. Give Exim a scan socket. Add a Unix socket to rspamd's normal worker, in `/etc/rspamd/local.d/worker-normal.inc`:

   ```
   bind_socket = "/run/rspamd/csm-normal.sock mode=0666";
   ```

   This replaces the normal worker's TCP listener. The socket and every parent directory must be owned by root or the rspamd user. Parent directories must not be writable by group or others, so a hosting account cannot replace the listener. Extra ACL entries on the socket or any parent directory block installation.

   Exim's runtime user must be able to search every parent directory and write to the socket. `mode=0666` grants socket write access.
3. Make rspamd accept every message Exim accepts. rspamd's default `max_message` (50 MiB) equals cPanel's default Exim limit, and Exim adds headers before scanning. Set `max_message` to Exim's `message_size_limit` plus at least 1 MiB in `/etc/rspamd/local.d/options.inc`, for example `max_message = 60mb;` with cPanel's 50M default.
4. Validate and reload rspamd: run `rspamadm configtest`, then `systemctl reload rspamd`.
5. Keep Exim running. CSM probes an Exim listener before and after each change.

A first install waits for these conditions. After installation, a definite failure (a condition that clearly fails, not a temporary error) makes CSM remove what it installed, when that is safe.

### What else blocks installation

CSM also refuses to install while any of these hold, and names the cause:

- Exim settings, ACLs or filters already act on spam scores, such as `deny_spam_score_over_*`, `ratelimit_spam_score_over_*` or automatic spam deletion and forwarded-spam restrictions.
- `/etc/exim.conf.local` holds another `spamd_address`.
- Cutthrough delivery, PRDR or CHUNKING is enabled.
- The Exim main log is not the one CSM reads (`log_file_path`).
- An Exim or rspamd unit cannot reload.
- Custom ACL hooks are disabled, or named lists used by the hooks are invalid.
- A file CSM manages is not safe to change, or holds malformed CSM markers.
- An rspamd override defeats the settings CSM writes. See [What CSM writes](#what-csm-writes).

CSM does not change WHM options, account toggles, Redis or rspamd worker settings to satisfy these conditions.

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

| Key | What it does |
|---|---|
| `enabled` | Turns the integration on. `enabled: true` is refused in [observe mode](observe-mode.md). |
| `dry_run` | Scans and logs what would happen, without rejecting, tagging or splitting recipients. |
| `rspamd_socket` | The scan socket from [Before you enable it](#before-you-enable-it). An absolute path of at most 107 characters using letters, digits, `/`, `.`, `_` and `-`. |
| `reject_score`, `tag_score` | Whole rspamd scores with `0 < tag_score < reject_score <= 1000`. |
| `feeds` | Selects optional blocklists. See [Feeds](#feeds). |
| `exempt` | On a Postfix host, recipient domains and mailboxes that are never filtered. cPanel hosts ignore it. |

### Notes on the keys

Setting `enabled` back to `false` requests removal of CSM's owned content. Conflicts or failures can prevent removal and produce findings.

Antispam stays inactive on a host that is neither a cPanel host running Exim nor a Postfix host. The daemon logs a warning at startup and whenever a configuration change is reloaded. Once such a host runs Postfix, for example after Postfix was installed or started after CSM, the next reload (`systemctl reload csm`) starts antispam without a restart.

On a Postfix host CSM's rspamd files already apply in dry run, and the host's own action thresholds decide on CSM's scores. See [Dry run and enforce](#dry-run-and-enforce).

`exempt` takes entries such as `example.com` or `postmaster@example.net`. CSM never learns from the Junk folders of exempt recipients. Entries are lower-cased, and only plain domains and mailboxes are accepted. On cPanel hosts each account's Spam Filters switch decides. See [Which mail is filtered](#which-mail-is-filtered).

`rspamd_socket` is not the `reputation.rspamd` controller URL. That optional setting reads rspamd's scan history for IP reputation and is unrelated to filtering.

### Reloading

All of these keys are hot-reloadable. After antispam starts, `systemctl reload csm` or a Settings save updates health tracking and requests a reconcile pass before forward-guard reconciliation. A reconcile pass is CSM's check of the installed integration against the configuration, with a repair where they differ.

Settings saved before antispam starts are picked up when it initializes, after the startup forward-guard reconciliation.

### Capabilities

The capabilities API lists what a build supports. None of these names means filtering is installed on the host:

| Capability | Meaning |
|---|---|
| `mail.antispam.v1` | The build supports this integration. |
| `mail.antispam.postfix.v1` | The build also supports Postfix hosts. |
| `mail.antispam.learning.v1` | The build can learn from Spam folders. |
| `mail.antispam.learning.postfix.v1` | The build can also learn from Junk folders on Postfix hosts. |

While learning runs, `csm status --json` carries an `antispam_learning` block.

## Rolling it out

1. Meet the conditions in [Before you enable it](#before-you-enable-it) and enable with `dry_run: true`.
2. Leave dry run on for at least 7 days. Review each would-reject decision in the Exim main log (`CSM-ANTISPAM event=scan ... decision=reject`), and watch for scan-error findings.
3. Do not enforce until all predicted rejects are classified, none rejects legitimate mail, and no scan or configuration failure finding remains.
4. Review which accounts are opted out today, and decide whether users may use the spam box (WHM Tweak Settings, `skipspambox`). See the note below on what that setting does.
5. Set `dry_run: false`. Check every 550 for a week. Return to dry run on a confirmed false positive.

The `skipspambox` setting only shows or hides the choice. Accounts that already have `~/.spamassassinboxenable` get tagged mail in their Spam folder either way. Turning the spam box off in WHM deletes that file from every account.

### Rolling back

Set `enabled: false` while CSM is in enforce mode. Successful removal reloads Exim, and new sessions stop using CSM filtering. Check for removal failures before assuming rollback completed. Observe mode leaves the installed integration untouched.

Sessions opened before removal retain their old hooks and may still scan. Those scans use operator or default rspamd settings after CSM's settings are removed, so scores can change and external lists can become active again.

## Feeds

A feed is an optional source of scoring data: a DNS blocklist, CSM's own IP map, or rspamd's map downloads. Every feed is off until you name it:

```yaml
email_protection:
  antispam:
    feeds:
      enabled: [psbl, mailspike]
      spamhaus_dqs_key_file: ""   # only for spamhaus_dqs
```

`enabled` is a list of feed names. The configuration is invalid when a name is unknown or repeated, or when `spamhaus_dqs` is named without a clean absolute `spamhaus_dqs_key_file`.

Feeds and map redirects need rspamd 4 or later. On an older or unreadable rspamd version CSM leaves rspamd's own lists and maps alone and reports it.

Check each list's terms against your use before you enable it:

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
| `surbl` | Free only for organizations under 1,000 users or 250,000 messages a day, and never inside a product or service sold for a fee; other use needs SURBL's paid data service. See the [SURBL usage policy](https://www.surbl.org/usage-policy). |
| `spamhaus_dqs` | Needs a DQS key. The free key covers non-commercial use under 100,000 queries a day; commercial use needs a paid key. |
| `csm_ip_map` | Local data only: CSM's block history, its threat feeds and the spam evidence it records. |
| `rspamd_maps` | Keeps rspamd's own map downloads from maps.rspamd.com; free use is non-commercial and under 5,000 queries a day, other use needs an agreement with rspamd. See [rspamd's usage policy](https://docs.rspamd.com/other/usage_policy/). |

### Maps without any feed

Without `rspamd_maps`, CSM redirects the rspamd.com maps it manages to local files. These are the copies the rspamd package installs in `/etc/rspamd/maps.d`, and package updates refresh them.

Some rules then have no data until you supply it:

- The freemail rules stay quiet until you put your own list in `/etc/rspamd/local.d/maps.d/freemail.map`.
- The disposable-address rules stay quiet until you put your own list in `/etc/rspamd/local.d/maps.d/disposable.map`.
- Phishing exceptions read `/etc/rspamd/local.d/maps.d/phishing_whitelist.inc` when it exists.

The redirect does not block network access to rspamd.com. Operator-owned files and additional maps can keep downloads active. CSM reports those it finds in enabled modules after the integration is installed and current.

### DNS feeds need a local resolver

Some blocklists refuse queries from public resolvers. CSM enables a DNS feed only when every nameserver rspamd uses is loopback, private, or inside the top-level `infra_ips`. rspamd uses `dns.nameserver` from its options, or `/etc/resolv.conf` when that is unset.

When your own resolvers sit on public addresses and refuse other networks, list their addresses or CIDRs in `infra_ips`. Hostnames do not count for this check. `infra_ips` changes need a CSM restart, not a reload.

Otherwise run a recursive resolver on the host and add this line to `/etc/rspamd/local.d/options.inc`:

```
dns { nameserver = ["127.0.0.1"]; }
```

CSM never edits `options.inc`. After changing it, run `rspamadm configtest`, reload rspamd, then reload CSM to request a check.

cPanel's local BIND usually recurses for localhost. cPanel's PowerDNS does not. When PowerDNS holds port 53, run the resolver on another port and name it with that port, for example `dns { nameserver = ["127.0.0.1:5353"]; }`.

A loopback or private address passes CSM's address check, but a resolver that forwards to a public resolver can still be refused.

[Resolver rules](#resolver-rules) covers the systemd-resolved stub and resolver list prefixes.

### Spamhaus DQS

1. Put the key alone in a root-owned file, mode 600, and name the file in `spamhaus_dqs_key_file`.
2. Let CSM know rspamd's group: set `User=` (and optionally `Group=`) in the rspamd unit. A root-started rspamd that changes user itself leaves the group unknown, and the feed stays off.
3. Make rspamd's log private, for example with `chmod 750 /var/log/rspamd` and `chmod 640` on the files in it. Set rspamd's log rotation to create new files with mode 640.

CSM reads the key on every check and never logs it. It writes the key only into `/etc/rspamd/override.d/rbl.conf`, mode 640, owned by root and rspamd's group.

The log must be private because rspamd writes the name of every failed lookup to it, and that name contains the key. CSM keeps `spamhaus_dqs` off, with a feed warning, while other users can read that log file. That is the rspamd package's default. [Log privacy for Spamhaus DQS](#log-privacy-for-spamhaus-dqs) has the exact rules.

The DQS rules also run without rspamd's own list monitoring. CSM probes ZEN's test points and reports failures without stopping lookups. Turn the feed off when a critical warning reports listings for a never-listed test point.

### CSM IP map

`csm_ip_map` gives rspamd CSM's own evidence about sender addresses. CSM rebuilds the map at start and every 10 minutes into `/var/lib/csm-rspamd/csm_ip.map`. rspamd scores listed senders through one rule, `CSM_IP`:

| Symbol | Listed when | Score |
|---|---|---|
| `CSM_IP_DROP` | the address is in a Spamhaus DROP network from CSM's threat feeds | 4 |
| `CSM_IP_BLOCKED` | CSM blocked the address permanently | 3 |
| `CSM_IP_MAIL_AUTH` | the address attacked SMTP or mail logins in the last 30 days | 3 |
| `CSM_IP_SPAM` | its spam evidence score is 50 or more, see [Spam evidence](#spam-evidence) | 3 |
| `CSM_IP_BLOCKLISTDE` | blocklist.de lists it in CSM's threat feeds | 2 |
| `CSM_IP_CINS` | CINS Army lists it in CSM's threat feeds | 2 |

Each address or network gets one line with its strongest symbol, so the map adds at most 4 to a message.

#### Addresses the map never lists

- Whitelisted addresses: operator, temporary and `reputation.whitelist`.
- Addresses in `infra_ips`.
- Private, loopback and link-local addresses.
- The server's own addresses.
- A network that contains one of the addresses above.

IPv4-mapped IPv6 addresses and CIDRs in `infra_ips` protect the same senders as their IPv4 forms.

A hostname in `infra_ips` counts as the addresses CSM's firewall resolver last resolved it to. This requires a running CSM firewall. Without it, use literal addresses or CIDRs. DNS changes affect the map on its next rebuild and spam evidence on the next scan record.

Entries only in `firewall.infra_ips` grant firewall access without suppressing spam evidence or map listings.

#### What the map feed needs

The feed stays off with a warning until all of these hold:

- The map exists as a regular root-owned file, mode 0640, in rspamd's service group, without extra ACLs.
- Every parent is a root-owned directory with no group or other write access or extra ACLs, and rspamd can traverse it. Symlinks cannot establish safe map access.
- CSM knows rspamd's group, as for [Spamhaus DQS](#spamhaus-dqs).
- CSM owns `/etc/rspamd/local.d/multimap.conf`, even with `rspamd_maps` selected. CSM replaces an operator-owned file there, see [Replaced files](#replaced-files). A file that is not safe to replace leaves the feed off.
- rspamd is version 4 or later, as for the other feeds.

CSM checks map access and the rspamd version again before it applies a queued request. A failed check leaves the installed configuration intact. The next regular check retries with the current host facts.

#### Checking that rspamd uses the map

While the rule is in use, CSM scans a canary message from 192.0.2.255 every 30 seconds to check that rspamd uses the current map. The scan stays out of rspamd's history and statistics.

`antispam_ip_map` reports either of these:

- CSM could not write the map.
- Two consecutive probes show rspamd still not using the current map after its 5-minute load grace.

A matching answer clears the finding. [IP map writes and removal](#ip-map-writes-and-removal) covers failed writes, dismissals and what happens when the map is removed.

### Scores

No feed symbol weighs more than 5, and the symbols of one feed add up to at most 14. No feed alone reaches the default reject score of 15. Each symbol counts once per message.

| Feed | Weights |
|---|---|
| SURBL | 3.5 for each of its four scoring categories. |
| Spamhaus DQS | 5 for ZEN, 3 and 2 for the DBL categories, 3 and 1 for newly seen domains. |
| URIBL grey and red lists | 0.5, because they also list domains that legitimate bulk senders use. |

Updated feed weights apply on the next successful reconcile while antispam is enabled and observe mode is off.

### Files

CSM owns these files while a feed or map redirect needs them:

| Files | When CSM owns them |
|---|---|
| `/etc/rspamd/override.d/rbl.conf` and `/etc/rspamd/override.d/rbl_group.conf` | With a DNS feed. They replace rspamd's own lists and their weights, so only the feeds you named run. |
| `forged_recipients.conf`, `mid.conf`, `mime_types.conf`, `whitelist.conf` and `multimap.conf` in `/etc/rspamd/local.d` | Without `rspamd_maps`. The local IP feed also needs `multimap.conf` when `rspamd_maps` is selected. |

CSM replaces an operator-owned file at one of these locations while it needs the file, see [Replaced files](#replaced-files). When a file is not safe to replace, CSM omits the DNS feeds or the affected map redirect.

An operator file CSM does not need stays. Its contents can still conflict with required settings and block core filtering. In particular, an `override.d/rbl.conf` that enables the RBL module defeats CSM's attempt to turn it off when no DNS feeds are usable. Resolve that conflict before enabling antispam.

### Feed findings

Each `antispam_feed` finding names the feed, `rspamd_maps` for maps, or `rbl` for loaded DNS-rule checks. The finding's details tell you which case applies:

| Case | Meaning and what to do |
|---|---|
| Feed off | The details give the reason, such as a public resolver, a key file with the wrong owner or mode, or a file CSM cannot own. Fix it; the feed returns on the next check. |
| Map redirect skipped | CSM could not manage that optional file. Check the operator's map settings; they may already use local copies. Move those settings out of CSM's target file if CSM should manage the redirect. |
| rspamd.com paths still loaded | rspamd still fetches those maps from rspamd.com. Redirect the named maps yourself, or enable `rspamd_maps` only if your use meets rspamd.com's terms. |
| Loaded rules differ during a routine check | rspamd runs a different set of blocklist rules from those CSM wrote. See [Loaded rules differ](#loaded-rules-differ). |
| IP-map rule differs or cannot be verified | CSM could not confirm that rspamd runs the `CSM_IP` rule as CSM wrote it. See [IP-map rule check](#ip-map-rule-check). |
| Refuses CSM's queries | The list answered with an error code, such as a refused resolver, a query limit or a rejected key. Those error-code answers add no score. |
| Does not answer | Three checks in a row got no answer through rspamd's resolver. Check that the resolver recurses and can reach the list. |
| Unexpected answer | The test point returned an unrecognized answer. Check the provider and resolver; only the configured listing codes can score. |
| Answers for addresses it never lists (Critical) | Turn the feed off and reload CSM. See [A list that answers for everything](#a-list-that-answers-for-everything). |

A listed test point that returns both listing and refusal codes also raises the "unexpected answer" warning. That does not prove that the list stopped scoring.

#### Loaded rules differ

The usual cause is an operator override. This is a warning only, and CSM leaves the installed filtering in place. Correct the overrides, validate and reload rspamd, then reload CSM.

#### IP-map rule check

With `csm_ip_map` enabled, CSM checks that multimap is enabled and that `CSM_IP` uses the managed map, the expected score and the complete symbol set. Symbol order does not matter.

- Extra rule options that can change matching or force an action are conflicts.
- Failed configuration dumps also produce a warning.
- Routine checks leave core filtering installed. Correct the override or command failure before retrying an apply.

#### A list that answers for everything

CSM's probes only report findings. They do not disable feeds, so you turn the feed off yourself.

A listing code still triggers this warning when the reply also contains a refusal code, because rspamd can score the listing code independently.

rspamd stops querying a list only after its own monitoring detects the problem. DQS monitoring is disabled, so its lookups continue until you turn it off.

#### An apply that fails the feed check

An apply that fails at `feeds_check` is reported as `antispam_apply_failed` and attempts to roll back. After that CSM holds the feeds back:

- CSM omits DNS feeds and `csm_ip_map` from subsequent applies, and does not rewrite the IP map meanwhile.
- The hold ends when the enabled feed names or the DQS key-file path change, or when CSM restarts.
- Reloading unchanged settings or replacing the key's contents does not clear the hold.

Fix the override before retrying.

[What the feed probes cover](#what-the-feed-probes-cover) lists the limits of CSM's probes.

## Spam evidence

While antispam is enabled, CSM reads each scan result Exim logs and records a verdict about the sending address:

| Scan result | Verdict |
|---|---|
| The score reaches the reject score | Spam |
| The score stays below the tag score | Ham |
| The score is in between, or the scan failed | None |

CSM first subtracts the score the CSM IP map gave the sender, so the map never feeds its own evidence.

Dry run and enforce record the same way. So do recipients with filtering off, because the verdict is about the sender.

CSM skips whitelisted addresses, `infra_ips`, private addresses and the server's own addresses. Postfix hosts record no verdicts; see [Scan records](#scan-records).

Spam evidence works with or without `csm_ip_map`, so you can review the data before turning the map on. After a CSM restart with `csm_ip_map` enabled, verdicts are not recorded until CSM has written the map again. Until then the map's share of a score is unknown.

### The spam score

A spam verdict creates or updates the sender's record on the Threat page. Ham only updates a record that already exists, so busy legitimate senders do not fill the attack database.

The spam score is the share of spam among recent verdicts. Each verdict loses half its weight every 7 days. Two recent spam verdicts and no ham reach 50, which lists the sender as `CSM_IP_SPAM`.

Spam evidence never blocks an address, never changes its threat score and is never reported to AbuseIPDB.

### How long a record is kept

CSM forgets a record that holds only spam evidence once its spam and ham verdicts have both lost nearly all their weight. That is about 47 days after a single spam message, and later for a sender with more verdicts. Ham on the record keeps it, so the next spam from a mostly clean sender does not list it.

These rules also apply:

- A record that also has attack findings, a block or a mail login attack in the last 30 days is kept.
- Every record leaves 90 days after its last spam verdict or finding. Ham does not extend that limit.
- Stored evidence without a decay timestamp keeps its weight, as it does when scoring the sender.
- The [spam evidence budget](#spam-evidence-budget) can drop a record that holds only spam evidence sooner.

CSM applies these retention rules at start and with every deep scan. Deep scans run hourly by default.

### IPv6 senders

An IPv6 sender is recorded and listed per /64 network, for example `2001:db8:1:2::/64`, so a sender that rotates addresses builds one score. IPv4 senders, including IPv4-mapped IPv6 addresses, stay per address.

Clearing or whitelisting an address inside the network forgets the network's evidence. The CSM IP map does not list a network that holds an excluded address.

Evidence recorded per IPv6 address by an earlier release stays until it expires or the [spam evidence budget](#spam-evidence-budget) drops it.

### Abuse reports

With `spam` in `reputation.report.classes`, CSM reports a sender to the central abuse database when rspamd keeps rejecting it and it has sent no clean mail recently. Senders of the shared mail services are never reported. Dry-run nodes count their verdicts too. See [Abuse Reporting](threat-intel.md#abuse-reporting).

### Where you see it

The Threat page's Spam column shows spam and ham counts and the spam score. A badge appears once the score reaches the listing threshold of 50. The badge does not confirm a listing: the feed may be off, and the map still skips excluded addresses.

The "Spam evidence only" filter lists senders by spam score. The IP lookup shows mail login attacks and spam verdicts.

### Spam evidence budget

The spam evidence budget is 50,000 records, about 22 MB of memory for records held only for spam evidence. It is fixed and has no setting.

Each time CSM records a verdict, it keeps those records at or under that budget. When the count is over the budget, CSM drops the weakest records until nine tenths of the budget remain, rounded down. CSM reports drops with a `spam_evidence_evicted` warning that names the most crowded network.

#### What to do about the warning

Look at the named network and its count. The count is how many records holding only spam evidence the network had when the drop began. It is not how many of the dropped records were its own, and the count alone does not show whether the network sent the flood.

Inspect the network's senders. If the network is hostile, block it in the [firewall](firewall.md).

#### What the budget protects

- Records with attack findings, a block or a mail login attack in the last 30 days are never dropped by this budget.
- Records with two or more verdicts are dropped only once such records fill nine tenths of the budget.

[How the spam evidence budget works](#how-the-spam-evidence-budget-works) has the counting rules, the drop order and the warning schedule.

## What CSM writes

| Where | What |
|---|---|
| `/usr/local/cpanel/etc/exim/acls` | Three Exim ACL hooks: `custom_begin_spam_scan_check`, `custom_begin_spam_scan` and `custom_begin_check_message_post`. CSM's content sits inside `# CSM-ANTISPAM BEGIN` and `# CSM-ANTISPAM END` markers. |
| `/etc/exim.conf.local` | One `spamd_address` line in the `@CONFIG@` section. |
| `/etc/rspamd/local.d` | `actions.conf`, `greylist.conf`, `rbl.conf`, `emails.conf`, `asn.conf`, `fuzzy_check.conf`, `phishing.conf` and `regexp.conf`. Each starts with `# csm-managed-version: 1`. |
| `/etc/rspamd/local.d` | `groups.conf`, which changes three symbol weights. See [Symbol weights](#symbol-weights). |
| Feed locations | The map redirect files and, with a DNS feed, the blocklist files listed under [Feeds](#feeds). |
| Learning locations | With learning on, the learning files listed under [Learning from Spam folders](#learning-from-spam-folders). |
| `/var/lib/csm/antispam` | A completion record. |

Content outside CSM's markers, including forward-guard blocks, is preserved. CSM regenerates its own blocks and files, so manual edits to them are overwritten. A file of the same name without CSM's header is replaced, see [Replaced files](#replaced-files). Removal leaves such a file alone.

### What the rspamd files turn off

These are off:

- Greylisting.
- The emails module.
- Sender-IP lookups to rspamd.com.
- Phishtank URL lookups to rspamd.com.
- Public fuzzy storage.

DNS block lists stay off unless a DNS feed is enabled.

The loaded `phishtank_enabled` setting must be the boolean `false`. Missing, duplicate or non-boolean values are configuration conflicts, just like `true`. CSM reports them and removes its integration when safe. Failed commands or malformed command output leave the integration in place for a later check.

### The invisible-character Subject rule

`regexp.conf` holds the `CSM_INVISIBLE_CJK_SUBJECT` rule. It matches a Subject with an invisible character, such as a zero-width space, next to a Chinese, Japanese or Korean letter. Spam uses invisible characters to split words so filters miss them.

- The rule checks the decoded Subject, including MIME-encoded ones.
- It covers kana, Han and Hangul letters with their half-width and supplementary forms.
- Punctuation does not trigger it.
- On its own the rule lifts a message above the default `tag_score` but not to the default `reject_score`.

Keep your own regexp rules in `/etc/rspamd/override.d/regexp.conf`.

### Symbol weights

`groups.conf` in `/etc/rspamd/local.d` changes three rspamd symbols:

| Symbol | Change | Reason |
|---|---|---|
| `HIDDEN_TEXT` | Weight lowered from 5 to 2. | Newsletters hide their preview line. At the default `tag_score` that rule plus one minor symbol tagged them. |
| `URL_VERY_LONG` | Counted once per message, not once per long link. | Newsletters full of tracking links are not tagged for that. |
| `DMARC_POLICY_REJECT` | Weight raised from 2 to 3. | Forged mail from a domain whose DMARC policy is reject reaches the tag score sooner. |

Your own weights take precedence:

- A symbol you define in any `*_group.conf` in `/etc/rspamd/local.d` keeps your weight. CSM leaves it out of its file.
- If one of those files cannot be read or uses includes, macros or multiline strings, CSM leaves all three weights to rspamd.
- Your `override.d` group files already take precedence.

CSM replaces an operator-owned `groups.conf`. One that is not safe to replace is left alone. rspamd then keeps its own weights and CSM reports an `rspamd_scores` warning.

### How CSM applies a change

Each change runs as one transaction in a short-lived root helper. systemd starts the helper outside CSM's sandbox, under the same lock as the forward guard. The helper does this:

1. Rebuilds the Exim configuration and checks it.
2. Reloads Exim and rspamd, only when needed.
3. Restores the previous state if a step fails.

If `systemd-run` is not available, CSM changes nothing.

Existing Exim SMTP sessions retain their old hooks. New sessions use the updated hooks. Account toggles are still read at each recipient. Reloading rspamd can change scoring for scans from either generation of Exim hooks.

### When CSM checks the integration

CSM checks the integration at startup, after each config reload and every 15 minutes. It repairs drift, such as a cPanel rebuild that dropped the hooks.

After fixing a condition that blocked it, run `systemctl reload csm` to request another check, even when `csm.yaml` is unchanged. A check already running finishes first; the reload does not wait for it.

[Pending changes and retries](#pending-changes-and-retries) covers what happens when another change holds the lock.

### Replaced files

CSM owns its rspamd files and the Roundcube include outright. When antispam is enabled and one of those paths holds your own file, CSM copies it to `/var/lib/csm/antispam/replaced` before writing its own.

Each copy is readable by root only. Its name is the UTC time followed by the escaped original path, for example `20261101T120000Z_%2Fetc%2Frspamd%2Flocal.d%2Factions.conf`.

#### Which files CSM replaces

CSM replaces only a regular file owned by root, with no group or other write access and no extra ACL entries, in directories protected the same way. Any other file at one of these paths blocks the install, or leaves the optional feature that needs it off. CSM repeats these checks before copying the file and before replacing it.

The Exim hook files and `/etc/exim.conf.local` are shared. CSM edits its own block there and never replaces them.

#### The warning and how to clear it

Each retained copy raises one `antispam_file_replaced` warning, in the same check that runs the update. The warning names the file and the copy, and says what CSM will do with the copy.

Move any settings you still need into a file CSM does not manage, then delete the copy to clear the warning. The warnings describe past replacements, including after antispam is disabled.

#### When a change fails

- CSM restores your file with its original owner, group and permissions.
- It deletes that copy only after the restore is durable, even if another file could not be restored.
- Copies made for replacements that never happened are removed too.
- If a restore cannot be confirmed, its copy remains for recovery.

#### When you disable antispam

| Host | What CSM does with the copies |
|---|---|
| cPanel | Deletes CSM's files and does not restore the copies. |
| Postfix | Puts the newest copy of each file back over CSM's own file and deletes that copy. Returning to dry run does the same for `actions.conf`, see [Dry run and enforce](#dry-run-and-enforce). |

On Postfix, older copies of the same file stay, and CSM never restores over a file it did not write. [Restore rules on Postfix](#restore-rules-on-postfix) lists the safety checks and the owner and mode a restored file gets.

## Postfix hosts

On a host without cPanel that runs Postfix, CSM manages rspamd only. Postfix already passes mail to rspamd's proxy worker as a milter, and rspamd applies the decision. CSM never edits Postfix's configuration. The sections above about cPanel accounts, Exim and Roundcube do not apply.

### Requirements

1. Postfix must pass mail to rspamd's proxy worker. `smtpd_milters` must name the address of an rspamd proxy worker that has `milter = yes`. CSM checks this read-only with `postconf` and rspamd's worker settings. Without this wiring CSM reports a definite `postfix_milter` precondition and installs nothing.

   When smtpd runs chrooted, a `unix:` milter path is resolved inside Postfix's queue directory, as Postfix does.

   `milter_mail_macros` must also include `{auth_authen}`, with the braces, as Postfix's default does. rspamd knows authenticated mail by it. Without it CSM reports the same precondition, because customers' outbound mail would be filtered as remote mail.

   CSM reads both settings from `main.cf` only. Per-service `-o smtpd_milters` overrides in `master.cf` are not read.
2. rspamd must refuse the mail it rejects. Set `discard_on_reject` and `quarantine_on_reject` to false, once each, for example in `/etc/rspamd/local.d/worker-proxy.inc`. See [Reject options on the proxy worker](#reject-options-on-the-proxy-worker).
3. Use rspamd 4.2 if you can. CSM accepts rspamd 3 or later, but its scope rule is tested with rspamd 4.2.3. The scope rule is the Lua rule CSM installs (`csm_scope.lua`). It decides which mail CSM's thresholds apply to and writes the scan records.
4. `/etc/rspamd/lua.local.d` must exist, owned by root and not writable by group or others. CSM's scope rule goes there.
5. Give CSM a scan socket. CSM uses it to check that rspamd answers. Add a Unix socket to rspamd's normal worker in `/etc/rspamd/local.d/worker-normal.inc`:

   ```
   bind_socket = "localhost:11333";
   bind_socket = "/run/rspamd/csm-normal.sock mode=0600";
   ```

   Only CSM uses this socket, as root, so mode 0600 is enough. Keep the first line if your proxy worker passes mail on to the normal worker and does not scan it itself.

   The socket and every parent directory must be owned by root or the rspamd user and not writable by group or others. Run `rspamadm configtest`, then `systemctl reload rspamd`.
6. rspamd must log to a file at `info` level. CSM reads its scan records from rspamd's log file, for example `/var/log/rspamd/rspamd.log`. See [rspamd log level](#rspamd-log-level).
7. rspamd must accept every message Postfix accepts. CSM warns when rspamd's `max_message` is below Postfix's `message_size_limit`.
8. Postfix and rspamd must be running.

#### Reject options on the proxy worker

Two options on rspamd's proxy worker keep the sender from ever being refused:

| Option | What rspamd's milter does with a message it rejects |
|---|---|
| `discard_on_reject` | Drops the message. |
| `quarantine_on_reject` | Accepts the message into Postfix's hold queue, where it stays until someone releases or deletes it. |

While either is set on a proxy worker Postfix passes mail to:

- CSM does not enforce, and removes an enforcing install, with a definite `milter_rejects` precondition.
- In dry run it is only a warning. There the mail the host itself rejects is dropped or held in the same way, and its sender is not refused either.

An option given more than once counts as set unless every value is false. So does any value that is not a boolean, such as null.

#### rspamd log level

`info` is rspamd's default level. Two settings hide the scan records from CSM:

- When rspamd logs to the journal or syslog, CSM warns and sees no scan records.
- At `notice`, `warning` or `error` level rspamd does not write them, and CSM does not warn. Set `level = "info";` in `/etc/rspamd/local.d/logging.inc`.

### Which mail is filtered

All unauthenticated mail from remote hosts is filtered, whatever domain it is addressed to. That includes mail Postfix relays for hosts in `mynetworks` on public addresses. List those hosts in `infra_ips`.

CSM never rejects or tags mail from these sources:

- A sender who authenticated to Postfix.
- rspamd's local networks (`local_addrs`), which include loopback and the private address ranges by default.
- An address in `infra_ips`.

Mail whose every recipient is in `exempt` is scored and logged, but never rejected or tagged. A domain entry matches that domain only, not its subdomains. One recipient outside the list is enough: the whole message is then filtered.

#### Your own rspamd settings rules

Your own rspamd settings rules, for example in `/etc/rspamd/local.d/settings.conf`, keep working. For mail CSM does not filter, CSM only raises the action thresholds on top of what your rule set.

A rule that limits which symbols run (`symbols_enabled` or `groups_enabled`) also skips CSM's scope rule. Mail it matches keeps the normal thresholds, even when it is authenticated, local or exempt, and gets no scan record.

### Dry run and enforce

A dry run on Postfix already changes how rspamd scores mail. rspamd is in the mail path, and CSM installs its scoring files from the first dry run, so it can predict its own decisions.

#### What changes from the first dry run

- Greylisting, the emails module and public fuzzy storage are off.
- rspamd's own DNS block lists are off, unless you name DNS feeds in `feeds.enabled`.
- Sender-IP and phishtank lookups to rspamd.com are off.
- Without the `rspamd_maps` feed, the rspamd.com maps CSM manages are read from local copies. The freemail and disposable-address lists stay empty until you fill them, see [Maps without any feed](#maps-without-any-feed).
- CSM's symbol weights and its invisible-character Subject rule apply.
- CSM's `milter_headers.conf` replaces yours, so other header routines you enabled there stop.
- Your own files at those paths are replaced, with a copy kept and an `antispam_file_replaced` warning, see [Replaced files](#replaced-files).

#### What stays the host's in dry run

CSM leaves `actions.conf` to the host in dry run. rspamd keeps rejecting and tagging at the host's own thresholds, applied to CSM's scores. This holds for all mail, including authenticated, local and exempt mail. Mail can therefore score differently than before CSM, in both directions.

CSM logs what it would have done with each scored message: `decision=reject`, `tag` or `none`, and `unfiltered` for exempt mail.

The dry run still rejects mail when the host's own reject threshold is at or below `reject_score`. That is the case with rspamd's built-in actions when there is no `actions.conf`. CSM raises a `dry_run_rejects` precondition warning, for example "dry run on this host still rejects: rspamd rejects at 15, at or below CSM's reject score of 15".

#### Enforcing

With `dry_run: false` CSM takes over `/etc/rspamd/local.d/actions.conf`. An existing file is copied first, see [Replaced files](#replaced-files). rspamd then rejects at `reject_score` and adds headers at `tag_score`.

CSM's thresholds never reject or tag authenticated, local, `infra_ips` or exempt mail. Other rspamd modules, such as antivirus, can still reject it.

#### Going back to dry run

CSM puts your `actions.conf` back from its newest copy, deletes that copy and clears its warning. Your thresholds decide again.

The file gets the owner and mode CSM's file had, which after a takeover are your original ones. If someone changed the owner of CSM's file or widened its permissions, the restored file gets root ownership and mode 0644 instead.

Without a copy CSM deletes its own file, and rspamd's built-in actions apply, which reject too.

### Headers and the Junk folder

CSM owns `/etc/rspamd/local.d/milter_headers.conf`. With it, rspamd handles two headers:

| Header | What rspamd does |
|---|---|
| `X-Spam-Status` | Removes any copy a message arrives with and adds its own: `X-Spam-Status: Yes, score=...` at the add header threshold, `No` below it. |
| `Authentication-Results` | Adds its own with the SPF, DKIM, DMARC and ARC results, and removes any copy the message arrived with, since a sender could forge one. |

In dry run the `X-Spam-Status` header follows the host's own add header threshold.

Authenticated and local mail is handled differently:

- rspamd's milter headers skip this mail, so CSM's scope rule removes the inbound `X-Spam-Status` copy itself.
- This mail gets no new `Authentication-Results` header and keeps any existing copies, so rspamd does not add login names to outbound mail.

Other header routines, such as `X-Spam-Level` or rspamd's extended headers, are off.

CSM leaves the `X-Spam: Yes` header of rspamd's proxy worker alone. Filing tagged mail into the Junk folder stays your Sieve rule, for example one that files `X-Spam: Yes` into Junk. CSM does not manage Sieve.

### Scan records

CSM's scope rule writes one `CSM-ANTISPAM event=scan` line per scored message into rspamd's log, at `info` level. rspamd logging at `notice` or above hides them. Authenticated, local and `infra_ips` mail get none.

These records count toward scan health and the Email Security page only. They do not feed spam evidence, the CSM IP map, the Threat page or abuse reports. The reason is that any local process can make rspamd log such a line through its local scan and milter listeners.

#### Failed scans

Failed scans come from Postfix's mail log. Postfix logs a warning each time its milter call to rspamd fails, and CSM raises `antispam_scan_error`. What happens to that mail depends on Postfix's `milter_default_action`:

| `milter_default_action` | What happens to the mail |
|---|---|
| `accept` | It is delivered unfiltered. |
| `tempfail` | It is deferred. |
| `reject` | It is rejected. |
| `quarantine` | It is held in Postfix's hold queue. |

### Files and learning

On a Postfix host CSM writes:

- The rspamd files and the completion record listed under [What CSM writes](#what-csm-writes), with `actions.conf` only while it enforces.
- `milter_headers.conf` in `/etc/rspamd/local.d`.
- `csm_scope.lua` in `/etc/rspamd/lua.local.d`.

It writes no Exim or Roundcube file. Each change reloads rspamd only. Disabling antispam removes these files and puts back the newest copy of each file CSM replaced, see [Replaced files](#replaced-files).

Learning installs the same rspamd files as on cPanel, without the webmail include. See [Learning from Junk folders](#learning-from-junk-folders).

If CSM cannot tell which mail server runs, it leaves an installed integration in place and reports a temporary `platform` precondition. This can happen while Postfix restarts on a host that also has Exim installed.

### Learning from Junk folders

With `learning.enabled: true` CSM learns from mail users move into their Dovecot Junk folder. Scores, limits, retention, stored messages, operator commands and findings work as described under [Learning from Spam folders](#learning-from-spam-folders), with these differences:

- Every mailbox Dovecot lists takes part. There is no per-mailbox switch and no opt-in file.
- Mailboxes and domains in `exempt` are not watched. CSM does not read their Junk folders.
- CSM reads the `new` and `cur` directories of each Junk folder. A report must be owned by the uid Dovecot stores that mailbox's mail as.
- Mail already in a Junk folder is never learned. The first pass records what is there, and only messages moved in later are reports.
- No webmail Junk-button include is installed.

#### Learning requirements

The [learning prerequisites](#prerequisites) apply, and also:

1. Run Dovecot 2.3. CSM lists users with `doveadm user '*'` and reads mail settings with `doveconf`. A userdb must be able to list its users, see [Listing Dovecot users](#listing-dovecot-users).
2. Mark Junk as `\Junk`. CSM finds Junk folders by `special_use = \Junk` in Dovecot's namespace mailbox settings, as Dovecot's example `15-mailboxes.conf` sets for `Junk`. A single configured mailbox is supported too.

   A folder named Junk without the flag is not watched. With no `\Junk` mailbox at all, every mailbox is skipped.
3. Store mail as Maildir in its default layout. CSM skips a mailbox stored another way, see [Mailboxes CSM skips](#mailboxes-csm-skips).
4. Give learning a Redis of its own. Learning never uses rspamd's Redis on Postfix, because other rspamd modules share it. Run a second Redis instance and set `learning.redis_socket` to its socket. Without it CSM reports `unsupported`.

   On Debian and Ubuntu the packaged `redis-server@.service` template runs an instance from `/etc/redis/redis-<name>.conf`. For an instance named `csm`, create its data directory:

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

   Start it with `systemctl enable --now redis-server@csm`. Size `maxmemory` for the hashes you expect to learn.

   The template's sandbox lets Redis write below `/var/lib/redis`, `/var/log/redis`, its run directory and, for cluster mode, `/etc/redis`. `systemctl cat redis-server@csm` shows the exact list on your system. `dir` must be in one of them for persistence to work. Use the data directory created above, not `/var/lib/redis` itself, where the main instance keeps its files.

   Give rspamd's user access through the socket's group, for example with `usermod -aG redis _rspamd`. No other user may be in that group. Then restart rspamd: a reload keeps the groups it started with, and its fuzzy worker would be refused by the socket.

   The Redis checks of the prerequisites apply to this socket. rspamd's global `redis` settings must not use sentinels, TLS or a named user, because rspamd would apply them to the learning Redis too.
5. Give CSM a private controller socket, as on cPanel. See [rspamd admin interface](#rspamd-admin-interface).
6. Store mail as a user that is not a service user. Users' Sieve scripts and Dovecot's mail processes run as the uid Dovecot stores mail as, such as `vmail`. CSM therefore treats every name of that uid as a user that can run tenant code, and none may be in the Redis socket's group. Mail stored as rspamd's or Redis's uid is refused with `unsafe_prerequisite`.

CSM checks these on every reconciliation pass while learning is requested. The learner and its Junk folder watcher start only once none of them fails.

#### Listing Dovecot users

| Userdb | Can it list users? |
|---|---|
| passwd or passwd-file | Yes. A passwd-file whose path holds `%` variables, such as one file per domain, cannot. |
| SQL or LDAP | Yes, with its iterate settings. |
| static, checkpassword or prefetch | No. |

What CSM reports depends on the failure:

| Case | What CSM does |
|---|---|
| No userdb can list users | Reports `unsupported` and leaves learning off. |
| Dovecot 2.4, whose mail settings changed | Reports `unsupported` and leaves learning off. |
| A userdb that can list users fails, for example while its SQL database is down | Reports `backend_unavailable`. Installed learning stays and new reports wait for a later check. |
| A temporary failure looking up an individual user | Pauses discovery, without cancelling reservations or pruning state. |
| Unusable or case-colliding user names | Pauses discovery, because their identities and mail owners cannot be established safely. |

#### Mailboxes CSM skips

CSM skips a mailbox in these cases:

- It uses another driver such as `mdbox` or `mbox`, `LAYOUT=fs`, or the `zlib` or `mail_crypt` plugin.
- Its uid is 0.
- CSM cannot use its home or mail location, such as a location with `DIRNAME`, `MAILBOXDIR` or a `%{if}` condition.
- Its lookup confirms the user does not exist.

Some conditions skip more than one mailbox:

- A `%{if}` in `mail_location` or a private namespace location skips every mailbox. CSM still reads their mail owners for isolation checks.
- Two users whose mail directories are the same, including a symlink alias, or one inside the other, are both skipped. CSM cannot tell their moves apart. The comparison also covers the directories of private namespaces that have no Junk folder.
- A mailbox whose mail location CSM cannot resolve also keeps the other mailboxes with the same uid out of learning, until CSM can tell them apart.

Known owners remain part of the isolation checks even when their mailboxes are skipped for another reason.

Skipped mailboxes are counted by reason in one `mailboxes_skipped` warning that names none of them. Learning goes on for the others.

#### Reporters

`learning.reporter` decides who casts one learning vote:

| Value | Who is one reporter |
|---|---|
| `domain`, the default | Each mail domain. Its mailboxes share one vote per cluster and one learning allowance. A domain that reaches its allowance pauses only its own new reports. |
| `mailbox` | Each mailbox, as each cPanel account is. |

A user without a domain, such as a system user, reports under its own uid in either mode.

Changing the mode, or `exempt`, restarts the Junk folder watcher:

- Votes already cast stay until their cluster expires. A cluster reported both before and after a mode change can therefore count the same domain or mailbox one extra time.
- Reports the old reporters had not sent yet are dropped.
- The Junk folders of domain mailboxes start new baselines.

#### Enabling learning on Postfix

1. Set up the Redis instance and the private controller socket above, then run `rspamadm configtest` and restart rspamd. A reload is not enough after adding rspamd's user to the socket's group.
2. Set `learning.enabled: true` and `learning.redis_socket`, then run `csm validate` and `systemctl reload csm`.
3. Check `antispam_learning` findings and `csm doctor`. Once learning runs, `csm status --json` carries an `antispam_learning` block.
4. Move a test message into a Junk folder. The next pass, within five minutes, picks it up.

### Rolling it out on Postfix

1. Meet the [requirements](#requirements). Choose `feeds.enabled` first, because the dry run already turns off rspamd's own DNS block lists and greylisting.
2. Enable with `dry_run: true`. Leave `exempt` empty unless a recipient must never be filtered.
3. Check that rspamd's loaded actions are still the host's (`rspamadm configdump actions`) and that no `dry_run_rejects` or `milter_rejects` warning appears.
4. Review each `antispam_file_replaced` copy, and check that greylisting and DNS block lists are as you intend.
5. Check that `CSM-ANTISPAM` lines appear in rspamd's log and that mail at the host's add header threshold still carries `X-Spam: Yes`.
6. Leave dry run on for at least 7 days. Review each would-reject decision in rspamd's log (`CSM-ANTISPAM event=scan ... decision=reject`) and watch for scan-error findings.
7. Set `dry_run: false`. Check every reject for a week. On a confirmed false positive, return to dry run: CSM puts your own `actions.conf` back.

To roll back, set `enabled: false`. CSM removes its rspamd files, puts back the files it replaced and reloads rspamd.

## Stalwart hosts

On a host whose mail server is Stalwart, CSM does not install or manage rspamd and puts nothing in the mail path. Stalwart's own spam filter and its own scores decide what happens to each message.

`csm stalwart setup` does three things:

- It makes Stalwart log the mail its filter rejects or discards.
- It reports whether the filter is on and at which scores it acts.
- It adds a spam rule, `CSM_IP`, that adds up to 4 to the spam score of senders on CSM's address list.

`csm doctor` checks the logging, whether the filter is on and at which scores it acts, and whether the filter's DNS blocklists answer. Neither command switches the filter on or off, or changes the scores at which it files mail to Junk, rejects or discards it.

The rule is the one setup step that changes what happens to mail. More mail from listed senders goes to Junk, or is rejected or discarded at the scores set in Stalwart. Switch the rule `CSM_IP` off in Stalwart to stop it.

Setup keeps existing tags and reports scores only for scoring tags. It lists other tags as non-scoring. See [Preparing Stalwart](detection-realtime.md#preparing-stalwart).

### Filter verdicts

CSM reads Stalwart's log and counts one verdict per message on the Email page: delivered, Junk, rejected or discarded.

| Message | How it is counted |
|---|---|
| Sent to several recipients, and went to Junk for any of them | Junk. |
| Delivered, including while the filter is off | Delivered. |
| Filed into a folder by a mailbox's own Sieve rule, Junk included | Delivered, because Stalwart logs such mail as not spam. |
| No local delivery within two minutes, because it was relayed, deferred or failed | Not counted. |
| From a logged-in sender, local mail between mailboxes included | Not counted. |
| Logged by Stalwart without a client address | Not counted. |
| More messages are waiting for their two minutes than CSM can hold, as under a flood | The extra ones count as "not matched". |
| A held queue ID that names conflicting messages | "Not matched", counted once for that ambiguous join. CSM records no sender evidence. |

Delivered and Junk messages are counted two minutes after CSM reads them, so the page lags by that much. A log line that repeats for the same queued message neither adds a verdict nor lengthens the two-minute wait.

Rejected and discarded show a dash until Stalwart has logged one.

### Spam evidence on Stalwart

Each counted message, except one not matched, also records a verdict about the sending address, as on cPanel (see [Spam evidence](#spam-evidence)):

| Stalwart's verdict | Evidence |
|---|---|
| Junk, rejected or discarded | Spam |
| Delivered | Ham |

Junk is spam at Stalwart's Junk score, not at a CSM score.

The same rules apply as on cPanel:

- CSM skips whitelisted addresses, `infra_ips`, private addresses and the server's own addresses.
- IPv6 senders are recorded and listed per /64 network. Clearing or whitelisting an address inside forgets the network's evidence.
- Spam evidence never blocks an address, never changes its threat score and is never reported.
- The [spam evidence budget](#spam-evidence-budget) applies.

Spam evidence on Stalwart does not need `email_protection.antispam`.

#### When no verdict is recorded

A sender on [CSM's address list](#csms-address-list-on-stalwart) gets no verdict unless CSM sees that the rule `CSM_IP` is off. The rule raised the score of its mail, so Stalwart's verdict on it says more about the list than about the sender. The list that counts is the one CSM builds at that moment, not what Stalwart holds.

While Stalwart's spam filter is off, no verdict is recorded at all.

The Email page counts these messages as usual.

### CSM's address list on Stalwart

CSM keeps its address list in Stalwart's lookup lists, where the rule `CSM_IP` reads it. The list holds the same addresses as the [CSM IP map](#csm-ip-map), from the same sources and with the same exceptions.

CSM checks the list at start and every 10 minutes, writes only what changed, and then has Stalwart load it. If loading fails twice, CSM keeps retrying on later checks, even when no keys need changing.

#### The lookup namespaces belong to CSM

The lookup namespaces whose names start with `csm-ip` belong to CSM. CSM deletes any key there that it did not add, so edits made there in Stalwart are undone within 10 minutes.

| State of the rule `CSM_IP` | What CSM does with the namespaces |
|---|---|
| Switched off in Stalwart | Empties them. This is how you stop the scoring. |
| Missing, or its type is not `Any` | Empties them. |
| Exists, has type `Any`, and is enabled | Fills them again. |

In observe mode CSM reads Stalwart but writes nothing, so the namespaces keep what they hold, even with the rule off. If Stalwart has not finished loading the list, the `stalwart_address_list` warning about it stays while CSM is in observe mode.

#### Stalwart findings

| Finding | When it warns |
|---|---|
| `stalwart_spam_filter_off` | Stalwart's spam filter is off, since Stalwart then scores no mail. A failed filter read leaves an existing warning in place until CSM can confirm the filter is on. |
| `stalwart_address_list` | CSM cannot inspect or read its key file, read the rule or list, write the list, or have Stalwart load it. |

When Stalwart refuses CSM's key, the `stalwart_address_list` message says to run `csm stalwart setup`. These warnings clear once recovery is confirmed.

#### CSM's key

CSM's key needs more access to keep the list, so run `csm stalwart setup` again after upgrading.

Without a key file CSM writes nothing to Stalwart and raises neither finding. Setup and `csm doctor` report the missing key. An unreadable key file raises `stalwart_address_list`.

### Not done on Stalwart

Apart from the rule for its address list, CSM does not change Stalwart's scores or rules, set up its DNS blocklists or check outgoing mail.

## rspamd admin interface

rspamd's controller answers admin and statistics requests. By default it trusts every connection from `127.0.0.1` and `::1` without a password. Every process on the server can connect there, including customer scripts. Such a process could read rspamd's history, which lists senders and recipients of scanned mail, or change scores and actions at runtime.

### What CSM reports

While antispam is enabled, CSM reports each controller listener that other users may reach as an `antispam_controller_open` finding. The finding names the listener and the reason. The reasons include cases where CSM cannot prove isolation:

- A trusted address that local processes can use: loopback, a wildcard, or one of the server's own addresses.
- A trust entry CSM cannot resolve, such as a map file or a hostname.
- No controller password at all, only an enable password, or an empty password.
- A controller configuration CSM cannot read in full, such as an unreadable worker type, an unsupported `enabled` or `count` value, a systemd socket, or a second controller worker.
- A Unix socket, or one of its parent directories, that other users can write to, or whose access CSM cannot verify.

For symlinked Unix sockets, a private directory protects only its own descendants. CSM also checks the resolved socket path. A private directory on a detour does not hide a socket reachable through its real path.

These warnings also update in observe mode and when an apply is busy. When `rspamadm` cannot run, CSM keeps the previous warnings until it can. Turning antispam off clears them even if CSM cannot cancel pending changes.

### Closing TCP access

Keep a controller password set and put this in `/etc/rspamd/override.d/worker-controller.inc`:

```
secure_ip = [];
```

rspamd ships with the placeholder password `q1`, which it rejects as client authentication, so this also works without setting your own. Two password states leave access open:

- With both `password` and `enable_password` unset, an empty `secure_ip` opens every command to everyone.
- Setting only `enable_password` leaves read-only access open.

### A private socket for local administration

For local administration add a private Unix socket in the same file:

```
bind_socket = "/run/rspamd/csm-controller.sock mode=0600";
bind_socket = "localhost:11334";
secure_ip = [];
```

Direct Unix socket connections get admin access without a password. Forwarded headers trigger additional trust and password checks, so local clients must send no forwarded headers.

Protect the socket this way:

- Keep the socket and its parent directories owned by root or rspamd, with no extended ACLs.
- Use socket mode 0600.
- Use non-symlink directories that other users cannot write to. Socket mode alone does not protect a replaceable parent.

Reload rspamd after the change. CSM never edits the controller settings.

### Statistics on the Email Security page

The Email Security page reads rspamd's counters through a Unix controller socket owned by rspamd, such as the private socket above. Failing that, it uses a loopback listener that `secure_ip` trusts. Without either it shows "Stats unavailable". CSM never uses the controller password.

## Learning from Spam folders

`email_protection.antispam.learning.enabled: true` makes rspamd learn from mail users move to their Spam folder. When several accounts report the same content, later copies of it score higher. Learning is off by default and requires antispam to be enabled. Enabling it is refused in [observe mode](observe-mode.md).

This section describes cPanel hosts. For Postfix hosts see [Learning from Junk folders](#learning-from-junk-folders).

Reported messages that share most of their text form a cluster. Enabling learning is consent to two things:

- CSM reads new messages in the Spam folders of participating accounts.
- CSM keeps one full message per learned cluster.

Clusters normally retire 90 days after their last report. Pauses and cleanup failures can retain messages longer, see [Stored messages](#stored-messages).

### Prerequisites

While learning is requested, CSM checks the conditions below during reconciliation:

- A definite failure requests removal of the learning configuration.
- A temporary probe failure keeps an existing installation.
- Learning findings do not disable core filtering. `antispam_learning` names the reason.

#### Versions

CSM needs rspamd 4.2.x and Redis 5.0.x, 6.2.x or 7.x. Other versions are refused.

#### Controller and control sockets

- rspamd has exactly one private controller Unix socket. It is owned by rspamd, mode 0600, in directories only root and rspamd can write to, with no extended ACLs.
- No other controller listener grants other users admin or read-only access. See [rspamd admin interface](#rspamd-admin-interface).
- rspamd's control socket is private to root and rspamd, with protected directories and no extended ACLs. Check the effective `control_socket` path and its permissions as well as the controller socket.

#### Redis for fuzzy storage

Learning needs one Redis server for fuzzy storage, reached only through a Unix socket:

- Redis has `port 0` and `tls-port 0`. A Redis build without TLS needs no `tls-port` setting.
- The socket is owned by root, rspamd or the `redis` service user, with no access for other users and no extended ACLs.
- Any group access is limited to `root`, `redis` and rspamd's service user. Service users must not be hosting accounts.
- Parent directories protect the socket from replacement.
- Redis has a positive `maxmemory` and `maxmemory-policy noeviction`.

CSM sends the Redis password only to a socket it has verified, and only on a connection served by that socket's owner.

Redis persistence is recommended. CSM warns only when both append-only persistence (`appendonly yes`) and snapshots (`save`) are disabled. While learning is active, CSM rebuilds missing learned values from stored messages.

[Who may own the Redis socket](#who-may-own-the-redis-socket) covers account records without a system user and unreadable account lists.

#### A Redis of its own

With `learning.redis_socket` set, learning uses that Redis and not rspamd's:

- CSM applies the Redis checks above to it.
- CSM refuses it while any other rspamd module or rspamd's global Redis settings name the same socket.
- CSM refuses it while those global settings use sentinels, TLS or a named user.
- CSM points the fuzzy worker at it with no password.

Learning moves to a new socket only after the socket passes these checks. Until then it keeps its current Redis.

#### rspamd's uid and log

rspamd's uid must be used by rspamd alone. No cPanel account may share it, and on Postfix no user but the service users may. If CSM cannot read every account's uid, learning waits: an installation stays, and nothing new is published until a later pass can check.

rspamd's log must be unreadable to other users, by file permissions or by CloudLinux CageFS. CageFS qualifies only for a file log under `/var/log/rspamd`, with every account confined and that directory absent from its skeleton.

#### No fuzzy rule of your own

You must have no local fuzzy rule and no enabled fuzzy worker of your own. CSM's files would replace them, so CSM refuses. The stock rule for rspamd.com is replaced on purpose.

### What learning installs

| File | Purpose |
|---|---|
| `fuzzy_check.conf` and `worker-fuzzy.inc` in `/etc/rspamd/override.d` | Local fuzzy scoring and storage. Mode 0640 for root and rspamd's group. |
| `fuzzy_group.conf` in `/etc/rspamd/local.d` | The `CSM_FUZZY_SPAM` score and its group cap. |
| `csm_learning.lua` in `/etc/rspamd/lua.local.d` | A controller plugin for message inspection. |
| `/usr/local/cpanel/base/3rdparty/roundcube/config/inc.d/zz-csm-antispam.inc.php` | Points Roundcube's Junk button at the Spam folder. |

#### The Roundcube include

The include changes the Junk button for every webmail user on the server, regardless of the account's Spam Filters switch. CSM replaces an operator-owned file at that path, see [Replaced files](#replaced-files). The `markasjunk` plugin must already be enabled; CSM does not enable it.

CSM checks the include by loading Roundcube's configuration with cPanel's PHP as the `nobody` user, never as root. If Roundcube does not load the Junk settings, or the check fails:

- CSM restores the previous include and reports `roundcube_unavailable`.
- The rest of the learning configuration stays installed.
- Later passes omit CSM's include until the learning configuration changes or CSM restarts.

A later include can override the settings.

#### Checking what rspamd loaded

After writing these files CSM checks what rspamd loaded. That includes the effective `CSM_FUZZY_SPAM` weight the controller reports, which can differ from the files after a runtime weight change.

A failed learning check attempts to roll back the change. Later passes omit learning until its configuration changes or CSM restarts. Fix the reported cause before restarting. Reloading unchanged settings does not clear the hold.

#### Which services reload

On an otherwise current, completed installation:

| Change | Reload |
|---|---|
| Only learning | rspamd reloads. Exim is not rebuilt. |
| Only the Roundcube include | Neither service reloads. |

An incomplete installation or Exim configuration drift can still require an Exim rebuild.

#### Keys

Keys live in `/var/lib/csm/antispam/learning/keys`, root only. Directories are mode 0700 and key files mode 0600.

- CSM creates a complete set when none exists.
- CSM refuses a partial or invalid set with `state_mismatch`, leaving learning off.
- Do not delete the surviving keys to start over. New keys cannot match hashes made with the old ones.

The learning ledger is CSM's record of learning requests and learned clusters, kept in the state database. It is bound to the hash keys and hash settings. A changed generation stops learning; CSM does not reuse the previous learning state.

#### Redis capacity

The Redis capacity warning starts at 75% of `maxmemory` and clears below 70%. It leaves the installed learning configuration in place and pauses the learner, including pending changes, until usage falls.

#### Turning learning off

Turning learning off requests removal of CSM's learning files and Roundcube include, while keeping the keys. Conflicts or transaction failures can prevent removal. Check findings before assuming learned scoring is gone.

Turning learning off also keeps stored messages and the learning ledger, but clears folder baselines and unsent reports. Enabling it again starts new baselines. Observe mode keeps everything and resumes where it stopped.

[How the learner stops](#how-the-learner-stops) describes what happens to calls in flight.

### How reports are found

Every five minutes CSM checks the main mailbox and each domain mailbox of every account whose Spam Filters switch is on. When `/etc/global_spamassassin_enable` exists, it checks every account.

CSM looks at the `new` and `cur` directories of two folders:

- `.spam`, the folder spam-box delivery and the webmail Junk button use.
- `.Junk`, which many mail clients use.

Folders are read without following links. CSM never creates folders or changes permissions.

There is one exception to the link rule: a `.spam` or `.Junk` that links to another folder of the same mailbox, such as `.spambox` on some older cPanel accounts. The link must use the folder's bare name or its exact path under the account's home. CSM reads that folder, and pointing the link elsewhere starts a fresh baseline.

#### Only new messages are reports

The first pass over a folder records what is already there without reading it. This record is the folder's baseline. Only messages that arrive after that are reports, so existing mail is never learned retroactively.

Moving a message within the folder or changing its flags does not report it again.

A pass reads at most 20 reports per account, takes turns between accounts, and stops before the next one is due. The rest wait for the next pass.

### What counts as a report

A report is a regular file owned by the account, at most 10 MiB, that did not change while CSM read it.

A message still linked from another folder, such as one delivery shared by several mailboxes, counts once it and its links have stayed unchanged for a full pass. The wait lets a move into or out of Spam finish before the message counts.

CSM skips a message in these cases, linked or not:

- Any `X-Spam-Status` header says `Yes`.
- That header cannot be parsed.
- The header block is malformed or too large.

A message whose MIME structure CSM cannot read is skipped as `no_digest`, for operator requests too.

Only the text parts of a report are learned, attached text included. Images and other attachments never are.

#### Reports are not authenticated

Tenants control their own mail. They can move any message they received, or deliver one locally. A forged `X-Spam-Status: Yes` header keeps a message from being learned. In dry run senders' headers are not removed, so forged headers have this effect on any message.

### Scores and limits

Each reporting account adds a fixed weight to the cluster:

| Reporting accounts | `CSM_FUZZY_SPAM` score, about |
|---|---|
| 1 | 2.9 |
| 2 | 5.4 |
| 3 | 7.2 |
| 4 | 8.4 |

With the default tag score of 6, a message needs reports from about three accounts to be tagged on that evidence alone. An operator mark from `csm antispam learn --spam` weighs as much as nine accounts.

Copies in multiple Spam folders or mailboxes of the same account still contribute only once to that cluster.

#### What joins a cluster

Messages that share most of their text join the same cluster, so later variants of a campaign score too. Newsletters built from one template can also be close enough to join.

A new message whose plain text and HTML versions differ starts its cluster from one of them, normally the larger. Attached messages are never used. Later copies score through that version.

Lowering or correcting a learned value removes and re-adds it, which can leave a short gap in which the message scores lower.

#### Learning in dry run

Learning writes scores with either value of antispam's `dry_run` setting. In dry run they affect the measured score. What happens to the message still follows the dry-run policy.

### Opt-out, disable and retention

#### When an account opts out

Turning an account's Spam Filters switch off stops CSM reading its folders at the next check and drops its unsent reports. That includes reports the learner accepted but has not yet sent to rspamd. This does not apply when `/etc/global_spamassassin_enable` exists: the global override prevents per-account opt-out, including learning.

- Each cluster of a report is handled on its own. A part whose update rspamd may already have received still completes.
- If the learner cannot cancel, CSM reports it and retries at the next check while the account stays opted out.
- Turning the switch back on starts new baselines.

#### When an account is removed

Removing a cPanel account drops its learner reports the same way, once its UID belongs to no remaining account.

- An account whose home directory CSM cannot use keeps its reports.
- While the account list is changing or cannot be read, every account keeps its reports and CSM retries at the next check.

#### What stays after opt-out or removal

What the account already contributed stays until the cluster expires or an operator forgets it. Opting out or removal does not delete it sooner.

#### Folders that disappear

Folders absent for 90 days are forgotten with their pending reports. Unresolved accounts, unreadable homes, incomplete mailbox lists and unsafe or unreadable folders keep their state until they can be checked again.

Links in an account's `etc` directory, such as cPanel's Roundcube database link, are not mail domains. CSM does not follow them and they do not hold back this cleanup.

#### Reports that fail

A message with three counted failures is skipped as `failed`. A backend error stops further submissions for that pass, and the next pass starts with the accounts after the one that failed. [How failed reports are counted](#how-failed-reports-are-counted) has the rules.

### Stored messages

Each learned cluster keeps one message, the first one reported, so the learner can restore its value if Redis loses it.

- CSM keeps the message's headers and text parts, without images or other attachments, under `/var/lib/csm/antispam/learning/anchors`, readable only by root.
- A cluster started from one version of a message keeps only that version.
- Messages saved by older versions keep their attachments until their cluster retires.

#### When a stored message is deleted

CSM deletes the message when the cluster retires, 90 days after its last report, or when an operator forgets it. Backups and file system snapshots can keep a copy longer.

Disabling learning, observe mode or unmet prerequisites can delay retirement and message deletion. Turning learning off keeps stored messages and state.

If deleting a retained message fails, CSM still removes its retired score and reports the cleanup error. New reports wait until cleanup succeeds.

Retained messages consume their learning allowance until deletion succeeds. The record that prevents a retired score from returning remains charged, including when a new cluster retires before its first contribution completes.

#### When a stored message stops matching its cluster

rspamd can hash the same message differently from one check to the next, because the words it hashes depend on the language it detects.

| Case | What CSM does |
|---|---|
| A stored message stops giving its cluster's value | Retires that cluster, removes its score and logs a warning. Other clusters and new reports are not affected. |
| An inspection fails | Leaves the cluster intact. |

Before either outcome, CSM tries the message's text-only form. If that form reproduces the learned digest, CSM publishes it. After a failed inspection, publication otherwise waits for a later retry.

Reports joined to a retired cluster contribute no vote. Operator spam requests report `skipped:superseded`.

#### Stored messages in backups

CSM's state archive (`csm store export`) leaves learning state out. `csm backup` includes it, see [Backup, restore and a fresh namespace](#backup-restore-and-a-fresh-namespace).

### Teaching and correcting learning

Root can learn a saved message as spam, or remove what one taught:

```
csm antispam learn --spam <file>...
csm antispam learn --forget <file>...
csm antispam learn --status [<request-id>...]
csm antispam learn --fresh-namespace
```

The daemon must be running. `--spam` and `--forget` require learning enabled and refuse observe mode.

| Option | What it does |
|---|---|
| `--spam` | Gives each matching cluster one operator mark, which weighs as much as nine reporting accounts. |
| `--forget` | Removes the clusters a file matches, with every account's contribution to them, and deletes their stored message. Other learned messages may still score similar mail. |
| `--status` | Shows what the daemon recorded for a request. See [Checking a request](#checking-a-request). |
| `--fresh-namespace` | Moves the learning state aside and empties it, so the next enable starts over. See [Backup, restore and a fresh namespace](#backup-restore-and-a-fresh-namespace). |

#### Rules for the files

Each file must be regular with one link, at most 10 MiB, and unchanged during reading. Symlinks anywhere in its path are refused. The snapshot is sent to the daemon as bytes.

#### Request IDs and replies

Each file gets a request ID, printed before it is sent. If printing fails, that file is not sent. A lost or truncated reply is retried once with the same ID and snapshot. Refusals and completed replies are not retried.

| Reply | Meaning |
|---|---|
| `pending` | The file was reserved. The daemon keeps publishing it in the background. |
| `deferred` | Nothing changed, because learning was busy or waiting on another change. Run the command again later. |

#### Checking a request

`csm antispam learn --status <request-id>` shows what the daemon recorded for a request, including clusters still publishing and their phase. Without an ID it lists the requests that are not finished.

Status only reads the ledger. It works with learning disabled or in observe mode.

If the command is interrupted, look its ID up with `--status`, or in the action log with `csm actions --op integrate.antispam_learn --json`. The action log records the request ID, escaped basename, outcome and full digests, never message content or headers.

A missing record does not prove that no change occurred. Running the command again makes a new request.

#### What forgetting does

Forgetting works for the whole server: the clusters a file matches lose every account's contribution.

CSM keeps a zero-value record for each forgotten value and keeps auditing it, so a late write cannot bring the score back unnoticed.

Forget is not a permanent allowlist. New reports of the same content start a new cluster.

#### Exit status

| Exit status | Meaning |
|---|---|
| 0 | Every file was learned, already learned, forgotten or matched nothing; `--status` and `--fresh-namespace` succeeded. |
| 1 | At least one file was refused, failed or is still pending, or the daemon could not complete the request. |
| 2 | The command line is not valid. |

### Backup, restore and a fresh namespace

`csm backup` stores the learning state as one bundle:

- The ledger in the state database.
- `/var/lib/csm/antispam/learning`, which holds the hash keys, transport keys and stored messages.

`csm restore` brings the bundle back and moves any learning directory it replaces to `learning.old-<UTC time>-<suffix>`.

Installation failures trigger rollback, but rollback itself can fail. Cleanup errors can also occur after the new bundle is installed. After any restore error, check the reported paths and resolve it before restarting CSM.

#### After a restore

Restored learning state holds new reports until the daemon has run with learning disabled outside observe mode. Enable learning again only when the backup is the current bundle. CSM cannot tell an old backup from the current one by comparing scores.

#### Starting a fresh namespace

If the backup is older, or storage was lost along with the keys, start a fresh namespace. With learning disabled, run:

```
csm antispam learn --fresh-namespace
```

The command does this:

1. Waits for a reconciliation pass that is running to finish.
2. Moves `/var/lib/csm/antispam/learning` to `learning.old-<UTC time>`.
3. Empties the learning and Spam folder state.

If emptying fails, CSM attempts to move the directory back and reports any failure to do so. Resolve that failure before enabling learning.

After a successful reset, the next enable creates new keys and a new storage prefix, and every folder starts a new baseline. Old reports are not replayed.

The old directory still holds full messages. Remove it once you do not need it any more. CSM never flushes Redis; old hashes stay under the old prefix until they expire.

### Learning findings

Each `antispam_learning` finding names one reason. Each reconcile pass reports server readiness. The running learner adds the reasons from `anchor_drift` on. On Postfix the learner also reports a Dovecot listing that failed in its last pass, until a later pass reads it.

| Reason | Meaning |
|---|---|
| `unsupported` | An rspamd or Redis version is outside the supported versions above, a Postfix host has no `learning.redis_socket`, or Dovecot runs 2.4 or has no userdb that can list its users; learning is disabled. |
| `unsafe_prerequisite` | Required isolation or Redis settings are unsafe or cannot be established; learning is disabled. |
| `state_mismatch` | The learning keys or learning state cannot be trusted; learning is disabled and nothing is adopted or deleted. See the cases below the table. |
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
| `account_capacity` | An account, or the operator, reached its learning allowance, or an account's Spam folder state reached its limit of 65536 messages. See the note below the table. |

`state_mismatch` covers three cases:

- Learning keys could not be created or loaded safely.
- Restored learning state awaits confirmation.
- The learner found its state out of step with its storage. The CSM log then names the disagreeing fuzzy digests.

With `account_capacity`, new reports from that account, or from the operator, are skipped or wait, and existing learning stays. Confirmed absent folders are forgotten after 90 days, which frees their share.

## Findings

| Check | Severity | Meaning |
|---|---|---|
| `antispam_precondition` | Warning | A required condition is not met. The message names the cause, such as `rspamd_socket` or `spamassassin_enabled`. A temporary cause keeps an installed integration; a definite one removes it when that is safe. |
| `antispam_apply_failed` | Warning, or Critical when the previous state could not be confirmed | An install, update or removal failed at the named step, or pending changes could not be canceled. |
| `antispam_file_replaced` | Warning | CSM replaced your own file at one of its paths and kept a copy. Deleting the copy clears it, and so does CSM putting the copy back on a Postfix host. See [Replaced files](#replaced-files). |
| `antispam_rspamd_down` | Warning | Three probes of the scan socket in a row failed. CSM probes every 20 seconds while antispam is enabled. |
| `antispam_rspamd_recovered` | Warning | Two probes in a row succeeded after an outage. |
| `antispam_scan_error` | Warning | The mail server logged a failed scan. One finding covers every failure until a scan succeeds. |
| `antispam_controller_open` | Warning | Other users may reach rspamd's admin or read-only interface, or CSM cannot verify isolation. See [rspamd admin interface](#rspamd-admin-interface). |
| `antispam_feed` | Warning, or Critical when a list answers for everything | A feed or map redirect is off, loaded rules differ, a list misbehaves, or rspamd still fetches maps from rspamd.com. These findings alone do not disable filtering. See [Feed findings](#feed-findings). |
| `antispam_ip_map` | Warning | The IP map could not be written, or rspamd has not confirmed the current map 5 minutes after a write. Core filtering is unaffected. See [CSM IP map](#csm-ip-map). |
| `antispam_learning` | Warning | One finding per learning readiness or removal problem. Core filtering is unaffected. See [Learning findings](#learning-findings). |
| `stalwart_spam_filter_off` | Warning | Stalwart's spam filter is off, so Stalwart scores no mail. See [CSM's address list on Stalwart](#csms-address-list-on-stalwart). |
| `stalwart_address_list` | Warning | CSM could not inspect or read its key file, read its rule or list, update the list, or have Stalwart load it. Run `csm stalwart setup` when the message says so. See [CSM's address list on Stalwart](#csms-address-list-on-stalwart). |
| `spam_evidence_evicted` | Warning | The spam evidence budget was reached and CSM dropped the weakest records. The message names the most crowded network and how many records it held. See [Spam evidence budget](#spam-evidence-budget). |

### While rspamd is down or scans fail

| Host | What happens to mail |
|---|---|
| cPanel | Mail is delivered without spam filtering. Exim adds no rejection for a scanner failure, and other mail checks keep running. |
| Postfix | Postfix's `milter_default_action` decides, see [Scan records](#scan-records). |

Disabling antispam clears the down and scan-error findings without a recovery notice. Preconditions or removal failures can still be reported.

### Dismissing and notifications

Dismissing a scan-error finding acknowledges the current episode. A successful scan clears that dismissal immediately, even between health probes. Disabling antispam or restarting CSM also resets it.

Undismissed scan errors keep the normal daily notification deduplication, so intermittent failures do not send one alert per message.

Rspamd outage and recovery notices do not consume the routine hourly alert budget. They honor notification suppressions and email check exclusions. Suppressed notices remain in history, the audit log and event streams.

### Scan records and scan health

Scan records in the Exim main log include the connecting sender's address as `ip=`. Scan health ignores records with a malformed non-empty address. Older records without that field, and records with an empty address, still count.

### Observe mode

In observe mode CSM changes no mail configuration. It only cancels changes still waiting to run. An installed integration is reported as `observe_mode`.

## rspamd timeouts

When a scan reaches rspamd's `task_timeout`, rspamd answers with the score it had so far. A slow rule that would have lowered the score is lost, so a timed-out scan can tag or reject mail a complete scan would pass.

Exim cannot tell the difference. rspamd's log records the timeout. If it shows timeouts, raise `task_timeout` or remove the slow rule.

## Tested versions

CSM is tested on cPanel 11.138 with cPanel's Exim 4.100.1:

- On AlmaLinux 8 with rspamd 4.2.1 and 4.2.2.
- On AlmaLinux 9 with rspamd 4.2.2.

CSM needs Exim 4.97 or later with content scanning and rspamd 3 or later.

## Details

The sections below are reference material for edge cases. You do not need them to run spam filtering.

### Resolver rules

These rules add to [DNS feeds need a local resolver](#dns-feeds-need-a-local-resolver).

#### The systemd-resolved stub

rspamd uses the systemd-resolved stub when its nameserver is 127.0.0.53 or 127.0.0.54 on port 53. CSM then asks systemd-resolved for every server it can forward to, and judges those. The list includes the fallback servers when no other server is configured.

If CSM cannot read that list, DNS feeds stay off with a warning. Other ports on the stub addresses count as separate local resolvers.

#### Resolver list prefixes

Resolver lists accept `master-slave:`, `round-robin:`, `random:`, and `hash:` prefixes without regard to case. Rspamd 4.2.2 does not support `sequential:`, and CSM leaves DNS feeds off for that setting.

#### Resolver warnings

A warning about an unreadable `/etc/resolv.conf` applies only when no explicit nameserver setting exists. Invalid explicit settings get their own warning.

### Log privacy for Spamhaus DQS

CSM enables `spamhaus_dqs` only when rspamd's log is private:

- The log and its directories must be owned by root or rspamd, with no extra ACLs or write access for other users.
- A private file or enclosing directory must restrict readers to root and rspamd, including group access.
- Symlinks and paths with dot components cannot establish privacy.
- CSM cannot verify syslog or console routing. Use `logging.type = file` with a private log.

CSM checks log privacy and the rspamd version again before it applies feeds.

### IP map writes and removal

These rules add to [CSM IP map](#csm-ip-map).

| Case | What CSM does |
|---|---|
| A write fails | Keeps the previous map, which rspamd keeps using. |
| The map is missing, or its file mode or rspamd's group changed | Writes the map again, even when its content is the same. |
| No installed rule reads the map | Deletes the map. A failed removal raises `antispam_apply_failed` and is retried on the next pass. |
| Removal failed and a later apply reuses the surviving map | Resumes monitoring the map and subtracts its score from new spam evidence. |

CSM forgets earlier probe failures when the map is removed, monitoring is disabled, observe mode is entered, or the scan socket changes.

Dismissing the `antispam_ip_map` warning acknowledges the current outage. Recovery clears the dismissal, so a later failure can notify again.

### What the feed probes cover

CSM probes only while antispam is enabled, observe mode is off, the installed integration is up to date and no installation condition is failing.

- It checks two test names per supported zone.
- It asks through rspamd's first nameserver, on the port rspamd uses, and looks up A records.
- It does not probe SEM's IPv6 zone or Spamhaus DBL and ZRD.

A healthy probe result does not establish the health of those zones or of other configured resolvers.

### How the spam evidence budget works

These rules add to [Spam evidence budget](#spam-evidence-budget).

#### Which records count

CSM counts the records at the verdict's observation time. A missing time uses the current time. Invalid addresses and ham from an untracked sender are ignored and do not trigger the budget.

Only records held for spam evidence alone count:

- Records with attack findings, a block or still-protected login evidence never count toward the budget and are never dropped for it.
- A record with a mail login attack counts only when that attack is more than 30 days old at the verdict's time and the record has no attack findings or block.

The count can exceed the budget in three ways:

- Startup loads unexpired evidence without trimming it to the budget. The count can stay over the budget until a verdict is recorded.
- The count grows as login evidence ages past 30 days.
- A delayed verdict counts records at its own earlier time. It can leave more than 50,000 countable records at the current time.

#### Which records are dropped first

Each record has a level: the weight its verdicts still have, rounded up to whole messages. The level is at least 2 once the record has two or more verdicts.

When a verdict is recorded and the count is over the budget, CSM drops records in this order until nine tenths of the budget remain:

1. Records of the lowest level go first.
2. Inside a level, records in the network that holds the most spam-only records go first. CSM counts networks per IPv6 /48 and per IPv4 /16 at the start of the pass.
3. When those counts tie, the record with the least weight goes first.

Higher levels are reached only after every lower-level record has been dropped. They can still be dropped when they alone exceed the trim target.

#### What a flood can remove

| Flood | Effect |
|---|---|
| Single messages from one network, one /48 or /16 | It loses its own records first, once that network holds more spam-only records than any other. |
| Single messages spread over many networks | It competes with the other records of the same level, whoever sent them. The most crowded networks go first, then the records with the least remaining weight when network counts tie. |
| Several messages from each address or /64 | It reaches the level that matches its message count and competes with every record of that level, listed senders included. |

A flood of single messages cannot remove a sender with two or more verdicts, a listed sender or a sender's ham history while records with two or more verdicts fill less than nine tenths of the budget. Above that, one pass trims the weakest of them once.

Senders that share a crowded /16 or /48 with a flood can lose records of the same level with it.

#### Budget warnings

CSM writes a warning to the daemon log at the first drop, then at most once per day of recorded verdict time while drops continue. It also queues the warning for alerts. A full queue can refuse it.

The warning gives the number of records dropped, names the most crowded network and says how many records that network held.

- The count in a later warning includes everything dropped since the previous one.
- Drops made after a warning are reported by the next warning. It comes with a later drop or with a deep scan, once a day has passed since the previous warning.
- A restart forgets drops not yet reported.

CSM removes evicted records from storage on the next successful flush. They can return after a crash before that flush.

The [API threat statistics](api.md) include the total dropped since the daemon started.

### Pending changes and retries

These rules add to [When CSM checks the integration](#when-csm-checks-the-integration).

- When another CSM change holds the lock, CSM tries again 20 seconds later.
- Before each check, CSM cancels antispam changes still waiting to run from an earlier check or an earlier daemon. It does this also while antispam is disabled or in observe mode.
- A change that is already running finishes first.

If cancelling fails, CSM raises a warning and retries. It retries after 20 seconds while antispam is enabled, and at the next regular check while it is disabled.

### Restore rules on Postfix

These rules add to [Replaced files](#replaced-files). They apply when CSM puts a copy back on a Postfix host.

- Restores require root-owned backups with mode 0600 in a root-only directory.
- A symlink, unsafe backup or unsafe destination permissions stop the transaction before mail configuration changes. Correct the permissions and retry.
- If a backup changes before completion, CSM rolls back and keeps that edit.
- Restores and their rollbacks never follow directory symlinks.

A restored file gets the owner and mode checked before the restore, which after a takeover are your original ones.

`/etc/rspamd/override.d/rbl.conf` written while a DQS key is set is the exception. CSM's file is owned by root, in rspamd's group, with mode 0640, and the restored file keeps that.

### Who may own the Redis socket

These rules add to [Redis for fuzzy storage](#redis-for-fuzzy-storage).

- A cPanel account record with no system user, such as cPanel's own `system` record, does not count as an account sharing the Redis owner when `/etc/passwd` does not list it either.
- If `/etc/passwd` cannot be read in full, or an account lookup fails for another reason, CSM does not trust a non-root Redis owner.
- On Postfix these account read failures pause learning and retain its installed configuration.
- CSM checks Dovecot mail owners again before it uses a dedicated Redis, including the owners of skipped mailboxes.

### How the learner stops

Disabling learning or entering observe mode stops native learning calls before configuration reconciliation. Calls already in flight are canceled and drained within their deadlines.

Reconciliation pauses the learner until a completed pass confirms that learning can resume.

### How failed reports are counted

These rules add to [Reports that fail](#reports-that-fail).

Reports stay pending while rspamd's fuzzy storage answers no lookup, however long that lasts. A failure counts against a message in these cases:

- Storage answered a lookup for another report earlier in the same pass.
- rspamd cannot process the message.
- The learner returns an error CSM cannot classify.

Such a message does not stop other accounts' reports.

When rspamd answers a message's inspection with an error, CSM inspects a fixed test message:

| Result for the test message | What CSM does |
|---|---|
| Storage answers it | The failure counts against the message, and the pass goes on with the next report. |
| Storage does not answer it | Submissions stop and the report stays pending without a counted failure, even if storage answered earlier in the pass. |

These never count as failures:

- Canceled or expired passes.
- Reconciliation pauses.
- Unsent controller requests.
- A wrong controller peer.
- Local state failures.

Unreadable learning state holds reports even when the learner cannot finish startup. The reports resume once the state is available.
