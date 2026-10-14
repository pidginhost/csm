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

All five are hot-reloadable: after antispam starts, `systemctl reload csm` or a
Settings save updates health tracking and requests a reconcile pass before
forward-guard reconciliation. Settings saved before antispam starts are picked
up when it initializes, after the startup forward-guard reconciliation.
`enabled: true` is refused in [observe mode](observe-mode.md).

`rspamd_socket` is not the `reputation.rspamd` controller URL. That optional
setting reads rspamd's scan history for IP reputation and is unrelated to
filtering.

The capabilities API lists `mail.antispam.v1` when a build supports this
integration; it does not mean filtering is installed on the host.

## What CSM writes

- three Exim ACL hooks under `/usr/local/cpanel/etc/exim/acls`
  (`custom_begin_spam_scan_check`, `custom_begin_spam_scan` and
  `custom_begin_check_message_post`), inside `# CSM-ANTISPAM BEGIN` and
  `# CSM-ANTISPAM END` markers;
- one `spamd_address` line in the `@CONFIG@` section of `/etc/exim.conf.local`;
- `actions.conf`, `greylist.conf`, `rbl.conf`, `emails.conf`, `asn.conf` and
  `fuzzy_check.conf` in `/etc/rspamd/local.d`, each starting with
  `# csm-managed-version: 1`. Greylisting, DNS block lists, the emails module,
  sender-IP lookups to rspamd.com and public fuzzy storage are off;
- a completion record in `/var/lib/csm/antispam`.

Content outside CSM's markers, including forward-guard blocks, is preserved.
CSM regenerates its own blocks and files, so manual edits to them are
overwritten. A file of the same name without CSM's header blocks the install;
removal leaves it alone.

Each change runs as one transaction in a short-lived root helper started by
systemd outside CSM's sandbox, under the same lock as the forward guard. It
rebuilds the Exim configuration, checks it, reloads Exim and rspamd only when
needed, and restores the previous state if a step fails. If `systemd-run` is
not available, CSM changes nothing.

CSM checks the integration at startup, after each config reload and every 15
minutes, and repairs drift, such as a cPanel rebuild that dropped the hooks.
When another CSM change holds the lock, it tries again 20 seconds later.

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
| `antispam_apply_failed` | Warning, or Critical when the previous state could not be confirmed | An install, update or removal failed at the named step. |
| `antispam_rspamd_down` | Warning | Three probes of the scan socket in a row failed. CSM probes every 20 seconds while antispam is enabled. |
| `antispam_rspamd_recovered` | Warning | Two probes in a row succeeded after an outage. |
| `antispam_scan_error` | Warning | Exim logged a failed scan. One finding covers every failure until a scan succeeds. |

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

In observe mode CSM reports and changes nothing; an installed integration is
reported as `observe_mode`.

## rspamd timeouts

When a scan reaches rspamd's `task_timeout`, rspamd answers with the score it
had so far. A slow rule that would have lowered the score is lost, so a
timed-out scan can tag or reject mail a complete scan would pass. Exim cannot
tell the difference; rspamd's log records the timeout. If it shows timeouts,
raise `task_timeout` or remove the slow rule.

## Tested versions

cPanel 11.138 with cPanel's Exim 4.100.1 and rspamd 4.2.1. CSM needs Exim 4.97
or later with content scanning and rspamd 3 or later.
