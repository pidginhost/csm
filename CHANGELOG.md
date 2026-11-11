# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 4.10.0 are archived: [4.0 to 4.9](docs/changelog/4.0-4.9.md), [3.40 to 3.43](docs/changelog/3.40-3.43.md), [3.30 to 3.39](docs/changelog/3.30-3.39.md), [3.20 to 3.29](docs/changelog/3.20-3.29.md), [3.10 to 3.19](docs/changelog/3.10-3.19.md), [3.0 to 3.9](docs/changelog/3.0-3.9.md), [2.x](docs/changelog/2.x.md).

## [Unreleased]

### Security

- A dismissed malware finding now alerts again when the file's content changes.
- Dismissing a finding whose file changed since the page loaded is refused, so the new content gets reviewed first.
- CSM is now built with Go 1.27.4, which fixes a crash in HTTP servers that limit request body size.
- Realtime WHM login alerts and the tokenless WHM request alert for CVE-2026-41940 now fire on the lines cPanel writes to its own access log.
- A user name containing a quote can no longer hide a cPanel or WHM request from realtime alerts.
- Alerts for requests through cPanel service subdomains no longer block, score or exempt the client address cPanel logged, which is unverified.
- `.htaccess` checks now report suspicious handler extensions listed after a `#` on the same line, which Apache still applies.
- A file CSM quarantined or cleaned now alerts again when it comes back, instead of being held back as a repeat.
- CSM now raises a Critical alert when a process writes back a file CSM quarantined or cleaned, and repeats that response.
- With process killing on, CSM now stops a process that writes back a file it removed, when a web request started it or it runs detached.

### Changed

- Automatic response forecasts refuse web findings when Apache, nginx or LiteSpeed rewrites logged client addresses or CSM cannot read that setting, and `csm doctor` reports it.

### Fixed

- On nginx hosts, `web_server.config_dir` now also sets where CSM reads the nginx configuration, as documented.
- cPanel, WHM and webmail access alerts no longer fire on text in referers or user agents, and webmail alerts count only login attempts.
- The web server hardening audit reads Apache continuations, section comments and include names correctly, and warns when its configuration cannot be read completely.
- Outbound mail from Stalwart's service account, or from users listed in `firewall.smtp_allow_users`, no longer raises a High direct SMTP egress finding.
- BPF enforcement no longer blocks outbound mail from users listed in `firewall.smtp_allow_users`.
- Restoring a mail message quarantined from a phishing finding now returns the whole message to the mail queue instead of failing, and a failed restore can be retried.

## [4.11.0] - 2026-11-10

### Highlights

- Security fixes harden CMS database scans, PHP webshell and phishing detection, mail checks, unban requests and challenge admin sessions.
- `trusted_proxies` entries that cover every address or an address of this host are no longer trusted; `csm validate` and `csm doctor` warn about them.
- PrestaShop shops are now scanned for injected script and new or promoted SuperAdmins.
- A finding cleared by Fix, Re-check or a rule update now alerts again if the same detection returns.
- Mail that crashes or stalls the attachment unpacker is now deferred instead of delivered unscanned, even with `email_av.fail_mode: open`.
- Automatic response forecasts refuse HTTP, cPanel and IP reputation findings from known CDN and website firewall edges.
- `csm scan --full` with `--wait` or `--report` exits with status 3 when a scan did not cover everything.

### Security

- With `web_server.trusted_proxies` or `challenge.trusted_proxies` set, HTTP checks no longer count requests against a trusted proxy whose forwarded header is missing or unreadable, and read past further trusted proxies in it.
- A `web_server.trusted_proxies` or `challenge.trusted_proxies` entry covering every address is no longer trusted: visitors cannot forge their address through it, and forwarded requests count against nobody.
- Addresses of this host in `challenge.trusted_proxies` are no longer trusted, so local accounts cannot pose as visitors; the challenge page refuses requests through them, so use the challenge socket.
- Joomla, Drupal, Magento and OpenCart re-checks look at every site on the account with its own database login, so a clean main site no longer clears another site's finding.
- Joomla, Drupal, Magento and OpenCart database scans and re-checks now catch script tags split by a tab or line break in the stored value.
- Joomla, Drupal, Magento and OpenCart scans keep checking the remaining tables when one table returns too many rows, so a flood of rows no longer hides an injection.
- A finding cleared by Fix, a performance fix, Re-check or a rule update now alerts again if the same detection returns.
- PHP and phishing checks now read `${'_POST'}` and `$GLOBALS['_POST']` as request input, so these spellings no longer hide a webshell or phishing kit.
- `challenge.verified_session` no longer issues admin sessions to this server's own addresses, so local accounts cannot guess `admin_secret` from loopback.
- Mail that crashes, exhausts or stalls the attachment unpacker is now deferred instead of delivered unscanned, even with `email_av.fail_mode: open`; observe mode still delivers it.
- A remote sender can no longer get a hosted mailbox reported as compromised through the wording of an email subject.
- The per-account PHP mail volume alert now counts each account's real outbound mail, and an email's subject or sender can no longer raise it.
- A crafted Message-ID can no longer hide or invent recipients in the stolen-mailbox and PHP mail volume checks.
- An unban request for one address no longer lifts a subnet block an operator added, and says when the address stays blocked or a subnet cannot be removed.

### Added

- PrestaShop shops are now scanned for injected script in settings, pages, products and categories, new back-office employees and new or promoted SuperAdmins (Critical); turn off with `disabled_checks: [db_content_prestashop]`.
- The challenge server can listen on a Unix socket that only your proxy's group can open, for a proxy on the same host.
- Admission refusal summaries explain missing address attribution, clients behind a trusted proxy and later refusals of queued responses, including disabled responses and lost queue positions.

### Changed

- HTTP checks and the challenge server now trust proxies listed in either `web_server.trusted_proxies` or `challenge.trusted_proxies`, and the challenge server refuses overlong forwarded chains.
- `csm validate` and `csm doctor` now warn about empty, unreadable or catch-all `trusted_proxies` entries, which CSM skips, and Settings refuses to save them.
- An address of this host listed in `web_server.trusted_proxies` is no longer trusted, so requests through a local proxy count against nobody; `csm validate` warns about such entries.
- `csm scan --full` now scans images last, and `--wait` and `--report` exit with status 3 when a scan did not cover everything, including skipped oversize files.
- New hosts set up with `csm install` now start from the packaged config, so they filter IPv6 and match the package's alert and detection settings.
- Automatic response forecasts refuse HTTP, cPanel and IP reputation findings from known CDN and website firewall edges, including networks in `thresholds.http_asn_crawl_reverse_proxy_asns` when the ASN database is loaded.
- Automatic response forecasts now include scheduled security scans, Exim history, IP reputation findings with recent local sightings and SMTP password sprays seen in a Postfix mail log.
- Automatic response forecasts reject unverified PHP relay addresses and never read a trusted proxy as the client; previews reject subnet targets from checks that only attribute single addresses.

### Fixed

#### Scanning

- Joomla, Drupal, Magento and OpenCart scans skip suspended accounts, so their checks complete again and earlier findings for those accounts clear on the next scan.
- JavaScript served through PHP no longer raises a Critical WSO or FilesMan webshell alert because a variable name contains "filesMan".
- Goto-obfuscated PHP, the shape licence-protected commercial modules also ship, is now reported for review instead of quarantined the moment it is written.
- Framework classes that handle admin uploads no longer raise Critical dropper alerts.
- JavaScript scans with widespread analysis failures use less memory, report truncated coverage details, and keep earlier detections visible.
- Realtime scanning skips files CSM already moved to quarantine, so a quarantine no longer logs a refused response or counts twice against the automatic response limit.

#### Mail

- Phishing sent from hosted accounts is now reported, stays open while still queued, and can be quarantined from its finding.

#### Blocking and challenges

- Realtime web, ModSecurity and cPanel API checks and the ModSecurity audit scan no longer block, score or report configured trusted proxies; informational events stay visible.
- Dry run no longer removes automatic subnet blocks from the firewall when the daemon starts.
- Scan findings no longer produce duplicate termination attempts or action log entries, including when termination fails or is refused.
- Incident correlation now follows `reputation.whitelist` changes on reload, and matches IPv6 entries however the address is written.
- Addresses the firewall never blocks, such as `firewall.infra_ips` entries and infra hostnames, are no longer sent to the challenge page.
- `csm doctor challenge` no longer fails the gate check, or asks for listener TLS and the port gate, behind a remote trusted proxy or the challenge socket.

#### PHP Shield

- PHP Shield no longer logs an `open_basedir` warning on every request to sites whose PHP pool cannot see the account's home folder.
- Re-running `csm enable --php-shield` or `csm install --php-shield` keeps your edited PHP Shield config; update its allowed IPs by hand after changing `infra_ips`.

#### Install and system

- Audit rules now load in full on servers without cPanel, so cron, account, temporary-folder execution and CSM tamper watches work there.
- Log rotation no longer skips CSM's own logs on servers installed from the package.

## [4.10.2] - 2026-11-08

### Highlights

- Crafted mail logins, FTP logins and web requests can no longer get unrelated addresses blocked.
- Scheduled scans see ModSecurity denials only in error logs CSM knows; list custom error logs in `modsec_error_log` or `web_server.error_logs`.
- `challenge.trusted_proxies` now accepts CIDR ranges, and visitors behind trusted proxies can no longer obtain challenge passes for other addresses.
- Ordinary server errors no longer appear as ModSecurity attacks or trigger false blocks.
- The malware scanning engine moves to YARA-X 1.23.0; shipped rules compile and match as before.

### Security

- An attacker can no longer get an unrelated address blocked, or exempt its own address from reputation blocks, through crafted mail login attempts.
- An attacker can no longer get an unrelated address blocked, or shown as the attacker in the Web UI, through crafted web requests that ModSecurity denies.
- An attacker can no longer get an unrelated address blocked through crafted FTP login attempts.
- Visitors behind trusted proxies can no longer obtain challenge passes for unrelated addresses or shared proxies.
- Crafted web requests can no longer hide ModSecurity denials from scheduled error-log scans; list custom error logs in `modsec_error_log` or `web_server.error_logs`.
- A hosted site can no longer get its visitors blocked by writing fake ModSecurity messages to the server logs.

### Changed

- The malware scanning engine moves to YARA-X 1.23.0, which fixes crashes on some third-party rules; shipped rules compile and match as before.
- Go dependencies are updated to their current releases.

### Fixed

#### ModSecurity and challenges

- `challenge.trusted_proxies` now accepts CIDR ranges, as documented.
- ModSecurity detections now name an IPv6 client by its own address on Apache and Nginx hosts.
- Ordinary server errors no longer appear as ModSecurity attacks or trigger false blocks.

#### Blocking and alerts

- Admission status lifetime counts now include responses refused or dropped before they reached the queue.
- Known-customer block emails no longer list a compromised mail or FTP login that caused the block, even when the block comes later.
- The known-customer block email now says that allowing an address trusts it on every port.
- A file quarantined by realtime protection no longer raises a second Critical self-deleting dropper alert.

#### Web UI and configuration

- The Performance page shows n/a for Redis when CSM cannot read it, and the API and MCP tool return null instead of zero.
- Reloading CSM no longer causes a false tamper alert after a config edit that changes no setting, or after a reload that fails partway.
- A config reload during a Web UI settings save no longer overwrites the saved settings.

## [4.10.1] - 2026-11-07

### Security

- PHP relay detection now counts form mail arriving through Amazon CloudFront, Fastly and BunnyCDN by default.

## [4.10.0] - 2026-11-07

### Highlights

- Alert email and the alert webhook now send each finding once, and attacks CSM already handled move to one daily summary that replaces the hourly block digest email.
- An automatic block that hits an address with a recent customer login now alerts at once, so you can release a real customer.
- The setting that hid alerts for blocked addresses is removed and ignored; `csm doctor` warns until you delete it from the config.
- Mail login spray detection for SMTP, IMAP and POP only reports until you switch on blocking.
- Detection of bots abusing website forms only reports until you switch on challenges.
- The firewall now drops incoming IPv4 TCP packets that carry IP options, which blocks the CVE-2026-98432 attack on unpatched kernels.

### Security

- The firewall now drops incoming IPv4 TCP packets that carry IP options, which blocks the CVE-2026-98432 attack on unpatched kernels.
- FTP log text crafted to look like a successful login no longer counts as one.
- PHP relay detection no longer lets forged forwarding headers split one script's mail history or trigger false multi-script abuse alerts.
- PHP relay detection now attributes mail to the server-observed address when the mail header lists more than one address.
- Mail login tracking no longer attributes incomplete or ambiguous log identities to a mailbox.
- Successful mail logins no longer excuse earlier attacks against other mailboxes or downgrade their compromise alerts.
- Mail subjects or greetings made to look like failed logins or rejected recipients no longer block a sending server, raise alerts or count as failed logins.
- Repeated logins with a cracked mail password no longer restore trust or exempt later password guessing from blocking.
- IMAP or POP logins during a mail backend outage no longer earn the standing that keeps an address from brute-force blocking.

### Added

- SMTP, IMAP and POP login protection catches slow password sprays across many sources and days, including logins to missing mailboxes, and forgives mistyped addresses; it only reports until switched on.
- Mail login sprayers stay blocked longer and are blocked again on return; customer unbans keep failure history, while operator releases and flushes clear it.
- CSM now alerts at once when an automatic block hits an address with a recent customer login, and one stale mail password no longer raises compromise alerts.
- CSM now reports bots that abuse website forms to mail strangers and names the form to fix; once switched on, it also challenges them.
- Support agents can read status, findings, mail, firewall and WAF data over a read-only MCP endpoint, off by default, that uses its own tokens on the Web UI port.
- Findings now warn when spam source reports wait because the list of shared mail services cannot be refreshed.

### Changed

- Alert email and the alert webhook now send each finding once, and attacks CSM already handled arrive in one daily summary that also replaces the hourly block digest email.
- The setting that hid alerts for blocked addresses is removed and ignored; doctor warns until you delete it from the config.
- CSM now starts when email and webhook alerts are both off; findings then show only in the Web UI and API.
- Forged mail that fails the sender domain's DMARC reject policy now lands in the Spam folder more often.
- Dry-run forecasts show new attacks rotating out older equal-priority blocks, and status and diagnostics show rotations, waits and scope shares.
- Admission previews and dry-run forecasts cap block lifetimes at the configured expiry, or at a replaced forecast block's end for returning addresses, and settings help states shipped limits.
- When spam learning stops because its records disagree with its storage, the CSM log now says what disagreed.

### Fixed

#### Email and antispam

- Legitimate bulk and transactional mail is less likely to be marked as spam when listed on URIBL's grey list.
- Antispam no longer overrides spam weights you set yourself in rspamd.
- Spam learning no longer stops for every report when rspamd hashes one learned message differently; only that message's learning is dropped.
- Mail from large shared services such as Gmail no longer crowds other senders out of spam source detection on busy hosts.

#### PHP relay detection

- PHP relay detection keeps its proxy exemptions when a policy file update is invalid.
- PHP relay detection now skips visitors arriving through Cloudflare and known payment services even when no policy file is installed.

#### Automatic response

- Admission previews and dry-run forecasts no longer start a new attack episode early when the system clock jumps forward.

#### Tools and CLI

- Doctor no longer reports CSM's own scan workers as CloudLinux cages missing the PHP Shield event mount.

[4.10.2]: https://github.com/pidginhost/csm/compare/v4.10.1...v4.10.2
[4.10.1]: https://github.com/pidginhost/csm/compare/v4.10.0...v4.10.1
[4.10.0]: https://github.com/pidginhost/csm/compare/v4.9.0...v4.10.0
