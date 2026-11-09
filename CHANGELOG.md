# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 4.10.0 are archived: [4.0 to 4.9](docs/changelog/4.0-4.9.md), [3.40 to 3.43](docs/changelog/3.40-3.43.md), [3.30 to 3.39](docs/changelog/3.30-3.39.md), [3.20 to 3.29](docs/changelog/3.20-3.29.md), [3.10 to 3.19](docs/changelog/3.10-3.19.md), [3.0 to 3.9](docs/changelog/3.0-3.9.md), [2.x](docs/changelog/2.x.md).

## [Unreleased]

### Added

- Admission refusal summaries in the action log name why an address was not attributed: no observation, unaccepted kind or target mismatch.

### Changed

- Automatic response forecasts reject unverified PHP relay addresses and stop trusting evidence after its allowed address sources change.
- Automatic response previews reject subnet targets from checks that only attribute individual addresses, including previously queued responses.

### Security

- Mail that crashes, exhausts or stalls the attachment unpacker is now deferred instead of delivered unscanned, even with `email_av.fail_mode: open`; observe mode still delivers it.
- A remote sender can no longer get a hosted mailbox reported as compromised through the wording of an email subject.

### Fixed

- Framework classes that handle admin uploads no longer raise Critical dropper alerts.
- The webserver integration installs with a loopback challenge listener behind your own proxy when `challenge.trusted_proxies` lists the listener's address.
- `csm doctor challenge` no longer fails the gate check, or asks for listener TLS and the port gate, when the listener sits behind `challenge.trusted_proxies`.
- Re-running `csm enable --php-shield` or `csm install --php-shield` keeps your edited PHP Shield config; update its allowed IPs by hand after changing `infra_ips`.
- Phishing sent from hosted accounts is now reported, stays open while still queued, and can be quarantined from its finding.

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
