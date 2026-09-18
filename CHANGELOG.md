# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 3.40.0 are archived: [3.30 to 3.39](docs/changelog/3.30-3.39.md), [3.20 to 3.29](docs/changelog/3.20-3.29.md), [3.10 to 3.19](docs/changelog/3.10-3.19.md), [3.0 to 3.9](docs/changelog/3.0-3.9.md), [2.x](docs/changelog/2.x.md).

## [Unreleased]

### Security

- Re-checking a finding no longer lowers its severity when the replacement file hides active content behind a malformed PHP opening tag or a PHP 8 attribute.
- Subnet blocking now catches ranges that rotate through addresses one block at a time. Addresses blocked in the last seven days count toward the threshold, including operator and permanent blocks, and the window is adjustable.
- Executable PHP can no longer pass as a comment-only stub and suppress a warning in sensitive WordPress directories.
- A file staged in a WordPress core, plugin or theme update that held other content before it was overwritten and then moved into place or deleted beside an identical installed copy is reported again as a self-deleting file, instead of passing as update cleanup.
- A PHP file could hide code behind a comment ended by a bare carriage return, or print its whole content as page text through a malformed opening tag, and still pass as an empty stub, a translation cache or version data. That skipped the location warning for PHP in uploads and other sensitive WordPress directories.

### Fixed

- The WordPress REST API exploit rule no longer fires High on security and analytics plugins that only mention the users endpoint in comments, settings or translations. It now requires a request to the endpoint that carries a password, which also catches account takeover code the old rule missed.
- The threat detail page labels the routed range an address belongs to as its GeoIP prefix, so it no longer reads as if the whole range were listed or blocked.
- A WordPress core update no longer raises a warning for the version file it copies into the upgrade directory. The file is recognised by content and holds only version data.
- A WordPress core update no longer raises a self-deleting file notice for the release files it unpacks but does not install, such as bundled themes. Each file must match the official checksum of the release now installed.

## [3.40.0] - 2026-09-18

### Highlights

- A backdoor hidden inside a working image file is now detected, together with the one line of PHP that loads it. Found from a live compromise where a picture carried a backdoor for two months without any check looking at it.
- Alert email drops sharply. Attacks whose source is already blocked or challenged, scanner probes answered by a verified front controller, successful FTP logins, and repeated scan-coverage warnings no longer reach the inbox. They all stay on the findings page.
- WordPress update activity no longer raises critical self-deleting file alerts: translations, the core version probe and plugin self-test files are recognised by content, not by path.
- A 24 hour block from the web interface no longer marks an address as malicious forever. A separate Block permanently action does that deliberately. Records created before this release are left as they are.
- Upgrade note: two login checks merge. `ftp_login_realtime` becomes `ftp_login` and `ssh_login_realtime` becomes `ssh_login_unknown_ip`. Old names in email exclusions and saved mutes keep working, so update them when convenient.
- The state database stopped growing from records that pruning skipped whenever the same write also pruned.

### Security

- Distinct FTP and SSH sessions no longer share an alert identity when log details are shortened. Queued SSH blocks also survive upgrades that merge login check names.
- Dismissing a scan coverage warning no longer hides it for good: it can alert again once the condition clears and returns. New analyzer failures stay visible, and account scan crashes keep separate alert histories for each account.
- Timed blocks in the web interface no longer shorten existing permanent or longer blocks. Undo respects later operator decisions.
- Image payload detection now covers more file layouts and avoids missed writes during recovery. Payload details no longer cause excessive processing on repetitive files.
- Executable code hidden inside a working image file is now detected. Image writes under hosted document roots were never inspected in real time and no rule looked past a file's name, so a picture could carry a backdoor indefinitely.
- A PHP file that pulls in an image, an archive or another non-executable file while reading request input is now reported, together with the file it pulls in. That one line is the loader half of the technique above and was previously indistinguishable from ordinary templating.
- A self-deleting file in WordPress update staging can no longer escape its alert by breaking the location where an installed copy of it would be looked for.
- Translation files with concealed executable content no longer qualify as harmless data.

### Added

- The Threat Intel page can now block an address permanently, on its own or over a selection, as a separate confirmed action next to the 24 hour block.

### Fixed

#### Alerts and email

- Existing login email exclusions and saved mutes survive the merged check names. Successful FTP logins and File Manager writes remain available to phpanel and event-stream consumers without sending operator notifications.
- A successful FTP login and a cPanel File Manager write are no longer emailed, and one FTP or SSH login is now reported once instead of twice by the realtime watcher and the periodic check. They stay on the findings page, in history and in correlation, and failed authentication, brute force and a login from a brute-force source still alert.
- A critical finding no longer carries the warnings batched with it past the hourly alert limit. Only delivered non-critical alerts count against that limit.
- Suppressing alerts for blocked addresses now also covers brute force, scanner and other attack alerts whose source was blocked or challenged, not only reputation alerts. Compromise evidence, successful logins, suspicious mail and attacks spread across many addresses still alert.
- Scan coverage warnings and check crash alerts no longer send a new email on every scan cycle when only their counts or crash details change; an ongoing condition now follows the normal daily reminder.
- Re-uploading the same identified WordPress plugin or theme release that cannot be checked against wordpress.org follows the normal daily reminder. A different version or site, or a package that cannot be fully identified, still alerts, and content findings remain separate.
- OWASP CRS attack rules logged by LiteSpeed are now recognised as attacks instead of unclassified, and an unclassified ModSecurity rule is reported once per day for the host instead of once for every source address.

#### Firewall and blocking

- Unblocking an IPv4-mapped address now clears the same temporary evidence as its IPv4 form.
- Manual block evidence survives threat-feed changes and migration, and bulk undo restores each address's prior block lifetime without reviving expired evidence. Duplicate selections no longer leave block records behind after undo.
- A 24 hour manual block from the web interface no longer marks the address as malicious forever. The threat record now expires with the firewall block, so a mistaken block of a customer address stops re-blocking it a day later. Blocks recorded before this release are left as they are, and the IP lookup now explains when an address is no longer blocked but still carries a permanent threat record.
- WAF attacker reports for link-local addresses no longer advise a block the firewall refuses, and subnet blocks rejected by safety guards are logged as refused rather than failed.

#### Detection

- PHP Shield no longer reports a webshell command parameter when a scanner probes a missing script and the site's verified, unmodified front controller answers instead. Modified or unverified scripts still alert, and quieted probes stay in the local event archive.
- WordPress translation and core updates no longer raise critical self-deleting file alerts when the updater copies a staged file into place and removes the original, including when file events arrive out of order. Only complete translation or version data qualifies, and a file removed from the same staging paths without an identical installed copy is still reported.
- Really Simple Security upload execution probes no longer raise critical self-deleting file alerts, including when file events arrive out of order or combined. Other content under the same name is still reported.
- A WordPress core update that stops after reading its new version file no longer raises a critical self-deleting file alert when that file matches the official release it names, while an unverified file is still reported. Checksum lookups are bounded, and a file changed while being read stays reported.
- Image and loader checks no longer mistake ordinary description text or plain-text partials for backdoors.

#### State and storage

- Pruning old firewall action records and daily finding totals now removes every expired entry. Some were skipped and left behind, so the state database kept growing.
- Restart advice now reflects reclaimable space in the state database, so a large file that is still mostly in use no longer triggers it.

#### Health and diagnostics

- `csm doctor` and the components view now keep reporting the YARA-X scanning worker as failed while it keeps crashing after restarts, instead of only when it cannot start at all. A restarted worker counts as recovered once it stays up for 30 seconds.
- The YARA-X worker crash alert now reports the current scanning outage without claiming recovery. It distinguishes scanning becoming available after a restart from worker health recovering after the replacement stays up for 30 seconds.

[Unreleased]: https://github.com/pidginhost/csm/compare/v3.40.0...HEAD
[3.40.0]: https://github.com/pidginhost/csm/compare/v3.39.0...v3.40.0
