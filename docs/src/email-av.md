# Email AV

CSM scans email attachments in real-time using ClamAV and YARA-X on the Exim mail spool.

## How It Works

1. **fanotify** watches the Exim spool directory for new messages, including every `split_spool_directory` hash subdirectory (the cPanel default layout); hash directories Exim creates later are picked up within a minute
2. Attachments are extracted and scanned by ClamAV (socket) and YARA-X (if available)
   Base64 and quoted-printable decoding tolerates stray characters, missing padding and malformed escapes. Encoded multipart bodies are decoded at every level. Ambiguous base64 is scanned under quartet and alphabet-only interpretations, and a valid padded prefix is scanned separately when data follows it. At most 16 additional interpretations are scanned per message. If decoding or multipart parsing reports an error, recovered content and later attachments are still scanned and the message is reported as incompletely scanned. Extraction size and MIME nesting limits still apply
3. Zip and tar.gz attachments are unpacked within configured size and file limits
4. Attachments are unpacked in a separate locked-down process with no network access, one per concurrent scan (`scan_concurrency`), started on first use. Extracted parts reach the scanners in memory and are never written to disk; each scan holds at most `max_extraction_size` of them. A process that times out, runs out of memory, crashes or sends an invalid reply makes the message an incomplete scan, which follows `fail_mode`
5. Attachment names written to logs and the UI use sanitized, shortened base names. Archive detection uses the full name, so shortening a displayed name does not prevent unpacking
6. Infected messages are quarantined with full metadata
7. Sender, recipient, and message ID are logged

Quarantine and release preserve each queue file's ownership, permissions, and
modification time, including when the move crosses filesystems. Release returns
the message to the queue directory it came from, including the hash directory
Exim uses when `split_spool_directory` is on.

Release accepts the flat queue root or the message's hash directory, named for
the sixth character in both 16- and 23-character Exim IDs. Other subdirectories
and hash-directory symlinks outside the trusted queue roots are rejected.

Quarantine persists recovery metadata before moving spool files and syncs file
contents and directory changes. A failed rollback retains the remaining
quarantine files. Release restores the body before publishing the queue header;
storage failures retain metadata and report the affected paths. Inspect both the
spool and quarantine locations before retrying a partially completed operation.

## Web UI

The **Email** page (`/email`) shows:
- AV watcher status (active, engine health)
- Scan statistics (scanned, infected, quarantined)
- Quarantined email list with release/delete actions

## API Endpoints

```
GET  /api/v1/email/stats         Scan statistics
GET  /api/v1/email/quarantine    Quarantined email list
GET  /api/v1/email/av/status     AV watcher status
POST /api/v1/email/quarantine/   Release or delete quarantined email
```

## Related Checks

- `email_content` - scans outbound email body for credentials and suspicious URLs; every base64 body and part, attachments included, is decoded with the same tolerance as attachment scanning, using live MIME headers and the declared multipart boundaries
- `email_weak_password` - detects email accounts with weak passwords
- `email_forwarder_audit` - audits forwarders for exfiltration redirects
- `mail_queue` - alerts on queue buildup (spam outbreak indicator)
- `mail_per_account` - per-account sending volume spikes

## Email password audit

The deep scan checks mailbox passwords against account-derived candidates and the
bundled weak-password list. Verification runs inside CSM; passwords and stored
hashes are never passed to subprocesses or included in findings. Confirmed matches
can still use the HIBP range API for breach counts, sending only a SHA1 prefix.

Supported stored formats follow [Dovecot password schemes](https://doc.dovecot.org/2.3/configuration_manual/authentication/password_schemes/):

| Scheme | Accepted format and audit limit |
| --- | --- |
| CRYPT, SHA512-CRYPT, SHA256-CRYPT | SHA crypt with a nonempty salt of up to 16 characters; 1,000 to 1,000,000 rounds, or the standard 5,000 when omitted |
| CRYPT, MD5-CRYPT | MD5 crypt with a nonempty salt of up to 8 characters |
| CRYPT, BLF-CRYPT | bcrypt 2a, 2b, or 2y; cost 4 through 14 |
| ARGON2I, ARGON2ID | Version 19; at most 64 MiB memory, 4 passes, and 4 lanes; salt 8 to 64 bytes, digest 16 to 64 bytes |
| PLAIN | Plaintext |
| PLAIN-MD5, LDAP-MD5, SMD5 | MD5 digests; salted variants allow 1 to 64 salt bytes |
| SHA, SHA1, SSHA, SHA256, SSHA256, SHA512, SSHA512 | SHA digests; salted variants allow 1 to 64 salt bytes |

Unprefixed hashes use CRYPT. cPanel shadow files, which add password aging
fields after the hash, are read the same way. Scheme names and `.hex`, `.b64`, and `.base64`
encoding suffixes are case-insensitive. Unsalted digests also accept Dovecot's
hex/base64 autodetection. DES crypt, bcrypt 2x, yescrypt, PBKDF2, and
mechanism-specific formats such as SCRAM are not audited.

Stored values are limited to 4 KiB and candidates to 256 bytes without embedded
NULs. At most three hash calculations run concurrently. Cancellation returns
promptly; a calculation already running keeps its worker slot until its bounded
work finishes.

An unsupported, malformed, or over-budget hash produces
`email_password_audit_incomplete`. CSM keeps earlier password findings and does
not record that mailbox as successfully audited. Other mailboxes continue to be
checked. When these are the only failures, the audit waits for
`password_check_interval_min` before trying again; temporary verification failures
remain eligible for retry on the next deep scan. Cycles skipped by the interval
preserve both earlier password findings and the audit warning. A completed audit
replaces them with its current results. Upgrading
starts a fresh audit even when an older CSM version recorded the same hash.
