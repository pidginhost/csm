# Email AV

CSM scans email attachments in real time using ClamAV and YARA-X on the Exim mail spool. An infected message raises a Critical finding and can be quarantined instead of delivered. Email AV is off by default.

## Turning it on

1. Set `email_av.enabled: true`. The other `email_av` keys are listed in [Configuration](configuration.md).
2. Set `quarantine_infected: true` if infected messages should be quarantined. Without it, CSM reports the infection and leaves the message in the queue.
3. Open the Email page in the Web UI and check the AV watcher status.

## How It Works

1. fanotify watches the Exim spool directory for new messages.
2. CSM extracts the attachments. ClamAV (socket) and YARA-X (if available) scan them.
3. Zip and tar.gz attachments are unpacked within configured size and file limits.
4. Infected messages raise a Critical finding. With `quarantine_infected: true`, CSM attempts to quarantine the queue files with their metadata. If the delivery hold expires first, a recipient may already have a copy.
5. Sender, recipient, and message ID are logged.

### Spool watching

The watch includes every `split_spool_directory` hash subdirectory, which is the cPanel default layout. Hash directories Exim creates later are picked up within a minute.

### The unpack process

Attachments are unpacked in a separate locked-down process with no network access. There is one process per concurrent scan (`scan_concurrency`), started on first use. [Parse worker units](service-confinement.md#parse-worker-units) describes how it is confined.

Extracted parts reach the scanners in memory and are never written to disk. Each scan holds at most `max_extraction_size` of them.

### Incomplete scans

The message becomes an incomplete scan when the unpack process:

- times out,
- runs out of memory,
- crashes, or
- sends an invalid reply.

Outside observe mode, CSM then requests deferral whatever `fail_mode` says. CSM can defer a message only while the kernel is still holding the message for a verdict (a fanotify permission event). In notification-only mode, the fallback when permission events are unavailable, CSM is told about the message but cannot hold or defer it.

A decoding or multipart parsing error also marks the message as incompletely scanned; see [Decoding malformed attachments](#decoding-malformed-attachments).

### Attachment names

Attachment names written to logs and the UI use sanitized, shortened base names. Archive detection uses the full name, so shortening a displayed name does not prevent unpacking.

## Quarantine and release

Quarantine and release preserve each queue file's ownership, permissions, and modification time, including when the move crosses filesystems.

Release returns the message to the queue directory it came from. This includes the hash directory Exim uses when `split_spool_directory` is on.

If a quarantine or a release completes only partially, inspect both the spool and quarantine locations before retrying. [Partly completed quarantine and release](#partly-completed-quarantine-and-release) lists what CSM keeps in each case.

## Web UI

The Email page (`/email`) shows:

- AV watcher status (active, engine health).
- Scan statistics (scanned, infected, quarantined).
- The quarantined email list, with release/delete actions.

## API Endpoints

```
GET  /api/v1/email/stats         Scan statistics
GET  /api/v1/email/quarantine    Quarantined email list
GET  /api/v1/email/av/status     AV watcher status
POST /api/v1/email/quarantine/   Release or delete quarantined email
```

## Related Checks

| Check | What it does |
| --- | --- |
| `email_content` | Scans outbound email body for credentials and suspicious URLs. |
| `email_weak_password` | Detects email accounts with weak passwords. |
| `email_forwarder_audit` | Audits forwarders for exfiltration redirects. |
| `mail_queue` | Alerts on queue buildup, a spam outbreak indicator. |
| `mail_per_account` | Reports per-account sending volume spikes. |

`email_content` decodes every base64 body and part, attachments included. It uses the same tolerance as attachment scanning, the live MIME headers and the declared multipart boundaries.

## Email password audit

The deep scan checks mailbox passwords against account-derived candidates and the bundled weak-password list.

Verification runs inside CSM. Passwords and stored hashes are never passed to subprocesses or included in findings. Confirmed matches can still use the HIBP range API for breach counts, sending only a SHA1 prefix.

### Supported stored formats

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

These rules apply when CSM reads a stored value:

- Unprefixed hashes use CRYPT.
- cPanel shadow files, which add password aging fields after the hash, are read the same way.
- Scheme names and `.hex`, `.b64`, and `.base64` encoding suffixes are case-insensitive.
- Unsalted digests also accept Dovecot's hex/base64 autodetection.

DES crypt, bcrypt 2x, yescrypt, PBKDF2, and mechanism-specific formats such as SCRAM are not audited.

### Limits

- Stored values are limited to 4 KiB.
- Candidates are limited to 256 bytes without embedded NULs.
- At most three hash calculations run concurrently.
- Cancellation returns promptly. A calculation already running keeps its worker slot until its bounded work finishes.

### Incomplete audits

An unsupported, malformed, or over-budget hash produces `email_password_audit_incomplete`. CSM keeps earlier password findings and does not record that mailbox as successfully audited. Other mailboxes continue to be checked.

| Case | When the audit tries again |
| --- | --- |
| These hash failures are the only failures | After `password_check_interval_min`. |
| Temporary verification failures | They remain eligible for retry on the next deep scan. |

Cycles skipped by the interval preserve both earlier password findings and the audit warning. A completed audit replaces them with its current results.

Upgrading starts a fresh audit even when an older CSM version recorded the same hash.

## Details

The sections below are reference material for edge cases of attachment scanning and quarantine.

### Decoding malformed attachments

- Base64 and quoted-printable decoding tolerates stray characters, missing padding and malformed escapes.
- Encoded multipart bodies are decoded at every level.
- Ambiguous base64 is scanned under quartet and alphabet-only interpretations. A valid padded prefix is scanned separately when data follows it.
- At most 16 additional interpretations are scanned per message.
- If decoding or multipart parsing reports an error, recovered content and later attachments are still scanned, and the message is reported as incompletely scanned.
- Extraction size and MIME nesting limits still apply.

### Where release can put a message

Release accepts the flat queue root or the message's hash directory. The hash directory is named for the sixth character in both 16- and 23-character Exim IDs.

Release rejects other subdirectories, and hash-directory symlinks outside the trusted queue roots.

### Partly completed quarantine and release

- Quarantine persists recovery metadata before moving spool files. It syncs file contents and directory changes.
- A failed rollback retains the remaining quarantine files.
- Release restores the body before publishing the queue header.
- Storage failures retain metadata and report the affected paths.
