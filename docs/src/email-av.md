# Email AV

CSM scans email attachments in real-time using ClamAV and YARA-X on the Exim mail spool.

## How It Works

1. **fanotify** watches the Exim spool directory for new messages
2. Attachments are extracted and scanned by ClamAV (socket) and YARA-X (if available)
3. Infected messages are quarantined with full metadata
4. Sender, recipient, and message ID are logged

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

- `email_content` - scans outbound email body for credentials and suspicious URLs
- `email_weak_password` - detects email accounts with weak passwords
- `email_forwarder_audit` - audits forwarders for exfiltration redirects
- `mail_queue` - alerts on queue buildup (spam outbreak indicator)
- `mail_per_account` - per-account sending volume spikes
