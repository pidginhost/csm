# Incident Response Runbook

Use this flow when CSM flags account compromise, mailbox takeover,
malicious database triggers, or outbound spam on a production cPanel
host.

## Safety rules

- Do not delete customer files during first response.
- Do not thaw, release, or purge queued mail until affected credentials
  are rotated or an operator approves the specific queue action.
- Do not close incidents until the account was reviewed, credentials
  were rotated or explicitly deferred, and a fresh scan is clean.
- Take a CSM backup before upgrading CSM or changing incident state.

## 1. Verify the deployed binary

Deploy only after the required GitLab pipeline passed and the package was
published.

```bash
/root/deploy-csm.sh check
/root/deploy-csm.sh upgrade
/opt/csm/csm version
/opt/csm/csm doctor --json
```

## 2. Take a backup

```bash
mkdir -p /root/csm-backups
/opt/csm/csm backup /root/csm-backups/csm-pre-response-$(date +%Y%m%d%H%M%S).tar.gz
sha256sum /root/csm-backups/csm-pre-response-*.tar.gz
```

Confirm the archive is readable:

```bash
gzip -t /root/csm-backups/csm-pre-response-*.tar.gz
tar -tzf /root/csm-backups/csm-pre-response-*.tar.gz | sed -n '1,80p'
```

## 3. Preserve evidence

```bash
mkdir -p /root/csm-forensics
/opt/csm/csm forensic-snapshot <account> --out /root/csm-forensics/<account>-$(date +%Y%m%d%H%M%S).tar.gz
sha256sum -c /root/csm-forensics/<account>-*.sha256
tar -xOzf /root/csm-forensics/<account>-*.tar.gz manifest.txt
```

Check the manifest for private-path exclusions, schema count, capture
errors, and `recent_mtimes_status=ok`.

## 4. Map affected accounts

Map incident domains and queued local senders to cPanel users before
rotating credentials or changing mail queue state.

```bash
/opt/csm/csm incidents list --status open --all
exim -bpc
exim -bp | exiqsumm
grep -E '^example.com:' /etc/trueuserdomains /etc/userdomains
whmapi1 listaccts searchtype=user search=<account> --output=json
```

Use native cPanel APIs for inventory:

```bash
uapi --user=<account> Email list_pops --output=json
uapi --user=<account> Ftp list_ftp --output=json
uapi --user=<account> Mysql list_users --output=json
```

## 5. Rotate credentials

Rotate the cPanel account password, FTP accounts, affected mailboxes,
WordPress administrator users, database users, and application secrets
for the affected account. Prefer WHM and UAPI calls or the control panel
over direct file edits.

Do this before releasing mail or marking incidents resolved unless the
operator explicitly defers rotation for a documented reason.

## 6. Review queued mail

Start with read-only summaries:

```bash
exim -bpc
exim -bp | exiqsumm
exim -bp
```

Review headers before any queue action:

```bash
exim -Mvh <message-id>
```

Group messages into:

- safe to remove: frozen bounces, obvious backscatter, duplicate failed
  delivery notices with no customer value
- do not touch: current customer conversations, invoices, form leads, or
  any message where the business value is unclear
- needs review: suspicious local sender messages, mixed external bulk
  mail, or messages tied to an account whose credentials are not rotated

Only remove or thaw message IDs that were reviewed:

```bash
exim -Mrm <message-id>
exim -Mt <message-id>
```

## 7. Review stale incidents

Preview first:

```bash
/opt/csm/csm incidents bulk-status --older-than 72h --status active --kind web_account_compromise --limit 20
/opt/csm/csm incidents bulk-status --older-than 24h --status active --kind mailbox_takeover --limit 20
```

Apply in bounded batches only after review:

```bash
/opt/csm/csm incidents bulk-status --older-than 72h --status active --kind web_account_compromise --limit 100 --apply --confirm --details "operator cleanup after review"
```

For mailbox incidents, confirm mailbox rotation or explicit operator
deferral before applying status changes.

## 8. Confirm recovery

```bash
/opt/csm/csm status --json
/opt/csm/csm doctor --json
exim -bpc
```

Keep the forensic archives, CSM backup, command notes, and queue
decisions with the incident record.
