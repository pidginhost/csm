# Installation

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
```

Auto-detects hostname, email, and generates a WebUI auth token. Prompts for confirmation before applying.

Non-interactive mode:

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash -s -- --email admin@example.com --non-interactive
```

## RPM (CentOS/AlmaLinux/CloudLinux)

```bash
rpm -i csm-VERSION-1.x86_64.rpm
vi /opt/csm/csm.yaml
csm validate
csm baseline
systemctl enable --now csm.service
```

## DEB (Ubuntu/Debian)

```bash
dpkg -i csm_VERSION_amd64.deb
vi /opt/csm/csm.yaml
csm validate
csm baseline
systemctl enable --now csm.service
```

## Manual (deploy.sh)

```bash
/opt/csm/deploy.sh install
vi /opt/csm/csm.yaml   # set hostname, alert email, infra IPs
csm validate
csm baseline
systemctl enable --now csm.service
```

## Post-Install

1. Edit `/opt/csm/csm.yaml` — set hostname, alert email, infrastructure IPs
2. Run `csm validate` to check config syntax (add `--deep` for connectivity probes)
3. Run `csm baseline` to record current state as known-good (see below)
4. Start the daemon: `systemctl enable --now csm.service`
5. Open the Web UI: `https://<server>:9443/login`

All installation methods produce the same installed state. RPM/DEB packages auto-detect hostname and email, and generate the auth token.

## Baseline Scan

The `csm baseline` command scans the entire server and records the current state as known-good. This is required on first install so CSM knows what's "normal" for your server.

**What it does:**
- Scans all cPanel accounts for malware, permissions, and configuration issues
- Records file hashes, email forwarder hashes, and plugin versions
- Stores everything in the bbolt database (`/opt/csm/state/csm.db`)

**How long it takes:** Depends on server size. A server with 100+ cPanel accounts and thousands of WordPress sites can take **5-10 minutes**. During this time, the daemon cannot start (bbolt lock).

**When to re-run:**
- After a fresh install
- After restoring from backup
- If the database is lost or corrupted (delete `csm.db` and re-run)
- You do NOT need to re-run for normal deploys/upgrades — the daemon handles incremental state

**Important:** The baseline scan holds the database lock. Do not start the daemon (`systemctl start csm`) until the baseline completes. The daemon will fail with "store: opening bbolt: timeout" if the baseline is still running.
