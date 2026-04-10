# Installation

## Supported Platforms

| Platform | Web server | Package | Notes |
|----------|-----------|---------|-------|
| cPanel/WHM on CloudLinux / AlmaLinux / Rocky | Apache (EA4) or LiteSpeed | .rpm | Primary target. All 62 checks run. |
| Plain AlmaLinux / Rocky / RHEL 8+ / CentOS Stream 8+ | Apache (`httpd`) or Nginx | .rpm | Generic Linux + web server checks. cPanel-specific checks are skipped cleanly. |
| Plain Ubuntu 20.04+ / Debian 11+ | Apache (`apache2`) or Nginx | .deb | Same as above, with `debsums`/`dpkg --verify` in place of `rpm -V`. |

The daemon auto-detects the OS, control panel (cPanel/Plesk/DirectAdmin/none), and web server (Apache/Nginx/LiteSpeed) at startup. The detected platform is logged at startup as:

```
[2026-04-10 08:13:37] platform: os=ubuntu/24.04 panel=none webserver=nginx
```

Check it with `journalctl -u csm.service | grep platform:` after starting the daemon.

## Quick Install (all platforms)

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
```

Auto-detects hostname, email, and generates a WebUI auth token. Prompts for confirmation before applying. Works on Debian/Ubuntu and RHEL-family distros.

Non-interactive mode:

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash -s -- --email admin@example.com --non-interactive
```

## RPM (AlmaLinux / Rocky / RHEL / CloudLinux / cPanel)

```bash
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm-VERSION-1.x86_64.rpm
sudo dnf install -y ./csm-VERSION-1.x86_64.rpm
vi /opt/csm/csm.yaml
csm validate
csm baseline
systemctl enable --now csm.service
```

On older hosts with yum: `sudo yum install -y ./csm-VERSION-1.x86_64.rpm`.

## DEB (Ubuntu / Debian)

```bash
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm_VERSION_amd64.deb
sudo apt install -y ./csm_VERSION_amd64.deb
vi /opt/csm/csm.yaml
csm validate
csm baseline
systemctl enable --now csm.service
```

Using `apt install ./file.deb` instead of `dpkg -i` pulls in recommended dependencies (`auditd`, `logrotate`) automatically.

## Verifying platform auto-detection

After `systemctl start csm.service`, the first line after "CSM daemon starting" reports what CSM detected:

```
[2026-04-10 08:13:37] CSM daemon starting
[2026-04-10 08:13:37] platform: os=almalinux/10.0 panel=none webserver=apache
[2026-04-10 08:13:37] Watching: /var/log/secure
[2026-04-10 08:13:37] Watching: /var/log/httpd/error_log
[2026-04-10 08:13:37] Watching: /var/log/httpd/access_log
```

If any field shows `none` or `unknown` when you expect something, the auto-detect missed it. File a bug with the output of `cat /etc/os-release`, `systemctl is-active nginx apache2 httpd`, and `which nginx apache2 httpd`.

## Optional system dependencies

CSM runs as a single static Go binary and has no hard dependencies beyond systemd, but a few host packages enable additional checks:

| Package | Platforms | Enables |
|---------|-----------|---------|
| `auditd` | All | Shadow file / SSH key tamper detection via auditd |
| `debsums` | Debian/Ubuntu | Cleaner system binary integrity output vs. `dpkg --verify` fallback |
| `logrotate` | All | Rotation of `/var/log/csm/monitor.log` |
| `wp-cli` | Optional | WordPress core integrity check |
| ModSecurity | All | WAF enforcement checks (see platform-specific install below) |

### Installing ModSecurity

CSM detects ModSecurity but doesn't install it for you. Platform-specific commands:

```bash
# Ubuntu/Debian + Nginx
sudo apt install libnginx-mod-http-modsecurity modsecurity-crs

# Ubuntu/Debian + Apache
sudo apt install libapache2-mod-security2 modsecurity-crs && sudo a2enmod security2

# AlmaLinux/Rocky/RHEL + Apache (requires EPEL)
sudo dnf install -y epel-release
sudo dnf install -y mod_security
sudo systemctl restart httpd

# AlmaLinux/Rocky/RHEL + Nginx (requires EPEL)
sudo dnf install -y epel-release
sudo dnf install -y nginx-mod-http-modsecurity
sudo systemctl restart nginx
```

After installing ModSecurity, run `csm check` and the `waf_status` finding should disappear.

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
