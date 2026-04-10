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

## APT repository (Debian / Ubuntu) — recommended

The package repository at `mirrors.pidginhost.com/csm/` is the preferred install method for Debian and Ubuntu. Future updates are picked up automatically via `apt upgrade`, and package metadata is GPG-signed so the trust chain is enforced by dpkg.

```bash
# 1. Install the signing key
curl -fsSL https://mirrors.pidginhost.com/csm/csm-signing.gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/csm.gpg

# 2. Add the repository
echo "deb [signed-by=/etc/apt/keyrings/csm.gpg] https://mirrors.pidginhost.com/csm/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/csm.list

# 3. Install
sudo apt update
sudo apt install csm
```

Works on Ubuntu 20.04+, Debian 11+, and any derivative. The single `stable` suite serves all Debian/Ubuntu releases — the Go binary is statically linked and has no per-release glibc dependency.

To upgrade later: `sudo apt update && sudo apt upgrade csm`.

## DNF repository (AlmaLinux / Rocky / RHEL / CloudLinux / cPanel) — recommended

```bash
sudo tee /etc/yum.repos.d/csm.repo >/dev/null <<'EOF'
[csm]
name=CSM - Continuous Security Monitor
baseurl=https://mirrors.pidginhost.com/csm/rpm/el$releasever/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.pidginhost.com/csm/csm-signing.gpg
EOF
sudo dnf install csm
```

The `$releasever` variable auto-selects the matching EL major (8, 9, or 10). Both `x86_64` and `aarch64` are published. Works on AlmaLinux 8+, Rocky 8+, RHEL 8+, CloudLinux 8+, and cPanel-managed hosts.

To upgrade later: `sudo dnf upgrade csm`.

## Quick Install (all platforms, one-shot)

For situations where you can't add a package repository (disconnected hosts, air-gapped mirrors, Docker base images):

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
```

Auto-detects hostname, email, and generates a WebUI auth token. Prompts for confirmation before applying. Works on Debian/Ubuntu and RHEL-family distros. Non-interactive mode:

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash -s -- --email admin@example.com --non-interactive
```

## Manual `.rpm` / `.deb` download

If you need a specific version or want to install without adding the repository:

```bash
# RHEL family
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm-VERSION-1.x86_64.rpm
sudo dnf install -y ./csm-VERSION-1.x86_64.rpm

# Debian/Ubuntu
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm_VERSION_amd64.deb
sudo apt install -y ./csm_VERSION_amd64.deb
```

Replace `VERSION` with a real version (e.g. `2.2.1`). Both files are also available at `https://mirrors.pidginhost.com/csm/deb/pool/main/c/csm/` and `https://mirrors.pidginhost.com/csm/rpm/elN/ARCH/` if you prefer to pin versions from the mirror.

## Post-install (all methods)

```bash
vi /opt/csm/csm.yaml                   # Set hostname, alert email, infra IPs
csm validate                           # Check config syntax
csm baseline                           # Record current state as known-good
systemctl enable --now csm.service     # Start the daemon
```

## Rollback to an older version

Both the APT and DNF repositories retain the **last 5 tagged releases** at any time. To downgrade:

```bash
# Debian/Ubuntu
sudo apt-cache policy csm              # Show available versions
sudo apt install csm=2.2.0-1

# RHEL family
sudo dnf --showduplicates list csm     # Show available versions
sudo dnf downgrade csm
```

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
