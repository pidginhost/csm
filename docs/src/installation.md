# Installation

## Supported Platforms

| Platform | Web server | Package | Notes |
|----------|-----------|---------|-------|
| cPanel/WHM on CloudLinux / AlmaLinux / Rocky | Apache (EA4) or LiteSpeed | .rpm | Primary target. Full cPanel account, WordPress, Exim, and WHM plugin coverage. |
| Plain AlmaLinux / Rocky / RHEL 8+ / CentOS Stream 8+ | Apache (`httpd`) or Nginx | .rpm | Generic Linux + web server checks. cPanel-specific checks are skipped cleanly. |
| Plain Ubuntu 20.04+ / Debian 11+ | Apache (`apache2`) or Nginx | .deb | Same as above, with `debsums`/`dpkg --verify` in place of `rpm -V`. |

The daemon auto-detects the OS, control panel (cPanel/Plesk/DirectAdmin/none), and web server (Apache/Nginx/LiteSpeed) at startup. The detected platform is logged at startup as:

```
[2026-04-10 08:13:37] platform: os=ubuntu/24.04 panel=none webserver=nginx
```

Check it with `journalctl -u csm.service | grep platform:` after starting the daemon.

## APT repository (Debian / Ubuntu) -- recommended

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

Works on Ubuntu 20.04+, Debian 11+, and any derivative. The single `stable` suite serves all Debian/Ubuntu releases -- the Go binary is statically linked and has no per-release glibc dependency.

To upgrade later: `sudo apt update && sudo apt upgrade csm`.

## DNF repository (AlmaLinux / Rocky / RHEL / CloudLinux / cPanel) -- recommended

```bash
# 1. Import the signing key into the RPM keyring
sudo rpm --import https://mirrors.pidginhost.com/csm/csm-signing.gpg

# 2. Add the repository
sudo tee /etc/yum.repos.d/csm.repo >/dev/null <<'EOF'
[csm]
name=CSM - Continuous Security Monitor
baseurl=https://mirrors.pidginhost.com/csm/rpm/el$releasever/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.pidginhost.com/csm/csm-signing.gpg
EOF

# 3. Install
sudo dnf install csm
```

The explicit `rpm --import` is important: without it, the first `dnf install csm` prompts "Is this ok [y/N]:" to trust the repo key, and `dnf install -y` answers package install prompts but not the key-trust prompt. If the prompt goes unanswered on a non-interactive install, dnf fails with `repomd.xml GPG signature verification error: Signing key not found`.

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

Replace `VERSION` with a real version (e.g. `2.2.2`). Both files are also available at `https://mirrors.pidginhost.com/csm/deb/pool/main/c/csm/` and `https://mirrors.pidginhost.com/csm/rpm/elN/ARCH/` if you prefer to pin versions from the mirror.

## Filesystem layout

The package uses FHS paths for config, state, drop-ins, and shipped profiles. Upgrades keep `/opt/csm/csm.yaml` as a compatibility link for older scripts:

| Concern | Current path |
|---|---|
| Main config | `/etc/csm/csm.yaml` |
| Legacy config link | `/opt/csm/csm.yaml` |
| Drop-in fragments | `/etc/csm/conf.d/*.yaml` |
| State directory | `/var/lib/csm/state/` |
| Shipped profiles | `/usr/lib/csm/profiles/` |
| Audit log | `/var/log/csm/audit.jsonl` |
| Binary | `/opt/csm/csm` |
| Quarantine | `/opt/csm/quarantine/` |
| YARA / signature rules | `/opt/csm/rules/` |

The systemd unit declares `StateDirectory=csm` and `ConfigurationDirectory=csm` so systemd manages permissions for the FHS directories. On upgrade, the package copies a real legacy main config into `/etc/csm/csm.yaml` when needed and points `/opt/csm/csm.yaml` at it. On first start the daemon copies a non-empty legacy `/opt/csm/state/` into `/var/lib/csm/state/` (only when the new directory is empty), then continues using the FHS state path. See [Upgrading - FHS migration](upgrading.md#fhs-migration-state-config-drop-ins-and-profiles) for the manual-binary-swap case.

## Post-install (all methods)

All installation methods produce the same installed state. RPM/DEB packages auto-detect hostname and email and generate the auth token; you still set the infrastructure IPs and confirm the alert address.

```bash
sudo vi /etc/csm/csm.yaml              # Set hostname, alert email, infra IPs
sudo csm validate                      # Check config syntax (--deep adds connectivity probes; validates merged conf.d too)
sudo systemctl enable --now csm.service
sudo csm baseline                      # Record current state as known-good via the daemon (must be running)
```

Then open the Web UI at `https://<server>:9443/login`. The baseline is detailed under [Baseline Scan](#baseline-scan).

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
vi /etc/csm/csm.yaml   # set hostname, alert email, infra IPs
csm validate
systemctl enable --now csm.service
csm baseline
```

## Baseline Scan

The `csm baseline` command scans the entire server and records the current state for change tracking. This is required on first install so CSM knows what's "normal" for your server. Findings that should never be silently trusted, such as non-standard MySQL superusers or WHM root API tokens, can still be reported on this first scan.

**What it does:**
- Scans all cPanel accounts for malware, permissions, and configuration issues
- Records file hashes, email forwarder hashes, and plugin versions
- Stores everything in the bbolt database (`/var/lib/csm/state/csm.db`)

**How long it takes:** Depends on server size. A server with 100+ cPanel accounts and thousands of WordPress sites can take **5-10 minutes**. The daemon must be running because the baseline is coordinated through the control socket.

**When to re-run:**
- After a fresh install
- After restoring from backup
- After an intentional state reset approved by the operator
- You do NOT need to re-run for normal deploys/upgrades -- the daemon handles incremental state

**Important:** Start `csm.service` before running `csm baseline`. If existing history would be cleared, rerun with `csm baseline --confirm` only after verifying that reset is intended.
