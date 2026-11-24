# Installation

Install CSM from the signed APT or DNF repository. That is the recommended method, and it delivers updates through the package manager. Three other methods are described below for hosts that need them. After any install, set the configuration, start the daemon and run a baseline scan; see [Post-install (all methods)](#post-install-all-methods).

| Method | When to use it |
|--------|----------------|
| [APT repository](#apt-repository-debian--ubuntu-recommended) | Debian and Ubuntu. Recommended. |
| [DNF repository](#dnf-repository-almalinux--rocky--rhel--cloudlinux--cpanel-recommended) | AlmaLinux, Rocky, RHEL and CloudLinux, including cPanel on those systems. Recommended. |
| [Online standalone installer](#online-standalone-installer) | The host has Internet access but cannot use the APT or DNF repository. |
| [Manual package download](#manual-rpm--deb-download) | You need a specific version, or want to install without adding the repository. |
| [deploy.sh](#manual-deploysh) | A manual install with the deploy script. |

## Supported Platforms

| Platform | Web server | Package | Notes |
|----------|-----------|---------|-------|
| AlmaLinux / Rocky / RHEL / CloudLinux / CentOS Stream 8+ | Apache (`httpd`), Nginx, LiteSpeed, or none | .rpm | Host, web, and mail checks for the detected stack, with `rpm -V` package integrity. |
| Ubuntu 20.04+ / Debian 11+ | Apache (`apache2`), Nginx, LiteSpeed, or none | .deb | Same, with `debsums`/`dpkg --verify` in place of `rpm -V`. |
| cPanel/WHM on CloudLinux / AlmaLinux / Rocky / Ubuntu | Apache (EA4) or LiteSpeed, with or without ea-nginx | .rpm or .deb | Adds cPanel account, WordPress, Exim, and WHM plugin coverage. |

Postfix hosts with Dovecot also get mail login detection and optional [rspamd spam filtering](antispam.md#postfix-hosts).

On hosts without cPanel, set `account_roots` for real-time document-root rules, scheduled YARA sweeps and web-root performance checks. Other account and CMS scans still depend on account layouts; see [deep check platform support](detection-deep.md#platform-support).

The daemon auto-detects the OS, the control panel (cPanel/Plesk/DirectAdmin/none) and the web server (Apache/Nginx/LiteSpeed) at startup. See [Verifying platform auto-detection](#verifying-platform-auto-detection).

<a id="apt-repository-debian--ubuntu--recommended"></a>
<a id="apt-repository-debian--ubuntu----recommended"></a>

## APT repository (Debian / Ubuntu), recommended

The package repository at `mirrors.pidginhost.com/csm/` is the preferred install method for Debian and Ubuntu. Updates are available through `apt upgrade`, and APT verifies the repository's signed metadata before installing packages.

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

This works on Ubuntu 20.04+, Debian 11+, and compatible derivatives. The single `stable` suite serves every supported release.

Production binaries dynamically link glibc with a build floor of 2.28, which is available on all supported distributions. YARA-X itself is linked into the executable.

To upgrade later: `sudo apt update && sudo apt upgrade csm`.

<a id="dnf-repository-almalinux--rocky--rhel--cloudlinux--cpanel--recommended"></a>
<a id="dnf-repository-almalinux--rocky--rhel--cloudlinux--cpanel----recommended"></a>

## DNF repository (AlmaLinux / Rocky / RHEL / CloudLinux / cPanel), recommended

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

# 3. Install (check the fingerprint below before accepting the key)
sudo dnf install csm
```

The `$releasever` variable auto-selects the matching EL major (8, 9, or 10). Both `x86_64` and `aarch64` are published. This works on AlmaLinux 8+, Rocky 8+, RHEL 8+, CloudLinux 8+, and cPanel hosts on those distributions.

To upgrade later: `sudo dnf upgrade csm`.

### The key prompt on first install

The first transaction against a new repository still prompts for the key, even after a successful `rpm --import`. The reason is that dnf uses two keyrings:

- `rpm --import` populates the RPM keyring, which covers `gpgcheck`, the signature on the package.
- It does not populate the separate keyring dnf keeps for `repo_gpgcheck`, the signature on the repository metadata.

The prompt looks like this:

```
Importing GPG key 0x81CD59B1:
 Userid     : "CSM Package Signing (CSM Repository Metadata Signing Key) <security@pidginhost.com>"
 Fingerprint: 3A70 4D78 3CF2 6055 B2AA 8F49 4E0F 27F5 81CD 59B1
Is this ok [y/N]:
```

Without `-y`, an unanswered key prompt defaults to no. A rejected key can produce an error such as:

```
Error: Failed to download metadata for repo 'csm':
repomd.xml GPG signature verification error: Bad GPG signature
```

The error alone does not distinguish an untrusted key from damaged or incorrectly signed metadata. Check the fingerprint against the value above, then verify the metadata signature:

```bash
base=https://mirrors.pidginhost.com/csm/rpm/el9/x86_64/repodata
curl -fsSLO $base/repomd.xml
curl -fsSLO $base/repomd.xml.asc
curl -fsSL https://mirrors.pidginhost.com/csm/csm-signing.gpg | gpg --import
gpg --verify repomd.xml.asc repomd.xml
# gpg: Good signature from "CSM Package Signing ... <security@pidginhost.com>"
```

### Unattended installs

For unattended installs, approve the repository key in provisioning first, then use `sudo dnf -y install csm`. DNF's [`assumeyes` option](https://dnf.readthedocs.io/en/stable/conf_ref.html#main-options) accepts key-import prompts as well as package prompts.

Keep both signature checks enabled. `-y` is not a substitute for verifying the expected key.

## Online standalone installer

Use the standalone installer when the host has Internet access but cannot use the APT or DNF repository. The installer does this:

1. It downloads the binary and supporting assets from the latest GitHub release.
2. It verifies their checksums.
3. It requires successful Ed25519 signature verification.
4. It installs outside the package manager.

```bash
curl -fsSLo /tmp/csm-install.sh https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh
less /tmp/csm-install.sh
sudo bash /tmp/csm-install.sh
```

The installer auto-detects the hostname and alert email, generates a Web UI token, and prompts before applying. For non-interactive mode:

```bash
sudo bash /tmp/csm-install.sh --email admin@example.com --non-interactive
```

This is not an offline or air-gapped installation path. Mirror the signed packages and repository metadata for disconnected environments.

### How the standalone installer verifies the release

Standalone verification uses one of these, in this order:

1. OpenSSL 3.0 or newer.
2. An already installed CSM build providing `csm verify-release`.
3. `python3-cryptography`.

EL8 and CloudLinux 8 have the last of these, so the standalone path works there even though their OpenSSL 1.1.1 cannot verify Ed25519.

A missing key, a missing current-release signature, an absent verifier, or a failed verification stops the install before executing the binary. See [Release signing](release-signing.md) for the narrowly scoped historical-release exception.

## Manual `.rpm` / `.deb` download

Use this method if you need a specific version or want to install without adding the repository. Verify the package's detached signature before invoking the package manager.

Save the trusted public key from [Release signing](release-signing.md#public-key) as `csm-signing.pub`. These commands require OpenSSL 3.0 or newer. Older hosts should use the signed repository above. Installing a local package does not by itself establish the repository signature chain.

```bash
# RHEL family
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm-VERSION-1.x86_64.rpm
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm-VERSION-1.x86_64.rpm.sig
openssl pkeyutl -verify -pubin -inkey csm-signing.pub -rawin \
  -sigfile csm-VERSION-1.x86_64.rpm.sig -in csm-VERSION-1.x86_64.rpm && \
  sudo dnf install -y ./csm-VERSION-1.x86_64.rpm

# Debian/Ubuntu
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm_VERSION_amd64.deb
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm_VERSION_amd64.deb.sig
openssl pkeyutl -verify -pubin -inkey csm-signing.pub -rawin \
  -sigfile csm_VERSION_amd64.deb.sig -in csm_VERSION_amd64.deb && \
  sudo apt install -y ./csm_VERSION_amd64.deb
```

Replace `VERSION` with a published version. Both files are also available from the package mirror if you need to pin a release without adding the repository.

## Manual (deploy.sh)

```bash
/opt/csm/deploy.sh install
vi /etc/csm/csm.yaml   # set hostname, alert email, infra IPs
csm validate
systemctl enable --now csm.service
csm baseline
```

## Post-install (all methods)

Set infrastructure IPs and confirm the alert address before starting the daemon, whichever method you used.

```bash
sudo vi /etc/csm/csm.yaml              # Set hostname, alert email, infra IPs
sudo csm validate                      # Check config syntax (--deep adds connectivity probes; validates merged conf.d too)
sudo systemctl enable --now csm.service
sudo csm baseline                      # Record current state as known-good via the daemon (must be running)
```

Then open the Web UI at `https://<server>:9443/login`. The baseline is detailed under [Baseline Scan](#baseline-scan).

RPM/DEB packages are the maintained installation path. They include package-manager ownership, integration profiles, UI assets, rules, and the prebuilt PAM module. The standalone installer supplies the runtime assets but does not register them with a package manager.

## Baseline Scan

The `csm baseline` command scans the entire server and records the current state for change tracking. It is required on first install so CSM knows what is normal for your server.

Start `csm.service` before running `csm baseline`. The daemon must be running because the baseline is coordinated through the control socket.

If the store contains history, the command stops and tells you to rerun it with `--confirm`. Use `csm baseline --confirm` only if you intend to replace the baseline.

### What it does

- It scans all cPanel accounts for malware, permissions, and configuration issues.
- It records file hashes, email forwarder hashes, and plugin versions.
- It writes baseline findings to `state.json` under the state directory. It records integrity hashes in the main config.

Findings that should never be silently trusted, such as non-standard MySQL superusers or WHM root API tokens, can still be reported on this first scan.

### How long it takes

The time depends on server size. A server with 100+ cPanel accounts and thousands of WordPress sites can take 5-10 minutes.

### When to re-run

Run the baseline again:

- after a fresh install,
- after restoring from backup if you intend to replace the restored baseline,
- after an intentional state reset approved by the operator.

You do not need to re-run it for normal deploys or upgrades. The daemon handles incremental state.

## Verifying platform auto-detection

The daemon logs the detected platform at startup. Check it with `journalctl -u csm.service | grep platform:` after starting the daemon. The line looks like this:

```
[2026-04-10 08:13:37] platform: os=ubuntu/24.04 panel=none webserver=nginx
```

After `systemctl start csm.service`, the first line after "CSM daemon starting" reports what CSM detected:

```
[2026-04-10 08:13:37] CSM daemon starting
[2026-04-10 08:13:37] platform: os=almalinux/10.0 panel=none webserver=apache
[2026-04-10 08:13:37] Watching: /var/log/secure
[2026-04-10 08:13:37] Watching: /var/log/httpd/error_log
[2026-04-10 08:13:37] Watching: /var/log/httpd/access_log
```

If any field shows `none` or `unknown` when you expect something, the auto-detect missed it. File a bug with the output of `cat /etc/os-release`, `systemctl is-active nginx apache2 httpd`, and `which nginx apache2 httpd`.

## Rollback to an older version

Both the APT and DNF repositories retain the last 5 tagged releases at any time. To downgrade:

```bash
# Debian/Ubuntu
sudo apt-cache policy csm              # Show available versions
sudo apt install csm=<version>-1

# RHEL family
sudo dnf --showduplicates list csm     # Show available versions
sudo dnf downgrade csm
```

## Optional system dependencies

The daemon runs as one executable plus packaged UI, rule, profile, and PAM assets. Release binaries require glibc 2.28 or newer, and the package depends on systemd. A few host packages enable additional checks:

| Package | Platforms | Enables |
|---------|-----------|---------|
| `auditd` | All | Shadow file / SSH key tamper detection via auditd |
| `debsums` | Debian/Ubuntu | Cleaner system binary integrity output vs. `dpkg --verify` fallback |
| `logrotate` | All | Rotation of `/var/log/csm/monitor.log`, `/var/log/csm/audit.jsonl`, and the PHP Shield event log |
| `wp-cli` | Optional | WordPress core integrity check; its absence is reported when WordPress sites are found or discovery is incomplete |
| ModSecurity | All | WAF enforcement checks (see platform-specific install below) |

### Installing ModSecurity

CSM detects ModSecurity but does not install it for you. Use the commands for your platform:

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

After installing ModSecurity, run `csm check`. The `waf_status` finding should disappear.

## Filesystem layout

The package uses FHS paths for config, state, drop-ins, and shipped profiles. Upgrades keep `/opt/csm/csm.yaml` as a compatibility link for older scripts.

| Concern | Current path |
|---|---|
| Main config | `/etc/csm/csm.yaml` |
| Legacy config link | `/opt/csm/csm.yaml` |
| Drop-in fragments | `/etc/csm/conf.d/*.yaml` |
| State directory | `/var/lib/csm/state/` |
| Shipped profiles | `/usr/lib/csm/profiles/` |
| Shipped config template | `/usr/lib/csm/csm.yaml.default` |
| Audit log | `/var/log/csm/audit.jsonl` |
| Binary | `/opt/csm/csm` |
| Quarantine | `/opt/csm/quarantine/` |
| YARA / signature rules | `/opt/csm/rules/` |

### Removing the package on Debian and Ubuntu

- Removing the package keeps the main config.
- Purging the package removes the main config and its package-created compatibility link.
- If the main config is a symlink, purge leaves its target in place.

## Details

The sections below are reference material on directory permissions and on upgrades from the legacy layout.

### Directory permissions

| Path | Mode | Reason |
|---|---|---|
| `/etc/csm` | 0750 | The package creates it. The daemon itself cannot write it; see [Service configuration writes](service-confinement.md). |
| `/var/lib/csm` | 0711 | Searchable but not listable, so Exim can reach the email forward guard files below it. |
| `/var/lib/csm/state/` | 0700 | Stays private. |

The systemd unit declares `StateDirectory=csm`, so systemd manages the shared parent at `/var/lib/csm`. The private state directory is below it.

The binary installer and package scripts also keep the shared state root searchable. This includes systemd 239, which does not reset an existing state directory's mode.

### The forward guard and the state root

- Applying the forward guard repairs legacy parent permissions without making private directories listable. It rejects symlinks in those parents.
- Install and `csm rehash` likewise refuse a symlinked `/var/lib/csm`. Relocate state with `state_path` instead.
- Lookup refreshes maintain search access to the lookup directory inside the daemon sandbox. Full guard application runs outside it.

### Migration from the legacy layout

- On upgrade, the package copies a real legacy main config into `/etc/csm/csm.yaml` when needed and points `/opt/csm/csm.yaml` at it.
- On first start, the daemon copies a non-empty legacy `/opt/csm/state/` into `/var/lib/csm/state/`, only when the new directory is empty. It then continues using the FHS state path.

See [Upgrading - FHS migration](upgrading.md#fhs-migration-state-config-drop-ins-and-profiles) for the manual-binary-swap case.

### Refreshing the service unit

When install or `csm rehash` refreshes the service unit, it creates any missing directory the unit requires before replacing the unit.

- Existing modes are preserved, except for the shared state root's required search bits.
- Optional paths and systemd-managed directories are left alone unless needed as parents of a required path.
- If a required directory cannot be created, the refresh fails and the previous unit stays in place.
