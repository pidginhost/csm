# Installation

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/install.sh | bash
```

Auto-detects hostname, email, and generates a WebUI auth token. Prompts for confirmation before applying.

Non-interactive mode:

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/install.sh | bash -s -- --email admin@example.com --non-interactive
```

## RPM (CentOS/AlmaLinux/CloudLinux)

```bash
rpm -i csm-VERSION-1.x86_64.rpm
vi /opt/csm/csm.yaml
csm baseline
systemctl enable --now csm.service
```

## DEB (Ubuntu/Debian)

```bash
dpkg -i csm_VERSION_amd64.deb
vi /opt/csm/csm.yaml
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

1. Edit `/opt/csm/csm.yaml` - set hostname, alert email, infrastructure IPs
2. Run `csm validate` to check config syntax (add `--deep` for connectivity probes)
3. Run `csm baseline` to record current state as known-good
4. Start the daemon: `systemctl enable --now csm.service`
5. Open the Web UI: `https://<server>:9443/login`

All installation methods produce the same installed state. RPM/DEB packages auto-detect hostname and email, and generate the auth token.
