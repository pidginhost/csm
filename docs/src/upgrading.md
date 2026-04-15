# Upgrading

## deploy.sh (recommended)

```bash
/opt/csm/deploy.sh upgrade
```

This will:
1. Stop the daemon
2. Back up the current binary
3. Download the new version
4. Verify SHA256 checksum
5. Extract UI assets and rules
6. Rehash config
7. Restart the daemon

Rolls back automatically on failure.

## Troubleshooting

**"store: opening bbolt: timeout"** -- This means another CSM process holds the database lock. Common causes:
- A `csm baseline`, `csm scan`, or `csm check-deep` command is still running
- The daemon was killed uncleanly (SIGKILL, OOM) and the lock file is stale

Fix: check if a CSM process is running (`pgrep csm`). If not, remove the stale lock:
```bash
rm -f /opt/csm/state/csm.lock
systemctl start csm
```

**Never delete `csm.db`** -- it contains all historical findings, firewall state, email forwarder baselines, and per-account data. If you delete it, the web UI will show empty data until the next full scan cycle (up to 60 minutes for deep scan findings). If you must reset, use `csm baseline` instead.

**Config changes require rehash** -- After editing `csm.yaml`, run `csm rehash` twice (the config hash is stored inside the config file, creating a circular dependency -- the second run stabilizes it). Or just restart via `systemctl restart csm`.

## RPM/DEB

```bash
yum update csm              # RPM
dpkg -i csm_NEW.deb         # DEB
```

Package managers handle stop/start automatically.
