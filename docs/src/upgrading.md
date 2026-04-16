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

**"store: opening bbolt: timeout"** -- Commands that need live daemon state now route through the control socket at `/var/run/csm/control.sock` and no longer open the database directly, so this error should only appear from `csm baseline`, `csm firewall ...`, or the `check-*` dry-run commands (the remaining in-process paths; see the roadmap for the phase-2 migration). If you hit it from one of those:

- A `csm baseline`, `csm scan`, or `csm check-deep` command is still running
- The daemon was killed uncleanly (SIGKILL, OOM) and the lock file is stale

Fix: check if a CSM process is running (`pgrep csm`). If not, remove the stale lock:
```bash
rm -f /opt/csm/state/csm.lock
systemctl start csm
```

**"csm: daemon not running"** -- CLI commands that talk to the daemon (`csm run-critical`, `csm run-deep`, `csm status`) exit 2 with this message when the control socket is missing. Start the daemon with `systemctl start csm`. Bootstrap commands that run before the daemon exists (`csm install`, `csm validate`, `csm verify`, `csm rehash`) do not require it.

**Never delete `csm.db`** -- it contains all historical findings, firewall state, email forwarder baselines, and per-account data. If you delete it, the web UI will show empty data until the next full scan cycle (up to 60 minutes for deep scan findings). If you must reset, use `csm baseline` instead.

**Config changes require rehash** -- After editing `csm.yaml`, run `csm rehash` twice (the config hash is stored inside the config file, creating a circular dependency -- the second run stabilizes it). Or just restart via `systemctl restart csm`.

## RPM/DEB

```bash
yum update csm              # RPM
dpkg -i csm_NEW.deb         # DEB
```

Package managers handle stop/start automatically.
