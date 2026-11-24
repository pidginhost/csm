# Pre-start hooks for the CSM daemon

CSM does not implement its own hook protocol, because systemd already ships one: drop-in units. This document shows how phpanel-server-agent, or any operator-supplied automation, adds a pre-start script that runs before the daemon starts.

## Recipe for phpanel-server-agent

1. Write your hook script. The convention is `/opt/phpanel/hooks/csm-prestart.sh`.

   ```bash
   #!/bin/bash
   set -e
   # Re-resolve the panel hostname and stash the IP for CSM's infra_ips.
   PANEL_IP=$(getent hosts panel.example.com | awk '{print $1}' | head -1)
   if [ -n "$PANEL_IP" ]; then
       cat > /etc/csm/conf.d/10-phpanel-runtime.yaml <<YAML
   infra_ips:
     - $PANEL_IP
   YAML
   fi
   ```

2. Install the drop-in. Copy the example from `/usr/lib/csm/profiles/csm-prestart.example.conf`, which the CSM package ships, to `/etc/systemd/system/csm.service.d/10-phpanel-prestart.conf`. Edit the `ExecStartPre=` line to point at your script.

3. Reload systemd.

   ```bash
   systemctl daemon-reload
   systemctl restart csm.service
   ```

4. Verify with `systemctl cat csm.service`. Your drop-in should appear at the bottom under `# /etc/systemd/system/csm.service.d/...`.

## Failure semantics

`ExecStartPre=` blocks startup on a non-zero exit. Use `ExecStartPre=-/path` (dash prefix) when you want CSM to start even if the hook fails.

For phpanel-server-agent's reconcile step, the dash prefix is recommended, so a transient panel outage does not keep CSM from running.

## Standard environment available to the hook

Neither CSM variable is available to the hook:

| Variable | In `ExecStartPre` | What to do |
|----------|-------------------|------------|
| `CSM_HOSTNAME` | Not available. CSM sets it at runtime. | If you need the hostname pre-start, read `/etc/hostname` directly. |
| `CSM_INFRA_IPS` | Not available, for the same reason. | Resolve from your panel agent's context. It knows the panel address. |

## Why drop-ins, not a custom hook directory

A `hook_pre_start:` config or a magic `/etc/csm/hooks/` directory would duplicate `systemd.unit(5)` drop-ins. Drop-ins already support:

- Per-service ordering.
- `ExecStartPre=`, which cancels the start on failure.
- `EnvironmentFile=`, which loads secrets.
- `User=`/`Group=`, which drop privileges.
- `Conditional*=`, which skips the start when prerequisites are absent.

Every distro CSM supports already runs systemd. Use it.
