# Pre-start hooks for the CSM daemon

CSM does not implement its own hook protocol because systemd already
ships one: drop-in units. This document shows how phpanel-server-agent
(or any operator-supplied automation) wires a pre-start script that runs
before the daemon binds.

## Why drop-ins, not a custom hook directory

Inventing a `hook_pre_start:` config or a magic `/etc/csm/hooks/`
directory would duplicate `systemd.unit(5)` drop-ins, which already
support: per-service ordering, `ExecStartPre=` (cancel start on failure),
`EnvironmentFile=` (load secrets), `User=`/`Group=` (privilege drop), and
`Conditional*=` (skip when prerequisites absent). Every distro CSM
supports already runs systemd. Use it.

## Recipe for phpanel-server-agent

1. **Author your hook script.** Convention: `/opt/phpanel/hooks/csm-prestart.sh`.

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

2. **Install the drop-in.** Copy the example from
   `/usr/lib/csm/profiles/csm-prestart.example.conf` (shipped by the
   CSM package) to `/etc/systemd/system/csm.service.d/10-phpanel-prestart.conf`,
   editing the `ExecStartPre=` line to point at your script.

3. **Reload systemd.**

   ```bash
   systemctl daemon-reload
   systemctl restart csm.service
   ```

4. **Verify** with `systemctl cat csm.service` - your drop-in should
   appear at the bottom under `# /etc/systemd/system/csm.service.d/...`.

## Standard environment available to the hook

- `CSM_HOSTNAME` - set by CSM at runtime, **not** available in
  `ExecStartPre`. If you need the hostname pre-start, read
  `/etc/hostname` directly.
- `CSM_INFRA_IPS` - same caveat. Resolve from your panel agent's
  context (it knows the panel address).

## Failure semantics

`ExecStartPre=` blocks startup on non-zero exit. Use `ExecStartPre=-/path`
(dash prefix) when you want CSM to start even if the hook fails. For
phpanel-server-agent's reconcile step, the dash prefix is recommended so
a transient panel outage doesn't keep CSM from running.
