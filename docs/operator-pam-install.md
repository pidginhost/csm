# PAM hook for CSM

The CSM daemon listens on `/var/run/csm/pam.sock` for authentication
events emitted by a PAM module (`pam_csm.so`). The module is shipped
with the package at `/usr/lib/csm/pam/pam_csm.so`; without it installed
the daemon's PAM listener stays attached but never hears anything, and
the dashboard reports the watcher as **deaf**.

## Quick install

```bash
sudo csm pam install        # preview first with --dry-run
sudo csm pam status         # confirm
```

`csm pam install` stages `pam_csm.so` into the platform's security
directory (`/lib64/security` on RHEL, `/lib/x86_64-linux-gnu/security`
on Debian) and appends two lines to the standard service files:

```
auth     optional   pam_csm.so # managed-by-csm
session  optional   pam_csm.so # managed-by-csm
```

Targets: `/etc/pam.d/sshd`, `/etc/pam.d/su`, `/etc/pam.d/sudo`,
`/etc/pam.d/password-auth` (RHEL) or `/etc/pam.d/common-auth` (Debian).
Files that don't exist on the host are skipped. Every edit creates a
timestamped `.csm-backup-YYYYMMDDTHHMMSSZ` next to the original.

## Safety rails

- The `optional` control flag is mandatory: a CSM outage **must not**
  block authentication. `csm pam install` writes nothing else.
- Test from a **second** SSH session before closing the one that
  installed. If SSH or sudo breaks, rename the `.csm-backup-` file
  back over the broken target and run `csm pam uninstall --keep-module`
  on the live session.
- The PAM module never reads or modifies passwords, never decides
  whether to permit auth, and never writes to disk. It opens a Unix
  socket, writes one line, closes.

## Rebuild from source

The package ships the C source alongside the compiled module so
operators can rebuild on hosts with a different libc:

```bash
cd /usr/lib/csm/pam
make
sudo install -m 0755 pam_csm.so /lib64/security/pam_csm.so   # RHEL
# or
sudo install -m 0755 pam_csm.so /lib/x86_64-linux-gnu/security/pam_csm.so  # Debian
```

Requires `gcc` and `libpam-devel` (RHEL) or `libpam0g-dev` (Debian).

## Uninstall

```bash
sudo csm pam uninstall       # removes the two lines and the module
sudo csm pam uninstall --keep-module   # only edits, leave .so in place
```

Uninstall is idempotent and creates one fresh `.csm-backup-` per file
it edits. The PAM listener's dashboard verdict returns to **deaf** the
next time the dashboard polls.

## What the dashboard tells you

| Dashboard label   | Meaning                                                                  |
| ----------------- | ------------------------------------------------------------------------ |
| `ok`              | Attached AND has emitted at least one finding in the last 7 days.       |
| `idle`            | Attached, upstream alive, no recent findings (healthy quiet).            |
| `deaf`            | Attached, but no upstream process is feeding the watcher.                |
| `degraded`        | The watcher failed to attach on startup (config error, missing kernel). |

For the PAM listener specifically, `deaf` is the verdict whenever the
socket has not received a single connection in the last 24 hours and
the daemon has been up longer than the 15-minute grace window. Hover
the badge in the UI for the install hint.
