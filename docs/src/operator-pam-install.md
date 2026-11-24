# PAM hook for CSM

CSM learns about logins from a PAM module, `pam_csm.so`. The module emits authentication events, and the CSM daemon listens for them on `/var/run/csm/pam.sock`.

The package ships the module at `/usr/lib/csm/pam/pam_csm.so`. Until you install it into PAM, the daemon's PAM listener stays attached but never hears anything, and the dashboard reports the watcher as `deaf` after the startup grace period.

## Quick install

```bash
sudo csm pam install        # preview first with --dry-run
sudo csm pam status         # confirm
```

Test from a second SSH session before you close the one that ran the install. [Safety rails](#safety-rails) explains how to recover if a login breaks.

`csm pam status` shows whether failed logins are reported.

## Safety rails

- The `optional` control flag is mandatory: a CSM outage **must not** block authentication. The installer marks each CSM hook `optional`.
- Test from a second SSH session before closing the one that installed. If SSH or sudo breaks, rename the `.csm-backup-` file back over the broken target and run `csm pam uninstall --keep-module` on the live session.
- The PAM module never reads or modifies passwords, never decides whether to permit auth, and never writes to disk. It opens a Unix socket, writes one line, closes.

## What the installer changes

### Module and success hooks

`csm pam install` stages `pam_csm.so` into the platform's security directory: `/lib64/security` on RHEL, `/lib/x86_64-linux-gnu/security` on Debian. It then appends two lines to the standard service files. These report successful logins:

```
auth     optional   pam_csm.so # managed-by-csm
session  optional   pam_csm.so # managed-by-csm
```

The installer edits these files:

- `/etc/pam.d/sshd`
- `/etc/pam.d/su`
- `/etc/pam.d/sudo`
- `/etc/pam.d/password-auth` (RHEL) or `/etc/pam.d/common-auth` (Debian)

It skips files that do not exist on the host. Every edit creates a timestamped `.csm-backup-YYYYMMDDTHHMMSSZ` next to the original.

### Failure hook

Failed logins need one more line. A PAM module cannot see whether the modules before it accepted the password. So the failure hook goes where only a failed attempt arrives: directly before the terminal `pam_deny.so` of the shared auth stack. That stack is `password-auth` on RHEL and `common-auth` on Debian, and the standard remote login services include it:

```
auth     optional   pam_csm.so authfail # managed-by-csm
```

Each attempt that reaches this denial is reported once, whichever service ran it. Earlier failures that return before it are not reported by this hook.

The installer refuses this edit when it cannot prove the placement is safe. See [When the installer refuses the failure hook](#when-the-installer-refuses-the-failure-hook).

## What CSM does with login events

| Event | What CSM does |
|-------|---------------|
| Failed SSH login | Counts it toward the PAM brute-force and credential-stuffing findings. Blocking follows `auto_response.block_ips`. |
| Successful SSH login | Clears those failures. A successful login through another service does not clear them. |
| Failed login from another service | Raises the non-blocking `pam_auth_failures` alert. |
| Login from a loopback address | Ignores it. |

CSM reads pure-ftpd, Dovecot and Exim logs separately. Other services, such as vsftpd, proftpd or webmin, get no blocking signal from PAM.

### Keep `UseDNS no`

The module passes on the remote host that sshd reports. With `UseDNS yes` that is a host name, which CSM cannot track or block. The daemon logs that once and ignores those logins. Keep `UseDNS no`, the OpenSSH default.

## When to run the installer again

Run `csm pam install` again in these two cases:

- You upgraded a host that was installed before the failure hook existed. Such a host reports successful logins only. The new run adds the failure hook and leaves the existing lines alone.
- On Debian or Ubuntu, you ran `pam-auth-update --force`. It regenerates `common-auth` and drops every CSM line.

## Uninstall

```bash
sudo csm pam uninstall       # removes managed hooks and the module
sudo csm pam uninstall --keep-module   # only edits, leave .so in place
```

Uninstall is idempotent. It does the following:

- It removes only lines marked `# managed-by-csm`.
- It restores any jump count that install widened.
- It creates one fresh `.csm-backup-` per file it edits.
- It leaves files with no managed hooks alone.

Uninstalling the hook stops new events. The dashboard can still show activity from the last 24 hours.

Uninstall stops on a file it cannot edit safely. See [When uninstall stops](#when-uninstall-stops).

## What the dashboard tells you

| Dashboard label   | Meaning                                                                  |
| ----------------- | ------------------------------------------------------------------------ |
| `ok`              | Attached AND has emitted at least one finding in the last 7 days.       |
| `idle`            | Attached, upstream alive, no recent findings (healthy quiet).            |
| `deaf`            | Attached, but no upstream process is feeding the watcher.                |
| `degraded`        | The watcher failed to attach on startup (config error, missing kernel). |

For the PAM listener specifically, `deaf` is the verdict when both of these hold:

- The socket has not received a single connection in the last 24 hours.
- The daemon has been up longer than the 15-minute grace window.

Hover the badge in the UI for the install hint.

## Rebuild from source

The package ships the C source alongside the compiled module, so you can rebuild on hosts with a different libc:

```bash
cd /usr/lib/csm/pam
make
sudo install -m 0755 pam_csm.so /lib64/security/pam_csm.so   # RHEL
# or
sudo install -m 0755 pam_csm.so /lib/x86_64-linux-gnu/security/pam_csm.so  # Debian
```

The build requires `gcc` and `libpam-devel` (RHEL) or `libpam0g-dev` (Debian).

From a source checkout, `make -C build/pam check` runs the module through real libpam stacks. It writes test services under `/etc/pam.d`, so run it as root in a throwaway container.

## Details

This section is reference material for the failure hook's placement rules and for uninstall errors.

### Jumps that skip the denial

Some stacks hold a jump that skips `pam_deny.so` on success, such as Debian's `[success=1 default=ignore] pam_unix.so`. The installer widens that jump by one, so it skips the hook too. Uninstall narrows it back, including jumps to or past the end.

### When the installer refuses the failure hook

The installer refuses the failure-hook edit when it cannot prove the placement is safe. Any shared stack that refuses it makes the command exit non-zero, even if another stack was hooked. Success hooks may already have been added to service files or the shared stack.

Placement is refused in each of these cases:

- The stack is a symlink, which is how authselect manages it on RHEL 8 and later. See [authselect on RHEL 8 and later](#authselect-on-rhel-8-and-later).
- There is no single `required` or `requisite` `pam_deny.so` auth line.
- A jump crosses an `include`, `substack` or `@include` line, so its target cannot be counted.
- An auth `include` or `@include` comes before the denial. Its own jumps can escape into this stack.
- A `required` denial is followed by an auth `reset` action, or by an expanded auth include that could clear its failure.
- A jump cannot be adjusted within PAM's integer range.
- The file uses line continuations or syntax the editor cannot parse.

### authselect on RHEL 8 and later

authselect rewrites the shared auth stack file (`password-auth`) on its next run, so the hook needs a custom authselect profile. Add the failure-hook line shown in [Failure hook](#failure-hook) to that profile's `password-auth`, before `pam_deny.so`. Widen any jumps that skip the denial so they also skip the hook.

### When uninstall stops

Uninstall stops with an error naming the file, and leaves the file as it is, when an edited file has one of these:

- An uncountable jump.
- An auth include before the failure hook.
- Syntax it cannot parse.

Restore the backup, or remove the marked lines by hand and fix the jumps. Parse errors identify the line without printing its module arguments.
