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
on Debian) and appends two lines to the standard service files. These
report successful logins:

```
auth     optional   pam_csm.so # managed-by-csm
session  optional   pam_csm.so # managed-by-csm
```

Targets: `/etc/pam.d/sshd`, `/etc/pam.d/su`, `/etc/pam.d/sudo`,
`/etc/pam.d/password-auth` (RHEL) or `/etc/pam.d/common-auth` (Debian).
Files that don't exist on the host are skipped. Every edit creates a
timestamped `.csm-backup-YYYYMMDDTHHMMSSZ` next to the original.

Failed logins need one more line. A PAM module cannot see whether the
modules before it accepted the password, so the failure hook goes where
only a failed attempt arrives: directly before the terminal `pam_deny.so`
of the shared auth stack (`password-auth` on RHEL, `common-auth` on
Debian), which the standard remote login services include:

```
auth     optional   pam_csm.so authfail # managed-by-csm
```

A jump that skips `pam_deny.so` on success, such as Debian's
`[success=1 default=ignore] pam_unix.so`, is widened by one so it skips the
hook too; uninstall narrows it back, including jumps to or past the end.
Each attempt that reaches this denial is reported once, whichever service
ran it. Earlier failures that return before it are not reported by this
hook. SSH failures drive the PAM brute-force and credential-stuffing
findings; only a successful SSH login clears those failures. Blocking
follows `auto_response.block_ips`. Failures from other services raise the non-blocking `pam_auth_failures` alert, since those
services have their own log detectors.

The installer refuses the failure-hook edit when it cannot prove the
placement is safe. Any shared stack that refuses it makes the command
exit non-zero, even if another stack was hooked. Success hooks may already
have been added to service files or the shared stack. Placement is refused
when:

- the stack is a symlink, which is how authselect manages it on RHEL 8 and
  later. authselect rewrites the file on its next run, so the hook needs a
  custom authselect profile; add the line above to that profile's
  `password-auth` before `pam_deny.so`, widening any jumps that skip the
  denial so they also skip the hook.
- there is no single `required` or `requisite` `pam_deny.so` auth line.
- a jump crosses an `include`, `substack` or `@include` line, so its target
  cannot be counted. An auth `include` or `@include` before the denial is
  also refused because its own jumps can escape into this stack.
- a `required` denial is followed by an auth `reset` action or an expanded
  auth include that could clear its failure.
- a jump cannot be adjusted within PAM's integer range, or the file uses
  line continuations or syntax the editor cannot parse.

On Debian and Ubuntu, `pam-auth-update --force` regenerates
`common-auth` and drops every CSM line; run `csm pam install` again after
it. `csm pam status` shows whether failed logins are reported.

Hosts installed before the failure hook existed report successful logins
only. Run `csm pam install` again after upgrading; it adds the failure
hook and leaves the existing lines alone.

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

From a source checkout, `make -C build/pam check` runs the module through
real libpam stacks. It writes test services under `/etc/pam.d`, so run it
as root in a throwaway container.

## Uninstall

```bash
sudo csm pam uninstall       # removes managed hooks and the module
sudo csm pam uninstall --keep-module   # only edits, leave .so in place
```

Uninstall is idempotent, removes only lines marked `# managed-by-csm`,
restores any jump count install widened, and creates one fresh
`.csm-backup-` per file it edits. Files with no managed hooks are left alone.
If an edited file has an uncountable jump, an auth include before the
failure hook, or syntax it cannot parse, uninstall stops with an error
naming the file and leaves it as it is; restore the backup or remove the
marked lines by hand and fix the jumps. Parse errors identify the line
without printing its module arguments. The PAM listener's dashboard verdict
returns to **deaf** the next time the dashboard polls.

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
