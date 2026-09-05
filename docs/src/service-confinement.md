# Service configuration writes

The packaged and CLI-installed units use `ProtectSystem=strict`. The daemon can
write these configuration directories when they exist:

| Directory | Runtime writer |
| --- | --- |
| `/etc/csm` | CSM configuration and fragments |
| `/etc/audit` | CSM audit rules and `augenrules` generated configuration |
| `/etc/modprobe.d` | Repair of an existing, opted-in AF_ALG mitigation marker |
| `/etc/apache2/conf.d` | cPanel Apache/LiteSpeed challenge snippet, virtual patches, and default overrides |
| `/etc/apache2/conf-enabled` | Debian Apache challenge snippet |
| `/etc/httpd/conf.d` | RHEL Apache challenge snippet |
| `/etc/nginx/conf.d` | Nginx challenge snippet |
| `/usr/local/apache/conf` | Legacy Apache virtual patches and overrides |
| `/usr/local/lsws/conf/templates` | Standalone LiteSpeed challenge template |

The other state, quarantine, account, spool and cPanel plugin grants remain in
place. Optional directory grants tolerate absent software. Install the relevant
web server before starting CSM; restart CSM after creating a previously absent
granted directory. Custom ModSecurity override locations require a drop-in that
grants only their parent directory, followed by `systemctl daemon-reload` and
`systemctl restart csm.service`. Atomic replacement requires a directory grant.
See [custom account roots](custom-account-roots.md) for account grants.

The daemon cannot write arbitrary files directly under `/etc`, SSH configuration,
account databases, or systemd unit files. The AF_ALG seccomp drop-in is installed
by the operator's `csm harden` CLI, outside the daemon. Periodic AF_ALG module
removal uses a bounded transient service with fixed module names; the daemon
retains `ProtectKernelModules=yes` and the module syscall restriction.

## Exim transactions

The forward guard sends one bounded JSON request over stdin to its own executable
in a transient service. The helper accepts only apply/remove operations and policy
data. It accepts no paths, command names or shell programs. Applying or removing
the managed Exim block, the cPanel rebuild, and rollback all run outside the
daemon mount namespace. Operator configuration is preserved. Lookup refreshes
remain under `/var/lib/csm` and do not rebuild Exim.

The helper requires root. An exclusive process lock rejects overlapping config
transactions without modifying Exim; the daemon reports the failure, and the
operator can reload after the earlier transaction finishes. Its lifetime is bounded, and a failed command is never
retried as an unsandboxed duplicate. Existing fixed Exim queue/query operations
also use transient services. If the systemd bus is unavailable, the existing
wrapper attempts direct execution once; inside the service, restricted writes
then fail and are reported. A scope unit is unsuitable because it inherits the
calling process's sandbox.

## Limits and validation

These restrictions reduce accidental and misdirected writes. CSM remains a
privileged root daemon: fanotify, firewall administration, BPF, process inspection
and remediation require elevated privileges. The unit retains its current
capabilities, and root access to the system bus permits transient services.
This is not a complete boundary against arbitrary code execution as root.
Reducing capabilities or separating privileged operations behind a separately
permissioned broker requires its own feature and kernel compatibility review.

`scripts/systemd-account-roots-test.sh` runs the actual packaged sandbox in a
disposable systemd environment. It checks unrelated `/etc` writes return `EROFS`,
managed directory atomic replacement, ModSecurity overrides, and Exim helper
apply/remove/rollback using a fixed command fixture. It also exercises account
quarantine, restore and process signaling. The Exim fixture validates the helper
transport and filesystem behavior; it does not validate a real cPanel rebuild.
The [cPanel release tests](cpanel-release-tests.md) exercise real daemon restarts and require a licensed image
and a live run to establish that platform's acceptance.
