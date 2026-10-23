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

The installer generates the unit for the systemd it finds. systemd 239 (EL8,
CloudLinux 8) does not know `ProtectHostname`, `ProtectKernelLogs` or
`ProtectClock`; it would log "Unknown lvalue" for each at every start and
ignore them, so the installer leaves them out there and prints which ones it
omitted. Newer systemd receives the full unit, identical to the packaged one.
A binary-swap upgrade keeps the existing unit; run `csm install` to regenerate
it.

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

## Parse worker units

The daemon reads tenant zip listings for the phishing-kit check in a separate
worker, started on demand as a transient unit with `systemd-run`. Each unit
gets these properties:

- `DynamicUser=yes`, `CapabilityBoundingSet=` (empty), `NoNewPrivileges=yes`;
- `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`;
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `PrivateDevices=yes`, `ProtectKernelTunables=yes`,
  `ProtectKernelModules=yes`, `ProtectControlGroups=yes`,
  `RestrictNamespaces=yes`, `RestrictRealtime=yes`,
  `MemoryDenyWriteExecute=yes`, `UMask=0077`;
- `SystemCallFilter=@system-service` and `SystemCallFilter=~personality`,
  with `SystemCallErrorNumber=EPERM`. The personality deny stands in for
  `LockPersonality=yes`, which `systemd-run` on systemd 239 rejects;
- `MemoryAccounting=yes`, `MemoryLimit=` and `MemoryMax=` set to the
  worker's memory cap, `MemorySwapMax=0`;
- `TasksMax=64`, `LimitNOFILE=256`, `LimitCORE=0`, `LimitFSIZE=` set above
  the largest listing, `CPUWeight=50`, and a one-hour `RuntimeMaxSec`.

The worker receives the zip as an open descriptor and returns entry names in
a sealed memfd. It cannot create IPv4 or IPv6 sockets. Unix sockets remain
available. `/home`, `/root` and `/run/user` are hidden; other account-home
locations are not. Most host files are read-only. The worker can still read
world-readable host files outside those directories and write in its private
temporary directories. The daemon does not forward its environment to the
unit; systemd supplies the service environment.

`MemoryLimit` caps RAM only on cgroup v1, so the daemon also writes
`memory.memsw.limit_in_bytes` in the unit's own memory cgroup, or
`memory.swappiness=0` where there is no swap accounting. On cgroup v2 it sets
`memory.swap.max` to 0, and refuses to use a worker on a host with swap on but
no swap accounting. The daemon can write those files because `csm.service`
has `ProtectControlGroups=no`. A worker whose memory cannot be capped or
measured gets no request, and the phishing check reports itself incomplete.
Without cgroup v2 swap accounting, the watchdog also checks that swap stays
off throughout the worker's lifetime.

The unit runs the daemon's own binary as its dynamic user, so the binary is
installed as mode 0711: others can execute it but not read it, and only root
can replace it. Its directories must be searchable by others. When they are
not, the daemon logs one line at startup, starts no worker, and the phishing
check reports itself incomplete.

Workers are killed by unit name with `systemctl kill`, never by a PID. If the
daemon dies, a worker waiting for a request reads end of file and exits. A
worker stuck parsing may remain until the lifetime cap stops it. At startup,
the daemon attempts to kill leftover `csm-parse-worker-*` units; cleanup
failures are logged and do not prevent startup.

`disabled_checks: [phishing]` disables scheduled phishing checks. Requested
account scans can still use the worker, and startup cleanup still runs.

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
