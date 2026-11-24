# Service configuration writes

The packaged and CLI-installed units use `ProtectSystem=strict`, so the CSM daemon sees most of the host as read-only. This page lists the directories the daemon can still write, how it saves its own configuration, and how the helper processes it starts are confined.

CSM remains a privileged root daemon. These restrictions reduce accidental and misdirected writes; see [Limits and validation](#limits-and-validation).

## Directories the daemon can write

The daemon can write these configuration directories when they exist:

| Directory | Runtime writer |
| --- | --- |
| `/etc/audit` | CSM audit rules and `augenrules` generated configuration |
| `/etc/modprobe.d` | Repair of an existing, opted-in AF_ALG mitigation marker |
| `/etc/apache2/conf.d` | cPanel Apache/LiteSpeed challenge snippet, virtual patches, and default overrides |
| `/etc/apache2/conf-enabled` | Debian Apache challenge snippet |
| `/etc/httpd/conf.d` | RHEL Apache challenge snippet |
| `/etc/nginx/conf.d` | Nginx challenge snippet |
| `/usr/local/apache/conf` | Legacy Apache virtual patches and overrides |
| `/usr/local/lsws/conf/templates` | Standalone LiteSpeed challenge template |

The unit also lets the daemon write its state, quarantine, account, spool and cPanel plugin paths. See [custom account roots](custom-account-roots.md) for account grants.

### When a directory does not exist yet

Optional directory grants tolerate absent software, so the unit starts on a host without that web server.

- Install the relevant web server before starting CSM.
- If you create a granted directory that was absent when CSM started, restart CSM.

### Custom ModSecurity override locations

A custom ModSecurity override location needs a drop-in that grants only its parent directory. Atomic replacement requires a directory grant. After adding the drop-in, run `systemctl daemon-reload` and `systemctl restart csm.service`.

### What the daemon cannot write

The daemon cannot write arbitrary files directly under `/etc`, SSH configuration, account databases, or systemd unit files.

Two AF_ALG changes happen outside the daemon's own write access:

- The operator's `csm harden` CLI installs the AF_ALG seccomp drop-in, outside the daemon.
- Periodic AF_ALG module removal uses a bounded transient service with fixed module names. The daemon retains `ProtectKernelModules=yes` and the module syscall restriction.

## How the daemon saves its configuration

The daemon cannot write `/etc/csm`. The package creates that directory with mode 0750. The daemon saves a configuration in these cases:

- Web UI settings.
- `csm baseline`.
- A firewall rollback.
- The re-sign after a reload.
- The verified fragment record at startup.

In each case the daemon hands the configuration, already signed, to `csm config-write`. That helper runs in a transient unit with `ProtectSystem=strict` and can write only the directory the configuration file resolves to.

### What the helper checks

Before writing anything, the helper rejects:

- a malformed configuration,
- an unsigned configuration,
- a fragment record that does not match its recorded hashes.

A rollback restores the signed snapshot unchanged and preserves the backup and the fragment record.

### When a save fails

| Case | Result |
| --- | --- |
| The configuration directory path holds whitespace, quotes, a backslash, `%` or `;` | The path cannot be named in a unit property, so saves there fail with an error. |
| The requested name or its resolved target is not a YAML file | The save is refused. Both must be YAML files. |
| A write fails | The failure reaches the operation that requested the save. |
| A rollback fails | The rollback keeps its pending recovery record and does not restart the daemon. |

Relative paths and legacy symlinks are resolved before the helper starts.

### Without systemd-run

When systemd-run is unavailable, the same helper runs directly with the caller's filesystem permissions. A read-only configuration directory still causes the save to fail. This fallback does not bypass the daemon's sandbox.

## The unit on older systemd

The installer generates the unit for the systemd it finds.

systemd 239 (EL8, CloudLinux 8) does not know `ProtectHostname`, `ProtectKernelLogs` or `ProtectClock`. It would log "Unknown lvalue" for each at every start and ignore them. The installer leaves them out there and prints which ones it omitted.

Newer systemd receives the full unit, identical to the packaged one.

A binary-swap upgrade keeps the existing unit. Run `csm install` to regenerate it.

## Exim transactions

The forward guard manages a block in the Exim configuration. To change it, the forward guard sends one bounded JSON request over stdin to its own executable, which runs as a helper in a transient service.

- The helper accepts only apply/remove operations and policy data. It accepts no paths, command names or shell programs.
- Applying or removing the managed Exim block, the cPanel rebuild, and rollback all run outside the daemon mount namespace.
- Operator configuration is preserved.
- Lookup refreshes remain under `/var/lib/csm` and do not rebuild Exim.
- The helper requires root.
- The helper's lifetime is bounded, and a failed command is never retried as an unsandboxed duplicate.

An exclusive process lock rejects overlapping config transactions without modifying Exim. The daemon reports the failure. You can reload after the earlier transaction finishes.

CSM's fixed Exim queue and query commands also run in transient services. If the systemd bus is unavailable, CSM runs the command directly, once. That run happens inside `csm.service`, so restricted writes fail and are reported.

A scope unit is unsuitable for this work because it inherits the calling process's sandbox.

## Parse worker units

The daemon hands two parsing jobs to separate workers:

- One worker reads tenant zip listings for the phishing-kit check.
- Mail workers unpack email attachments when email AV is on.

Each worker starts on demand as a transient unit with `systemd-run`. There is one unit for zip listings, and one per `email_av.scan_concurrency` slot for mail.

### Unit properties

Each unit gets these properties:

| Area | Properties |
| --- | --- |
| User and privileges | `DynamicUser=yes`, `CapabilityBoundingSet=` (empty), `NoNewPrivileges=yes` |
| Network | `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` |
| Lockdown | `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `MemoryDenyWriteExecute=yes`, `UMask=0077` |
| System calls | `SystemCallFilter=@system-service` and `SystemCallFilter=~personality`, with `SystemCallErrorNumber=EPERM` |
| Memory | `MemoryAccounting=yes`, `MemoryLimit=` and `MemoryMax=` set to the worker's memory cap, `MemorySwapMax=0` |
| Resource limits | `TasksMax=64`, `LimitNOFILE=256`, `LimitCORE=0`, `CPUWeight=50`, a one-hour `RuntimeMaxSec`, and `LimitFSIZE=` |
| Memory pressure | `OOMScoreAdjust=1000` and a `Slice=` of its own |
| Hidden paths | `InaccessiblePaths=-` for each account home volume that `ProtectHome=yes` does not cover |

Notes on single properties:

- The personality deny stands in for `LockPersonality=yes`, which `systemd-run` on systemd 239 rejects.
- `LimitFSIZE=` is 64 MiB for zip listings. For mail it is 1 MiB above `email_av.max_attachment_size`, and never below 64 MiB.
- `OOMScoreAdjust=1000` makes parse workers preferred victims under host memory pressure.
- `Slice=` is set to a slice of its own per unit name prefix, directly under `system.slice`. An example is `system-csm\x2dparse\x2dworker\x2dmail0.slice`.
- `InaccessiblePaths=-` covers the account roots outside `/home` (for example `/var/www/vhosts` on Plesk) and the sibling volumes registered cPanel accounts live on, such as `/home2`. The list is read once when the daemon sets up its workers, or when `csm scan` starts one.

### What a worker can reach

- A worker cannot create IPv4 or IPv6 sockets. Unix sockets remain available.
- `/home`, `/root`, `/run/user` and the account home volumes listed above are hidden. An account volume created after the daemon started is not hidden until the daemon restarts.
- Most host files are read-only. The worker can still read world-readable host files outside those directories and write in its private temporary directories.
- The daemon does not forward its environment to the unit. systemd supplies the service environment.

Input and output pass as open descriptors. The zip worker receives the zip as an open descriptor and returns entry names in a sealed memfd. A mail worker receives the message's spool header and body as open descriptors and returns each attachment in its own sealed memfd. The daemon scans those and closes them.

### Binary permissions

The unit runs the daemon's own binary as its dynamic user, so the binary is installed as mode 0711. Others can execute it but not read it, and only root can replace it.

Package, CLI and script installs set this mode under any umask and make the installation directory searchable by others. Its subdirectories keep their private modes. A rolled-back upgrade restores the previous mode.

### When a worker cannot be used

| Case | What CSM does |
| --- | --- |
| The binary or a directory above it is not executable by others | Logs one line at startup, raises a Critical `email_av_isolation_unavailable` finding, and starts no worker. |
| The worker's memory cannot be capped or measured | Sends the worker no request. See [Worker memory and swap caps](#worker-memory-and-swap-caps). |
| A unit fails to start | Raises the same finding, at most once an hour. See [Limit on the start-failure finding](#limit-on-the-start-failure-finding). |

In each case the phishing check reports itself incomplete, and mail is handled as an incomplete scan under `email_av.fail_mode`.

### Turning the workers off

`disabled_checks: [phishing]` disables scheduled phishing checks. Requested account scans can still use the worker, and startup cleanup still runs.

`email_av.enabled: false` starts no mail workers.

### How workers stop

Workers are killed by unit name with `systemctl kill`, never by a PID.

- If the daemon dies, a worker waiting for a request reads end of file and exits.
- A worker stuck parsing may remain until the lifetime cap stops it.
- At startup, the daemon attempts to kill leftover `csm-parse-worker-*` units. Cleanup failures are logged and do not prevent startup.
- A worker the daemon stops on purpose, such as at shutdown, is logged as `stopped` and never as a memory failure.

### PHP taint worker

The PHP taint worker runs in the same kind of unit, named `csm-phptaint-worker-<generation>`, with a 512 MiB memory cap and no file writes. At startup the daemon attempts to kill leftover `csm-phptaint-worker-*` units.

The binary's permissions are checked before each worker launch. If the dynamic user cannot execute it, the daemon logs why and candidate files are reported as not analyzed. The same happens when a unit fails to start or dies. These failures appear as `worker_failure` coverage gaps.

`disabled_checks: [php_taint_deep]` stops new analyses. Startup cleanup still runs.

### YARA-X workers

YARA-X runs in two units of the same kind.

| Unit | Job | Memory cap |
| --- | --- | --- |
| `csm-yara-compile-worker-<generation>` | Runs each rule compile, from rule text the daemon passes in memory. The compiler cannot open include files. | 1 GiB |
| `csm-yara-worker-<generation>` | Runs scans, with no file writes and the compiled rules loaded from memory. There is one scan worker. | 512 MiB plus a file allowance, see below |

The scan worker's file allowance is `thresholds.full_scan_max_file_mb`. With mail scanning on, it is the larger of that value and `email_av.max_attachment_size`. A reload that changes the file cap applies to the next scan worker.

Both units allow executable memory, which YARA-X needs for its compiled rules. The other lockdown properties are unchanged. At startup the daemon attempts to kill leftover units of both kinds.

While no worker can scan, files and mail attachments are reported as not scanned by YARA, never as clean.

`signatures.yara_worker_enabled: false` runs YARA-X inside the daemon as root instead. `csm validate` warns about it.

### Workers started by `csm scan`

The in-process `csm scan <user>` command starts its own worker on demand. Its unit prefix includes the CLI process ID, so concurrent scans use distinct slices and cannot attribute another scan's OOM kill to their own worker.

The scan report warns when worker setup, startup or archive listing fails, even if later archives are checked successfully. A scan with unchecked archives does not report the account as clean.

## Limits and validation

These restrictions reduce accidental and misdirected writes. They are not a complete boundary against arbitrary code execution as root.

- CSM remains a privileged root daemon. fanotify, firewall administration, BPF, process inspection and remediation require elevated privileges.
- The unit retains its current capabilities.
- Root access to the system bus permits transient services.

Reducing capabilities, or separating privileged operations behind a separately permissioned broker, requires its own feature and kernel compatibility review.

### How the sandbox is tested

`scripts/systemd-account-roots-test.sh` runs the actual packaged sandbox in a disposable systemd environment. It checks:

- that unrelated `/etc` writes return `EROFS`,
- atomic replacement in a managed directory,
- ModSecurity overrides,
- Exim helper apply/remove/rollback, using a fixed command fixture,
- account quarantine, restore and process signaling.

The Exim fixture validates the helper transport and filesystem behavior. It does not validate a real cPanel rebuild. The [cPanel release tests](cpanel-release-tests.md) exercise real daemon restarts. They require a licensed image and a live run to establish that platform's acceptance.

## Details

The sections below are reference material for edge cases of the helper and worker units.

### Configuration helper unit

The `csm config-write` unit does not declare `ConfigurationDirectory=`, because systemd binds that directory writable even under `ProtectSystem=strict`.

The helper keeps the host temporary directories visible, so configurations there remain reachable. Only the resolved configuration directory is writable.

### Worker slices and CPU weight

Before launching a worker, CSM sets its slice's runtime `CPUWeight=50` through systemd. CPU weights compare siblings, so the service's weight alone would not limit its share against the daemon outside that slice.

Slice setup shares the worker's startup timeout, and a failure prevents the launch.

The slices stay after their units end. They contain no processes but retain their accounting metadata. Empty slices and their runtime settings remain until reboot.

On cgroup v2, a replacement worker waits for earlier units in its slice to disappear before taking the slice's OOM snapshot. If they outlive the startup timeout, the replacement gets no request and reports a startup failure.

### Worker memory and swap caps

On cgroup v1 `MemoryLimit` caps RAM only, so the daemon also limits swap itself.

| Host | What the daemon does |
| --- | --- |
| cgroup v1 with swap accounting | Writes `memory.memsw.limit_in_bytes` in the unit's own memory cgroup. |
| cgroup v1 without swap accounting | Writes `memory.swappiness=0` there. |
| cgroup v2 | Sets `memory.swap.max` to 0. |
| cgroup v2 with swap on but no swap accounting | Refuses to use a worker. |

The daemon can write those files because `csm.service` has `ProtectControlGroups=no`.

Without cgroup v2 swap accounting, the watchdog also checks that swap stays off throughout the worker's lifetime.

### Worker log output

A worker's standard error reaches the daemon's log through a pipe, never directly.

- Each line is cut to 512 bytes and quoted, so control characters and newlines cannot forge log lines.
- At most 256 lines or 64 KiB of log entries are logged per worker unit. After that one "further output dropped" line is logged and the rest is discarded.
- Error text in a worker's reply is quoted the same way.
- When the launcher exits, final diagnostics drain for at most one second. The log reader then closes even if another process still holds its writer.

### Limit on the start-failure finding

Failed unit starts raise `email_av_isolation_unavailable` at most once an hour.

- This includes starts refused because the daemon has exhausted its descriptors. Those failures do not make CSM pause worker restarts (the worker breaker).
- Mail and zip workers share one hourly allowance. It carries over when the daemon restarts its mail spool watcher.
- A finding rejected by a full alert queue leaves the allowance available for a retry.
