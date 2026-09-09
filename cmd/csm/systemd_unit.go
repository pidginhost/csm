package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// systemdDirectiveSince lists the sandbox directives that older systemd
// rejects with "Unknown lvalue" at every start, keyed by the release that
// introduced each. EL8 and CloudLinux 8 ship 239.
var systemdDirectiveSince = []struct {
	name  string
	since int
}{
	{"ProtectHostname", 242},
	{"ProtectKernelLogs", 244},
	{"ProtectClock", 245},
}

// unsupportedSystemdDirectives returns the directives a systemd of the given
// version does not know, oldest first. Version 0 means unknown and keeps
// every directive: a warning is cheaper than a missing protection.
func unsupportedSystemdDirectives(version int) []string {
	if version <= 0 {
		return nil
	}
	var out []string
	for _, d := range systemdDirectiveSince {
		if version < d.since {
			out = append(out, d.name)
		}
	}
	return out
}

// parseSystemdVersion reads the major version from `systemctl --version`
// output ("systemd 239 (239-82.el8_10.19)"). Anything unparseable is 0.
func parseSystemdVersion(out string) int {
	line, _, _ := strings.Cut(out, "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "systemd" {
		return 0
	}
	v, err := strconv.Atoi(fields[1])
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

// detectSystemdVersion asks the running systemd for its version; 0 when it
// cannot be determined, which keeps the full unit.
func detectSystemdVersion() int {
	out, err := exec.Command("systemctl", "--version").Output()
	if err != nil {
		return 0
	}
	return parseSystemdVersion(string(out))
}

// systemdServiceUnitFor renders the unit for a host running the given
// systemd version, leaving out the directives that version rejects together
// with the comment lines that explain them. The packaged unit stays the full
// one; only the installer's generated copy is trimmed.
func systemdServiceUnitFor(binaryPath string, systemdVersion int) string {
	full := systemdServiceUnit(binaryPath)
	drop := unsupportedSystemdDirectives(systemdVersion)
	if len(drop) == 0 {
		return full
	}
	var out []string
	var pendingComments []string
	for _, line := range strings.Split(full, "\n") {
		if strings.HasPrefix(line, "#") {
			pendingComments = append(pendingComments, line)
			continue
		}
		dropped := false
		for _, name := range drop {
			if strings.HasPrefix(line, name+"=") {
				dropped = true
				break
			}
		}
		if dropped {
			pendingComments = nil
			continue
		}
		out = append(out, pendingComments...)
		pendingComments = nil
		out = append(out, line)
	}
	out = append(out, pendingComments...)
	return strings.Join(out, "\n")
}

func systemdServiceUnit(binaryPath string) string {
	return fmt.Sprintf(`[Unit]
Description=CSM - Continuous Security Monitor Daemon
After=network.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=%s daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
TimeoutStartSec=120
WatchdogSec=300
# Let the daemon stop its workers before systemd kills remaining processes.
# A cgroup-wide SIGTERM can reach a worker before the daemon enters shutdown.
KillMode=mixed

StateDirectory=csm
StateDirectoryMode=0700
RuntimeDirectory=csm
RuntimeDirectoryMode=0755
# The challenge maps the web servers read (Apache/LSWS RewriteMap, nginx map
# include) are part of the web server's configuration: Apache validates them
# at parse time and nginx fails on a missing include. They must outlive
# csm.service (package upgrades, restores, reboots), so they live in the cache
# directory, which systemd keeps across stops, not the runtime directory it
# deletes on every stop.
CacheDirectory=csm
CacheDirectoryMode=0755
ConfigurationDirectory=csm
ConfigurationDirectoryMode=0750
LogsDirectory=csm
LogsDirectoryMode=0750

# Sandboxing. CSM runs as root because fanotify, BPF cgroup attach, and
# firewall mutation all need root capabilities. Everything below restricts
# the blast radius of a compromised daemon without dropping the privileges
# the legitimate workload needs.
NoNewPrivileges=yes
ProtectSystem=strict
# Home isolation remains disabled: the daemon must write under /home to
# quarantine malware and truncate bloated account error_logs (Performance >
# Empty log file). The read-only home mode is enforced after writable path
# grants, so it would still leave /home read-only. ProtectSystem=strict keeps
# paths outside explicit writable grants read-only; only the explicit -/home
# grant below reopens account home directories. Custom roots need the
# validated drop-in printed by csm systemd-roots.
ProtectHome=no
# -/opt/csm/state (tolerate-absent) covers installs that still pin the legacy
# state_path (state_path: /opt/csm/state) instead of the FHS default
# /var/lib/csm/state; without the grant the bbolt state db is read-only under
# ProtectSystem=strict. The "-" is required: FHS installs never create this
# dir (the package ships every other /opt/csm grant but not this one), and an
# unprefixed grant makes systemd fail the namespace setup (226/NAMESPACE) so
# the daemon cannot start.
ReadWritePaths=/var/lib/csm -/opt/csm/state /var/log/csm -/var/log/csm-php-shield /etc/csm /opt/csm/quarantine /opt/csm/policies
ReadWritePaths=/opt/csm/rules -/opt/csm/deploy.sh -/home /tmp /var/tmp -/dev/shm
# Configuration writes stay within managed subsystem directories. Exim's
# atomic config update and rebuild run together in a fixed-purpose transient
# service; the daemon does not need write access to the whole /etc directory.
ReadWritePaths=-/etc/audit -/etc/modprobe.d
ReadWritePaths=-/etc/apache2/conf.d -/etc/apache2/conf-enabled -/etc/httpd/conf.d -/etc/nginx/conf.d
ReadWritePaths=-/usr/local/apache/conf -/usr/local/lsws/conf/templates
ReadWritePaths=-/usr/local/cpanel/whostmgr/docroot/cgi -/var/cpanel
ReadWritePaths=-/var/spool/cron -/var/spool/exim/input -/var/spool/exim4/input
# NOTE: exim log grants deliberately removed. Exim opens its main/panic logs
# and aborts even for a read-only query like "exim -bpc", so the queue probe
# used to need them writable. File-scoped (non-directory) ReadWritePaths
# entries are silently ignored by systemd 239 (EL8/CloudLinux 8), which left
# the grant a no-op and every queue probe failing with "Cannot open main log
# file" -- unnoticed, because the check reported nothing on error. CSM now runs
# exim queries through systemd-run as a transient unit forked by PID 1, outside
# this sandbox, so no /var/log write access is needed here at all.
# CSM's af_alg check runs "kcarectl --patch-info" to detect a Copy Fail
# (CVE-2026-31431) KernelCare livepatch. kcarectl rewrites its feature-flags
# cache under /var/cache/kcare on every run; when that write is blocked it
# floods the journal with EROFS failures and retries kernel-tunable writes
# (also blocked by ProtectKernelTunables) at each daemon start. Granting the
# cache dir lets kcarectl run as it does outside the sandbox -- silently --
# without relaxing any kernel-tunable protection. "-" tolerates hosts that do
# not have KernelCare installed (Ubuntu/AlmaLinux without kcare).
ReadWritePaths=-/var/cache/kcare
# CSM inspects the host's real /dev/shm; a private /dev would hide it.
PrivateDevices=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
# Performance checks read dmesg for recent OOM kills.
ProtectKernelLogs=no
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RemoveIPC=yes
# /tmp scanning needs the host's real /tmp so PrivateTmp must stay off.
PrivateTmp=no
# BPF cgroup-sock attach writes to cgroupfs, so cgroup access must remain
# writable. Leaving ProtectControlGroups disabled is intentional.
ProtectControlGroups=no
# AF_UNIX for the control socket, AF_INET/AF_INET6 for HTTP and outbound
# threat-intel, AF_NETLINK for nftables.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service @network-io @file-system
SystemCallFilter=bpf fanotify_init fanotify_mark inotify_init inotify_init1 inotify_add_watch inotify_rm_watch perf_event_open
SystemCallFilter=clone clone3 execve execveat fork vfork mmap mprotect munmap mremap brk
SystemCallFilter=pidfd_open pidfd_send_signal
# One "~" negates the whole line; repeating it per entry makes systemd
# read "~@swap" as a syscall NAME, fail to parse it, and drop it.
SystemCallFilter=~@reboot @swap @module @raw-io @mount @cpu-emulation
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`, binaryPath)
}
