package main

import "fmt"

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

StateDirectory=csm
StateDirectoryMode=0700
RuntimeDirectory=csm
RuntimeDirectoryMode=0755
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
ProtectHome=read-only
# /opt/csm/state covers installs that still pin the legacy state_path
# (state_path: /opt/csm/state) instead of the FHS default /var/lib/csm/state;
# without it the bbolt state db is read-only under ProtectSystem=strict and the
# daemon cannot start.
ReadWritePaths=/var/lib/csm /opt/csm/state /var/log/csm /etc/csm /opt/csm/quarantine /opt/csm/policies
ReadWritePaths=/opt/csm/rules -/opt/csm/deploy.sh -/home /tmp /var/tmp -/dev/shm
# /etc: CSM atomically maintains the forward-guard router/transport in
# /etc/exim.conf.local. The temp file must be a sibling in /etc, so a
# file-scoped grant is not enough. The heavyweight cPanel rebuild
# (buildeximconf) runs as a separate transient systemd service and is not
# limited by csm.service's sandbox; the daemon only needs /etc for the atomic
# write above.
ReadWritePaths=/etc -/usr/local/apache/conf
ReadWritePaths=-/usr/local/cpanel/whostmgr/docroot/cgi -/var/cpanel
ReadWritePaths=-/var/spool/cron -/var/spool/exim/input -/var/spool/exim4/input
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
SystemCallFilter=~@reboot ~@swap ~@module ~@raw-io ~@mount ~@cpu-emulation
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`, binaryPath)
}
