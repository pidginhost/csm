package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagedSystemdUnitMatchesInstallerUnit(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "build", "packaging", "systemd", "csm.service"))
	if err != nil {
		t.Fatalf("read packaged unit: %v", err)
	}
	if got, want := string(body), systemdServiceUnit("/opt/csm/csm"); got != want {
		t.Fatalf("packaged systemd unit diverged from installer unit\npackaged:\n%s\ninstaller:\n%s", got, want)
	}
}

func TestSystemdServiceUnitKeepsDaemonRuntimeAccess(t *testing.T) {
	unit := systemdServiceUnit("/opt/csm/csm")

	for _, want := range []string{
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=read-only",
		"PrivateDevices=no",
		"ProtectKernelLogs=no",
		"PrivateTmp=no",
		"ProtectControlGroups=no",
		"SystemCallErrorNumber=EPERM",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("systemd unit missing %q", want)
		}
	}

	for _, bad := range []string{
		"PrivateDevices=yes",
		"ProtectKernelLogs=yes",
		"AF_PACKET",
		"~@debug",
	} {
		if strings.Contains(unit, bad) {
			t.Errorf("systemd unit still contains %q", bad)
		}
	}

	rwPaths := unitDirectiveFields(unit, "ReadWritePaths")
	for _, want := range []string{
		"/var/lib/csm",
		"/opt/csm/state",
		"/etc",
		"/var/log/csm",
		"/etc/csm",
		"/opt/csm/quarantine",
		"/opt/csm/policies",
		"/opt/csm/rules",
		"-/opt/csm/deploy.sh",
		"-/home",
		"/tmp",
		"/var/tmp",
		"-/dev/shm",
		"-/usr/local/apache/conf",
		"-/usr/local/cpanel/whostmgr/docroot/cgi",
		"-/var/cpanel",
		"-/var/spool/cron",
		"-/var/spool/exim/input",
		"-/var/spool/exim4/input",
	} {
		if !rwPaths[want] {
			t.Errorf("ReadWritePaths missing %s", want)
		}
	}

	families := unitDirectiveFields(unit, "RestrictAddressFamilies")
	for _, want := range []string{"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"} {
		if !families[want] {
			t.Errorf("RestrictAddressFamilies missing %s", want)
		}
	}
	if families["AF_PACKET"] {
		t.Error("RestrictAddressFamilies includes unused AF_PACKET")
	}

	syscalls := unitDirectiveFields(unit, "SystemCallFilter")
	for _, want := range []string{
		"clone",
		"clone3",
		"execve",
		"execveat",
		"mmap",
		"bpf",
		"perf_event_open",
		"fanotify_init",
		"fanotify_mark",
		"inotify_init",
		"inotify_init1",
		"inotify_add_watch",
		"inotify_rm_watch",
	} {
		if !syscalls[want] {
			t.Errorf("SystemCallFilter missing %s", want)
		}
	}
}

func unitDirectiveFields(unit, key string) map[string]bool {
	prefix := key + "="
	out := make(map[string]bool)
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		for _, field := range strings.Fields(strings.TrimPrefix(line, prefix)) {
			out[field] = true
		}
	}
	return out
}
