package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
		"ProtectHome=no",
		"PrivateDevices=no",
		"ProtectKernelTunables=yes",
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
		"ProtectKernelTunables=no",
		"ProtectKernelLogs=yes",
		"AF_PACKET",
		"~@debug",
		// The read-only home mode is not overridable by the writable /home
		// grant. It breaks quarantine and error-log truncation, so the
		// generated unit must not set that mode.
		"ProtectHome=read-only",
	} {
		if strings.Contains(unit, bad) {
			t.Errorf("systemd unit still contains %q", bad)
		}
	}

	rwPaths := unitDirectiveFields(unit, "ReadWritePaths")
	for _, want := range []string{
		"/var/lib/csm",
		// Tolerate-absent: FHS installs never create /opt/csm/state, and an
		// unprefixed grant fails systemd's namespace setup.
		"-/opt/csm/state",
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
		"-/var/log/exim_mainlog",
		"-/var/log/exim_paniclog",
		"-/var/log/exim_rejectlog",
		"-/var/log/exim4",
		// KernelCare cache dir: the af_alg Copy Fail probe runs
		// "kcarectl --patch-info", which writes its feature-flags cache
		// here. Without the grant kcarectl floods the journal with EROFS
		// failures on every daemon start.
		"-/var/cache/kcare",
	} {
		if !rwPaths[want] {
			t.Errorf("ReadWritePaths missing %s", want)
		}
	}
	for path := range rwPaths {
		cleanPath := strings.TrimPrefix(path, "-")
		if cleanPath == "/root" || strings.HasPrefix(cleanPath, "/root/") {
			t.Errorf("ReadWritePaths must not make root home writable: %s", path)
		}
		if cleanPath == "/run/user" || strings.HasPrefix(cleanPath, "/run/user/") {
			t.Errorf("ReadWritePaths must not make user runtime homes writable: %s", path)
		}
	}

	allowedVarLogWritePaths := map[string]bool{
		"/var/log/csm":             true,
		"-/var/log/exim_mainlog":   true,
		"-/var/log/exim_paniclog":  true,
		"-/var/log/exim_rejectlog": true,
		"-/var/log/exim4":          true,
	}
	for path := range rwPaths {
		cleanPath := strings.TrimPrefix(path, "-")
		if cleanPath != "/var/log" && !strings.HasPrefix(cleanPath, "/var/log/") {
			continue
		}
		if !allowedVarLogWritePaths[path] {
			t.Errorf("ReadWritePaths grants unexpected /var/log path %s", path)
		}
		if strings.Contains(cleanPath, "*") {
			t.Errorf("ReadWritePaths must not rely on unsupported glob %s", path)
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

func TestSystemdServiceUnitKeepsKcareGrantNarrow(t *testing.T) {
	unit := systemdServiceUnit("/opt/csm/csm")
	rwPaths := unitDirectiveFields(unit, "ReadWritePaths")

	if !rwPaths["-/var/cache/kcare"] {
		t.Fatal("ReadWritePaths must tolerate an absent KernelCare cache dir")
	}
	if rwPaths["/var/cache/kcare"] {
		t.Error("ReadWritePaths must not require the KernelCare cache dir to exist")
	}

	for path := range rwPaths {
		cleanPath := strings.TrimPrefix(path, "-")
		if cleanPath == "/proc" || strings.HasPrefix(cleanPath, "/proc/") ||
			cleanPath == "/sys" || strings.HasPrefix(cleanPath, "/sys/") {
			t.Errorf("ReadWritePaths must not reopen kernel tunables: %s", path)
		}
		if cleanPath == "/var/cache" || strings.HasPrefix(cleanPath, "/var/cache/") {
			if path != "-/var/cache/kcare" {
				t.Errorf("ReadWritePaths grants unexpected cache path %s", path)
			}
		}
	}
}

func TestSystemdServiceUnitRequiresOnlyPackagedWritablePaths(t *testing.T) {
	unit := systemdServiceUnit("/opt/csm/csm")
	rwPaths := unitDirectiveFields(unit, "ReadWritePaths")
	packagedPaths := packagedContentPaths(t)
	hostProvidedPaths := map[string]bool{
		"/etc":     true,
		"/tmp":     true,
		"/var/tmp": true,
	}
	systemdCreatedPaths := map[string]bool{
		"/etc/csm":     true,
		"/var/lib/csm": true,
		"/var/log/csm": true,
	}

	for path := range rwPaths {
		if strings.HasPrefix(path, "-") {
			continue
		}
		if _, ok := hostProvidedPaths[path]; ok {
			continue
		}
		if _, ok := systemdCreatedPaths[path]; ok {
			continue
		}
		if packageProvidesPath(packagedPaths, path) {
			continue
		}
		t.Errorf("unprefixed ReadWritePaths entry %s is not guaranteed to exist before sandbox setup", path)
	}
}

func TestSystemdServiceUnitToleratesAbsentLegacyStateDir(t *testing.T) {
	// The legacy /opt/csm/state grant must be tolerate-absent ("-" prefix).
	// FHS installs default state_path to /var/lib/csm/state and never create
	// /opt/csm/state; the package ships every other /opt/csm grant as a dir
	// but not this one. An unprefixed grant makes systemd fail the mount
	// namespace setup (status=226/NAMESPACE) when the dir is missing, so the
	// daemon cannot start. Regression test for issue #28.
	unit := systemdServiceUnit("/opt/csm/csm")
	rwPaths := unitDirectiveFields(unit, "ReadWritePaths")

	if !rwPaths["-/opt/csm/state"] {
		t.Error("ReadWritePaths must tolerate an absent legacy /opt/csm/state dir")
	}
	if rwPaths["/opt/csm/state"] {
		t.Error("ReadWritePaths must not require the legacy /opt/csm/state dir to exist")
	}
}

func packagedContentPaths(t *testing.T) []string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "build", "nfpm.yaml"))
	if err != nil {
		t.Fatalf("read nfpm package manifest: %v", err)
	}
	var manifest struct {
		Contents []struct {
			Dst string `yaml:"dst"`
		} `yaml:"contents"`
	}
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("parse nfpm package manifest: %v", err)
	}
	paths := make([]string, 0, len(manifest.Contents))
	for _, entry := range manifest.Contents {
		if entry.Dst != "" {
			paths = append(paths, strings.TrimRight(entry.Dst, "/"))
		}
	}
	return paths
}

func packageProvidesPath(packagedPaths []string, path string) bool {
	for _, packagedPath := range packagedPaths {
		if packagedPath == path || strings.HasPrefix(packagedPath, path+"/") {
			return true
		}
	}
	return false
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
