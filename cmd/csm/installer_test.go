package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"gopkg.in/yaml.v3"
)

func TestImmutableUnsupportedClassifiesFilesystemErrors(t *testing.T) {
	for _, out := range []string{
		"chattr: Operation not supported while setting flags on /opt/csm/csm",
		"chattr: Inappropriate ioctl for device while reading flags on /opt/csm/csm",
	} {
		if !immutableUnsupported([]byte(out)) {
			t.Errorf("immutableUnsupported(%q) = false, want true", out)
		}
	}
	for _, out := range []string{
		"chattr: Permission denied while setting flags on /opt/csm/csm",
		"",
	} {
		if immutableUnsupported([]byte(out)) {
			t.Errorf("immutableUnsupported(%q) = true, want false", out)
		}
	}
}

func TestInstallToleratesUnsupportedImmutableFilesystem(t *testing.T) {
	root := t.TempDir()
	inst := &Installer{
		BinaryPath:  filepath.Join(root, "opt", "csm", "csm"),
		CommandPath: filepath.Join(root, "usr", "sbin", "csm"),
		ConfigPath:  filepath.Join(root, "etc", "csm", "csm.yaml"),
		StatePath:   filepath.Join(root, "var", "lib", "csm", "state"),
		LogPath:     filepath.Join(root, "var", "log", "csm", "monitor.log"),
		operations: &installerOperations{
			getuid:          func() int { return 0 },
			deployAuditd:    func() error { return nil },
			deploySystemd:   func() error { return nil },
			deployLogrotate: func() error { return nil },
			setImmutable:    func(string, bool) error { return fmt.Errorf("%w: overlayfs", errImmutableUnsupported) },
		},
	}
	if err := inst.Install(); err != nil {
		t.Fatalf("unsupported immutable filesystem aborted install: %v", err)
	}
}

func TestInstallStillFailsOnGenuineImmutableError(t *testing.T) {
	root := t.TempDir()
	inst := &Installer{
		BinaryPath:  filepath.Join(root, "opt", "csm", "csm"),
		CommandPath: filepath.Join(root, "usr", "sbin", "csm"),
		ConfigPath:  filepath.Join(root, "etc", "csm", "csm.yaml"),
		StatePath:   filepath.Join(root, "var", "lib", "csm", "state"),
		LogPath:     filepath.Join(root, "var", "log", "csm", "monitor.log"),
		operations: &installerOperations{
			getuid:          func() int { return 0 },
			deployAuditd:    func() error { return nil },
			deploySystemd:   func() error { return nil },
			deployLogrotate: func() error { return nil },
			setImmutable:    func(string, bool) error { return errors.New("permission denied") },
		},
	}
	err := inst.Install()
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("Install error = %v, want genuine immutable failure", err)
	}
}

func TestUninstallToleratesUnsupportedImmutableClear(t *testing.T) {
	root := t.TempDir()
	binPath := filepath.Join(root, "csm")
	if err := os.WriteFile(binPath, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	var removedBinary bool
	inst := &Installer{
		BinaryPath:  binPath,
		CommandPath: filepath.Join(root, "cmd"),
		ConfigPath:  filepath.Join(root, "csm.yaml"),
		StatePath:   filepath.Join(root, "state"),
		LogPath:     filepath.Join(root, "log", "monitor.log"),
		operations: &installerOperations{
			getuid:           func() int { return 0 },
			runCommand:       func(string, ...string) error { return nil },
			daemonLive:       func() bool { return false },
			setImmutable:     func(string, bool) error { return fmt.Errorf("%w: overlayfs", errImmutableUnsupported) },
			removeAuditd:     func() error { return nil },
			acquireStateLock: func(string) (func(), error) { return func() {}, nil },
			glob:             func(string) ([]string, error) { return nil, nil },
			remove: func(path string) error {
				if path == binPath {
					removedBinary = true
				}
				return nil
			},
			removeAll: func(string) error { return nil },
		},
	}
	if err := inst.Uninstall(false); err != nil {
		t.Fatalf("unsupported immutable clear aborted uninstall: %v", err)
	}
	if !removedBinary {
		t.Fatal("uninstall did not proceed to remove the binary")
	}
}

func TestParseInstallFlags(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		phpShield   bool
		phpOnly     bool
		packageMode bool
	}{
		{name: "none", args: []string{"csm", "install"}},
		{name: "php-shield", args: []string{"csm", "install", "--php-shield"}, phpShield: true},
		{name: "php-shield-only", args: []string{"csm", "install", "--php-shield-only"}, phpOnly: true},
		{name: "package-mode", args: []string{"csm", "install", "--package-mode"}, packageMode: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			phpShield, phpOnly, packageMode := parseInstallFlags(tc.args)
			if phpShield != tc.phpShield || phpOnly != tc.phpOnly || packageMode != tc.packageMode {
				t.Fatalf("parseInstallFlags(%v) = (%t, %t, %t), want (%t, %t, %t)",
					tc.args, phpShield, phpOnly, packageMode, tc.phpShield, tc.phpOnly, tc.packageMode)
			}
		})
	}
}

func TestParseUninstallFlags(t *testing.T) {
	if purge, err := parseUninstallFlags([]string{"csm", "uninstall"}); err != nil || purge {
		t.Fatalf("default uninstall = purge %t, error %v; want preserve", purge, err)
	}
	if purge, err := parseUninstallFlags([]string{"csm", "uninstall", "--purge"}); err != nil || !purge {
		t.Fatalf("purge uninstall = purge %t, error %v; want purge", purge, err)
	}
	if _, err := parseUninstallFlags([]string{"csm", "uninstall", "--force"}); err == nil {
		t.Fatal("unknown uninstall flag must fail")
	}
}

func TestResolveUninstallStorageUsesConfiguredStateWithoutPurge(t *testing.T) {
	cfg := &config.Config{
		ConfigFile: "/srv/csm/csm.yaml",
		ConfigDir:  "/srv/csm/conf.d",
		StatePath:  "/srv/csm/state",
	}
	configPath, configDir, statePath, err := resolveUninstallStorage(false, preferredConfigPath, func() (*config.Config, error) {
		return cfg, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if configPath != cfg.ConfigFile || configDir != cfg.ConfigDir || statePath != cfg.StatePath {
		t.Fatalf("resolved uninstall storage = (%q, %q, %q), want configured paths", configPath, configDir, statePath)
	}
}

func TestResolveUninstallStorageMissingConfigPolicy(t *testing.T) {
	missing := func() (*config.Config, error) { return nil, os.ErrNotExist }
	configPath, configDir, statePath, err := resolveUninstallStorage(false, preferredConfigPath, missing)
	if err != nil {
		t.Fatal(err)
	}
	if configPath != preferredConfigPath || configDir != defaultConfDir || statePath != defaultStatePath {
		t.Fatalf("missing-config defaults = (%q, %q, %q)", configPath, configDir, statePath)
	}
	if _, _, _, err := resolveUninstallStorage(true, preferredConfigPath, missing); err == nil {
		t.Fatal("purge must refuse when configured storage cannot be resolved")
	}
	invalid := errors.New("invalid config")
	if _, _, _, err := resolveUninstallStorage(false, preferredConfigPath, func() (*config.Config, error) {
		return nil, invalid
	}); !errors.Is(err, invalid) {
		t.Fatalf("invalid config error = %v, want %v", err, invalid)
	}
}

func TestConfiguredImmutableDefaultsTrueOnUnreadableConfig(t *testing.T) {
	if got := configuredImmutable(filepath.Join(t.TempDir(), "missing.yaml")); !got {
		t.Error("unreadable config must fail safe to immutable=true")
	}

	explicitFalse := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(explicitFalse, []byte("integrity:\n  immutable: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := configuredImmutable(explicitFalse); got {
		t.Error("explicit immutable: false must be honored")
	}

	absentKey := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(absentKey, []byte("hostname: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := configuredImmutable(absentKey); !got {
		t.Error("config without the key must default to immutable=true")
	}
}

func TestCommandSymlinkSkippedInPackageMode(t *testing.T) {
	inst := &Installer{CommandPath: "/usr/sbin/csm", PackageMode: true}
	if got := inst.commandSymlinkPath(); got != "" {
		t.Errorf("package mode must not manage the command symlink, got %q", got)
	}
	inst.PackageMode = false
	if got := inst.commandSymlinkPath(); got != "/usr/sbin/csm" {
		t.Errorf("standalone install must manage the command symlink, got %q", got)
	}
}

// Standalone hosts only run `csm rehash` on upgrade (deploy.sh never re-runs
// `csm install`), so rehash is the path that must maintain the PATH launcher.
func TestRehashMaintainsCommandSymlink(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	rehash := string(body)
	start := strings.Index(rehash, "func runRehash()")
	if start < 0 {
		t.Fatal("runRehash not found")
	}
	end := strings.Index(rehash[start:], "\nfunc ")
	if end < 0 {
		end = len(rehash) - start
	}
	if !strings.Contains(rehash[start:start+end], "ensureCommandSymlink(commandPath, binaryPath)") {
		t.Error("runRehash must maintain the command symlink for standalone upgrades")
	}
}

func TestDiscoverPHPShieldIniDirsFindsEveryEAPHPVersion(t *testing.T) {
	root := t.TempDir()
	dirs := []string{
		filepath.Join(root, "opt/cpanel/ea-php56/root/etc/php.d"),
		filepath.Join(root, "opt/cpanel/ea-php84/root/etc/php.d"),
		filepath.Join(root, "opt/cpanel/ea-php85/root/etc/php.d"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	oldGlobs := phpShieldIniDirGlobs
	phpShieldIniDirGlobs = []string{filepath.Join(root, "opt/cpanel/ea-php*/root/etc/php.d")}
	t.Cleanup(func() { phpShieldIniDirGlobs = oldGlobs })

	got := discoverPHPShieldIniDirs()
	if len(got) != len(dirs) {
		t.Fatalf("discovered %d dirs, want %d: %v", len(got), len(dirs), got)
	}
	for i, want := range dirs {
		if got[i] != want {
			t.Errorf("dir[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestEnsurePHPShieldEventLogCreatesReachableWriteOnlyPath(t *testing.T) {
	oldDir := phpShieldEventDir
	oldLog := phpShieldEventLogPath
	phpShieldEventDir = filepath.Join(t.TempDir(), "php-shield")
	phpShieldEventLogPath = filepath.Join(phpShieldEventDir, "events.log")
	t.Cleanup(func() {
		phpShieldEventDir = oldDir
		phpShieldEventLogPath = oldLog
	})

	if err := ensurePHPShieldEventLog(); err != nil {
		t.Fatal(err)
	}

	dirInfo, err := os.Stat(phpShieldEventDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0733 {
		t.Fatalf("event dir permissions = %v, want 0733", got)
	}
	if dirInfo.Mode()&os.ModeSticky == 0 {
		t.Fatal("event dir must have sticky bit set")
	}

	logInfo, err := os.Stat(phpShieldEventLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := logInfo.Mode().Perm(); got != 0622 {
		t.Fatalf("event log permissions = %v, want 0622", got)
	}
}

func TestPatchConfigPHPShieldReSignsIntegrity(t *testing.T) {
	confDir := t.TempDir()
	t.Setenv("CSM_CONFIG_DIR", confDir)

	path := filepath.Join(t.TempDir(), "csm.yaml")
	data := []byte(`# keep operator comments
hostname: example.com
php_shield:
  enabled: false
integrity:
  binary_hash: "sha256:existing"
  config_hash: "sha256:stale"
  confd_hash: ""
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	inst := &Installer{ConfigPath: path}
	if err := inst.patchConfigPHPShield(true); err != nil {
		t.Fatalf("patchConfigPHPShield: %v", err)
	}

	final, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(final), "# keep operator comments") {
		t.Fatalf("operator comment was not preserved:\n%s", final)
	}
	if !strings.Contains(string(final), "enabled: true") {
		t.Fatalf("php_shield.enabled was not enabled:\n%s", final)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PHPShield.Enabled {
		t.Fatal("php_shield.enabled = false, want true")
	}
	if cfg.Integrity.BinaryHash != "sha256:existing" {
		t.Fatalf("binary_hash = %q, want preserved value", cfg.Integrity.BinaryHash)
	}
	stable, err := integrity.HashConfigStable(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Integrity.ConfigHash != stable {
		t.Fatalf("config_hash = %q, want %q", cfg.Integrity.ConfigHash, stable)
	}
}

func TestPatchConfigPHPShieldAddsMissingSection(t *testing.T) {
	confDir := t.TempDir()
	t.Setenv("CSM_CONFIG_DIR", confDir)

	path := filepath.Join(t.TempDir(), "csm.yaml")
	data := []byte(`hostname: example.com
integrity:
  binary_hash: ""
  config_hash: ""
  confd_hash: ""
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	inst := &Installer{ConfigPath: path}
	if err := inst.patchConfigPHPShield(true); err != nil {
		t.Fatalf("patchConfigPHPShield: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PHPShield.Enabled {
		t.Fatal("php_shield.enabled = false, want true")
	}
}

func TestInstallerRuntimeDirsCreateSandboxRequiredPaths(t *testing.T) {
	installRoot := filepath.Join(t.TempDir(), "opt", "csm")
	statePath := filepath.Join(t.TempDir(), "var", "lib", "csm", "state")
	logPath := filepath.Join(t.TempDir(), "var", "log", "csm", "monitor.log")

	got := installerRuntimeDirs(installRoot, statePath, logPath)
	for _, want := range []string{
		installRoot,
		statePath,
		filepath.Dir(logPath),
		filepath.Join(installRoot, "quarantine"),
		filepath.Join(installRoot, "rules"),
		filepath.Join(installRoot, "policies"),
		filepath.Join(installRoot, "policies", "php_relay"),
	} {
		if !slices.Contains(got, want) {
			t.Errorf("installerRuntimeDirs missing %s", want)
		}
	}
}

func TestEnsureCommandSymlinkCreatesAndPreservesExpectedLink(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "opt", "csm", "csm")
	commandPath := filepath.Join(dir, "usr", "sbin", "csm")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := ensureCommandSymlink(commandPath, binaryPath); err != nil {
		t.Fatalf("ensureCommandSymlink: %v", err)
	}
	if err := ensureCommandSymlink(commandPath, binaryPath); err != nil {
		t.Fatalf("ensureCommandSymlink idempotent call: %v", err)
	}
	target, err := os.Readlink(commandPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != binaryPath {
		t.Fatalf("command symlink target = %q, want %q", target, binaryPath)
	}
}

func TestEnsureCommandSymlinkRefusesUnrelatedPath(t *testing.T) {
	dir := t.TempDir()
	commandPath := filepath.Join(dir, "usr", "sbin", "csm")
	if err := os.MkdirAll(filepath.Dir(commandPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(commandPath, []byte("operator file"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureCommandSymlink(commandPath, "/opt/csm/csm"); err == nil {
		t.Fatal("ensureCommandSymlink replaced an unrelated path")
	}
	data, err := os.ReadFile(commandPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "operator file" {
		t.Fatalf("unrelated command path changed to %q", data)
	}
}

func TestSetBinaryImmutableAppliesConfiguredState(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "args")
	chattr := filepath.Join(dir, "chattr")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$CAPTURE\"\n"
	if err := os.WriteFile(chattr, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("CAPTURE", capture)

	for _, tc := range []struct {
		enabled bool
		want    string
	}{
		{enabled: true, want: "+i /opt/csm/csm\n"},
		{enabled: false, want: "-i /opt/csm/csm\n"},
	} {
		if err := setBinaryImmutable("/opt/csm/csm", tc.enabled); err != nil {
			t.Fatalf("setBinaryImmutable(%v): %v", tc.enabled, err)
		}
		got, err := os.ReadFile(capture)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Fatalf("setBinaryImmutable(%v) args = %q, want %q", tc.enabled, got, tc.want)
		}
	}
}

// The installer template must ship bot_ranges with the same auto-update posture
// as the packaged default and production reference, so the three default-config
// sources stay in sync.
func TestDeployDefaultConfigEnablesBotRangesAutoUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "csm", "csm.yaml")
	if deployErr := deployDefaultConfig(path); deployErr != nil {
		t.Fatalf("deployDefaultConfig: %v", deployErr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes generated config: %v", err)
	}
	if cfg.Reputation.BotRanges.AutoUpdate == nil || !*cfg.Reputation.BotRanges.AutoUpdate {
		t.Fatal("installer default reputation.bot_ranges.auto_update must be explicitly true")
	}
	if cfg.Reputation.BotRanges.UpdateInterval != "24h" {
		t.Fatalf("installer default reputation.bot_ranges.update_interval = %q, want 24h", cfg.Reputation.BotRanges.UpdateInterval)
	}
	assertInstallerRawBotRangesAutoUpdate(t, data)
}

func TestDeployDefaultConfigIncludesWebUIMetricsToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "csm", "csm.yaml")
	if deployErr := deployDefaultConfig(path); deployErr != nil {
		t.Fatalf("deployDefaultConfig: %v", deployErr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	var raw map[string]any
	if unmarshalErr := yaml.Unmarshal(data, &raw); unmarshalErr != nil {
		t.Fatalf("unmarshal generated config: %v", unmarshalErr)
	}
	webui, ok := raw["webui"].(map[string]any)
	if !ok {
		t.Fatalf("generated config webui section has type %T, want map", raw["webui"])
	}
	gotToken, ok := webui["auth_token"].(string)
	if !ok || len(gotToken) != 64 {
		t.Fatalf("installer default webui.auth_token = %#v, want 64-character generated token", webui["auth_token"])
	}
	if _, decodeErr := hex.DecodeString(gotToken); decodeErr != nil {
		t.Fatalf("installer default webui.auth_token is not hexadecimal: %v", decodeErr)
	}
	if got, ok := webui["metrics_token"].(string); !ok || got != "" {
		t.Fatalf("installer default webui.metrics_token = %#v, want empty placeholder", webui["metrics_token"])
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes generated config: %v", err)
	}

	if !cfg.WebUI.Enabled {
		t.Fatal("installer default config must enable the web UI like the packaged default")
	}
	if cfg.WebUI.Listen != "0.0.0.0:9443" {
		t.Fatalf("WebUI.Listen = %q, want 0.0.0.0:9443", cfg.WebUI.Listen)
	}
	if cfg.WebUI.MetricsToken != "" {
		t.Fatalf("WebUI.MetricsToken = %q, want empty placeholder", cfg.WebUI.MetricsToken)
	}
}

func TestInstallerInstallFailsWhenSystemdDeploymentFails(t *testing.T) {
	root := t.TempDir()
	inst := &Installer{
		BinaryPath:  filepath.Join(root, "opt", "csm", "csm"),
		CommandPath: filepath.Join(root, "usr", "sbin", "csm"),
		ConfigPath:  filepath.Join(root, "etc", "csm", "csm.yaml"),
		StatePath:   filepath.Join(root, "var", "lib", "csm", "state"),
		LogPath:     filepath.Join(root, "var", "log", "csm", "monitor.log"),
		operations: &installerOperations{
			getuid:          func() int { return 0 },
			deployAuditd:    func() error { return nil },
			deploySystemd:   func() error { return errors.New("systemd write failed") },
			deployLogrotate: func() error { return nil },
		},
	}

	err := inst.Install()
	if err == nil || !strings.Contains(err.Error(), "systemd write failed") {
		t.Fatalf("Install error = %v, want systemd deployment failure", err)
	}
}

func TestInstallerInstallAllowsUnavailableOptionalIntegrations(t *testing.T) {
	root := t.TempDir()
	inst := &Installer{
		BinaryPath:  filepath.Join(root, "opt", "csm", "csm"),
		CommandPath: filepath.Join(root, "usr", "sbin", "csm"),
		ConfigPath:  filepath.Join(root, "etc", "csm", "csm.yaml"),
		StatePath:   filepath.Join(root, "var", "lib", "csm", "state"),
		LogPath:     filepath.Join(root, "var", "log", "csm", "monitor.log"),
		operations: &installerOperations{
			getuid:          func() int { return 0 },
			deployAuditd:    func() error { return errors.New("augenrules unavailable") },
			deploySystemd:   func() error { return nil },
			deployLogrotate: func() error { return errors.New("logrotate unavailable") },
			setImmutable:    func(string, bool) error { return nil },
		},
	}
	if err := inst.Install(); err != nil {
		t.Fatalf("optional integration failure aborted install: %v", err)
	}
}

func TestInstallerUninstallRefusesDeletionWhileDaemonStillLive(t *testing.T) {
	removed := false
	inst := &Installer{
		BinaryPath: "/opt/csm/csm",
		StatePath:  "/var/lib/csm/state",
		LogPath:    "/var/log/csm/monitor.log",
		operations: &installerOperations{
			getuid:     func() int { return 0 },
			runCommand: func(string, ...string) error { return errors.New("stop failed") },
			daemonLive: func() bool { return true },
			remove: func(string) error {
				removed = true
				return nil
			},
			removeAll: func(string) error {
				removed = true
				return nil
			},
		},
	}

	err := inst.Uninstall(false)
	if err == nil || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("Uninstall error = %v, want daemon still running", err)
	}
	if removed {
		t.Fatal("uninstall removed files while daemon was still live")
	}
}

func TestInstallerUninstallRefusesDeletionWhileDaemonStateLockHeld(t *testing.T) {
	removed := false
	inst := &Installer{
		StatePath: "/var/lib/csm/state",
		operations: &installerOperations{
			getuid:           func() int { return 0 },
			runCommand:       func(string, ...string) error { return nil },
			daemonLive:       func() bool { return false },
			acquireStateLock: func(string) (func(), error) { return nil, errors.New("lock held") },
			remove: func(string) error {
				removed = true
				return nil
			},
		},
	}
	err := inst.Uninstall(false)
	if err == nil || !strings.Contains(err.Error(), "state lock") {
		t.Fatalf("Uninstall error = %v, want state-lock refusal", err)
	}
	if removed {
		t.Fatal("uninstall removed files while daemon state lock was held")
	}
}

func TestInstallerUninstallPreservesStateAndLogsWithoutPurge(t *testing.T) {
	var removed, removedAll []string
	inst := &Installer{
		BinaryPath:  "/opt/csm/csm",
		CommandPath: "/usr/sbin/csm",
		ConfigPath:  "/etc/csm/csm.yaml",
		StatePath:   "/var/lib/csm/state",
		LogPath:     "/var/log/csm/monitor.log",
		operations: &installerOperations{
			getuid:           func() int { return 0 },
			runCommand:       func(string, ...string) error { return nil },
			daemonLive:       func() bool { return false },
			setImmutable:     func(string, bool) error { return nil },
			removeAuditd:     func() error { return nil },
			acquireStateLock: func(string) (func(), error) { return func() {}, nil },
			glob:             func(string) ([]string, error) { return nil, nil },
			remove: func(path string) error {
				removed = append(removed, path)
				return nil
			},
			removeAll: func(path string) error {
				removedAll = append(removedAll, path)
				return nil
			},
		},
	}

	if err := inst.Uninstall(false); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(removed, inst.BinaryPath) {
		t.Fatalf("binary was not removed: %v", removed)
	}
	if slices.Contains(removedAll, inst.StatePath) || slices.Contains(removedAll, filepath.Dir(inst.LogPath)) {
		t.Fatalf("state or logs removed without --purge: %v", removedAll)
	}
}

func TestInstallerUninstallPurgeUsesResolvedConfigDirectory(t *testing.T) {
	var removedAll []string
	inst := &Installer{
		BinaryPath: "/opt/csm/csm",
		ConfigPath: "/opt/csm/csm.yaml",
		ConfigDir:  "/etc/csm/conf.d",
		StatePath:  "/srv/csm/state",
		LogPath:    "/var/log/csm/monitor.log",
		operations: &installerOperations{
			getuid:           func() int { return 0 },
			runCommand:       func(string, ...string) error { return nil },
			daemonLive:       func() bool { return false },
			setImmutable:     func(string, bool) error { return nil },
			removeAuditd:     func() error { return nil },
			acquireStateLock: func(string) (func(), error) { return func() {}, nil },
			glob:             func(string) ([]string, error) { return nil, nil },
			remove:           func(string) error { return nil },
			removeAll: func(path string) error {
				removedAll = append(removedAll, path)
				return nil
			},
		},
	}

	if err := inst.Uninstall(true); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(removedAll, inst.ConfigDir) {
		t.Fatalf("resolved config directory was not purged: %v", removedAll)
	}
	if !slices.Contains(removedAll, filepath.Dir(inst.BinaryPath)) {
		t.Fatalf("CSM install directory was not purged: %v", removedAll)
	}
	if slices.Contains(removedAll, "/opt/csm/conf.d") {
		t.Fatalf("purge derived the wrong config directory from legacy config path: %v", removedAll)
	}
}

func TestPurgeStateDirContentsRetainsAuthoritativeLock(t *testing.T) {
	statePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(statePath, daemonStateLockFileName), []byte("lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "csm.db"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(statePath, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := purgeStateDirContents(statePath, os.RemoveAll); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != daemonStateLockFileName {
		t.Fatalf("state contents after purge = %v, want only %s", entries, daemonStateLockFileName)
	}
}

func TestPurgeInstallTreeRetainsNestedAuthoritativeStateLock(t *testing.T) {
	installRoot := t.TempDir()
	statePath := filepath.Join(installRoot, "state")
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{
		filepath.Join(installRoot, "configs", "csm.yaml"):  "config",
		filepath.Join(installRoot, "rules", "malware.yar"): "rule",
		filepath.Join(statePath, daemonStateLockFileName):  "lock",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := purgeInstallTree(installRoot, statePath, os.RemoveAll); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(statePath, daemonStateLockFileName)); err != nil {
		t.Fatalf("authoritative state lock was removed: %v", err)
	}
	for _, removed := range []string{filepath.Join(installRoot, "configs"), filepath.Join(installRoot, "rules")} {
		if _, err := os.Stat(removed); !os.IsNotExist(err) {
			t.Fatalf("purged install content %s still exists: %v", removed, err)
		}
	}
}

func TestDeployDefaultConfigReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "csm", "csm.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("hostname: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if deployErr := deployDefaultConfig(path); deployErr != nil {
		t.Fatalf("deployDefaultConfig: %v", deployErr)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("default config was rewritten in place, want rename")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadBytes(data); err != nil {
		t.Fatalf("LoadBytes generated config: %v", err)
	}
}

func assertInstallerRawBotRangesAutoUpdate(t *testing.T, data []byte) {
	t.Helper()

	var raw struct {
		Reputation map[string]yaml.Node `yaml:"reputation"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("generated config yaml.Unmarshal: %v", err)
	}
	botRanges, ok := raw.Reputation["bot_ranges"]
	if !ok {
		t.Fatal("installer default missing reputation.bot_ranges")
	}
	var fields map[string]yaml.Node
	if err := botRanges.Decode(&fields); err != nil {
		t.Fatalf("installer default reputation.bot_ranges decode: %v", err)
	}

	autoUpdateNode, ok := fields["auto_update"]
	if !ok {
		t.Fatal("installer default missing reputation.bot_ranges.auto_update")
	}
	var autoUpdate bool
	if err := autoUpdateNode.Decode(&autoUpdate); err != nil {
		t.Fatalf("installer default reputation.bot_ranges.auto_update decode: %v", err)
	}
	if !autoUpdate {
		t.Fatal("installer default reputation.bot_ranges.auto_update = false, want true")
	}

	intervalNode, ok := fields["update_interval"]
	if !ok {
		t.Fatal("installer default missing reputation.bot_ranges.update_interval")
	}
	var interval string
	if err := intervalNode.Decode(&interval); err != nil {
		t.Fatalf("installer default reputation.bot_ranges.update_interval decode: %v", err)
	}
	if interval != "24h" {
		t.Fatalf("installer default reputation.bot_ranges.update_interval = %q, want 24h", interval)
	}
}

// TestDeployDefaultConfigDOSExemptFirewallDefaults guards that the installer
// template ships firewall.dos_exempt_ranges and the provider-toggle with
// effective values consistent with the runtime defaults.  Provider ranges are
// NOT tested here -- they are sourced from SPF at runtime, never in YAML.
func TestDeployDefaultConfigDOSExemptFirewallDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "csm", "csm.yaml")
	if err := deployDefaultConfig(path); err != nil {
		t.Fatalf("deployDefaultConfig: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}

	if len(cfg.Firewall.DOSExemptRanges) != 0 {
		t.Errorf("installer default dos_exempt_ranges = %v, want empty", cfg.Firewall.DOSExemptRanges)
	}
	if !cfg.Firewall.ExemptKnownMailProviders() {
		t.Error("installer default dos_exempt_known_mail_providers effective = false, want true")
	}

	// The toggle must be explicitly present so operators can discover and
	// disable it; omitting it causes silent three-source drift.
	var raw struct {
		Firewall map[string]yaml.Node `yaml:"firewall"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("yaml.Unmarshal for firewall raw check: %v", err)
	}
	if _, ok := raw.Firewall["dos_exempt_known_mail_providers"]; !ok {
		t.Error("installer default must explicitly document firewall.dos_exempt_known_mail_providers")
	}
	if _, ok := raw.Firewall["dos_exempt_ranges"]; !ok {
		t.Error("installer default must explicitly document firewall.dos_exempt_ranges")
	}
}
