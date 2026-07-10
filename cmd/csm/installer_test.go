package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"gopkg.in/yaml.v3"
)

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
	if got, ok := webui["auth_token"].(string); !ok || got != "" {
		t.Fatalf("installer default webui.auth_token = %#v, want empty placeholder", webui["auth_token"])
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
