package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/config"
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

func TestDeployDefaultConfigIncludesWebUIMetricsToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "csm", "csm.yaml")
	if err := deployDefaultConfig(path); err != nil {
		t.Fatalf("deployDefaultConfig: %v", err)
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
