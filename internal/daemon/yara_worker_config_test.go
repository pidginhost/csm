package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// recordYaraWorkerArgs starts the backend against a helper that records its
// arguments and exits, and returns the flags the worker was given.
func recordYaraWorkerArgs(t *testing.T, cfg *config.Config) map[string]string {
	t.Helper()
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	worker := filepath.Join(dir, "worker")
	if err := os.WriteFile(worker, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > '"+argsPath+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: cfg, binaryPath: worker, stopCh: make(chan struct{})}
	// Avoid a retry loop after the deliberately short-lived helper exits.
	close(d.stopCh)
	if err := d.initYaraBackend(); err == nil {
		t.Fatal("argument recorder unexpectedly served YARA requests")
	}
	defer d.stopYaraBackend()
	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	values := make(map[string]string)
	for i := 1; i+1 < len(args); i += 2 {
		values[args[i]] = args[i+1]
	}
	return values
}

func TestYaraWorkerInheritsEffectiveRuleConfiguration(t *testing.T) {
	confDir := t.TempDir()
	cfg := &config.Config{ConfigFile: "/custom/csm.yaml", ConfigDir: confDir}
	cfg.Signatures.RulesDir = "/custom/rules"
	cfg.Signatures.DisabledRules = []string{"php_goto_obfuscation", "Other_Rule"}

	values := recordYaraWorkerArgs(t, cfg)

	for flag, want := range map[string]string{"--config": cfg.ConfigFile, "--config-dir": cfg.ConfigDir, "--rules-dir": cfg.Signatures.RulesDir} {
		if values[flag] != want {
			t.Errorf("%s = %q, want %q", flag, values[flag], want)
		}
	}
	var disabled []string
	if err := json.Unmarshal([]byte(values["--disabled-rules"]), &disabled); err != nil {
		t.Fatalf("missing effective disabled list: %v", err)
	}
	if !reflect.DeepEqual(disabled, cfg.Signatures.DisabledRules) {
		t.Fatalf("disabled rules = %v, want %v", disabled, cfg.Signatures.DisabledRules)
	}
}

// The daemon treats a missing conf.d as "no fragments", but the worker treats
// an explicit --config-dir that does not exist as a fatal error. Forwarding the
// daemon's missing default directory kept the worker from ever starting.
func TestYaraWorkerOmitsMissingConfigDir(t *testing.T) {
	cfg := &config.Config{ConfigFile: "/custom/csm.yaml", ConfigDir: filepath.Join(t.TempDir(), "conf.d")}
	cfg.Signatures.RulesDir = "/custom/rules"

	values := recordYaraWorkerArgs(t, cfg)

	if got, ok := values["--config-dir"]; ok {
		t.Fatalf("worker was given missing conf.d %q", got)
	}
	if values["--config"] != cfg.ConfigFile {
		t.Fatalf("--config = %q, want %q", values["--config"], cfg.ConfigFile)
	}
}

// A worker that cannot start leaves every YARA scan disabled. Record it as a
// failed watcher so doctor and the status API report the outage instead of an
// overall OK, and record recovery once the backend activates.
func TestYaraWorkerStartReportsWatcherState(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = t.TempDir()
	dir := t.TempDir()
	worker := filepath.Join(dir, "worker")
	if err := os.WriteFile(worker, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: cfg, binaryPath: worker, stopCh: make(chan struct{})}
	close(d.stopCh)
	if err := d.initYaraBackend(); err == nil {
		t.Fatal("failing worker unexpectedly started")
	}
	defer d.stopYaraBackend()

	attached, recorded := d.WatcherStatuses()[yaraWorkerWatcher]
	if !recorded || attached {
		t.Fatalf("failed worker start recorded=%t attached=%t, want recorded failure", recorded, attached)
	}

	d.activateYaraBackend(d.yaraSup)
	if !d.WatcherStatuses()[yaraWorkerWatcher] {
		t.Fatal("activated worker was not recorded as attached")
	}
}
