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

func TestYaraWorkerInheritsEffectiveRuleConfiguration(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	worker := filepath.Join(dir, "worker")
	if err := os.WriteFile(worker, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > '"+argsPath+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &config.Config{ConfigFile: "/custom/csm.yaml", ConfigDir: "/custom/conf.d"}, binaryPath: worker, stopCh: make(chan struct{})}
	d.cfg.Signatures.RulesDir = "/custom/rules"
	d.cfg.Signatures.DisabledRules = []string{"php_goto_obfuscation", "Other_Rule"}
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
	for flag, want := range map[string]string{"--config": d.cfg.ConfigFile, "--config-dir": d.cfg.ConfigDir, "--rules-dir": d.cfg.Signatures.RulesDir} {
		if values[flag] != want {
			t.Errorf("%s = %q, want %q", flag, values[flag], want)
		}
	}
	var disabled []string
	if err := json.Unmarshal([]byte(values["--disabled-rules"]), &disabled); err != nil {
		t.Fatalf("missing effective disabled list: %v", err)
	}
	if !reflect.DeepEqual(disabled, d.cfg.Signatures.DisabledRules) {
		t.Fatalf("disabled rules = %v, want %v", disabled, d.cfg.Signatures.DisabledRules)
	}
}
