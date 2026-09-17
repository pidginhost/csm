package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestYaraWorkerUsesSupervisorDisabledRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(path, []byte("signatures:\n  disabled_rules: [disk_rule]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want []string
		bad  bool
	}{
		{"manual", nil, []string{"disk_rule"}, false},
		{"snapshot", []string{"--disabled-rules", `["active_rule"]`}, []string{"active_rule"}, false},
		{"empty snapshot", []string{"--disabled-rules", `null`}, nil, false},
		{"missing", []string{"--disabled-rules"}, nil, true},
		{"invalid", []string{"--disabled-rules", `broken`}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--config", path, "--inherited-config-dir", ""}, tc.args...)
			cfg, _, err := yaraWorkerConfig(args)
			if (err != nil) != tc.bad {
				t.Fatalf("error = %v, want bad=%t", err, tc.bad)
			}
			if !tc.bad && !reflect.DeepEqual(cfg.DisabledRules, tc.want) {
				t.Fatalf("disabled = %v, want %v", cfg.DisabledRules, tc.want)
			}
		})
	}
}

func TestYaraWorkerConfigDirectoryPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	unsafe := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(dir, "safe")
	if err := os.Mkdir(safe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(safe, "rules.yaml"), []byte("signatures:\n  disabled_rules: [fragment_rule]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, env, wantDir, wantErr string
		args                        []string
	}{
		{name: "inherited missing", env: unsafe, args: []string{"--inherited-config-dir", missing}, wantDir: missing},
		{name: "inherited empty", env: unsafe, args: []string{"--inherited-config-dir", ""}},
		{name: "inherited fragments", env: unsafe, args: []string{"--inherited-config-dir", safe}, wantDir: safe},
		{name: "inherited relative", args: []string{"--inherited-config-dir", "relative"}, wantErr: "absolute"},
		{name: "inherited writable", args: []string{"--inherited-config-dir", unsafe}, wantErr: "writable"},
		{name: "inherited file", args: []string{"--inherited-config-dir", path}, wantErr: "not a directory"},
		{name: "explicit missing", args: []string{"--config-dir", missing}, wantErr: "--config-dir refused"},
		{name: "explicit empty", args: []string{"--config-dir", ""}, wantErr: "non-empty"},
		{name: "explicit empty config", args: []string{"--config", "", "--inherited-config-dir", ""}, wantErr: "reading config"},
		{name: "explicit fragments", env: missing, args: []string{"--config-dir", safe}, wantDir: safe},
		{name: "environment missing", env: missing, wantErr: "CSM_CONFIG_DIR refused"},
		{name: "environment fragments", env: safe, wantDir: safe},
		{name: "conflicting flags", args: []string{"--config-dir", missing, "--inherited-config-dir", ""}, wantErr: "cannot be combined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CSM_CONFIG_DIR", tc.env)
			args := append([]string{"--config", path}, tc.args...)
			worker, loaded, err := yaraWorkerConfig(args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantDir := tc.wantDir
			if wantDir == safe {
				wantDir, err = filepath.EvalSymlinks(safe)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(worker.DisabledRules, []string{"fragment_rule"}) {
					t.Fatalf("fragment rules = %v", worker.DisabledRules)
				}
			}
			if loaded.ConfigDir != wantDir {
				t.Fatalf("config directory = %q, want %q", loaded.ConfigDir, wantDir)
			}
		})
	}
}
