package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// `csm config show` reads only the config files. The running daemon holds the
// state database's exclusive lock for its whole lifetime, so a config dump
// that opens the database fails on every live host.
func TestConfigShowRunsWhileDaemonHoldsStore(t *testing.T) {
	const childEnv = "CSM_TEST_CONFIG_SHOW_CONFIG"
	if path := os.Getenv(childEnv); path != "" {
		os.Args = []string{"csm", "config", "show", "--config", path, "--config-dir", filepath.Join(filepath.Dir(path), "conf.d")}
		configShow()
		return
	}

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	for _, p := range []string{stateDir, filepath.Join(dir, "conf.d")} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(dir, "csm.yaml")
	body := fmt.Sprintf("hostname: host.example.test\nstate_path: %q\n", stateDir)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Stand in for the daemon: hold the database open, and with it the lock.
	db, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), childEnv+"="+cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("config show failed while the store was locked: %v\n%s", err, out)
	}
	for _, want := range []string{"hostname: host.example.test\n", "state_path: " + stateDir + "\n"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("config show output missing %q:\n%s", want, out)
		}
	}
}

// Integrations read `csm config show --json` without the service environment
// that holds the callback secrets. Show only displays the redacted config, so
// an unset secret variable must not stop it; the daemon load still refuses it.
func TestConfigShowWithoutRuntimeSecretEnv(t *testing.T) {
	const childEnv = "CSM_TEST_CONFIG_SHOW_NO_SECRET"
	const secretEnv = "CSM_TEST_SHOW_VERDICT_HMAC_UNSET"
	if path := os.Getenv(childEnv); path != "" {
		os.Args = []string{"csm", "config", "show", "--json", "--config", path, "--config-dir", filepath.Join(filepath.Dir(path), "conf.d")}
		configShow()
		return
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "csm.yaml")
	body := "firewall:\n  enabled: true\n  ipv6: true\n" +
		"auto_response:\n  verdict_callback:\n    enabled: true\n" +
		"    url: https://panel.example.test/api/csm/verdict\n" +
		"    hmac_secret_env: " + secretEnv + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(secretEnv, "")
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"csm", "config", "show", "--config", cfgPath, "--config-dir", filepath.Join(dir, "conf.d")}
	if _, err := tryLoadConfigLite(); err == nil || !strings.Contains(err.Error(), secretEnv) {
		t.Fatalf("daemon load with the secret unset: err = %v, want the fail-closed secret error", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), childEnv+"="+cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("config show failed with the secret unset: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `"enabled": true`) || !strings.Contains(string(out), `"ipv6": true`) {
		t.Errorf("config show output missing the firewall settings:\n%s", out)
	}
}
