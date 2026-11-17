package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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
// that holds the callback secrets. Only the redacted view can skip that check.
func TestConfigShowRuntimeSecretEnv(t *testing.T) {
	const childEnv = "CSM_TEST_CONFIG_SHOW_NO_SECRET"
	const secretEnv = "CSM_TEST_SHOW_VERDICT_HMAC_UNSET"
	const callbackURL = "https://panel.example.test/api/csm/verdict"
	if os.Getenv(childEnv) == "1" {
		os.Args = append([]string{"csm", "config", "show"}, flag.Args()...)
		main()
		os.Exit(0)
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A relative config filename can also look like a display flag.
	cfgPath := filepath.Join(dir, "--no-redact")
	body := "firewall:\n  enabled: true\n  ipv6: true\n" +
		"auto_response:\n  verdict_callback:\n    enabled: true\n" +
		"    url: " + callbackURL + "\n" +
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
	runTest := "-test.run=^" + t.Name() + "$"
	for _, tc := range []struct {
		name     string
		path     string
		noRedact bool
		envValue string
		wantURL  string
	}{
		{name: "redacted without secret", path: cfgPath, wantURL: "https://panel.example.test/[REDACTED]"},
		{name: "flag as config path", path: filepath.Base(cfgPath), envValue: t.Name(), wantURL: "https://panel.example.test/[REDACTED]"},
		{name: "unredacted without secret", path: cfgPath, noRedact: true},
		{name: "unredacted with secret", path: cfgPath, noRedact: true, envValue: t.Name(), wantURL: callbackURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{runTest, "--", "--config", tc.path, "--config-dir", filepath.Join(dir, "conf.d"), "--json"}
			if tc.noRedact {
				args = append(args, "--no-redact")
			}
			cmd := exec.CommandContext(ctx, exe, args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), childEnv+"=1", secretEnv+"="+tc.envValue)
			out, err := cmd.Output()
			if tc.wantURL == "" {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(string(exitErr.Stderr), secretEnv) || len(out) != 0 {
					t.Fatalf("expected missing-secret error and empty stdout, got err=%v, stdout bytes=%d", err, len(out))
				}
				return
			}
			if err != nil {
				t.Fatalf("config show failed: %v", err)
			}
			var result struct {
				Firewall     struct{ Enabled, IPv6 bool }
				AutoResponse struct {
					VerdictCallback struct{ URL string } `json:"verdict_callback"`
				} `json:"auto_response"`
			}
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}
			if !result.Firewall.Enabled || !result.Firewall.IPv6 || result.AutoResponse.VerdictCallback.URL != tc.wantURL {
				t.Error("unexpected firewall settings or callback URL in config output")
			}
		})
	}
}
