package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestPrepareDaemonStateMigratesBeforeOpeningStore(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "legacy")
	statePath := filepath.Join(root, "state")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	opened := false
	openStore := func(cfg *config.Config) error {
		opened = true
		if cfg.StatePath != statePath {
			t.Fatalf("StatePath = %q, want %q", cfg.StatePath, statePath)
		}
		if _, err := os.Stat(filepath.Join(statePath, "state.json")); err != nil {
			t.Fatalf("legacy state was not copied before store open: %v", err)
		}
		return os.WriteFile(filepath.Join(statePath, "csm.db"), []byte("opened"), 0o600)
	}

	migrated, err := prepareDaemonState(&config.Config{StatePath: statePath}, legacy, openStore)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("migrated = false, want true")
	}
	if !opened {
		t.Fatal("openStore was not called")
	}
}

func TestEnsureHomeEnvPopulatesWhenUnset(t *testing.T) {
	saved, hadHome := os.LookupEnv("HOME")
	t.Cleanup(func() {
		if hadHome {
			_ = os.Setenv("HOME", saved)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})

	if err := os.Unsetenv("HOME"); err != nil {
		t.Fatalf("unset HOME: %v", err)
	}
	ensureHomeEnv()
	if got := os.Getenv("HOME"); got == "" {
		t.Fatal("ensureHomeEnv left HOME empty; expected user.Current().HomeDir")
	}
}

func TestEnsureHomeEnvLeavesExistingValueAlone(t *testing.T) {
	saved, hadHome := os.LookupEnv("HOME")
	t.Cleanup(func() {
		if hadHome {
			_ = os.Setenv("HOME", saved)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})

	if err := os.Setenv("HOME", "/tmp/sentinel-home"); err != nil {
		t.Fatalf("set HOME: %v", err)
	}
	ensureHomeEnv()
	if got := os.Getenv("HOME"); got != "/tmp/sentinel-home" {
		t.Fatalf("ensureHomeEnv overwrote HOME to %q; expected /tmp/sentinel-home", got)
	}
}
