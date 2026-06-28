package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestPrepareDaemonStateLocksBeforeMigration(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "legacy")
	statePath := filepath.Join(root, "state")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, lock, err := prepareDaemonState(&config.Config{StatePath: statePath}, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if !migrated {
		t.Fatal("migrated = false, want true")
	}
	if _, err := os.Stat(filepath.Join(statePath, "state.json")); err != nil {
		t.Fatalf("legacy state was not copied while startup lock was held: %v", err)
	}
	if _, err := os.Stat(filepath.Join(statePath, "csm.lock")); err != nil {
		t.Fatalf("startup lock was not created after migration: %v", err)
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
