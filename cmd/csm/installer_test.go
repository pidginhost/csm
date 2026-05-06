package main

import (
	"os"
	"path/filepath"
	"testing"
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
