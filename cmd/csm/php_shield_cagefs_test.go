package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withCageFSMountPoints points the CageFS helpers at a temporary mount-points
// file and records the commands the helper would run.
func withCageFSMountPoints(t *testing.T, contents string) (path string, ran *[][]string) {
	t.Helper()

	dir := t.TempDir()
	path = filepath.Join(dir, "cagefs.mp")
	if contents != "" {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var calls [][]string
	oldPath, oldRun := cagefsMountPointsPath, cagefsRunCommand
	cagefsMountPointsPath = path
	cagefsRunCommand = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() {
		cagefsMountPointsPath, cagefsRunCommand = oldPath, oldRun
	})
	return path, &calls
}

// A host without CageFS has no mount-points file. The helper must do nothing
// rather than creating one, which would leave junk on every non-CloudLinux box.
func TestEnsurePHPShieldCageFSMountSkipsHostWithoutCageFS(t *testing.T) {
	path, ran := withCageFSMountPoints(t, "")

	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatalf("no CageFS -> unexpected error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("mount-points file must not be created on a host without CageFS")
	}
	if len(*ran) != 0 {
		t.Errorf("no CageFS -> ran %v, want no commands", *ran)
	}
}

// Without this mount the Shield event directory does not exist inside the cage,
// so tenant PHP cannot append events and the daemon sees nothing.
func TestEnsurePHPShieldCageFSMountAddsEventDir(t *testing.T) {
	existing := "/var/lib/mysql\n/opt\n@/var/spool/cron,700\n"
	path, ran := withCageFSMountPoints(t, existing)

	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "\n"+phpShieldEventDir+"\n") {
		t.Errorf("event dir not added as its own shared-mount line:\n%s", got)
	}
	if !strings.HasPrefix(got, existing) {
		t.Errorf("existing operator and vendor entries must be preserved:\n%s", got)
	}
	if len(*ran) != 1 || (*ran)[0][0] != "cagefsctl" {
		t.Fatalf("ran %v, want a single cagefsctl invocation", *ran)
	}
	if !strings.Contains(strings.Join((*ran)[0], " "), "--remount-all") {
		t.Errorf("ran %v, want --remount-all so live cages pick up the mount", (*ran)[0])
	}
}

// Re-running the installer must not append a duplicate line or remount every
// cage on a server that is already configured.
func TestEnsurePHPShieldCageFSMountIsIdempotent(t *testing.T) {
	existing := "/var/lib/mysql\n" + phpShieldEventDir + "\n"
	path, ran := withCageFSMountPoints(t, existing)

	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != existing {
		t.Errorf("already-configured file rewritten:\ngot:  %q\nwant: %q", got, existing)
	}
	if len(*ran) != 0 {
		t.Errorf("already configured -> ran %v, want no remount", *ran)
	}
}

// An operator who mounted the directory read-only or per-user made a deliberate
// choice. Appending our own line would silently create a conflicting entry.
func TestEnsurePHPShieldCageFSMountLeavesOperatorEntryAlone(t *testing.T) {
	existing := "/var/lib/mysql\n!" + phpShieldEventDir + "\n"
	path, ran := withCageFSMountPoints(t, existing)

	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != existing {
		t.Errorf("operator entry must not be edited:\ngot:  %q\nwant: %q", got, existing)
	}
	if len(*ran) != 0 {
		t.Errorf("operator entry present -> ran %v, want no remount", *ran)
	}
}

// Both install and upgrade must leave the Shield able to log: the event log has
// to exist on the host AND be reachable from inside the cages. Wiring only the
// first is what left the Shield silently dropping every event on CloudLinux.
func TestEnsurePHPShieldRuntimePathsConfiguresLogAndCage(t *testing.T) {
	mpPath, ran := withCageFSMountPoints(t, "/var/lib/mysql\n")

	eventDir := filepath.Join(t.TempDir(), "csm-php-shield")
	oldDir, oldLog := phpShieldEventDir, phpShieldEventLogPath
	phpShieldEventDir = eventDir
	phpShieldEventLogPath = filepath.Join(eventDir, "events.log")
	t.Cleanup(func() {
		phpShieldEventDir, phpShieldEventLogPath = oldDir, oldLog
	})

	if err := ensurePHPShieldRuntimePaths(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(phpShieldEventLogPath); err != nil {
		t.Errorf("event log not created: %v", err)
	}
	data, err := os.ReadFile(mpPath) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), eventDir) {
		t.Errorf("event dir not exposed to CageFS:\n%s", data)
	}
	if len(*ran) != 1 {
		t.Errorf("ran %v, want one remount", *ran)
	}
}

// A cage remount that fails must not abort the install and leave the host
// half-configured. The Shield still protects without its log, and the entry
// stays on disk so a later remount picks it up.
func TestEnsurePHPShieldRuntimePathsSurvivesRemountFailure(t *testing.T) {
	mpPath, _ := withCageFSMountPoints(t, "/var/lib/mysql\n")
	cagefsRunCommand = func(string, ...string) error {
		return errors.New("cagefsctl: CageFS is disabled")
	}

	eventDir := filepath.Join(t.TempDir(), "csm-php-shield")
	oldDir, oldLog := phpShieldEventDir, phpShieldEventLogPath
	phpShieldEventDir = eventDir
	phpShieldEventLogPath = filepath.Join(eventDir, "events.log")
	t.Cleanup(func() {
		phpShieldEventDir, phpShieldEventLogPath = oldDir, oldLog
	})

	if err := ensurePHPShieldRuntimePaths(); err != nil {
		t.Fatalf("remount failure must not fail the install, got %v", err)
	}

	data, err := os.ReadFile(mpPath) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), eventDir) {
		t.Errorf("mount entry must survive a failed remount:\n%s", data)
	}
}

// A mount-points file whose last line has no newline must not gain a line that
// merges with the previous entry.
func TestEnsurePHPShieldCageFSMountHandlesMissingTrailingNewline(t *testing.T) {
	path, _ := withCageFSMountPoints(t, "/var/lib/mysql")

	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); !strings.Contains(got, "/var/lib/mysql\n") {
		t.Errorf("appended line merged with the previous entry:\n%q", got)
	}
}
