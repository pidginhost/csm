package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

// withCageFSDoctorPaths points the doctor check at a temporary CageFS layout.
// mountPoints is written only when non-empty; skeletonEntry creates the
// skeleton directory that proves the mount was actually applied.
func withCageFSDoctorPaths(t *testing.T, mountPoints string, skeletonEntry bool) {
	t.Helper()

	dir := t.TempDir()
	mpPath := filepath.Join(dir, "cagefs.mp")
	if mountPoints != "" {
		if err := os.WriteFile(mpPath, []byte(mountPoints), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	skeleton := filepath.Join(dir, "cagefs-skeleton")
	if skeletonEntry {
		if err := os.MkdirAll(filepath.Join(skeleton, phpShieldEventDir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	oldMP, oldSkel := cagefsMountPointsPath, cagefsSkeletonPath
	cagefsMountPointsPath, cagefsSkeletonPath = mpPath, skeleton
	t.Cleanup(func() {
		cagefsMountPointsPath, cagefsSkeletonPath = oldMP, oldSkel
	})
}

// Every non-CloudLinux host lacks the mount-points file. The check must stay
// silent there rather than reporting a CageFS problem on a Debian box.
func TestPHPShieldCageFSDoctorCheckSilentWithoutCageFS(t *testing.T) {
	withCageFSDoctorPaths(t, "", false)

	if checks := phpShieldCageFSDoctorChecks(); len(checks) != 0 {
		t.Errorf("no CageFS -> %d check(s), want none", len(checks))
	}
}

// The mount is registered and applied: the Shield can reach its socket.
func TestPHPShieldCageFSDoctorCheckOKWhenApplied(t *testing.T) {
	withCageFSDoctorPaths(t, "/var/lib/mysql\n"+phpShieldEventDir+"\n", true)

	checks := phpShieldCageFSDoctorChecks()
	if len(checks) != 1 {
		t.Fatalf("got %d check(s), want 1", len(checks))
	}
	if checks[0].Status != "ok" {
		t.Errorf("applied mount -> status %q, want ok (%s)", checks[0].Status, checks[0].Message)
	}
}

// The gap this check exists for: the installer registered the mount, but no
// operator has remounted the cages, so PHP cannot see the socket and every
// Shield detection is silently dropped.
func TestPHPShieldCageFSDoctorCheckFailsWhenRegisteredButNotApplied(t *testing.T) {
	withCageFSDoctorPaths(t, "/var/lib/mysql\n"+phpShieldEventDir+"\n", false)

	checks := phpShieldCageFSDoctorChecks()
	if len(checks) != 1 {
		t.Fatalf("got %d check(s), want 1", len(checks))
	}
	if checks[0].Status != "fail" {
		t.Errorf("registered but unapplied -> status %q, want fail", checks[0].Status)
	}
	if !strings.Contains(checks[0].Fix, "cagefsctl") {
		t.Errorf("fix %q must name the cagefsctl remount that applies it", checks[0].Fix)
	}
	if !strings.Contains(strings.ToLower(checks[0].Message), "drop") {
		t.Errorf("message %q must say events are being dropped", checks[0].Message)
	}
}

// CageFS is present but the Shield was never registered at all -- a host where
// the installer ran before this support existed, or where the entry was removed.
func TestPHPShieldCageFSDoctorCheckFailsWhenNotRegistered(t *testing.T) {
	withCageFSDoctorPaths(t, "/var/lib/mysql\n/opt\n", false)

	checks := phpShieldCageFSDoctorChecks()
	if len(checks) != 1 {
		t.Fatalf("got %d check(s), want 1", len(checks))
	}
	if checks[0].Status != "fail" {
		t.Errorf("unregistered -> status %q, want fail", checks[0].Status)
	}
	if !strings.Contains(checks[0].Fix, "--php-shield") {
		t.Errorf("fix %q must point at re-running the shield install", checks[0].Fix)
	}
}

// An operator entry that is read-only or per-user cannot carry the socket, so
// it must not be reported as a working shared mount.
func TestPHPShieldCageFSDoctorCheckFailsOnIncompatibleMount(t *testing.T) {
	withCageFSDoctorPaths(t, "/var/lib/mysql\n!"+phpShieldEventDir+"\n", true)

	checks := phpShieldCageFSDoctorChecks()
	if len(checks) != 1 {
		t.Fatalf("got %d check(s), want 1", len(checks))
	}
	if checks[0].Status != "fail" {
		t.Errorf("read-only mount -> status %q, want fail", checks[0].Status)
	}
}

// The check has to reach the report an operator actually runs, and only when
// the Shield is enabled -- a host not running it has nothing to remount for.
func TestBuildDoctorReportIncludesCageFSMountCheck(t *testing.T) {
	defer config.SetSSHDConfigPath(filepath.Join(t.TempDir(), "absent"))()
	withCageFSDoctorPaths(t, "/var/lib/mysql\n"+phpShieldEventDir+"\n", false)

	cfg := validDoctorConfig()
	cfg.PHPShield.Enabled = true
	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}

	report := buildDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func() ([]byte, error) { return payload, nil },
	)
	for _, check := range report.Checks {
		if check.Name == "php shield: cagefs event mount" {
			if check.Status != "fail" {
				t.Errorf("unapplied mount -> status %q, want fail", check.Status)
			}
			return
		}
	}
	t.Fatalf("doctor omitted the CageFS mount check: %+v", report.Checks)
}

// With the Shield disabled the mount is irrelevant; reporting it would be noise
// on every host that does not run runtime protection.
func TestBuildDoctorReportSkipsCageFSCheckWhenShieldDisabled(t *testing.T) {
	defer config.SetSSHDConfigPath(filepath.Join(t.TempDir(), "absent"))()
	withCageFSDoctorPaths(t, "/var/lib/mysql\n"+phpShieldEventDir+"\n", false)

	cfg := validDoctorConfig()
	cfg.PHPShield.Enabled = false
	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}

	report := buildDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func() ([]byte, error) { return payload, nil },
	)
	for _, check := range report.Checks {
		if check.Name == "php shield: cagefs event mount" {
			t.Fatalf("shield disabled -> check must not appear: %+v", check)
		}
	}
}
