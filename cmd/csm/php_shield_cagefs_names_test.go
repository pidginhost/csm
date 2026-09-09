package main

import (
	"strings"
	"testing"
)

// An operator fixes a blind cage per account, so the report has to say which
// accounts those are; a bare count sends them to remount every cage.
func TestPHPShieldCageFSDoctorNamesMissingCages(t *testing.T) {
	withCageFSDoctorPaths(t, "/var/lib/mysql\n"+phpShieldEventDir+"\n", false)
	cagefsCageMountSample = func() ([]string, int, error) { return []string{"alice", "bob"}, 12, nil }

	checks := phpShieldCageFSDoctorChecks()
	if len(checks) != 1 || checks[0].Status != "fail" {
		t.Fatalf("checks = %+v", checks)
	}
	msg := checks[0].Message
	if !strings.HasPrefix(msg, "2 of 12 sampled cages lack the event mount (alice, bob)") {
		t.Errorf("message does not name the cages: %q", msg)
	}
	if !strings.Contains(checks[0].Fix, "cagefsctl --remount alice") || !strings.Contains(checks[0].Fix, "cagefsctl --remount bob") {
		t.Errorf("fix does not give the per-account command: %q", checks[0].Fix)
	}
}

// A long list is capped so the report stays readable; the count is exact.
func TestPHPShieldCageFSDoctorCapsNamedCages(t *testing.T) {
	withCageFSDoctorPaths(t, "/var/lib/mysql\n"+phpShieldEventDir+"\n", false)
	names := []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8"}
	cagefsCageMountSample = func() ([]string, int, error) { return names, 40, nil }

	checks := phpShieldCageFSDoctorChecks()
	msg := checks[0].Message
	if !strings.HasPrefix(msg, "8 of 40 sampled cages lack the event mount (a1, a2, a3, a4, a5 and 3 more)") {
		t.Errorf("message = %q", msg)
	}
	if strings.Contains(msg, "a6") {
		t.Errorf("message lists beyond the cap: %q", msg)
	}
	if !strings.Contains(checks[0].Fix, "cagefsctl --remount-all") {
		t.Errorf("fix for many cages must offer the remount-all path: %q", checks[0].Fix)
	}
}

// The sampler names a cage by its account; a uid without a passwd entry is
// still reported, as its uid.
func TestCageAccountNameFallsBackToUID(t *testing.T) {
	old := cagefsAccountNameForUID
	t.Cleanup(func() { cagefsAccountNameForUID = old })
	cagefsAccountNameForUID = func(uid uint64) (string, bool) {
		if uid == 1001 {
			return "alice", true
		}
		return "", false
	}
	if got := cageDisplayName(1001); got != "alice" {
		t.Errorf("known uid = %q", got)
	}
	if got := cageDisplayName(4242); got != "uid:4242" {
		t.Errorf("unknown uid = %q", got)
	}
}

// UID labels identify unresolved cages, but cagefsctl requires an account
// name. They must stay visible without becoming invalid remount commands.
func TestPHPShieldCageFSDoctorRemountFixForUnknownUIDs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing []string
		wantFix string
	}{
		{
			name:    "unknown only",
			missing: []string{"uid:1001"},
			wantFix: "resolve account names for uid:1001, then use `cagefsctl --remount <user>`",
		},
		{
			name:    "mixed",
			missing: []string{"alice", "uid:1001"},
			wantFix: "apply per account with `cagefsctl --remount alice`; resolve account names for uid:1001, then use `cagefsctl --remount <user>`",
		},
		{
			name:    "cap includes unresolved cages",
			missing: []string{"uid:1001", "uid:1002", "uid:1003", "uid:1004", "uid:1005", "alice"},
			wantFix: "resolve account names for uid:1001, uid:1002, uid:1003, uid:1004, uid:1005, then use `cagefsctl --remount <user>`, or all at once with `cagefsctl --remount-all` in a maintenance window",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCageFSDoctorPaths(t, phpShieldEventDir+"\n", false)
			cagefsCageMountSample = func() ([]string, int, error) { return tc.missing, 12, nil }
			checks := phpShieldCageFSDoctorChecks()
			if len(checks) != 1 || checks[0].Status != "fail" {
				t.Fatalf("checks = %+v, want one failure", checks)
			}
			if !strings.Contains(checks[0].Message, "uid:1001") {
				t.Errorf("unresolved cage missing from report: %q", checks[0].Message)
			}
			want := tc.wantFix + "; a remount kills processes inside the cages it rebuilds"
			if checks[0].Fix != want {
				t.Errorf("fix = %q, want %q", checks[0].Fix, want)
			}
		})
	}
}
