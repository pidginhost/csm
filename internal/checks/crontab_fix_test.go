package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withCrontabAllowedRoots redirects fixCrontabAllowedRoots for a single test
// so fixSuspiciousCrontab can operate on a file under t.TempDir() instead of
// the real /var/spool/cron.
func withCrontabAllowedRoots(t *testing.T, dir string) {
	t.Helper()
	old := fixCrontabAllowedRoots
	fixCrontabAllowedRoots = []string{dir}
	t.Cleanup(func() { fixCrontabAllowedRoots = old })
}

// withQuarantineDirCF is a local swap of the package-level quarantineDir so
// these tests never write to the real /opt/csm/quarantine. The CF suffix
// keeps the symbol distinct from withQuarantineDir (defined in a linux-only
// test file) so crontab-fix tests stay cross-platform.
func withQuarantineDirCF(t *testing.T, dir string) {
	t.Helper()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
}

// mustEvalSymlinks resolves dir through filepath.EvalSymlinks. On darwin
// t.TempDir() hands back a path under /var/folders which is a symlink to
// /private/var/folders; fixSuspiciousCrontab's allowed-root check compares
// the symlink-resolved path, so tests must feed it the resolved form.
func mustEvalSymlinks(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	return resolved
}

// TestMatchCrontabPatterns_GsocketDefunctFixtures is a regression guard: the
// five sanitized captures of the 2026-03-24 'defunct-kernel' attack on
// cluster6 must continue to match crontabSuspiciousPatterns. Losing a match
// here means an attacker variant would now slip past both CheckCrontabs
// and makeAccountCrontabCheck.
func TestMatchCrontabPatterns_GsocketDefunctFixtures(t *testing.T) {
	dir := filepath.Join("testdata", "crontabs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	saw := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "gsocket_defunct_kernel_") {
			continue
		}
		saw++
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		matched := matchCrontabPatterns(string(data))
		if len(matched) == 0 {
			t.Errorf("%s: expected patterns to match, none did", e.Name())
			continue
		}
		// Each fixture must fire on the template markers specifically; the
		// 'base64 -d|bash' chain and the 'defunct-kernel' comment header are
		// the two most attacker-stable tokens on this template.
		wantAny := []string{"defunct-kernel", "SEED PRNG", "base64 -d|bash"}
		hit := false
		for _, m := range matched {
			for _, w := range wantAny {
				if strings.EqualFold(m, w) {
					hit = true
				}
			}
		}
		if !hit {
			t.Errorf("%s: matched %v but none of the stable template markers %v fired",
				e.Name(), matched, wantAny)
		}
	}
	if saw < 5 {
		t.Fatalf("expected at least 5 gsocket_defunct_kernel fixtures, saw %d", saw)
	}
}

// TestMatchCrontabPatterns_BenignNoMatch ensures a normal-looking user
// crontab does not trip the heuristic.
func TestMatchCrontabPatterns_BenignNoMatch(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "crontabs", "benign_01.crontab"))
	if err != nil {
		t.Fatalf("read benign fixture: %v", err)
	}
	if matched := matchCrontabPatterns(string(data)); len(matched) > 0 {
		t.Errorf("benign crontab matched patterns %v (false positive)", matched)
	}
}

// TestFixSuspiciousCrontab_QuarantinesAndTruncates verifies the live
// remediation path: the bad crontab is copied to quarantine with a metadata
// sidecar, and the source file is truncated to zero bytes.
func TestFixSuspiciousCrontab_QuarantinesAndTruncates(t *testing.T) {
	// Temp spool so we never touch /var/spool/cron during tests.
	// EvalSymlinks because t.TempDir() returns /var/folders/... on darwin
	// which resolves to /private/var/... and would escape the allowed root
	// inside fixSuspiciousCrontab's path-boundary check.
	spool := mustEvalSymlinks(t, t.TempDir())
	withCrontabAllowedRoots(t, spool)
	qdir := filepath.Join(t.TempDir(), "quarantine")
	withQuarantineDirCF(t, qdir)

	fixture, err := os.ReadFile(filepath.Join("testdata", "crontabs", "gsocket_defunct_kernel_01.crontab"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	target := filepath.Join(spool, "victim1")
	if writeErr := os.WriteFile(target, fixture, 0600); writeErr != nil {
		t.Fatalf("stage crontab: %v", writeErr)
	}

	res := fixSuspiciousCrontab(target)
	if !res.Success {
		t.Fatalf("fixSuspiciousCrontab failed: %+v", res)
	}

	// Source must be truncated to zero bytes, mode 0600.
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected 0-byte crontab after fix, got %d", info.Size())
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}

	// Exactly one quarantined copy + one .meta sidecar must exist.
	qentries, err := os.ReadDir(qdir)
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	var payload, meta string
	for _, e := range qentries {
		name := filepath.Join(qdir, e.Name())
		if strings.HasSuffix(e.Name(), ".meta") {
			meta = name
		} else {
			payload = name
		}
	}
	if payload == "" || meta == "" {
		t.Fatalf("expected quarantine payload + .meta, got %v", qentries)
	}
	quarData, err := os.ReadFile(payload)
	if err != nil {
		t.Fatalf("read quarantine payload: %v", err)
	}
	if string(quarData) != string(fixture) {
		t.Error("quarantine payload does not match original fixture bytes")
	}
	metaBytes, err := os.ReadFile(meta)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(metaBytes, &parsed); err != nil {
		t.Fatalf("parse meta json: %v", err)
	}
	if got, _ := parsed["original_path"].(string); got != target {
		t.Errorf("meta original_path = %q, want %q", got, target)
	}
	if got, _ := parsed["reason"].(string); got != "suspicious_crontab remediation" {
		t.Errorf("meta reason = %q, want suspicious_crontab remediation", got)
	}
}

// TestFixSuspiciousCrontab_RejectsPathOutsideAllowedRoot keeps the
// remediation bounded to the cron spool. A finding that points somewhere
// else (e.g. /etc or a user home) must not be blindly truncated.
func TestFixSuspiciousCrontab_RejectsPathOutsideAllowedRoot(t *testing.T) {
	allowed := t.TempDir()
	withCrontabAllowedRoots(t, allowed)
	withQuarantineDirCF(t, filepath.Join(t.TempDir(), "q"))

	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("0 * * * * defunct-kernel\n"), 0600); err != nil {
		t.Fatalf("stage outside: %v", err)
	}
	res := fixSuspiciousCrontab(outside)
	if res.Success {
		t.Fatalf("expected rejection for path outside allowed root, got success: %+v", res)
	}
	if !strings.Contains(res.Error, "outside the allowed") {
		t.Errorf("expected 'outside the allowed' error, got: %q", res.Error)
	}
}

// TestHasFix_SuspiciousCrontab and TestApplyFix_SuspiciousCrontab_RouteWired
// guarantee the public API exposes the new fix. Missing this wiring is how
// the previous gap (FixDescription advertised a fix that ApplyFix refused to
// run) stayed invisible.
func TestHasFix_SuspiciousCrontab(t *testing.T) {
	if !HasFix("suspicious_crontab") {
		t.Error("HasFix should return true for suspicious_crontab now that fixSuspiciousCrontab exists")
	}
}

func TestApplyFix_SuspiciousCrontab_RouteWired(t *testing.T) {
	spool := mustEvalSymlinks(t, t.TempDir())
	withCrontabAllowedRoots(t, spool)
	withQuarantineDirCF(t, filepath.Join(t.TempDir(), "q"))

	target := filepath.Join(spool, "victim1")
	if err := os.WriteFile(target, []byte("0 * * * * defunct-kernel\n"), 0600); err != nil {
		t.Fatalf("stage: %v", err)
	}

	res := ApplyFix("suspicious_crontab",
		"Suspicious pattern in crontab for user victim1: defunct-kernel",
		"",
		target)
	if !res.Success {
		t.Fatalf("ApplyFix should route suspicious_crontab to fixSuspiciousCrontab, got %+v", res)
	}
}
