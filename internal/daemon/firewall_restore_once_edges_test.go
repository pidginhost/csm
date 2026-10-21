package daemon

import (
	"os"
	"strings"
	"testing"
	"time"
)

// A failed kernel restore cannot be advertised as a completed rollback.
// A scheduled ruleset-only restore cannot settle a pending configuration.
func TestFirewallRestoreOnceFailureStatusAndRefusal(t *testing.T) {
	d, confirmFile, rollbackFile, _ := expiredWindowWithUnreadableConfig(t, `{"blocked":[]}`)
	t.Setenv("NFT_RESTORE_FAIL", "1")
	d.recoverFirewallApplyConfirmed()
	requirePathMissing(t, firewallRestoredPath(rollbackFile))
	st := firewallConfirmationStatus(d.cfg.StatePath)
	if st == nil || st.Error == "" || strings.Contains(st.Error, "was restored") {
		t.Fatalf("failed restore claims completion: %+v", st)
	}
	marker := newFirewallConfirmMarker(time.Now().Add(time.Hour))
	writeTestFile(t, confirmFile, string(marker))
	d.recoverFirewallApplyConfirmed()
	firewallDeadmanMu.Lock()
	err := rejectPendingFirewallConfirmation(confirmFile)
	firewallDeadmanMu.Unlock()
	if err == nil || strings.Contains(err.Error(), "wait for") {
		t.Fatalf("waiting cannot settle unreadable configuration: %v", err)
	}
}

// A second callback for the same window must not replay a completed
// restore. Confirmation must clear its scheduled marker too.
func TestFirewallRestoreOnceDuplicateCallbackAndDisarm(t *testing.T) {
	d, confirmFile, rollbackFile, seenFile := expiredWindowWithUnreadableConfig(t, `{"blocked":[]}`)
	marker := mustRead(t, confirmFile)
	d.recoverFirewallApplyConfirmed()
	later := `{"blocked":[{"ip":"192.0.2.20"}]}`
	writeTestFile(t, firewallStateFileFor(rollbackFile), later)
	if err := os.Remove(seenFile); err != nil {
		t.Fatal(err)
	}
	firewallDeadmanMu.Lock()
	err := restoreFirewallRollback(confirmFile, rollbackFile, marker)
	firewallDeadmanMu.Unlock()
	if err == nil {
		t.Fatal("unreadable configuration settled")
	}
	requirePathMissing(t, seenFile)
	if got := string(mustRead(t, firewallStateFileFor(rollbackFile))); got != later {
		t.Fatalf("duplicate callback restored old state: %q", got)
	}
	firewallDeadmanMu.Lock()
	firewallDeadmanArmed = marker
	_, _, legacy := firewallRollbackFiles(d.cfg.StatePath)
	err = settleFirewallDeadmanLocked(confirmFile, rollbackFile, legacy)
	armed := len(firewallDeadmanArmed)
	firewallDeadmanMu.Unlock()
	if err != nil || armed != 0 {
		t.Fatalf("confirmation left armed marker: %d, %v", armed, err)
	}
}

// No completion record may suppress a retry after state restoration or
// completion publication failed. Directory fixtures work even as root.
func TestFirewallRestoreOnceWaitsForCompletion(t *testing.T) {
	for _, failure := range []string{"state", "record"} {
		t.Run(failure, func(t *testing.T) {
			d, confirmFile, rollbackFile, seenFile := expiredWindowWithUnreadableConfig(t, `{"blocked":[]}`)
			blocked := firewallRestoredPath(rollbackFile)
			if failure == "state" {
				blocked = firewallStateFileFor(rollbackFile)
				if err := os.Remove(blocked); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			d.recoverFirewallApplyConfirmed()
			requirePathExists(t, seenFile)
			if firewallRestoreRecorded(rollbackFile, mustRead(t, confirmFile)) {
				t.Fatal("incomplete restore was recorded")
			}
			if err := os.Remove(blocked); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(seenFile); err != nil {
				t.Fatal(err)
			}
			d.recoverFirewallApplyConfirmed()
			requirePathExists(t, seenFile)
			if !firewallRestoreRecorded(rollbackFile, mustRead(t, confirmFile)) {
				t.Fatal("successful retry was not recorded")
			}
		})
	}
}

// A disabled or failed engine cannot make its pending confirmation vanish,
// and cannot claim a repaired configuration was installed.
func TestFirewallRestoreOnceNeedsEngine(t *testing.T) {
	d, confirmFile, rollbackFile, _ := expiredWindowWithUnreadableConfig(t, `{"blocked":[]}`)
	held := true
	setFirewallBatchHold(func(h bool) { held = h })
	d.recoverFirewallApplyConfirmed()
	d.cfg.Firewall = nil
	if st := d.AutomationStatus().FirewallConfirmation; st == nil || st.Error == "" {
		t.Fatalf("disabled firewall hides recovery: %+v", st)
	}
	writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), `{"enabled":true}`)
	d.recoverFirewallApplyConfirmed()
	requirePathExists(t, confirmFile)
	if !held {
		t.Fatal("missing engine released the hold")
	}
	if st := firewallConfirmationStatus(d.cfg.StatePath); st == nil || !strings.Contains(st.Error, "engine is unavailable") {
		t.Fatalf("missing engine claimed repair: %+v", st)
	}
}

// Replacing a rollback hook must not cancel its scheduled window. Resetting
// the hook between daemon lifetimes must clear the scheduled identity.
func TestFirewallRestoreOnceHookKeepsScheduledWindow(t *testing.T) {
	marker := newFirewallConfirmMarker(time.Now().Add(time.Hour))
	firewallDeadmanMu.Lock()
	firewallDeadmanArmed = marker
	firewallDeadmanMu.Unlock()
	t.Cleanup(func() { setFirewallDeadmanOnRollback(nil) })
	setFirewallDeadmanOnRollback(func() {})
	firewallDeadmanMu.Lock()
	got := string(firewallDeadmanArmed)
	firewallDeadmanMu.Unlock()
	if got != string(marker) {
		t.Fatalf("hook replacement disarmed window: %q", got)
	}
	setFirewallDeadmanOnRollback(nil)
	firewallDeadmanMu.Lock()
	armed := len(firewallDeadmanArmed)
	firewallDeadmanMu.Unlock()
	if armed != 0 {
		t.Fatalf("reset left a scheduled window: %d", armed)
	}
}

// A recorded ruleset-only restore proves this window had an unreadable
// configuration. Deleting it cannot turn the window into a legacy one.
func TestFirewallRestoreOnceMissingConfigKeepsHold(t *testing.T) {
	d, confirmFile, rollbackFile, seenFile := expiredWindowWithUnreadableConfig(t, `{"blocked":[]}`)
	held := true
	setFirewallBatchHold(func(h bool) { held = h })
	d.recoverFirewallApplyConfirmed()
	if err := os.Remove(firewallConfigSnapshotPath(rollbackFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(seenFile); err != nil {
		t.Fatal(err)
	}
	// A stale hook cannot substitute for the missing saved configuration.
	called := false
	setFirewallDeadmanOnRollback(func() { called = true })
	oldApply := applyFirewallEngine
	applyFirewallEngine = func(*Daemon) error { called = true; return nil }
	t.Cleanup(func() { applyFirewallEngine = oldApply })
	d.recoverFirewallApplyConfirmed()
	requirePathExists(t, confirmFile)
	requirePathMissing(t, seenFile)
	if !held || called || !firewallRestoreRecorded(rollbackFile, mustRead(t, confirmFile)) {
		t.Fatalf("missing saved config settled: held=%v called=%v", held, called)
	}
	if st := firewallConfirmationStatus(d.cfg.StatePath); st == nil || !strings.Contains(st.Error, "configuration is missing") {
		t.Fatalf("missing saved config status: %+v", st)
	}
}

// A corrupt marker still owns a recovery window. Empty marker bytes must
// neither replay a completed restore nor make an empty sidecar proof.
func TestFirewallRestoreOnceEmptyMarker(t *testing.T) {
	d, confirmFile, rollbackFile, seenFile := expiredWindowWithUnreadableConfig(t, `{"blocked":[]}`)
	writeTestFile(t, confirmFile, "")
	held := true
	setFirewallBatchHold(func(h bool) { held = h })
	d.recoverFirewallApplyConfirmed()
	requirePathExists(t, seenFile)
	if !held || !firewallRestoreRecorded(rollbackFile, nil) {
		t.Fatal("empty marker's successful rollback was not recorded")
	}
	if len(mustRead(t, firewallRestoredPath(rollbackFile))) == 0 {
		t.Fatal("an empty sidecar could stand in for a completed restore")
	}
	later := `{"blocked":[{"ip":"192.0.2.20"}]}`
	writeTestFile(t, firewallStateFileFor(rollbackFile), later)
	if err := os.Remove(seenFile); err != nil {
		t.Fatal(err)
	}
	d.recoverFirewallApplyConfirmed()
	requirePathMissing(t, seenFile)
	requirePathExists(t, confirmFile)
	if got := string(mustRead(t, firewallStateFileFor(rollbackFile))); got != later || !held {
		t.Fatalf("empty marker replayed restoration: state=%q held=%v", got, held)
	}
	// Truncating the proof must permit a retry, even for an empty marker.
	writeTestFile(t, firewallRestoredPath(rollbackFile), "")
	d.recoverFirewallApplyConfirmed()
	requirePathExists(t, seenFile)
	if got := string(mustRead(t, firewallStateFileFor(rollbackFile))); got != `{"blocked":[]}` {
		t.Fatalf("an empty proof suppressed recovery: %q", got)
	}
}
