package daemon

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// expiredWindowWithUnreadableConfig writes an expired window whose saved
// engine configuration cannot be read, with a state snapshot of before.
func expiredWindowWithUnreadableConfig(t *testing.T, before string) (*Daemon, string, string, string) {
	t.Helper()
	d, confirmFile, rollbackFile, _, seenFile := setupFirewallDeadmanState(t)
	writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(time.Now().Add(-time.Minute))))
	writeTestFile(t, rollbackFile, "flush ruleset\n")
	writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), "{")
	writeTestFile(t, firewallStateFileFor(rollbackFile), before)
	if err := snapshotFirewallState(rollbackFile); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		setFirewallBatchHold(nil)
		setFirewallDeadmanOnRollback(nil)
	})
	return d, confirmFile, rollbackFile, seenFile
}

// Operator ruling 6 ("restore once"): when a pending window's saved
// configuration is unreadable, its kernel and state restore runs once and
// is recorded. Later restarts keep the blocks added since instead of
// restoring the window's start again; the window stays pending and holds
// admission until a repaired configuration or a confirmation settles it.
// A repaired configuration is restored and rebuilt on the current state.
func TestRecoveredWindowRestoresOnce(t *testing.T) {
	before := `{"blocked":[{"ip":"203.0.113.9","reason":"before"}]}`
	d, confirmFile, rollbackFile, seenFile := expiredWindowWithUnreadableConfig(t, before)
	stateFile := firewallStateFileFor(rollbackFile)
	writeTestFile(t, stateFile, `{"blocked":[]}`)
	held := true
	setFirewallBatchHold(func(h bool) { held = h })
	var restored *firewall.FirewallConfig
	applied := 0
	oldRestore, oldApply := restoreFirewallEngineConfig, applyFirewallEngine
	restoreFirewallEngineConfig = func(_ *Daemon, cfg *firewall.FirewallConfig) { restored = cfg }
	applyFirewallEngine = func(*Daemon) error { applied++; return nil }
	t.Cleanup(func() { restoreFirewallEngineConfig, applyFirewallEngine = oldRestore, oldApply })

	d.recoverFirewallApplyConfirmed()
	requirePathExists(t, seenFile)
	if got, err := os.ReadFile(stateFile); err != nil || string(got) != before {
		t.Fatalf("first recovery state = %q, %v; want the window's start", got, err)
	}
	requirePathExists(t, confirmFile)
	if !held {
		t.Fatal("an unreadable configuration released admission")
	}

	// A block added after the rollback survives the next restart.
	added := `{"blocked":[{"ip":"203.0.113.9","reason":"before"},{"ip":"192.0.2.20","reason":"later"}]}`
	writeTestFile(t, stateFile, added)
	if err := os.Remove(seenFile); err != nil {
		t.Fatal(err)
	}
	d.recoverFirewallApplyConfirmed()
	requirePathMissing(t, seenFile)
	if got, err := os.ReadFile(stateFile); err != nil || string(got) != added {
		t.Fatalf("second recovery state = %q, %v; want the blocks added since", got, err)
	}
	requirePathExists(t, confirmFile)
	if st := firewallConfirmationStatus(d.cfg.StatePath); !held || st == nil || !strings.Contains(st.Error, "restored, but not its configuration") {
		t.Fatalf("held %v, status %+v after a second restart", held, st)
	}

	writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), `{"enabled":true}`)
	d.recoverFirewallApplyConfirmed()
	requirePathMissing(t, seenFile)
	if restored == nil || !restored.Enabled || applied != 1 {
		t.Fatalf("repaired configuration: restored %+v, applied %d times", restored, applied)
	}
	if got, err := os.ReadFile(stateFile); err != nil || string(got) != added {
		t.Fatalf("repaired recovery state = %q, %v", got, err)
	}
	if held {
		t.Fatal("a settled window kept admission held")
	}
	requirePathMissing(t, confirmFile)
	requirePathMissing(t, firewallRestoredPath(rollbackFile))
	requirePathMissing(t, firewallStateSnapshotPath(rollbackFile))
}

// A repaired configuration that cannot be applied keeps the window
// pending without restoring again, and a record that names another window
// is not this one's restore.
func TestRecoveredWindowRestoreOnceFailures(t *testing.T) {
	before := `{"blocked":[]}`
	d, confirmFile, rollbackFile, seenFile := expiredWindowWithUnreadableConfig(t, before)
	writeTestFile(t, firewallRestoredPath(rollbackFile), string(firewallRestoreProof(mustRead(t, confirmFile))))
	writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), `{"enabled":true}`)
	oldRestore, oldApply := restoreFirewallEngineConfig, applyFirewallEngine
	restoreFirewallEngineConfig = func(*Daemon, *firewall.FirewallConfig) {}
	applyFirewallEngine = func(*Daemon) error { return errors.New("fixture apply failure") }
	t.Cleanup(func() { restoreFirewallEngineConfig, applyFirewallEngine = oldRestore, oldApply })
	d.recoverFirewallApplyConfirmed()
	requirePathExists(t, confirmFile)
	if st := firewallConfirmationStatus(d.cfg.StatePath); st == nil || !strings.Contains(st.Error, "fixture apply failure") {
		t.Fatalf("status after a failed apply = %+v", st)
	}

	requirePathMissing(t, seenFile)

	// A record that names another window is not this one's restore.
	writeTestFile(t, firewallRestoredPath(rollbackFile), "another window")
	writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), "{")
	d.recoverFirewallApplyConfirmed()
	requirePathExists(t, seenFile)
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Status and doctor show a pending window: when it rolls back while a
// rollback is scheduled, otherwise why it cannot settle by itself.
func TestFirewallConfirmationStatus(t *testing.T) {
	d, confirmFile, rollbackFile, _, _ := setupFirewallDeadmanState(t)
	t.Cleanup(func() { setFirewallDeadmanOnRollback(nil) })
	if st := firewallConfirmationStatus(d.cfg.StatePath); st != nil {
		t.Fatalf("no window = %+v", st)
	}
	deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(deadline)))
	writeTestFile(t, rollbackFile, "flush ruleset\n")
	d.recoverFirewallApplyConfirmed()
	if st := firewallConfirmationStatus(d.cfg.StatePath); st == nil || !st.Deadline.Equal(deadline) || st.Error != "" {
		t.Fatalf("scheduled window = %+v", st)
	}
	writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), "{")
	d.recoverFirewallApplyConfirmed()
	if st := firewallConfirmationStatus(d.cfg.StatePath); st == nil || !strings.Contains(st.Error, "restores the ruleset only") {
		t.Fatalf("scheduled window without its configuration = %+v", st)
	}
	setFirewallDeadmanOnRollback(nil)
	writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(deadline)))
	if st := firewallConfirmationStatus(d.cfg.StatePath); st == nil || !strings.Contains(st.Error, "no rollback is scheduled") {
		t.Fatalf("unscheduled window = %+v", st)
	}
	// A scheduled rollback that ran and failed is no longer scheduled.
	if err := os.Remove(firewallConfigSnapshotPath(rollbackFile)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_RESTORE_FAIL", "1")
	writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(time.Now().Add(100*time.Millisecond))))
	d.recoverFirewallApplyConfirmed()
	until := time.Now().Add(5 * time.Second)
	for st := firewallConfirmationStatus(d.cfg.StatePath); st == nil || st.Error == ""; st = firewallConfirmationStatus(d.cfg.StatePath) {
		if time.Now().After(until) {
			t.Fatalf("a failed rollback still reads as scheduled: %+v", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Status carries the window while the firewall is on.
	d.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	if st := d.AutomationStatus().FirewallConfirmation; st == nil || !strings.Contains(st.Error, "no rollback is scheduled") {
		t.Fatalf("automation status window = %+v", st)
	}
}

// The refusal of a second change names only what works: waiting helps
// only while a rollback is scheduled and its configuration is readable;
// confirmation still requires successful marker removal.
func TestPendingWindowRefusalNamesWhatWorks(t *testing.T) {
	d, confirmFile, rollbackFile, _, _ := setupFirewallDeadmanState(t)
	t.Cleanup(func() { setFirewallDeadmanOnRollback(nil) })
	writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(time.Now().Add(time.Hour))))
	writeTestFile(t, rollbackFile, "flush ruleset\n")
	d.recoverFirewallApplyConfirmed()
	refuse := func() string {
		t.Helper()
		firewallDeadmanMu.Lock()
		defer firewallDeadmanMu.Unlock()
		err := rejectPendingFirewallConfirmation(confirmFile)
		if err == nil || !strings.Contains(err.Error(), "confirmation already pending") || !strings.Contains(err.Error(), "csm firewall confirm") {
			t.Fatalf("refusal = %v", err)
		}
		return err.Error()
	}
	if got := refuse(); !strings.Contains(got, "wait for its rollback at") {
		t.Fatalf("scheduled refusal = %q", got)
	}
	writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(time.Now().Add(time.Hour))))
	if got := refuse(); strings.Contains(got, "wait") {
		t.Fatalf("unscheduled refusal = %q", got)
	}
}
