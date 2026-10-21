package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// recordBatchHolds installs a recorder of admission batch holds and
// reports, for each, whether the rollback snapshot existed yet.
func recordBatchHolds(t *testing.T, rollbackFile string) *[]batchHold {
	t.Helper()
	var holds []batchHold
	setFirewallBatchHold(func(held bool) {
		_, err := os.Stat(rollbackFile)
		holds = append(holds, batchHold{held: held, snapshot: err == nil})
	})
	t.Cleanup(func() { setFirewallBatchHold(nil) })
	return &holds
}

type batchHold struct{ held, snapshot bool }

func lastHold(holds []batchHold) bool { return len(holds) > 0 && holds[len(holds)-1].held }

// An apply-confirmed window holds admission's block batches from before
// its snapshot until it ends, so a rollback cannot erase a row the owner
// wrote inside it, and a row written before it is in the snapshot (design
// C9). Confirmation and a rollback both end the hold.
func TestApplyConfirmedWindowHoldsBlockBatches(t *testing.T) {
	for _, end := range []string{"confirm", "rollback"} {
		t.Run(end, func(t *testing.T) {
			d, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)
			holds := recordBatchHolds(t, rollbackFile)
			if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if len(*holds) != 1 || !(*holds)[0].held || (*holds)[0].snapshot {
				t.Fatalf("holds = %+v; want one hold before the snapshot", *holds)
			}
			switch end {
			case "confirm":
				config.SetActive(d.cfg)
				t.Cleanup(func() { config.SetActive(nil) })
				c := &ControlListener{d: d}
				if _, err := c.handleFirewallConfirm(nil); err != nil {
					t.Fatal(err)
				}
			default:
				marker, err := os.ReadFile(confirmFile)
				if err != nil {
					t.Fatal(err)
				}
				firewallDeadmanMu.Lock()
				err = restoreFirewallRollback(confirmFile, rollbackFile, marker)
				firewallDeadmanMu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			if lastHold(*holds) {
				t.Fatalf("holds = %+v; the window's end kept batches held", *holds)
			}
		})
	}
}

// A window that fails to apply and restores the previous ruleset ends at
// once; one whose restore also fails stays armed and keeps batches held
// until the deadman restores it.
func TestApplyConfirmedFailureReleasesBlockBatchesOnlyWhenRestored(t *testing.T) {
	for _, restoreFails := range []bool{false, true} {
		_, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)
		if restoreFails {
			t.Setenv("NFT_RESTORE_FAIL", "1")
		}
		holds := recordBatchHolds(t, rollbackFile)
		err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return errors.New("nft transaction rejected") })
		if err == nil {
			t.Fatal("applyFirewallDeadman succeeded, want apply failure")
		}
		if lastHold(*holds) != restoreFails {
			t.Fatalf("restore fails %v: holds = %+v", restoreFails, *holds)
		}
	}
}

// Startup recovery ends the hold of a window it restores and keeps it for
// a window still open.
func TestRecoveredWindowKeepsBlockBatchesHeldOnlyWhileOpen(t *testing.T) {
	for _, open := range []bool{false, true} {
		d, confirmFile, rollbackFile, _, _ := setupFirewallDeadmanState(t)
		deadline := time.Now().Add(-time.Minute)
		if open {
			deadline = time.Now().Add(time.Hour)
		}
		writeTestFile(t, confirmFile, deadline.UTC().Format(time.RFC3339))
		writeTestFile(t, rollbackFile, "flush ruleset\n")
		held := true
		setFirewallBatchHold(func(h bool) { held = h })
		t.Cleanup(func() { setFirewallBatchHold(nil) })
		d.recoverFirewallApplyConfirmed()
		if held != open {
			t.Fatalf("open %v: batches held %v after recovery", open, held)
		}
	}
}

// Restore the engine configuration before releasing admission. A marker
// that cleanup cannot remove still permits rollback, so the hold stays.
func TestApplyConfirmedFailureKeepsHoldThroughRestoreAndCleanup(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "restored", true: "marker_cleanup"}[cleanupFails], func(t *testing.T) {
			_, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)
			held, restored := false, false
			setFirewallBatchHold(func(h bool) {
				if !h && !restored {
					t.Error("released admission before restoring the engine configuration")
				}
				held = h
			})
			t.Cleanup(func() { setFirewallBatchHold(nil) })
			err := applyFirewallDeadmanPrepared(confirmFile, rollbackFile, legacyRollbackFile, time.Hour,
				func() (*firewall.FirewallConfig, error) { return &firewall.FirewallConfig{}, nil },
				func(*firewall.FirewallConfig) { restored = true },
				func() error {
					if cleanupFails {
						if err := os.Remove(confirmFile); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(confirmFile, 0o700); err != nil {
							t.Fatal(err)
						}
						writeTestFile(t, filepath.Join(confirmFile, "occupied"), "fixture")
					}
					return errors.New("fixture apply failure")
				})
			if err == nil || !restored || held != cleanupFails {
				t.Fatalf("error %v, restored %v, held %v", err, restored, held)
			}
		})
	}
}

func TestRecoveredWindowWithoutMarkerReleasesHold(t *testing.T) {
	d, _, _, _, _ := setupFirewallDeadmanState(t)
	held := true
	setFirewallBatchHold(func(h bool) { held = h })
	t.Cleanup(func() { setFirewallBatchHold(nil) })
	d.recoverFirewallApplyConfirmed()
	if held {
		t.Fatal("a settled window retained its admission hold")
	}
}

// A kernel restore cannot settle a window whose engine configuration could
// not be recovered. Keep the marker and hold until repair or confirmation.
func TestRecoveredWindowWithUnreadableConfigKeepsHold(t *testing.T) {
	oldApply := applyFirewallEngine
	applyFirewallEngine = func(*Daemon) error { return nil }
	t.Cleanup(func() { applyFirewallEngine = oldApply })
	for _, hadState := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent_state", true: "saved_state"}[hadState], func(t *testing.T) {
			d, confirmFile, rollbackFile, _, seenFile := setupFirewallDeadmanState(t)
			writeTestFile(t, confirmFile, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
			writeTestFile(t, rollbackFile, "flush ruleset\n")
			writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), "{")
			stateFile := firewallStateFileFor(rollbackFile)
			before := `{"blocked":[{"ip":"203.0.113.9","reason":"before"}]}`
			if hadState {
				writeTestFile(t, stateFile, before)
			}
			if err := snapshotFirewallState(rollbackFile); err != nil {
				t.Fatal(err)
			}
			assertRestored := func() {
				t.Helper()
				if !hadState {
					requirePathMissing(t, stateFile)
					return
				}
				got, err := os.ReadFile(stateFile)
				if err != nil || string(got) != before {
					t.Fatalf("rollback state = %q, %v; want original snapshot", got, err)
				}
			}
			writeTestFile(t, stateFile, `{"blocked":[]}`)
			held := true
			setFirewallBatchHold(func(h bool) { held = h })
			t.Cleanup(func() {
				setFirewallBatchHold(nil)
				setFirewallDeadmanOnRollback(nil)
			})
			d.recoverFirewallApplyConfirmed()
			if !held {
				t.Fatal("configuration recovery failure released admission")
			}
			requirePathExists(t, seenFile)
			requirePathExists(t, confirmFile)
			requirePathExists(t, rollbackFile)
			assertRestored()
			requirePathExists(t, firewallStateSnapshotPath(rollbackFile))
			// Legacy changes remain possible while the window is pending.
			// Operator ruling 6: the restore ran once, so a repaired
			// configuration settles the window and keeps them.
			later := `{"blocked":[{"ip":"192.0.2.20"}]}`
			writeTestFile(t, stateFile, later)
			writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), "{}")
			d.recoverFirewallApplyConfirmed()
			if held {
				t.Fatal("repaired configuration kept admission held")
			}
			if got, err := os.ReadFile(stateFile); err != nil || string(got) != later {
				t.Fatalf("state after a repaired configuration = %q, %v; want the later blocks kept", got, err)
			}
			requirePathMissing(t, confirmFile)
			requirePathMissing(t, firewallStateSnapshotPath(rollbackFile))
		})
	}
}

func TestApplyConfirmedPreparationRunsWhileHeld(t *testing.T) {
	_, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)
	held := false
	setFirewallBatchHold(func(h bool) { held = h })
	t.Cleanup(func() { setFirewallBatchHold(nil) })
	failure := errors.New("configuration refused")
	err := applyFirewallDeadmanPrepared(confirmFile, rollbackFile, legacyRollbackFile, time.Hour,
		func() (*firewall.FirewallConfig, error) {
			if !held {
				t.Error("configuration preparation ran before admission was held")
			}
			return nil, failure
		}, nil, func() error { t.Error("apply ran after preparation failed"); return nil })
	if !errors.Is(err, failure) || held {
		t.Fatalf("preparation error %v, held %v", err, held)
	}
}

// Snapshot debris cannot keep admission held once no marker can roll it back.
// Cleanup still reports its error, and an armed marker still keeps the hold.
func TestApplyConfirmedCleanupReleasesOnlyADisarmedWindow(t *testing.T) {
	for _, end := range []string{"confirm", "confirm_missing", "rollback"} {
		t.Run(end, func(t *testing.T) {
			d, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)
			marker := newFirewallConfirmMarker(time.Now().Add(-time.Minute))
			if end != "confirm_missing" {
				writeTestFile(t, confirmFile, string(marker))
			}
			writeTestFile(t, rollbackFile, "flush ruleset\n")
			// Fail cleanup after marker removal, without failing kernel or state restore.
			if err := os.Mkdir(legacyRollbackFile, 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(legacyRollbackFile, "occupied"), "fixture")
			held, restored := true, false
			setFirewallBatchHold(func(h bool) { held = h })
			setFirewallDeadmanOnRollback(func() { restored = true })
			t.Cleanup(func() { setFirewallBatchHold(nil); setFirewallDeadmanOnRollback(nil) })
			var err error
			if end == "rollback" {
				firewallDeadmanMu.Lock()
				err = restoreFirewallRollback(confirmFile, rollbackFile, marker)
				firewallDeadmanMu.Unlock()
			} else {
				config.SetActive(d.cfg)
				t.Cleanup(func() { config.SetActive(nil) })
				_, err = (&ControlListener{d: d}).handleFirewallConfirm(nil)
			}
			if err == nil {
				t.Fatal("snapshot cleanup failure was hidden")
			}
			requirePathMissing(t, confirmFile)
			if held || restored != (end == "rollback") {
				t.Fatalf("disarmed window: held %v, restored %v", held, restored)
			}
			firewallDeadmanMu.Lock()
			stale := firewallDeadmanOnRollback != nil || firewallDeadmanConfigErr != nil
			firewallDeadmanMu.Unlock()
			if stale {
				t.Fatal("disarmed window retained recovery state")
			}
		})
	}
}

// Confirmation is the operator escape from unreadable saved configuration.
// Both re-apply handlers reject the marker, then reach config validation once
// it is removed; no real engine or kernel call is needed to prove that boundary.
func TestRecoveredWindowConfirmationUnblocksReapply(t *testing.T) {
	d, confirmFile, rollbackFile, _, _ := setupFirewallDeadmanState(t)
	d.fwEngine = new(firewall.Engine)
	config.SetActive(d.cfg)
	t.Cleanup(func() { config.SetActive(nil) })
	writeTestFile(t, confirmFile, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	writeTestFile(t, rollbackFile, "flush ruleset\n")
	writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), "{")
	held := true
	setFirewallBatchHold(func(h bool) { held = h })
	t.Cleanup(func() { setFirewallBatchHold(nil); setFirewallDeadmanOnRollback(nil) })
	d.recoverFirewallApplyConfirmed()
	c := &ControlListener{d: d}
	for _, run := range []func() error{
		func() error { _, err := c.handleFirewallRestart(nil); return err },
		func() error { _, err := c.handleFirewallApplyConfirmed(nil); return err },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "confirmation already pending") {
			t.Fatalf("pending window reapply = %v", err)
		}
	}
	if _, err := c.handleFirewallConfirm(nil); err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatal("confirmation retained the hold after unreadable config")
	}
	firewallDeadmanMu.Lock()
	stale := firewallDeadmanConfigErr != nil || firewallDeadmanOnRollback != nil
	firewallDeadmanMu.Unlock()
	if stale {
		t.Fatal("confirmation retained the old configuration fault")
	}
	for _, run := range []func() error{
		func() error { _, err := c.handleFirewallRestart(nil); return err },
		func() error { _, err := c.handleFirewallApplyConfirmed(nil); return err },
	} {
		if err := run(); err == nil || err.Error() != "config file path unknown" {
			t.Fatalf("disarmed window did not reach config validation: %v", err)
		}
	}
}
