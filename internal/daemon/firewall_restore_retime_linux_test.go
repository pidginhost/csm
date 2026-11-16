//go:build linux

package daemon

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// retimeCall is what one retiming of the blocked sets found: the rows
// gated, admission still held, and the engine configuration put back.
type retimeCall struct{ gated, held, configured bool }

// retimedFirewall is gatedFirewall with a recorder in place of the
// engine's retiming. *configured is what each call records as the state
// of the engine configuration.
func retimedFirewall(t *testing.T, unproven, configured *bool) (d *Daemon, start func(), calls *[]retimeCall) {
	t.Helper()
	calls = &[]retimeCall{}
	var state string
	d, state, start = gatedFirewall(t, unproven, func(ops *firewallStartupOps) {
		ops.retime = func(engine *firewall.Engine) error {
			*calls = append(*calls, retimeCall{
				gated:      gatedRows(readStartupRows(t, state)),
				held:       errors.Is(engine.ProbeBlockState(), firewall.ErrConfirmPending),
				configured: *configured,
			})
			return errors.New("fixture retime failure")
		}
	})
	return d, start, calls
}

// A rollback restores the kernel ruleset from a dump taken when its window
// opened, so each timed block comes back with the time it had left then.
// The blocked sets are retimed from the saved rows once per restore: after
// the rows are gated and the engine configuration is back, and before
// admission is released. A retiming that fails does not keep admission
// held.
func TestRolledBackWindowRetimesItsBlocksBeforeRelease(t *testing.T) {
	for _, mode := range []string{"deadman", "failed apply", "restart"} {
		t.Run(mode, func(t *testing.T) {
			unproven, configured := false, true
			d, start, calls := retimedFirewall(t, &unproven, &configured)
			confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(d.cfg.StatePath)
			prepare := func() (*firewall.FirewallConfig, error) {
				configured = false
				unproven = true
				return &firewall.FirewallConfig{}, nil
			}
			restore := func(*firewall.FirewallConfig) { configured = true }
			switch mode {
			case "deadman":
				start()
				if err := applyFirewallDeadmanPrepared(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, prepare, restore, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				marker := mustRead(t, confirmFile)
				firewallDeadmanMu.Lock()
				err := restoreFirewallRollback(confirmFile, rollbackFile, marker)
				firewallDeadmanMu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			case "failed apply":
				start()
				if err := applyFirewallDeadmanPrepared(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, prepare, restore, func() error { return errors.New("fixture apply failure") }); err == nil {
					t.Fatal("a failed apply reported success")
				}
			default:
				writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(time.Now().Add(-time.Minute))))
				writeTestFile(t, rollbackFile, "flush ruleset\n")
				writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), `{"enabled":true}`)
				if err := snapshotFirewallState(rollbackFile); err != nil {
					t.Fatal(err)
				}
				configured = false
				oldRestore := restoreFirewallEngineConfig
				restoreFirewallEngineConfig = func(*Daemon, *firewall.FirewallConfig) { configured = true }
				t.Cleanup(func() { restoreFirewallEngineConfig = oldRestore })
				start()
				unproven = true
				d.recoverFirewallApplyConfirmed()
			}
			if len(*calls) != 1 || (*calls)[0] != (retimeCall{gated: true, held: true, configured: true}) {
				t.Fatalf("retimings = %+v; want one, with the rows gated, admission held and the configuration back", *calls)
			}
			if errors.Is(d.fwEngine.ProbeBlockState(), firewall.ErrConfirmPending) {
				t.Fatal("a failed retiming kept admission held")
			}
		})
	}
}

// Only a restore makes the timers stale. A confirmed window and a restore
// that failed retime nothing; a restore whose window stays pending retimes
// when the window ends, and a rollback's retiming is not repeated when a
// later window is confirmed.
func TestWindowRetimesOnlyAfterARestore(t *testing.T) {
	for _, mode := range []string{"confirmed", "failed restore", "no state snapshot", "restored, still pending", "confirmed after a rollback"} {
		t.Run(mode, func(t *testing.T) {
			unproven, configured := true, true
			d, start, calls := retimedFirewall(t, &unproven, &configured)
			confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(d.cfg.StatePath)
			c := &ControlListener{d: d}
			switch mode {
			case "confirmed":
				start()
				if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				if _, err := c.handleFirewallConfirm(nil); err != nil {
					t.Fatal(err)
				}
			case "failed restore", "no state snapshot":
				start()
				if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				if mode == "failed restore" {
					t.Setenv("NFT_RESTORE_FAIL", "1")
				} else if err := os.Remove(firewallStateSnapshotPath(rollbackFile)); err != nil {
					t.Fatal(err)
				}
				marker := mustRead(t, confirmFile)
				firewallDeadmanMu.Lock()
				err := restoreFirewallRollback(confirmFile, rollbackFile, marker)
				firewallDeadmanMu.Unlock()
				if mode == "failed restore" && err == nil {
					t.Fatal("a failed restore reported success")
				}
				if mode == "no state snapshot" && err != nil {
					t.Fatal(err)
				}
			case "confirmed after a rollback":
				start()
				for _, rollBack := range []bool{true, false} {
					if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
						t.Fatal(err)
					}
					if !rollBack {
						if _, err := c.handleFirewallConfirm(nil); err != nil {
							t.Fatal(err)
						}
						continue
					}
					marker := mustRead(t, confirmFile)
					firewallDeadmanMu.Lock()
					err := restoreFirewallRollback(confirmFile, rollbackFile, marker)
					firewallDeadmanMu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
				if len(*calls) != 1 {
					t.Fatalf("retimings over a rollback and a later confirmation = %+v; want the rollback's alone", *calls)
				}
				return
			default:
				writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(time.Now().Add(-time.Minute))))
				writeTestFile(t, rollbackFile, "flush ruleset\n")
				writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), "{")
				if err := snapshotFirewallState(rollbackFile); err != nil {
					t.Fatal(err)
				}
				// Confirmation accepts current configuration without recovering
				// the unreadable saved configuration.
				configured = false
				start()
				d.recoverFirewallApplyConfirmed()
				if len(*calls) != 0 || !errors.Is(d.fwEngine.ProbeBlockState(), firewall.ErrConfirmPending) {
					t.Fatalf("a window still pending: retimings %+v", *calls)
				}
				if _, err := c.handleFirewallConfirm(nil); err != nil {
					t.Fatal(err)
				}
				if len(*calls) != 1 || (*calls)[0] != (retimeCall{gated: true, held: true, configured: false}) {
					t.Fatalf("retimings when the pending window ended = %+v; want one before the release", *calls)
				}
				return
			}
			if len(*calls) != 0 {
				t.Fatalf("retimings without a restore = %+v; want none", *calls)
			}
		})
	}
}
