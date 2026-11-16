//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

var (
	gateHeldAction    = "act_" + strings.Repeat("4", 32)
	gateSettledAction = "act_" + strings.Repeat("5", 32)
)

const gateOperatorIP = "198.51.100.70"

// gatedFirewall is a daemon whose saved rows are an admission block the
// ledger will call unproven, one it will call settled, and an operator's
// block. start runs its firewall startup; the ledger answers only once
// *unproven is set.
func gatedFirewall(t *testing.T, unproven *bool) (d *Daemon, state string, start func()) {
	t.Helper()
	installFakeNft(t)
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	previousCfg := config.Active()
	config.SetActive(cfg)
	previousBlocker := incidentSprayBlocker
	firewallMetricsMu.RLock()
	previousMetricsEngine := firewallMetricsEngine
	firewallMetricsMu.RUnlock()
	d = New(cfg, nil, nil, "")
	t.Cleanup(func() {
		close(d.stopCh)
		config.SetActive(previousCfg)
		checks.SetIPBlocker(nil)
		SetIncidentSprayBlocker(previousBlocker)
		setFirewallMetricsEngine(previousMetricsEngine)
		setFirewallBatchHold(nil)
		setFirewallRowGate(nil)
		setFirewallDeadmanOnRollback(nil)
	})
	state = filepath.Join(cfg.StatePath, "firewall", "state.json")
	expires := time.Now().Add(time.Hour).UTC()
	writeStartupRows(t, state, []firewall.BlockedEntry{
		{IP: "192.0.2.70", ActionID: gateHeldAction, ExpiresAt: expires},
		{IP: "192.0.2.71", ActionID: gateSettledAction, ExpiresAt: expires},
		{IP: gateOperatorIP, Reason: "operator"},
	})
	only := func(ids []string, keep ...string) []string {
		return slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return !slices.Contains(keep, id) })
	}
	start = func() {
		d.startFirewallUsing(firewallStartupOps{
			newEngine: firewall.NewEngine,
			apply:     func(*firewall.Engine) error { return nil },
			unproven: func(ids []string) ([]string, error) {
				if !*unproven {
					return nil, nil
				}
				return only(ids, gateHeldAction, gateSettledAction), nil
			},
			settled: func(ids []string) ([]string, error) { return only(ids, gateSettledAction), nil },
		})
		if d.fwEngine == nil {
			t.Fatal("the firewall did not start")
		}
	}
	return d, state, start
}

// gatedRows reports whether rows are the gated state: the unproven block
// marked, the settled one gone and the operator's block untouched.
func gatedRows(rows []firewall.BlockedEntry) bool {
	return len(rows) == 2 && rows[0].ActionID == gateHeldAction && rows[0].Unverified &&
		rows[1].IP == gateOperatorIP && !rows[1].Unverified
}

// A rollback puts state.json back as it was when its window opened, so
// every mark and removal the ledger asked for since is lost with it. The
// rows are gated on the ledger again after each such restore and before
// admission is released: a block the ledger counts as evicted or failed
// must not read as an enforced block.
func TestRolledBackWindowGatesItsRowsAgain(t *testing.T) {
	for _, mode := range []string{"deadman", "failed apply", "restart", "restart, unreadable configuration"} {
		t.Run(mode, func(t *testing.T) {
			unproven := false
			d, state, start := gatedFirewall(t, &unproven)
			confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(d.cfg.StatePath)
			var atRelease []firewall.BlockedEntry
			watchRelease := func() {
				setFirewallBatchHold(func(held bool) {
					if !held {
						atRelease = readStartupRows(t, state)
					}
					d.fwEngine.HoldBlockBatches(held)
				})
			}
			switch mode {
			case "deadman":
				start()
				watchRelease()
				if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				// Inside the window the ledger learns of the eviction and
				// the owner marks the row, as its retirement does.
				unproven = true
				if n, err := d.fwEngine.MarkBlockActionsUnverified([]string{gateHeldAction}); n != 1 || err != nil {
					t.Fatalf("marking inside the window = %d, %v", n, err)
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
				watchRelease()
				unproven = true
				if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return errors.New("fixture apply failure") }); err == nil {
					t.Fatal("a failed apply reported success")
				}
			default:
				// The snapshot of a window a restart interrupted predates
				// what this start's gate writes.
				writeTestFile(t, confirmFile, string(newFirewallConfirmMarker(time.Now().Add(-time.Minute))))
				writeTestFile(t, rollbackFile, "flush ruleset\n")
				if err := snapshotFirewallState(rollbackFile); err != nil {
					t.Fatal(err)
				}
				if mode == "restart, unreadable configuration" {
					writeTestFile(t, firewallConfigSnapshotPath(rollbackFile), "{")
				}
				unproven = true
				start()
				watchRelease()
				if !gatedRows(readStartupRows(t, state)) {
					t.Fatalf("rows after startup = %+v", readStartupRows(t, state))
				}
				d.recoverFirewallApplyConfirmed()
			}
			if rows := readStartupRows(t, state); !gatedRows(rows) {
				t.Fatalf("rows after the restore = %+v; want the unproven row marked and the settled row gone", rows)
			}
			if blocks, err := d.fwEngine.BlockedEntries(); err != nil || len(blocks) != 1 || blocks[0].IP != gateOperatorIP {
				t.Fatalf("enforced blocks after the restore = %+v, %v; want the operator's block alone", blocks, err)
			}
			held := errors.Is(d.fwEngine.ProbeBlockState(), firewall.ErrConfirmPending)
			if wantHeld := mode == "restart, unreadable configuration"; held != wantHeld {
				t.Fatalf("admission held %v after the restore, want %v", held, wantHeld)
			}
			if !held && !gatedRows(atRelease) {
				t.Fatalf("rows when admission was released = %+v; want them gated first", atRelease)
			}
		})
	}
}

// Older windows have no saved rows. Their current rows must not be used
// to rewrite the restored kernel image.
func TestRolledBackWindowWithoutStateSnapshotKeepsRows(t *testing.T) {
	unproven := false
	d, state, start := gatedFirewall(t, &unproven)
	confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(d.cfg.StatePath)
	start()
	if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(firewallStateSnapshotPath(rollbackFile)); err != nil {
		t.Fatal(err)
	}
	unproven = true
	marker := mustRead(t, confirmFile)
	firewallDeadmanMu.Lock()
	err := restoreFirewallRollback(confirmFile, rollbackFile, marker)
	firewallDeadmanMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if rows := readStartupRows(t, state); len(rows) != 3 || rows[0].Unverified {
		t.Fatalf("legacy window changed current rows: %+v", rows)
	}
}

// A successful nft restore does not hide a failed state restore.
func TestFailedRollbackRestoreOfStateDoesNotGateRows(t *testing.T) {
	unproven := false
	d, state, start := gatedFirewall(t, &unproven)
	confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(d.cfg.StatePath)
	start()
	if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	snapshot := firewallStateSnapshotPath(rollbackFile)
	if err := os.Remove(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}
	unproven = true
	marker := mustRead(t, confirmFile)
	firewallDeadmanMu.Lock()
	err := restoreFirewallRollback(confirmFile, rollbackFile, marker)
	firewallDeadmanMu.Unlock()
	if err == nil {
		t.Fatal("failed state restore reported success")
	}
	if rows := readStartupRows(t, state); len(rows) != 3 || rows[0].Unverified {
		t.Fatalf("failed state restore gated rows: %+v", rows)
	}
	if !errors.Is(d.fwEngine.ProbeBlockState(), firewall.ErrConfirmPending) {
		t.Fatal("failed state restore released admission")
	}
}

// A restore that fails leaves state.json as the window wrote it, so
// nothing is gated again.
func TestFailedRollbackRestoreDoesNotGateRows(t *testing.T) {
	unproven := false
	d, state, start := gatedFirewall(t, &unproven)
	confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(d.cfg.StatePath)
	start()
	if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	unproven = true
	t.Setenv("NFT_RESTORE_FAIL", "1")
	marker := mustRead(t, confirmFile)
	firewallDeadmanMu.Lock()
	err := restoreFirewallRollback(confirmFile, rollbackFile, marker)
	firewallDeadmanMu.Unlock()
	if err == nil {
		t.Fatal("a failed restore reported success")
	}
	if rows := readStartupRows(t, state); len(rows) != 3 || rows[0].Unverified {
		t.Fatalf("rows after a failed restore = %+v; want them untouched", rows)
	}
	if _, statErr := os.Stat(confirmFile); statErr != nil {
		t.Fatalf("the window did not stay pending: %v", statErr)
	}
}
