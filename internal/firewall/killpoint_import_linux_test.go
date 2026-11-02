//go:build linux

package firewall_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// Kill points around an import's eviction: a Critical block takes the
// slot of an import, a stamped legacy block the engine lists, in a batch
// that deletes it. The process stops at each step. An import has no
// record the startup gate reads, so its row restores it after any restart
// until the owner retires that row, also once the ledger verified its
// removal: the restart over-blocks until the import's own expiry. The
// block is held back until its outcome is recorded.
func TestImportEvictionConvergesAfterAKill(t *testing.T) {
	const importIP, blockIP = "203.0.113.75", "203.0.113.76"
	for _, tc := range []struct {
		name string
		kill firewall.KillPoint
		// sent is whether the kernel took the batch; finish records the
		// verified eviction and retire then removes the import's row.
		sent, finish, retire bool
	}{
		{"before the intent", firewall.KillBeforeIntent, false, false, false},
		{"before the kernel", firewall.KillBeforeKernel, false, false, false},
		{"before the readback", firewall.KillBeforeReadback, true, false, false},
		{"before the outcome", "", true, false, false},
		{"before the retirement", "", true, true, false},
		{"after the retirement", "", true, true, true},
	} {
		for _, reboot := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reboot=%t", tc.name, reboot), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					at := time.Now().UTC().Round(0)
					dir := t.TempDir()
					stateDir := filepath.Join(dir, "firewall")
					if err := os.MkdirAll(stateDir, 0o700); err != nil {
						t.Fatal(err)
					}
					statePath := filepath.Join(stateDir, "state.json")
					row := firewall.BlockedEntry{IP: importIP, Reason: "auto-block: legacy", Source: firewall.SourceAutoResponse, BlockedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Hour), Automatic: true}
					data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{row}})
					if err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(statePath, data, 0o600); err != nil {
						t.Fatal(err)
					}
					k := newKillLedger(t, dir, at)
					if err = k.l.StartLive(admission.LegacyHandover{}); err != nil {
						t.Fatal(err)
					}
					kernel := map[string]time.Duration{importIP: time.Hour}
					e, _ := k.engine(stateDir, at, kernel, nil, "")
					adm, err := e.BlockAdmissionSnapshot(nil, nil)
					if err != nil || len(adm.Imports) != 1 {
						t.Fatalf("snapshot %+v, %v; want the import listed", adm, err)
					}
					imp := adm.Imports[0]
					target, err := admission.CanonicalAddress(imp.IP, admission.Caps{IPv6: true})
					if err != nil {
						t.Fatal(err)
					}
					k.l.SetOccupants(&admission.SetOccupancy{Limit: 5, Unclaimed: 3, General: adm.Imported})
					k.l.SetImports([]admission.EvictionVictim{{Action: admission.ActionID(imp.ID), Target: target, Tier: admission.ImportTier, Partition: admission.PartitionGeneral, ExpiresAt: imp.ExpiresAt}})
					high := k.reserveAt(blockIP, admission.SeverityCritical, at.Add(2*time.Hour))
					m := k.runMember(high, blockIP)
					if m.Victim != (firewall.BlockVictim{Action: imp.ID, IP: importIP, ExpiresAt: row.ExpiresAt}) {
						t.Fatalf("the block claimed %+v", m.Victim)
					}

					e, _ = k.engine(stateDir, at, kernel, map[string]time.Duration{blockIP: 2 * time.Hour}, tc.kill)
					func() {
						if tc.kill != "" {
							defer func() {
								if got := recover(); got != tc.kill {
									t.Fatalf("kill point = %v, want %v", got, tc.kill)
								}
							}()
						}
						results, applyErr := e.ApplyBlockBatch([]firewall.BlockMember{m})
						if applyErr != nil || results[0].Effect != firewall.BlockApplied || results[0].Victim != firewall.VictimRemoved {
							t.Fatalf("eviction batch = %+v, %v", results, applyErr)
						}
					}()
					wantKernel := map[string]time.Duration{importIP: time.Hour}
					if tc.sent {
						wantKernel = map[string]time.Duration{blockIP: 2 * time.Hour}
					}
					if !maps.Equal(kernel, wantKernel) {
						t.Fatalf("after the stop the kernel holds %v; want %v", kernel, wantKernel)
					}
					if tc.finish {
						if _, _, err = k.l.FinishEviction(high.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
							t.Fatal(err)
						}
					}
					if tc.retire {
						clear, retireErr := e.RetireBlockActions([]firewall.BlockAction{{Action: imp.ID, IP: importIP}})
						if retireErr != nil || len(clear) != 1 || !clear[0] {
							t.Fatalf("retiring the import's row = %v, %v", clear, retireErr)
						}
					}
					if reboot {
						clear(kernel)
					}

					restart := at.Add(time.Minute)
					k.restart(restart, reboot)
					engine, seed := k.engine(stateDir, restart, kernel, nil, "")
					gate(t, k, restart, engine, statePath, seed)
					want := map[string]time.Duration{importIP: 59 * time.Minute}
					switch {
					case tc.retire:
						want = map[string]time.Duration{blockIP: 119 * time.Minute}
					case tc.finish:
						want[blockIP] = 119 * time.Minute
					}
					if !maps.Equal(kernel, want) {
						t.Fatalf("after the restart the kernel holds %v; want %v", kernel, want)
					}
					if _, held := killRows(t, statePath)[importIP]; held == tc.retire {
						t.Fatalf("import row held %t after the restart; want %t", held, !tc.retire)
					}
					if s := k.l.Status().Effects; s.General != 1 || s.Reserved != 0 {
						t.Fatalf("the ledger counts %+v; want the block's slot alone", s)
					}
					wantState := admission.StateUnknown
					if tc.finish {
						wantState = admission.StateVerified
					}
					if a := k.attempt(m.Action); a.State != wantState {
						t.Fatalf("the block after the restart = %+v; want %v", a, wantState)
					}
				})
			})
		}
	}
}
