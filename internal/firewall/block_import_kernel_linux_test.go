//go:build linux && nftkernel

package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A legacy automatic block stamps its row, which the snapshot lists as an
// import. In a full set a member takes the import's slot in one
// transaction, and retirement then removes the import's row by its name.
func TestKernelBlockBatchEvictsAnImport(t *testing.T) {
	for _, tc := range []struct{ family, victim, member string }{
		{"v4", "203.0.113.60", "203.0.113.21"},
		{"v6", "2001:db8::60", "2001:db8::21"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			e := newKernelBatchEngine(t)
			e.cfg.DenyTempIPLimit = 1
			if _, err := e.BlockIPOutcome(tc.victim, "auto-block: legacy", time.Hour); err != nil {
				t.Fatal(err)
			}
			adm, err := e.BlockAdmissionSnapshot(nil, nil)
			if err != nil || len(adm.Imports) != 1 || adm.Imports[0].IP != tc.victim {
				t.Fatalf("snapshot %+v, %v; want the legacy block listed", adm, err)
			}
			imp := adm.Imports[0]
			m := kernelBlockMember("act_evict", tc.member, time.Hour)
			m.Victim = BlockVictim{Action: imp.ID, IP: imp.IP, ExpiresAt: imp.ExpiresAt}
			results, err := e.ApplyBlockBatch([]BlockMember{m})
			if err != nil || effects(results) != "applied/" || results[0].Victim != VictimRemoved {
				t.Fatalf("results %+v, %v", results, err)
			}
			set := e.setBlocked
			if tc.family == "v6" {
				set = e.setBlocked6
			}
			v4 := kernelBlockElements(t, e, set)
			_, member := v4[m.IP]
			_, kept := v4[imp.IP]
			if !member || kept {
				t.Fatalf("kernel holds %v", v4)
			}
			clear, err := e.RetireBlockActions([]BlockAction{{Action: imp.ID, IP: imp.IP}})
			if err != nil || len(clear) != 1 || !clear[0] {
				t.Fatalf("retiring the import = %v, %v", clear, err)
			}
			data, err := os.ReadFile(filepath.Join(e.statePath, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			var state FirewallState
			if err = json.Unmarshal(data, &state); err != nil {
				t.Fatal(err)
			}
			for _, row := range state.Blocked {
				if row.IP == imp.IP {
					t.Fatalf("the import's row stayed: %+v", row)
				}
			}
		})
	}
}
