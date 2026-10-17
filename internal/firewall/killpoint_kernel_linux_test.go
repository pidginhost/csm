//go:build linux && nftkernel

package firewall

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// Kill point in the kernel (spec 5.4, design P10): a batch killed after
// the kernel took it, before its readback, leaves its element in the
// kernel and its row unmarked. A new engine on the same state, once the
// startup gate has marked the row, applies a ruleset without that element
// and keeps the operator's block. Retirement then finds nothing of the
// attempt and removes its row.
func TestKernelKilledBatchLeavesNothingAfterRestart(t *testing.T) {
	for _, addr := range []string{"203.0.113.20", "2001:db8::20"} {
		completed := false
		t.Run(addr, func(t *testing.T) {
			e := newKernelBatchEngine(t)
			if err := e.BlockIPForce("198.51.100.9", "manual", 0); err != nil {
				t.Fatal(err)
			}
			member := kernelBlockMember("act_"+strings.Repeat("7", 32), addr, time.Hour)
			kill := KillBeforeReadback
			e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
				elements, err := e.conn.GetSetElements(set)
				for _, el := range elements {
					if net.IP(el.Key).Equal(net.ParseIP(member.IP)) {
						panic(kill)
					}
				}
				return elements, err
			}
			func() {
				defer func() {
					if got := recover(); got != kill {
						t.Fatalf("kill point = %v, want %v", got, kill)
					}
				}()
				_, _ = e.ApplyBlockBatch([]BlockMember{member})
			}()
			set := e.setBlocked
			if net.ParseIP(addr).To4() == nil {
				set = e.setBlocked6
			}
			if _, ok := kernelBlockElements(t, e, set)[member.IP]; !ok {
				t.Fatal("the killed batch left nothing in the kernel")
			}
			if rows := e.loadStateFile().Blocked; len(rows) != 2 {
				t.Fatalf("the killed batch left rows %+v", rows)
			}

			restarted, err := NewEngine(&FirewallConfig{Enabled: true, IPv6: true}, filepath.Dir(e.statePath))
			if err != nil {
				t.Fatal(err)
			}
			marked, err := restarted.MarkBlockActionsUnverified([]string{member.Action})
			if err != nil || marked != 1 {
				t.Fatalf("mark = %d, %v", marked, err)
			}
			if err = restarted.Apply(); err != nil {
				t.Fatal(err)
			}
			v4 := kernelBlockElements(t, restarted, restarted.setBlocked)
			v6 := kernelBlockElements(t, restarted, restarted.setBlocked6)
			if _, ok := v4["198.51.100.9"]; !ok || len(v4) != 1 || len(v6) != 0 {
				t.Fatalf("after the restart the kernel holds %v and %v; want only the operator block", v4, v6)
			}
			if restarted.IsBlocked(member.IP) || !restarted.IsBlocked("198.51.100.9") {
				t.Fatal("IsBlocked disagrees with the restored rules")
			}
			rules, err := restarted.conn.GetRules(restarted.table, &nftables.Chain{Name: "input", Table: restarted.table})
			if err != nil || len(rules) == 0 {
				t.Fatalf("restart installed no input rules: %v", err)
			}
			clear, err := restarted.RetireBlockActions([]BlockAction{{Action: member.Action, IP: member.IP}})
			if err != nil || len(clear) != 1 || !clear[0] {
				t.Fatalf("retirement = %v, %v", clear, err)
			}
			if rows := restarted.loadStateFile().Blocked; len(rows) != 1 || rows[0].IP != "198.51.100.9" {
				t.Fatalf("after retirement the rows are %+v", rows)
			}
			completed = true
		})
		// A passing parent must not hide skipped namespace setup in a child.
		if !completed {
			t.Errorf("kernel case %s did not complete", addr)
		}
	}
}
