//go:build linux && nftkernel

package firewall

import (
	"errors"
	"testing"
	"time"

	"github.com/google/nftables/expr"
)

// The rules Apply builds hold both drops as a kernel dump decodes them.
// Without the IPv4 drop a batch writes and sends nothing; a new Apply
// restores the drop and the batch runs.
func TestKernelBlockBatchRefusesAMissingDropRule(t *testing.T) {
	e := newKernelBatchEngine(t)
	if err := e.ProbeBlockState(); err != nil {
		t.Fatalf("probe after Apply = %v", err)
	}
	rules, listErr := e.conn.GetRules(e.table, e.chainIn)
	if listErr != nil {
		t.Fatal(listErr)
	}
	deleted := false
	for _, rule := range rules {
		if len(rule.Exprs) == 5 {
			lookup, ok := rule.Exprs[3].(*expr.Lookup)
			if !ok || lookup.SetName != e.setBlocked.Name {
				continue
			}
			if err := e.conn.DelRule(rule); err != nil {
				t.Fatal(err)
			}
			deleted = true
		}
	}
	if !deleted {
		t.Fatal("no IPv4 drop rule in the kernel dump")
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	m := kernelBlockMember("act_rules", "203.0.113.70", time.Hour)
	if results, err := e.ApplyBlockBatch([]BlockMember{m}); !errors.Is(err, ErrBlockRules) || results != nil {
		t.Fatalf("batch without the drop = %+v, %v; want ErrBlockRules", results, err)
	}
	if v4 := kernelBlockElements(t, e, e.setBlocked); len(v4) != 0 {
		t.Fatalf("refused batch reached the kernel: %v", v4)
	}
	if state, _ := e.loadStateFileRawLocked(); len(state.Blocked) != 0 {
		t.Fatalf("refused batch wrote rows: %+v", state.Blocked)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	results, err := e.ApplyBlockBatch([]BlockMember{m})
	if err != nil || len(results) != 1 || results[0].Effect != BlockApplied {
		t.Fatalf("batch after Apply = %+v, %v", results, err)
	}
}

// Replacement preserves the handle, so handle equality alone cannot prove
// that the rule still drops source addresses in either family.
func TestKernelBlockBatchRefusesAnAlteredDropRule(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			e := newKernelBatchEngine(t)
			set, ip := e.setBlocked, "203.0.113.71"
			if ipv6 {
				set, ip = e.setBlocked6, "2001:db8::71"
			}
			rules, err := e.conn.GetRules(e.table, e.chainIn)
			if err != nil {
				t.Fatal(err)
			}
			changed := false
			for _, r := range rules {
				if len(r.Exprs) != 5 {
					continue
				}
				lookup, ok := r.Exprs[3].(*expr.Lookup)
				if !ok || lookup.SetName != set.Name {
					continue
				}
				payload, ok := r.Exprs[2].(*expr.Payload)
				if !ok {
					t.Fatal("source drop has no payload load")
				}
				payload.Offset += payload.Len
				e.conn.ReplaceRule(r)
				changed = true
			}
			if !changed {
				t.Fatal("no source drop to replace")
			}
			if err = e.conn.Flush(); err != nil {
				t.Fatal(err)
			}
			m := kernelBlockMember("act_altered", ip, time.Hour)
			if results, err := e.ApplyBlockBatch([]BlockMember{m}); !errors.Is(err, ErrBlockRules) || results != nil {
				t.Fatalf("altered source drop = %+v, %v", results, err)
			}
			if got := kernelBlockElements(t, e, set); len(got) != 0 {
				t.Fatalf("altered source drop allowed elements: %+v", got)
			}
			if state, ok := e.loadStateFileRawLocked(); !ok || len(state.Blocked) != 0 {
				t.Fatalf("altered source drop wrote rows: %+v, readable=%v", state.Blocked, ok)
			}
		})
	}
}
