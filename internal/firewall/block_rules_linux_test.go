//go:build linux

package firewall

import (
	"errors"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// inputRules is an input chain as Apply builds it: a rule before the drops,
// the drops of both blocked sets, and a rule after them.
func inputRules(set4, set6 *nftables.Set) []*nftables.Rule {
	accept := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	return []*nftables.Rule{
		{Handle: 11, Exprs: []expr.Any{&expr.Counter{}}},
		{Handle: 12, Exprs: buildSetMatchRuleExprs(set4, expr.VerdictDrop, 2, 12, 4)},
		{Handle: 13, Exprs: buildSetMatchRuleExprs(set6, expr.VerdictDrop, 10, 8, 16)},
		{Handle: 14, Exprs: accept},
	}
}

// applyOne runs one fresh member through a batch and reports what it did
// to the state file and the kernel.
func applyOne(t *testing.T, f *batchFixture) ([]BlockResult, int, error) {
	t.Helper()
	m := f.member("act_rules", "203.0.113.60")
	f.onFlush = func() { f.live[m.IP] = m.ExpiresAt.Sub(f.at) }
	writes := f.countWrites(t)
	results, err := f.e.ApplyBlockBatch([]BlockMember{m})
	return results, *writes, err
}

// A ruleset reloaded during a batch gives the drops new handles: nothing
// is written or sent.
func TestApplyBlockBatchRefusesRulesChangedDuringTheBatch(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.onRuleDump = func(n int) {
		if n == 2 {
			f.rules = inputRules(f.e.setBlocked, f.e.setBlocked6)
			f.rules[1].Handle = 22
		}
	}
	results, writes, err := applyOne(t, f)
	if !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
		t.Fatalf("reloaded rules = %+v, %v, writes=%d sends=%d; want ErrBlockRules and nothing written", results, err, writes, f.sends)
	}
}

// A rule inserted ahead of the drops can accept what they would drop.
func TestApplyBlockBatchRefusesARuleInsertedBeforeTheDrops(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.onRuleDump = func(n int) {
		if n == 2 {
			f.rules = append([]*nftables.Rule{{Handle: 30, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}}, f.rules...)
		}
	}
	results, writes, err := applyOne(t, f)
	if !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
		t.Fatalf("inserted rule = %+v, %v, writes=%d sends=%d; want ErrBlockRules and nothing written", results, err, writes, f.sends)
	}
}

// Rules after the drops do not decide whether a blocked address passes.
func TestApplyBlockBatchAllowsRulesAddedAfterTheDrops(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.onRuleDump = func(n int) {
		if n == 2 {
			f.rules = append(f.rules, &nftables.Rule{Handle: 31, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}})
		}
	}
	results, _, err := applyOne(t, f)
	if err != nil || len(results) != 1 || results[0].Effect != BlockApplied || f.ruleDumps != 2 {
		t.Fatalf("rule after the drops = %+v, %v, dumps=%d; want applied after two dumps", results, err, f.ruleDumps)
	}
}

// Without the drop of either filtered family no batch runs and the probe
// keeps admission held. With IPv6 filtering off only the IPv4 drop counts.
func TestBlockBatchesRequireTheDropRules(t *testing.T) {
	for name, drop := range map[string]int{"IPv4 drop": 1, "IPv6 drop": 2} {
		f := newBatchFixture(t, FirewallState{})
		f.rules = append(f.rules[:drop:drop], f.rules[drop+1:]...)
		if err := f.e.ProbeBlockState(); !errors.Is(err, ErrBlockRules) {
			t.Fatalf("%s missing: probe = %v, want ErrBlockRules", name, err)
		}
		if results, writes, err := applyOne(t, f); !errors.Is(err, ErrBlockRules) || writes != 0 || f.sends != 0 {
			t.Fatalf("%s missing: batch = %+v, %v, writes=%d sends=%d", name, results, err, writes, f.sends)
		}
	}
	f := newBatchFixture(t, FirewallState{})
	f.e.cfg.IPv6 = false
	f.rules = append(f.rules[:2:2], f.rules[3:]...)
	if err := f.e.ProbeBlockState(); err != nil {
		t.Fatalf("IPv6 off without its drop: probe = %v", err)
	}
	if results, _, err := applyOne(t, f); err != nil || len(results) != 1 || results[0].Effect != BlockApplied {
		t.Fatalf("IPv6 off without its drop: batch = %+v, %v", results, err)
	}
}

// An inverted lookup or a rule that does not drop is not the drop of a
// blocked set.
func TestBlockBatchesNeedADropOfTheSet(t *testing.T) {
	for name, edit := range map[string]func(*nftables.Rule){
		"inverted": func(r *nftables.Rule) { r.Exprs[3].(*expr.Lookup).Invert = true },
		"accepts":  func(r *nftables.Rule) { r.Exprs[4] = &expr.Verdict{Kind: expr.VerdictAccept} },
	} {
		f := newBatchFixture(t, FirewallState{})
		edit(f.rules[1])
		if err := f.e.ProbeBlockState(); !errors.Is(err, ErrBlockRules) {
			t.Fatalf("%s: probe = %v, want ErrBlockRules", name, err)
		}
	}
}

// Every accepted drop must cover the source address for its own family.
func TestBlockBatchesRejectNonSourceDrops(t *testing.T) {
	for _, index := range []int{1, 2} {
		for name, edit := range map[string]func(*nftables.Rule){
			"destination":      func(r *nftables.Rule) { r.Exprs[2].(*expr.Payload).Offset += r.Exprs[2].(*expr.Payload).Len },
			"family":           func(r *nftables.Rule) { r.Exprs[1].(*expr.Cmp).Data = []byte{0} },
			"inequality":       func(r *nftables.Rule) { r.Exprs[1].(*expr.Cmp).Op = expr.CmpOpNeq },
			"meta source":      func(r *nftables.Rule) { r.Exprs[0].(*expr.Meta).SourceRegister = true },
			"meta key":         func(r *nftables.Rule) { r.Exprs[0].(*expr.Meta).Key = expr.MetaKeyL4PROTO },
			"meta register":    func(r *nftables.Rule) { r.Exprs[0].(*expr.Meta).Register = 2 },
			"compare register": func(r *nftables.Rule) { r.Exprs[1].(*expr.Cmp).Register = 2 },
			"load register":    func(r *nftables.Rule) { r.Exprs[2].(*expr.Payload).DestRegister = 2 },
			"lookup register":  func(r *nftables.Rule) { r.Exprs[3].(*expr.Lookup).SourceRegister = 2 },
			"payload write":    func(r *nftables.Rule) { r.Exprs[2].(*expr.Payload).OperationType = expr.PayloadWrite },
			"payload base":     func(r *nftables.Rule) { r.Exprs[2].(*expr.Payload).Base = expr.PayloadBaseTransportHeader },
			"payload width":    func(r *nftables.Rule) { r.Exprs[2].(*expr.Payload).Len-- },
			"map":              func(r *nftables.Rule) { r.Exprs[3].(*expr.Lookup).IsDestRegSet = true },
			"wrong set":        func(r *nftables.Rule) { r.Exprs[3].(*expr.Lookup).SetName = "other_set" },
			"extra predicate": func(r *nftables.Rule) {
				r.Exprs = append(r.Exprs[:4:4], &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}}, r.Exprs[4])
			},
		} {
			t.Run(name+string(rune('0'+index)), func(t *testing.T) {
				f := newBatchFixture(t, FirewallState{})
				edit(f.rules[index])
				if err := f.e.ProbeBlockState(); !errors.Is(err, ErrBlockRules) {
					t.Fatalf("non-source drop probe = %v", err)
				}
				if checks, err := f.e.CheckBlockBatchEffects([]BlockMember{f.member("act_check", "203.0.113.61")}); !errors.Is(err, ErrBlockRules) || checks != nil {
					t.Fatalf("non-source drop member check = %+v, %v", checks, err)
				}
				if results, writes, err := applyOne(t, f); !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
					t.Fatalf("non-source drop batch = %+v, %v, writes=%d sends=%d", results, err, writes, f.sends)
				}
			})
		}
	}
}

// Kernel dumps can omit a transaction set ID and use equivalent register
// aliases. Neither changes the packet bytes tested by the drop.
func TestBlockBatchesAcceptDumpAliases(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	for _, r := range f.rules[1:3] {
		r.Exprs[0].(*expr.Meta).Register = 8
		r.Exprs[1].(*expr.Cmp).Register = 1
		r.Exprs[2].(*expr.Payload).DestRegister = 8
		r.Exprs[3].(*expr.Lookup).SourceRegister = 1
		r.Exprs[3].(*expr.Lookup).SetID = 0
	}
	if results, _, err := applyOne(t, f); err != nil || len(results) != 1 || results[0].Effect != BlockApplied {
		t.Fatalf("decoded drop = %+v, %v", results, err)
	}
}

func TestApplyBlockBatchRulesBracketSetDump(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	dump := f.e.liveBlockedDump
	f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		f.rules[1].Handle = 22
		return dump(set)
	}
	if results, writes, err := applyOne(t, f); !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
		t.Fatalf("rule change during set dump = %+v, %v, writes=%d sends=%d", results, err, writes, f.sends)
	}
}

func TestApplyBlockBatchRuleDumpErrors(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		f := newBatchFixture(t, FirewallState{})
		dump := f.e.blockRuleDump
		calls := 0
		f.e.blockRuleDump = func() ([]*nftables.Rule, error) {
			calls++
			if calls == failAt {
				return nil, errors.New("rule dump unavailable")
			}
			return dump()
		}
		if results, writes, err := applyOne(t, f); !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
			t.Fatalf("dump %d: %+v, %v, writes=%d sends=%d", failAt, results, err, writes, f.sends)
		}
	}
}
