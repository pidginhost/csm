//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// GetRules omits expression types its decoder does not know. The raw dump
// must retain an extra register load rather than certify the remaining drop.
func TestBlockRulesDumpRejectsUnknownExpressions(t *testing.T) {
	for _, family := range []struct {
		name string
		rule int
		key  uint32
	}{{"IPv4", 1, unix.NFT_RT_NEXTHOP4}, {"IPv6", 2, unix.NFT_RT_NEXTHOP6}} {
		for _, changeAt := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/dump%d", family.name, changeAt), func(t *testing.T) {
				f := newBatchFixture(t, FirewallState{})
				useRawBlockRules(t, f, func(dump, rule int, expressions []netlink.Attribute) []netlink.Attribute {
					if dump >= changeAt && rule == family.rule {
						load := netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: nltest.MustMarshalAttributes([]netlink.Attribute{
							{Type: unix.NFTA_EXPR_NAME, Data: []byte("rt\x00")},
							{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{Type: unix.NFTA_RT_DREG, Data: binaryutil.BigEndian.PutUint32(unix.NFT_REG_1)},
								{Type: unix.NFTA_RT_KEY, Data: binaryutil.BigEndian.PutUint32(family.key)},
							})},
						})}
						return slices.Insert(expressions, 3, load)
					}
					return expressions
				})
				if results, writes, err := applyOne(t, f); !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
					t.Fatalf("extra register load: results=%+v err=%v writes=%d sends=%d", results, err, writes, f.sends)
				}
				if err := f.e.ProbeBlockState(); !errors.Is(err, ErrBlockRules) {
					t.Fatalf("probe accepted the extra load: %v", err)
				}
				members := []BlockMember{f.member("act_check", "203.0.113.61")}
				if checks, err := f.e.CheckBlockBatchEffects(members); !errors.Is(err, ErrBlockRules) || checks != nil {
					t.Fatalf("member check accepted the extra load: %+v, %v", checks, err)
				}
				dumps := f.ruleDumps
				if forecast, err := f.e.BlockAdmissionSnapshot(members, nil); err != nil || len(forecast.Answers) != 1 || forecast.Answers[0].Refusal != "" || f.ruleDumps != dumps {
					t.Fatalf("rule refusal affected the forecast: %+v, %v", forecast, err)
				}
			})
		}
	}
}

func TestBlockRulesDumpErrorsWriteNothing(t *testing.T) {
	for _, fault := range []string{"transport", "header", "attributes"} {
		t.Run(fault, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			useRawBlockRules(t, f, nil)
			transport := f.e.conn.TestDial
			f.e.conn.TestDial = func(req []netlink.Message) ([]netlink.Message, error) {
				if fault == "transport" {
					return nil, errors.New("dump unavailable")
				}
				messages, err := transport(req)
				if err != nil || len(messages) == 0 {
					return messages, err
				}
				if fault == "header" {
					messages[0].Data = messages[0].Data[:3]
				} else {
					messages[0].Data = append(messages[0].Data[:4:4], 1)
				}
				return messages, nil
			}
			if results, writes, err := applyOne(t, f); !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
				t.Fatalf("dump failure: results=%+v err=%v writes=%d sends=%d", results, err, writes, f.sends)
			}
		})
	}
}

func TestBlockRulesDumpAcceptsSourceDrops(t *testing.T) {
	for _, aliases := range []bool{false, true} {
		t.Run(fmt.Sprint(aliases), func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			if aliases {
				for _, rule := range f.rules[1:3] {
					rule.Exprs[0].(*expr.Meta).Register = unix.NFT_REG32_00
					rule.Exprs[2].(*expr.Payload).DestRegister = unix.NFT_REG32_00
					rule.Exprs[3].(*expr.Lookup).SetID = 0
				}
			}
			useRawBlockRules(t, f, nil)
			if results, _, err := applyOne(t, f); err != nil || len(results) != 1 || results[0].Effect != BlockApplied || f.ruleDumps != 2 {
				t.Fatalf("source drops: results=%+v err=%v dumps=%d", results, err, f.ruleDumps)
			}
		})
	}
}

// Unknown expressions on other rules must not stall batches, but those
// rules' handles still participate in the prefix comparison.
func TestBlockRulesDumpKeepsOtherRuleHandles(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			useRawBlockRules(t, f, func(dump, rule int, expressions []netlink.Attribute) []netlink.Attribute {
				if rule != 0 {
					return expressions
				}
				if dump == 2 && changed {
					f.rules[0].Handle++
				}
				return []netlink.Attribute{{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: nltest.MustMarshalAttributes([]netlink.Attribute{
					{Type: unix.NFTA_EXPR_NAME, Data: []byte("unknown\x00")},
					{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA},
				})}}
			})
			results, writes, err := applyOne(t, f)
			if changed {
				if !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
					t.Fatalf("changed prefix: results=%+v err=%v writes=%d sends=%d", results, err, writes, f.sends)
				}
			} else if err != nil || len(results) != 1 || results[0].Effect != BlockApplied {
				t.Fatalf("unchanged prefix: results=%+v err=%v", results, err)
			}
		})
	}
}

func useRawBlockRules(t *testing.T, f *batchFixture, edit func(int, int, []netlink.Attribute) []netlink.Attribute) {
	t.Helper()
	f.e.blockRuleDump = nil
	transport := f.e.conn.TestDial
	f.e.conn.TestDial = func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) != 1 || req[0].Header.Type != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETRULE {
			return transport(req)
		}
		f.ruleDumps++
		var messages []netlink.Message
		for i, rule := range f.rules {
			var expressions []netlink.Attribute
			for _, ex := range rule.Exprs {
				data, err := expr.Marshal(byte(f.e.setBlocked.Table.Family), ex)
				if err != nil {
					t.Fatal(err)
				}
				expressions = append(expressions, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: data})
			}
			if edit != nil {
				expressions = edit(f.ruleDumps, i, expressions)
			}
			attrs := nltest.MustMarshalAttributes([]netlink.Attribute{
				{Type: unix.NFTA_RULE_TABLE, Data: []byte("csm\x00")},
				{Type: unix.NFTA_RULE_CHAIN, Data: []byte("input\x00")},
				{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(rule.Handle)},
				{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: nltest.MustMarshalAttributes(expressions)},
			})
			messages = append(messages, netlink.Message{
				Header: netlink.Header{Type: unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE, Sequence: req[0].Header.Sequence, PID: req[0].Header.PID},
				Data:   append([]byte{byte(f.e.setBlocked.Table.Family), 0, 0, 0}, attrs...),
			})
		}
		return nltest.Multipart(append(messages, netlink.Message{Header: netlink.Header{Sequence: req[0].Header.Sequence, PID: req[0].Header.PID}}))
	}
}

// A source drop is certified only from exactly the five expressions Apply
// emits: a renamed expression, an expression after the verdict or a rule
// without a handle refuses the batch.
func TestBlockRulesDumpRejectsAlteredExpressionLists(t *testing.T) {
	rename := func(attr netlink.Attribute, name string) netlink.Attribute {
		fields, err := netlink.UnmarshalAttributes(attr.Data)
		if err != nil {
			t.Fatal(err)
		}
		for i := range fields {
			if fields[i].Type == unix.NFTA_EXPR_NAME {
				fields[i].Data = []byte(name + "\x00")
			}
		}
		attr.Data = nltest.MustMarshalAttributes(fields)
		return attr
	}
	for name, edit := range map[string]func(int, []netlink.Attribute) []netlink.Attribute{
		"renamed expression": func(_ int, expressions []netlink.Attribute) []netlink.Attribute {
			expressions[0] = rename(expressions[0], "xmeta")
			return expressions
		},
		"expression after the verdict": func(_ int, expressions []netlink.Attribute) []netlink.Attribute {
			data, err := expr.Marshal(unix.NFPROTO_INET, &expr.Counter{})
			if err != nil {
				t.Fatal(err)
			}
			return append(expressions, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: data})
		},
		"no handle": nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			if edit == nil {
				f.rules[1].Handle = 0
				useRawBlockRules(t, f, nil)
			} else {
				useRawBlockRules(t, f, func(_, rule int, expressions []netlink.Attribute) []netlink.Attribute {
					if rule == 1 {
						return edit(rule, expressions)
					}
					return expressions
				})
			}
			if results, writes, err := applyOne(t, f); !errors.Is(err, ErrBlockRules) || results != nil || writes != 0 || f.sends != 0 {
				t.Fatalf("%s: results=%+v err=%v writes=%d sends=%d", name, results, err, writes, f.sends)
			}
		})
	}
}
