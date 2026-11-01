//go:build linux

package firewall

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func passiveRangeRule(family byte, start, end int) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(start))},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(end))},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// The input chain accepts the passive FTP range on both families when one is
// configured and has no range accept when it is closed.
func TestInputChainPassiveFTPRange(t *testing.T) {
	for _, tc := range []struct {
		name       string
		start, end int
		want       bool
	}{
		{"default range", 49152, 65534, true},
		{"closed", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := &Engine{
				cfg:       &FirewallConfig{IPv6: true, PassiveFTPStart: tc.start, PassiveFTPEnd: tc.end},
				conn:      conn,
				statePath: t.TempDir(),
			}
			e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
			set := func(name string) *nftables.Set {
				return &nftables.Set{Table: e.table, Name: name, KeyType: nftables.TypeIPAddr}
			}
			e.setInfra, e.setInfra6 = set("infra_ips"), set("infra_ips6")
			e.setBlocked, e.setBlocked6 = set("blocked_ips"), set("blocked_ips6")
			e.setBlockedNet, e.setBlockedNet6 = set("blocked_nets"), set("blocked_nets6")
			e.setCountry = set("country_block")
			if err := e.createInputChain(); err != nil {
				t.Fatal(err)
			}
			if err := conn.Flush(); err != nil {
				t.Fatal(err)
			}
			for _, family := range []byte{2, 10} {
				rule := captureChainRuleData(t, "input", passiveRangeRule(family, tc.start, tc.end))
				if got := outputRuleIndex(*captured, rule) >= 0; got != tc.want {
					t.Errorf("family %d range accept present = %v, want %v", family, got, tc.want)
				}
			}
		})
	}
}
