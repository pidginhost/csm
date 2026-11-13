//go:build linux

package firewall

import (
	"net"
	"reflect"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
)

func inAllow(port int, sources ...string) []InAllowRule {
	return []InAllowRule{{Port: port, Sources: sources}}
}

// wantInAllowRule is the rule one source should render to: family guard,
// TCP, masked source address at offset, destination port, accept.
func wantInAllowRule(family byte, offset, length uint32, network string, port uint16) []expr.Any {
	_, n, err := net.ParseCIDR(network)
	if err != nil {
		panic(err)
	}
	addr := n.IP.To4()
	if length == 16 {
		addr = n.IP.To16()
	}
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
	}
	if ones, bits := n.Mask.Size(); ones < bits {
		exprs = append(exprs, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: n.Mask, Xor: make([]byte, length)})
	}
	return append(exprs,
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// A bare address is a host route, and a source written with host bits covers
// its whole network rather than matching nothing.
func TestInAllowRendersIPv4Sources(t *testing.T) {
	got := inAllowRuleExprs(inAllow(3306, "203.0.113.10", "198.51.100.0/28", "192.0.2.11/24"), false)
	want := [][]expr.Any{
		wantInAllowRule(2, 12, 4, "203.0.113.10/32", 3306),
		wantInAllowRule(2, 12, 4, "198.51.100.0/28", 3306),
		wantInAllowRule(2, 12, 4, "192.0.2.0/24", 3306),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %v, want one source match per entry on port 3306", got)
	}
}

func TestInAllowRendersIPv6Sources(t *testing.T) {
	got := inAllowRuleExprs(inAllow(3306, "2001:db8::11", "2001:db8:1::/64"), true)
	want := [][]expr.Any{
		wantInAllowRule(10, 8, 16, "2001:db8::11/128", 3306),
		wantInAllowRule(10, 8, 16, "2001:db8:1::/64", 3306),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %v, want IPv6 source matches on port 3306", got)
	}
}

func TestInAllowKeepsEachEntryOnItsOwnPort(t *testing.T) {
	rules := append(inAllow(3306, "203.0.113.10"), inAllow(5432, "198.51.100.7")...)
	got := inAllowRuleExprs(rules, false)
	want := [][]expr.Any{
		wantInAllowRule(2, 12, 4, "203.0.113.10/32", 3306),
		wantInAllowRule(2, 12, 4, "198.51.100.7/32", 5432),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %v, want each source on its own entry's port only", got)
	}
}

// Nothing malformed or world-wide may render a rule wider than the operator
// asked for; a public port belongs in tcp_in.
func TestInAllowSkipsWhatItCannotScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []InAllowRule
		ipv6  bool
	}{
		{"ipv6 source with ipv6 off", inAllow(3306, "2001:db8::11"), false},
		{"unparseable source", inAllow(3306, "db1.example.com"), true},
		{"empty source", inAllow(3306, ""), true},
		{"world-wide ipv4", inAllow(3306, "0.0.0.0/0"), true},
		{"world-wide ipv6", inAllow(3306, "::/0"), true},
		{"mapped world-wide ipv4", inAllow(3306, "::ffff:192.0.2.11/96"), true},
		{"world-wide with host bits", inAllow(3306, "192.0.2.11/0"), true},
		{"no sources", inAllow(3306), true},
		{"port zero", inAllow(0, "203.0.113.10"), true},
		{"negative port", inAllow(-1, "203.0.113.10"), true},
		{"port above range", inAllow(65536, "203.0.113.10"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := inAllowRuleExprs(tc.rules, tc.ipv6); len(got) != 0 {
				t.Fatalf("rendered %d rules, want none", len(got))
			}
		})
	}
}

// One bad source must not take the entry's good sources with it.
func TestInAllowSkipsOnlyTheBadSource(t *testing.T) {
	got := inAllowRuleExprs(inAllow(3306, "db1.example.com", "203.0.113.10", "0.0.0.0/0"), true)
	want := [][]expr.Any{wantInAllowRule(2, 12, 4, "203.0.113.10/32", 3306)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %v, want only the valid source", got)
	}
}

// A declared source must reach its port whatever else blocks it: the accept
// follows the infra accept and precedes every blocklist and country drop.
func TestInAllowPrecedesBlocklists(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := &Engine{
		cfg:       &FirewallConfig{IPv6: true, TCPInAllow: inAllow(3306, "203.0.113.10", "2001:db8::11")},
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
	msgs := *captured
	infra := ruleMsgIndexForSet(msgs, "infra_ips6")
	if infra < 0 {
		t.Fatal("infra accept missing from the input chain")
	}
	firstDrop := len(msgs)
	for _, name := range []string{"blocked_ips", "blocked_ips6", "blocked_nets", "blocked_nets6", "country_block"} {
		i := ruleMsgIndexForSet(msgs, name)
		if i < 0 {
			t.Fatalf("%s drop missing from the input chain", name)
		}
		if i < firstDrop {
			firstDrop = i
		}
	}
	for _, rule := range [][]expr.Any{wantInAllowRule(2, 12, 4, "203.0.113.10/32", 3306), wantInAllowRule(10, 8, 16, "2001:db8::11/128", 3306)} {
		i := outputRuleIndex(msgs, captureChainRuleData(t, "input", rule))
		if i < 0 {
			t.Fatal("source accept missing from the input chain")
		}
		if i <= infra || i >= firstDrop {
			t.Fatalf("source accept at %d, want after infra accept %d and before the first drop %d", i, infra, firstDrop)
		}
	}
}

func appliedInAllowRules(t *testing.T, e *Engine, captured *[]netlink.Message) int {
	t.Helper()
	*captured = nil
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if outputRuleIndex(*captured, captureChainRuleData(t, "input", wantInAllowRule(2, 12, 4, "203.0.113.10/32", 3306))) >= 0 {
		return 1
	}
	return 0
}

// Reload (`csm firewall restart`, apply-confirmed) and rollback swap the
// config with SetConfig and apply again; both rebuild the whole ruleset.
func TestInAllowFollowsReloadAndRollback(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	before := &FirewallConfig{TCPOut: []int{443}}
	e := &Engine{conn: conn, cfg: before, statePath: t.TempDir(), listTables: func() ([]*nftables.Table, error) { return nil, nil }}
	if n := appliedInAllowRules(t, e, captured); n != 0 {
		t.Fatalf("initial apply rendered %d source rules, want none", n)
	}
	after := *before
	after.TCPInAllow = inAllow(3306, "203.0.113.10")
	e.SetConfig(&after)
	if n := appliedInAllowRules(t, e, captured); n != 1 {
		t.Fatal("reload did not render the source rule")
	}
	e.SetConfig(before)
	if n := appliedInAllowRules(t, e, captured); n != 0 {
		t.Fatal("rollback kept the source rule")
	}
}
