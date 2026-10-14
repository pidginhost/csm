//go:build linux

package firewall

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
)

const vrrpProto = 112

func vrrpPeers(peers ...string) []ProtocolAllowRule {
	return []ProtocolAllowRule{{Protocol: "vrrp", Peers: peers}}
}

// wantProtocolRule is the rule a peer or group should render to: family
// guard, IP protocol, masked address at offset, accept.
func wantProtocolRule(family byte, offset, length uint32, network string) []expr.Any {
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
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{vrrpProto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
	}
	if ones, bits := n.Mask.Size(); ones < bits {
		exprs = append(exprs, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: n.Mask, Xor: make([]byte, length)})
	}
	return append(exprs,
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

func TestProtocolAllowRendersIPv4Peers(t *testing.T) {
	in, out := protocolAllowRuleExprs(vrrpPeers("192.0.2.11", "198.51.100.0/24"), false)
	wantIn := [][]expr.Any{
		wantProtocolRule(2, 12, 4, "192.0.2.11/32"),
		wantProtocolRule(2, 12, 4, "198.51.100.0/24"),
	}
	wantOut := [][]expr.Any{
		wantProtocolRule(2, 16, 4, "192.0.2.11/32"),
		wantProtocolRule(2, 16, 4, "198.51.100.0/24"),
		wantProtocolRule(2, 16, 4, "224.0.0.18/32"),
	}
	if !reflect.DeepEqual(in, wantIn) {
		t.Errorf("input rules = %v, want source matches on each peer", in)
	}
	if !reflect.DeepEqual(out, wantOut) {
		t.Errorf("output rules = %v, want destination matches on each peer and the VRRP group", out)
	}
}

func TestProtocolAllowRendersIPv6Peers(t *testing.T) {
	in, out := protocolAllowRuleExprs(vrrpPeers("2001:db8::11", "2001:db8:1::/64"), true)
	wantIn := [][]expr.Any{
		wantProtocolRule(10, 8, 16, "2001:db8::11/128"),
		wantProtocolRule(10, 8, 16, "2001:db8:1::/64"),
	}
	wantOut := [][]expr.Any{
		wantProtocolRule(10, 24, 16, "2001:db8::11/128"),
		wantProtocolRule(10, 24, 16, "2001:db8:1::/64"),
		wantProtocolRule(10, 24, 16, "ff02::12/128"),
	}
	if !reflect.DeepEqual(in, wantIn) {
		t.Errorf("input rules = %v, want source matches on each peer", in)
	}
	if !reflect.DeepEqual(out, wantOut) {
		t.Errorf("output rules = %v, want destination matches on each peer and the VRRPv3 group", out)
	}
}

// With dual-stack filtering off every IPv6 packet is already accepted, so an
// IPv6 peer needs no rule; nothing malformed or world-wide may render a rule
// wider than the operator asked for.
func TestProtocolAllowSkipsWhatItCannotScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []ProtocolAllowRule
		ipv6  bool
	}{
		{"ipv6 peer with ipv6 off", vrrpPeers("2001:db8::11"), false},
		{"unknown protocol", []ProtocolAllowRule{{Protocol: "gre", Peers: []string{"192.0.2.11"}}}, true},
		{"unparseable peer", vrrpPeers("db1.example.com"), true},
		{"world-wide ipv4", vrrpPeers("0.0.0.0/0"), true},
		{"world-wide ipv6", vrrpPeers("::/0"), true},
		{"no peers", vrrpPeers(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out := protocolAllowRuleExprs(tc.rules, tc.ipv6)
			if len(in) != 0 || len(out) != 0 {
				t.Fatalf("rendered %d input and %d output rules, want none", len(in), len(out))
			}
		})
	}
}

// The multicast group is accepted once per family however many entries name
// the protocol.
func TestProtocolAllowGroupRuleOncePerFamily(t *testing.T) {
	rules := append(vrrpPeers("192.0.2.11"), vrrpPeers("192.0.2.12", "2001:db8::12")...)
	_, out := protocolAllowRuleExprs(rules, true)
	groups := 0
	for _, r := range out {
		if reflect.DeepEqual(r, wantProtocolRule(2, 16, 4, "224.0.0.18/32")) || reflect.DeepEqual(r, wantProtocolRule(10, 24, 16, "ff02::12/128")) {
			groups++
		}
	}
	if len(out) != 5 || groups != 2 {
		t.Fatalf("output rules = %d with %d group rules, want 3 peers and one group per family", len(out), groups)
	}
}

func captureChainRuleData(t *testing.T, chain string, exprs []expr.Any) []byte {
	t.Helper()
	conn, captured := nftConnCapturingRules(t)
	table := conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	c := conn.AddChain(&nftables.Chain{Name: chain, Table: table})
	conn.AddRule(&nftables.Rule{Table: table, Chain: c, Exprs: exprs})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, msg := range *captured {
		if bytes.Contains(msg.Data, []byte("immediate\x00")) {
			return append([]byte(nil), msg.Data...)
		}
	}
	t.Fatal("captured batch has no rule message")
	return nil
}

// A VRRP peer an operator or detector blocked must keep passing VRRP: a
// member that stops hearing its peer claims the VIP too. The accept follows
// the infra accept and precedes every blocklist drop.
func TestProtocolAllowPrecedesBlocklists(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := &Engine{
		cfg:       &FirewallConfig{IPv6: true, ProtocolAllow: vrrpPeers("192.0.2.11", "2001:db8::11")},
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
	firstDrop := len(msgs)
	for _, set := range []string{"blocked_ips", "blocked_ips6", "blocked_nets", "blocked_nets6", "country_block"} {
		if i := ruleMsgIndexForSet(msgs, set); i >= 0 && i < firstDrop {
			firstDrop = i
		}
	}
	for _, rule := range [][]expr.Any{wantProtocolRule(2, 12, 4, "192.0.2.11/32"), wantProtocolRule(10, 8, 16, "2001:db8::11/128")} {
		i := outputRuleIndex(msgs, captureChainRuleData(t, "input", rule))
		if i < 0 {
			t.Fatal("peer accept missing from the input chain")
		}
		if i <= infra || i >= firstDrop {
			t.Fatalf("peer accept at %d, want after infra accept %d and before the first blocklist drop %d", i, infra, firstDrop)
		}
	}
}

func TestProtocolAllowOpensRestrictedOutput(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := &Engine{cfg: &FirewallConfig{TCPOut: []int{443}, ProtocolAllow: vrrpPeers("192.0.2.11")}, conn: conn}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	if err := e.createOutputChain(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, rule := range [][]expr.Any{wantProtocolRule(2, 16, 4, "192.0.2.11/32"), wantProtocolRule(2, 16, 4, "224.0.0.18/32")} {
		if outputRuleIndex(*captured, captureOutputRuleData(t, rule)) < 0 {
			t.Fatal("restricted output chain lacks a protocol_allow accept")
		}
	}
}

func appliedProtocolRules(t *testing.T, e *Engine, captured *[]netlink.Message) int {
	t.Helper()
	*captured = nil
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	peerIn := captureChainRuleData(t, "input", wantProtocolRule(2, 12, 4, "192.0.2.11/32"))
	peerOut := captureOutputRuleData(t, wantProtocolRule(2, 16, 4, "192.0.2.11/32"))
	found := 0
	for _, data := range [][]byte{peerIn, peerOut} {
		if outputRuleIndex(*captured, data) >= 0 {
			found++
		}
	}
	return found
}

// Reload (`csm firewall restart`, apply-confirmed) and rollback swap the
// config with SetConfig and apply again; both rebuild the whole ruleset.
func TestProtocolAllowFollowsReloadAndRollback(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	before := &FirewallConfig{TCPOut: []int{443}}
	e := &Engine{conn: conn, cfg: before, statePath: t.TempDir(), listTables: func() ([]*nftables.Table, error) { return nil, nil }}
	if n := appliedProtocolRules(t, e, captured); n != 0 {
		t.Fatalf("initial apply rendered %d protocol rules, want none", n)
	}
	after := *before
	after.ProtocolAllow = vrrpPeers("192.0.2.11")
	e.SetConfig(&after)
	if n := appliedProtocolRules(t, e, captured); n != 2 {
		t.Fatalf("reload rendered %d of the input and output peer rules", n)
	}
	e.SetConfig(before)
	if n := appliedProtocolRules(t, e, captured); n != 0 {
		t.Fatalf("rollback kept %d protocol rules", n)
	}
}
