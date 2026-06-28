//go:build linux

package firewall

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// The four per-IP meter rules (syn, conn-rate, udp, connlimit) live in the
// dual-stack `inet csm` table and load the source address with a raw
// network-header payload (offset 12, len 4). Without an NFPROTO==IPV4 guard that
// load also runs on IPv6 packets, where offset 12..15 is bytes 4..7 of the
// 16-byte IPv6 source, so a fake IPv4 key gets written into the IPv4-typed meter
// set. These tests pin the guard as the first two expressions of every builder,
// ahead of any saddr load or dos_exempt lookup.

// assertIPv4NFProtoGuardPrefix verifies exprs begins with the two-expression
// NFPROTO==IPV4 guard and that nothing reads the (family-ambiguous) network
// header before it.
func assertIPv4NFProtoGuardPrefix(t *testing.T, exprs []expr.Any) {
	t.Helper()
	if len(exprs) < 2 {
		t.Fatalf("expr list len = %d, want >= 2 for the NFPROTO guard prefix", len(exprs))
	}
	m, ok := exprs[0].(*expr.Meta)
	if !ok {
		t.Fatalf("exprs[0] = %T, want *expr.Meta (NFPROTO load)", exprs[0])
	}
	if m.Key != expr.MetaKeyNFPROTO {
		t.Errorf("exprs[0] Meta.Key = %v, want MetaKeyNFPROTO", m.Key)
	}
	if m.Register != 1 {
		t.Errorf("exprs[0] Meta.Register = %d, want 1", m.Register)
	}
	c, ok := exprs[1].(*expr.Cmp)
	if !ok {
		t.Fatalf("exprs[1] = %T, want *expr.Cmp (NFPROTO==IPV4)", exprs[1])
	}
	if c.Op != expr.CmpOpEq {
		t.Errorf("exprs[1] Cmp.Op = %v, want CmpOpEq", c.Op)
	}
	if c.Register != 1 {
		t.Errorf("exprs[1] Cmp.Register = %d, want 1", c.Register)
	}
	if len(c.Data) != 1 || c.Data[0] != 2 { // NFPROTO_IPV4 == 2
		t.Errorf("exprs[1] Cmp.Data = %v, want [2] (NFPROTO_IPV4)", c.Data)
	}
	// Nothing may read the network header or do a set lookup before the guard.
	for i := 0; i < 2 && i < len(exprs); i++ {
		if p, ok := exprs[i].(*expr.Payload); ok && p.Base == expr.PayloadBaseNetworkHeader {
			t.Errorf("exprs[%d] loads the network header before the NFPROTO guard", i)
		}
		if _, ok := exprs[i].(*expr.Lookup); ok {
			t.Errorf("exprs[%d] is a set Lookup before the NFPROTO guard", i)
		}
	}
}

func TestSYNMeterHasIPv4Guard(t *testing.T) {
	e := &Engine{
		cfg:      &FirewallConfig{SYNFloodProtection: true},
		meterSYN: &nftables.Set{Name: "meter_syn", ID: 3},
	}
	assertIPv4NFProtoGuardPrefix(t, e.synFloodRuleExprs())
}

func TestUDPMeterHasIPv4Guard(t *testing.T) {
	e := &Engine{
		cfg:      &FirewallConfig{UDPFlood: true, UDPFloodRate: 100, UDPFloodBurst: 20},
		meterUDP: &nftables.Set{Name: "meter_udp", ID: 4},
	}
	assertIPv4NFProtoGuardPrefix(t, e.udpFloodRuleExprs(100, 20))
}

func TestConnMeterHasIPv4GuardNoExempt(t *testing.T) {
	e := &Engine{
		cfg:       &FirewallConfig{ConnRateLimit: 50},
		meterConn: &nftables.Set{Name: "meter_conn", ID: 1},
	}
	assertIPv4NFProtoGuardPrefix(t, e.connMeterRuleExprs(50, 25))
}

func TestConnMeterHasIPv4GuardWithExempt(t *testing.T) {
	e := &Engine{
		cfg:          &FirewallConfig{ConnRateLimit: 50},
		setDOSExempt: &nftables.Set{Name: "dos_exempt_nets", ID: 42},
		meterConn:    &nftables.Set{Name: "meter_conn", ID: 1},
	}
	exprs := e.connMeterRuleExprs(50, 25)
	assertIPv4NFProtoGuardPrefix(t, exprs)
	// Guard must precede the exempt lookup; exempt Payload+Lookup follow at 2/3.
	if _, ok := exprs[2].(*expr.Payload); !ok {
		t.Errorf("exprs[2] = %T, want *expr.Payload (exempt saddr load after guard)", exprs[2])
	}
	lk, ok := exprs[3].(*expr.Lookup)
	if !ok || !lk.Invert {
		t.Errorf("exprs[3] = %T, want inverted *expr.Lookup (dos_exempt guard after NFPROTO guard)", exprs[3])
	}
}

func TestConnlimitHasIPv4GuardNoExempt(t *testing.T) {
	e := &Engine{
		cfg:          &FirewallConfig{ConnLimit: 10},
		meterConnlim: &nftables.Set{Name: "meter_connlimit", ID: 2},
	}
	assertIPv4NFProtoGuardPrefix(t, e.connlimitRuleExprs(10))
}

func TestConnlimitHasIPv4GuardWithExempt(t *testing.T) {
	e := &Engine{
		cfg:          &FirewallConfig{ConnLimit: 10},
		setDOSExempt: &nftables.Set{Name: "dos_exempt_nets", ID: 42},
		meterConnlim: &nftables.Set{Name: "meter_connlimit", ID: 2},
	}
	exprs := e.connlimitRuleExprs(10)
	assertIPv4NFProtoGuardPrefix(t, exprs)
	if _, ok := exprs[2].(*expr.Payload); !ok {
		t.Errorf("exprs[2] = %T, want *expr.Payload (exempt saddr load after guard)", exprs[2])
	}
	lk, ok := exprs[3].(*expr.Lookup)
	if !ok || !lk.Invert {
		t.Errorf("exprs[3] = %T, want inverted *expr.Lookup (dos_exempt guard after NFPROTO guard)", exprs[3])
	}
}
