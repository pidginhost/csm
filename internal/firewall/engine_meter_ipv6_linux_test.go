//go:build linux

package firewall

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// IPv6 parity for the per-IP flood meters. After the IPv4 family guard, IPv6
// packets skip the v4-only syn/conn/udp meters entirely, so they get no per-IP
// metering. These tests pin the v6 builders: an NFPROTO==IPV6 guard, a source
// load masked to the /64 prefix (IPv6 hosts own whole /64s and rotate addresses
// within them, so /128 metering is trivially evaded), and the v6 meter set.
// There is deliberately no v6 connlimit: that would re-add the vulnerable
// nf_conncount crash surface on the affected kernel.

// wantV6Mask64 keeps the high 8 bytes (network prefix) and zeroes the low 8
// bytes (interface identifier).
var wantV6Mask64 = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var wantV6MaskXorZero = make([]byte, 16)

func assertIPv6NFProtoGuardPrefix(t *testing.T, exprs []expr.Any) {
	t.Helper()
	if len(exprs) < 2 {
		t.Fatalf("expr list len = %d, want >= 2 for the NFPROTO guard prefix", len(exprs))
	}
	m, ok := exprs[0].(*expr.Meta)
	if !ok || m.Key != expr.MetaKeyNFPROTO || m.Register != 1 {
		t.Fatalf("exprs[0] = %#v, want Meta{NFPROTO, reg 1}", exprs[0])
	}
	c, ok := exprs[1].(*expr.Cmp)
	if !ok || c.Op != expr.CmpOpEq || len(c.Data) != 1 || c.Data[0] != 10 {
		t.Fatalf("exprs[1] = %#v, want Cmp{==, [10] NFPROTO_IPV6}", exprs[1])
	}
}

// assertMaskedV6SaddrDynsetKey verifies the rule loads the IPv6 source (offset
// 8, len 16), masks it to /64, and feeds that masked key into a Dynset on the
// named set. An exempt lookup may load the full (unmasked) source earlier in the
// rule, so the helper scans for the source load that is followed by the /64
// mask rather than assuming it is the first one.
func assertMaskedV6SaddrDynsetKey(t *testing.T, exprs []expr.Any, setName string) {
	t.Helper()
	for i, e := range exprs {
		p, ok := e.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != 8 || p.Len != 16 {
			continue
		}
		if i+1 >= len(exprs) {
			continue
		}
		b, ok := exprs[i+1].(*expr.Bitwise)
		if !ok || b.SourceRegister != 1 || b.DestRegister != 1 || b.Len != 16 ||
			!bytes.Equal(b.Mask, wantV6Mask64) || !bytes.Equal(b.Xor, wantV6MaskXorZero) {
			continue // not the masked meter key (e.g. the exempt lookup's load)
		}
		if i+2 >= len(exprs) {
			t.Fatalf("masked IPv6 key at exprs[%d] has no following Dynset into %s", i, setName)
		}
		ds, ok := exprs[i+2].(*expr.Dynset)
		if !ok || ds.SrcRegKey != 1 || ds.SetName != setName {
			t.Fatalf("exprs[%d] = %#v, want Dynset keyed from masked reg1 into %s", i+2, exprs[i+2], setName)
		}
		return
	}
	t.Fatalf("no /64-masked IPv6 saddr key feeding a Dynset found in %d exprs", len(exprs))
}

func TestSYNMeter6GuardMaskAndSet(t *testing.T) {
	e := &Engine{
		cfg:       &FirewallConfig{SYNFloodProtection: true, IPv6: true},
		meterSYN6: &nftables.Set{Name: "meter_syn6", ID: 13},
	}
	exprs := e.synFloodRuleExprs6()
	assertIPv6NFProtoGuardPrefix(t, exprs)
	assertMaskedV6SaddrDynsetKey(t, exprs, "meter_syn6")
}

func TestUDPMeter6GuardMaskAndSet(t *testing.T) {
	e := &Engine{
		cfg:       &FirewallConfig{UDPFlood: true, UDPFloodRate: 100, UDPFloodBurst: 20, IPv6: true},
		meterUDP6: &nftables.Set{Name: "meter_udp6", ID: 14},
	}
	exprs := e.udpFloodRuleExprs6(100, 20)
	assertIPv6NFProtoGuardPrefix(t, exprs)
	assertMaskedV6SaddrDynsetKey(t, exprs, "meter_udp6")
}

func TestConnMeter6GuardMaskAndSetNoExempt(t *testing.T) {
	e := &Engine{
		cfg:        &FirewallConfig{ConnRateLimit: 50, IPv6: true},
		meterConn6: &nftables.Set{Name: "meter_conn6", ID: 15},
	}
	exprs := e.connMeterRuleExprs6(50, 25)
	assertIPv6NFProtoGuardPrefix(t, exprs)
	assertMaskedV6SaddrDynsetKey(t, exprs, "meter_conn6")
	if findLookupBySet(exprs, "dos_exempt_nets6") != nil {
		t.Error("no exempt lookup expected when setDOSExempt6 is nil")
	}
}

func TestConnMeter6CarriesV6ExemptLookup(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{ConnRateLimit: 50, IPv6: true},
		setDOSExempt6: &nftables.Set{Name: "dos_exempt_nets6", ID: 8},
		meterConn6:    &nftables.Set{Name: "meter_conn6", ID: 15},
	}
	exprs := e.connMeterRuleExprs6(50, 25)
	assertIPv6NFProtoGuardPrefix(t, exprs)
	assertMaskedV6SaddrDynsetKey(t, exprs, "meter_conn6")
	lk := findInvertedLookup(exprs)
	if lk == nil || lk.SetName != "dos_exempt_nets6" {
		t.Fatalf("expected inverted lookup into dos_exempt_nets6, got %#v", lk)
	}
}

func TestConnMeter6ReloadsRegisterAfterV6ExemptLookup(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{ConnRateLimit: 50, IPv6: true},
		setDOSExempt6: &nftables.Set{Name: "dos_exempt_nets6", ID: 8},
		meterConn6:    &nftables.Set{Name: "meter_conn6", ID: 15},
	}
	exprs := e.connMeterRuleExprs6(50, 25)
	assertIPv6NFProtoGuardPrefix(t, exprs)

	fullSaddr, ok := exprs[2].(*expr.Payload)
	if !ok || fullSaddr.DestRegister != 1 || fullSaddr.Base != expr.PayloadBaseNetworkHeader ||
		fullSaddr.Offset != 8 || fullSaddr.Len != 16 {
		t.Fatalf("exprs[2] = %#v, want full IPv6 saddr load into reg1 for exempt lookup", exprs[2])
	}
	lk, ok := exprs[3].(*expr.Lookup)
	if !ok || !lk.Invert || lk.SourceRegister != 1 || lk.SetName != "dos_exempt_nets6" {
		t.Fatalf("exprs[3] = %#v, want inverted lookup into dos_exempt_nets6 from reg1", exprs[3])
	}
	ct, ok := exprs[4].(*expr.Ct)
	if !ok || ct.Register != 1 || ct.Key != expr.CtKeySTATE {
		t.Fatalf("exprs[4] = %#v, want ct-state reload into reg1", exprs[4])
	}
	maskedSaddr, ok := exprs[7].(*expr.Payload)
	if !ok || maskedSaddr.DestRegister != 1 || maskedSaddr.Base != expr.PayloadBaseNetworkHeader ||
		maskedSaddr.Offset != 8 || maskedSaddr.Len != 16 {
		t.Fatalf("exprs[7] = %#v, want IPv6 saddr reload into reg1 for meter key", exprs[7])
	}
	mask, ok := exprs[8].(*expr.Bitwise)
	if !ok || mask.SourceRegister != 1 || mask.DestRegister != 1 || mask.Len != 16 ||
		!bytes.Equal(mask.Mask, wantV6Mask64) || !bytes.Equal(mask.Xor, wantV6MaskXorZero) {
		t.Fatalf("exprs[8] = %#v, want /64 mask in reg1 with zero XOR", exprs[8])
	}
	ds, ok := exprs[9].(*expr.Dynset)
	if !ok || ds.SrcRegKey != 1 || ds.SetName != "meter_conn6" {
		t.Fatalf("exprs[9] = %#v, want Dynset keyed from masked reg1 into meter_conn6", exprs[9])
	}
}

func TestSYNMeter6ReadsTCPFlagsBeforeSourceKey(t *testing.T) {
	e := &Engine{
		cfg:       &FirewallConfig{SYNFloodProtection: true, IPv6: true},
		meterSYN6: &nftables.Set{Name: "meter_syn6", ID: 13},
	}
	exprs := e.synFloodRuleExprs6()
	assertIPv6NFProtoGuardPrefix(t, exprs)

	l4, ok := exprs[2].(*expr.Meta)
	if !ok || l4.Key != expr.MetaKeyL4PROTO || l4.Register != 1 {
		t.Fatalf("exprs[2] = %#v, want L4 protocol reload into reg1", exprs[2])
	}
	flags, ok := exprs[4].(*expr.Payload)
	if !ok || flags.DestRegister != 1 || flags.Base != expr.PayloadBaseTransportHeader ||
		flags.Offset != 13 || flags.Len != 1 {
		t.Fatalf("exprs[4] = %#v, want TCP flags at transport-header offset 13", exprs[4])
	}
	flagMask, ok := exprs[5].(*expr.Bitwise)
	if !ok || flagMask.SourceRegister != 1 || flagMask.DestRegister != 1 || flagMask.Len != 1 ||
		!bytes.Equal(flagMask.Mask, []byte{0x12}) || !bytes.Equal(flagMask.Xor, []byte{0x00}) {
		t.Fatalf("exprs[5] = %#v, want SYN/ACK TCP flag mask in reg1", exprs[5])
	}
	synCmp, ok := exprs[6].(*expr.Cmp)
	if !ok || synCmp.Op != expr.CmpOpEq || synCmp.Register != 1 || !bytes.Equal(synCmp.Data, []byte{0x02}) {
		t.Fatalf("exprs[6] = %#v, want SYN-only comparison in reg1", exprs[6])
	}
	saddr, ok := exprs[7].(*expr.Payload)
	if !ok || saddr.DestRegister != 1 || saddr.Base != expr.PayloadBaseNetworkHeader ||
		saddr.Offset != 8 || saddr.Len != 16 {
		t.Fatalf("exprs[7] = %#v, want IPv6 saddr load after TCP flag check", exprs[7])
	}
}

func TestIPv6MeterHelpersReturnFreshTwoCapSlices(t *testing.T) {
	guard1 := ipv6NFProtoGuard()
	guard2 := ipv6NFProtoGuard()
	if len(guard1) != 2 || cap(guard1) != 2 || len(guard2) != 2 || cap(guard2) != 2 {
		t.Fatalf("ipv6NFProtoGuard len/cap = %d/%d and %d/%d, want fresh 2-cap slices",
			len(guard1), cap(guard1), len(guard2), cap(guard2))
	}
	guard1[0] = nil
	if guard2[0] == nil {
		t.Fatal("ipv6NFProtoGuard returned aliased backing arrays")
	}

	e := &Engine{setDOSExempt6: &nftables.Set{Name: "dos_exempt_nets6", ID: 8}}
	lookup1 := e.dosExemptV6Lookup(1)
	lookup2 := e.dosExemptV6Lookup(1)
	if len(lookup1) != 2 || cap(lookup1) != 2 || len(lookup2) != 2 || cap(lookup2) != 2 {
		t.Fatalf("dosExemptV6Lookup len/cap = %d/%d and %d/%d, want fresh 2-cap slices",
			len(lookup1), cap(lookup1), len(lookup2), cap(lookup2))
	}
	lookup1[0] = nil
	if lookup2[0] == nil {
		t.Fatal("dosExemptV6Lookup returned aliased backing arrays")
	}
}

// TestCreateSetsNoConnlimitV6 locks the deliberate absence of a v6 connlimit
// set: keying concurrent connections per v6 source would re-introduce the
// nf_conncount GC crash surface on the affected kernel.
func TestCreateSetsNoConnlimitV6(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := &Engine{
		cfg:       &FirewallConfig{SYNFloodProtection: true, ConnRateLimit: 50, ConnLimit: 10, UDPFlood: true, UDPFloodRate: 100, UDPFloodBurst: 20, IPv6: true},
		conn:      conn,
		statePath: t.TempDir(),
	}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	if err := e.createSets(); err != nil {
		t.Fatalf("createSets: %v", err)
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	for _, m := range *captured {
		if ruleMsgReferencesSet(m, "meter_connlimit6") {
			t.Fatal("a meter_connlimit6 set was created; v6 connlimit must not exist")
		}
	}
	// Sanity: the v6 rate meters DO get created.
	for _, name := range []string{"meter_syn6", "meter_conn6", "meter_udp6"} {
		found := false
		for _, m := range *captured {
			if ruleMsgReferencesSet(m, name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected v6 set %s to be created", name)
		}
	}
}
