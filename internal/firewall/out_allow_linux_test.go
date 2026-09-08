//go:build linux

package firewall

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestOutAllowMappedCIDRMatchesIPv4Subnet(t *testing.T) {
	for _, tc := range []struct{ mapped, plain string }{
		{"::ffff:203.0.113.155/120", "203.0.113.0/24"},
		{"::ffff:203.0.113.155/96", "0.0.0.0/0"},
		{"::ffff:203.0.113.155/128", "203.0.113.155/32"},
	} {
		t.Run(tc.mapped, func(t *testing.T) {
			got := buildOutAllowExprs(rule(tc.mapped, 49152, 65534), false)
			want := buildOutAllowExprs(rule(tc.plain, 49152, 65534), false)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("mapped prefix must enforce the same subnet as %s", tc.plain)
			}
		})
	}
}

func TestOutAllowAddressExpressionWidthsAndGuards(t *testing.T) {
	for _, dst := range []string{"203.0.113.155/24", "203.0.113.155/32", "2001:db8::1234/64", "2001:db8::1/128", "0.0.0.0/0", "::/0"} {
		t.Run(dst, func(t *testing.T) {
			_, network, err := net.ParseCIDR(dst)
			if err != nil {
				t.Fatal(err)
			}
			ones, bits := network.Mask.Size()
			length, offset, family := uint32(4), uint32(16), byte(2)
			if bits == 128 {
				length, offset, family = 16, 24, 10
			}
			exprs := buildOutAllowExprs(rule(dst, 49152, 65534), true)
			if len(exprs) < 8 {
				t.Fatalf("missing family/protocol/port guards: %v", exprs)
			}
			wantGuard := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			}
			if !reflect.DeepEqual(exprs[:4], wantGuard) {
				t.Fatal("family and TCP guards must precede all payload loads")
			}
			p := networkPayload(t, exprs)
			if ones == 0 {
				if p != nil || len(exprs) != 8 {
					t.Fatal("any-destination rule must retain family guard without address expressions")
				}
				return
			}
			if p == nil || p.Offset != offset || p.Len != length {
				t.Fatalf("destination payload = %+v, want offset %d len %d", p, offset, length)
			}
			cmpIndex := 5
			if ones < bits {
				b, ok := exprs[5].(*expr.Bitwise)
				if !ok || b.Len != length || len(b.Mask) != int(length) || len(b.Xor) != int(length) || !bytes.Equal(b.Mask, network.Mask) || !bytes.Equal(b.Xor, make([]byte, length)) {
					t.Fatalf("bitwise must mask exactly the loaded address width: %#v", exprs[5])
				}
				cmpIndex++
			}
			c, ok := exprs[cmpIndex].(*expr.Cmp)
			if !ok || c.Op != expr.CmpOpEq || !bytes.Equal(c.Data, network.IP) {
				t.Fatalf("destination comparison must use the masked network: %#v", exprs[cmpIndex])
			}
		})
	}
}

func TestOutAllowFollowsEverySMTPDrop(t *testing.T) {
	for _, ipv4Bypass := range []bool{false, true} {
		cfg := &FirewallConfig{IPv6: true, TCPOut: []int{443}, TCP6Out: []int{443}, SMTPBlock: true, SMTPPorts: []int{25, 465, 587}}
		if ipv4Bypass {
			cfg.TCPOut = nil
		}
		cfg.TCPOutAllow = []OutAllowRule{rule("203.0.113.155", 1, 65535), rule("2001:db8::1", 1, 65535)}
		conn, captured := nftConnCapturingRules(t)
		e := &Engine{cfg: cfg, conn: conn}
		e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
		if err := e.createOutputChain(); err != nil {
			t.Fatal(err)
		}
		if err := conn.Flush(); err != nil {
			t.Fatal(err)
		}
		for _, r := range cfg.TCPOutAllow {
			allowIndex := outputRuleIndex(*captured, captureOutputRuleData(t, buildOutAllowExprs(r, true)))
			if allowIndex < 0 {
				t.Fatalf("outbound allow missing for %s", r.Dst)
			}
			for _, port := range cfg.SMTPPorts {
				dropIndex := outputRuleIndex(*captured, captureOutputRuleData(t, smtpDropRuleExprsForTest(port)))
				if dropIndex < 0 || dropIndex >= allowIndex {
					t.Fatalf("SMTP %d drop index %d must precede allow index %d", port, dropIndex, allowIndex)
				}
				if ipv4Bypass {
					bypassIndex := outputRuleIndex(*captured, captureOutputRuleData(t, familyBypassRuleExprs(2)))
					if bypassIndex <= dropIndex || bypassIndex >= allowIndex {
						t.Fatalf("IPv4 bypass index %d must be between SMTP drop %d and allow %d", bypassIndex, dropIndex, allowIndex)
					}
				}
			}
		}
	}
}

func TestOutAllowSkipsInvalidRanges(t *testing.T) {
	for _, bounds := range [][2]int{{0, 8443}, {8443, 65536}, {8444, 8443}, {-1, 65535}} {
		if got := buildOutAllowExprs(rule("0.0.0.0/0", bounds[0], bounds[1]), true); got != nil {
			t.Errorf("invalid bounds %v emitted %d expressions", bounds, len(got))
		}
	}
}

func networkPayload(t *testing.T, exprs []expr.Any) *expr.Payload {
	t.Helper()
	for _, e := range exprs {
		if p, ok := e.(*expr.Payload); ok && p.Base == expr.PayloadBaseNetworkHeader {
			return p
		}
	}
	return nil
}

func rule(dst string, start, end int) OutAllowRule {
	return OutAllowRule{Dst: dst, PortStart: start, PortEnd: end}
}

// The neighbouring helper buildPortAllowExprs matches the SOURCE address at
// offset 12. This rule lives in the output chain and must match the
// DESTINATION at offset 16, or it allows egress to the wrong hosts entirely.
func TestOutAllowMatchesIPv4Destination(t *testing.T) {
	p := networkPayload(t, buildOutAllowExprs(rule("203.0.113.155/32", 49152, 65534), false))
	if p == nil {
		t.Fatal("no network-header match emitted; the rule would allow the range to every destination")
	}
	if p.Offset != 16 || p.Len != 4 {
		t.Errorf("IPv4 daddr payload = offset %d len %d, want offset 16 len 4 (offset 12 is the source)", p.Offset, p.Len)
	}
}

func TestOutAllowMatchesIPv6Destination(t *testing.T) {
	p := networkPayload(t, buildOutAllowExprs(rule("2001:db8::1/128", 49152, 65534), true))
	if p == nil {
		t.Fatal("no network-header match emitted for the IPv6 destination")
	}
	if p.Offset != 24 || p.Len != 16 {
		t.Errorf("IPv6 daddr payload = offset %d len %d, want offset 24 len 16 (offset 8 is the source)", p.Offset, p.Len)
	}
}

func TestOutAllowMasksCIDRPrefix(t *testing.T) {
	exprs := buildOutAllowExprs(rule("203.0.113.0/24", 49152, 65534), false)
	var found *expr.Bitwise
	for _, e := range exprs {
		if b, ok := e.(*expr.Bitwise); ok {
			found = b
		}
	}
	if found == nil {
		t.Fatal("a /24 destination must be masked; without it only the exact .0 address matches")
	}
	if want := []byte{0xff, 0xff, 0xff, 0x00}; !bytes.Equal(found.Mask, want) {
		t.Errorf("mask = %v, want %v", found.Mask, want)
	}
}

func TestOutAllowBoundsPortRange(t *testing.T) {
	exprs := buildOutAllowExprs(rule("203.0.113.155/32", 49152, 65534), false)
	var gte, lte bool
	for _, e := range exprs {
		c, ok := e.(*expr.Cmp)
		if !ok {
			continue
		}
		switch c.Op {
		case expr.CmpOpGte:
			gte = bytes.Equal(c.Data, []byte{0xc0, 0x00}) // 49152
		case expr.CmpOpLte:
			lte = bytes.Equal(c.Data, []byte{0xff, 0xfe}) // 65534
		}
	}
	if !gte || !lte {
		t.Errorf("port range bounds missing: gte=%v lte=%v", gte, lte)
	}
}

// 0.0.0.0/0 is a supported choice, and the honest encoding of "any" is no
// address match at all rather than a mask that compares nothing.
func TestOutAllowAnyDestinationEmitsNoAddressMatch(t *testing.T) {
	exprs := buildOutAllowExprs(rule("0.0.0.0/0", 49152, 65534), false)
	if len(exprs) == 0 {
		t.Fatal("any-destination is supported and must still emit a rule")
	}
	if p := networkPayload(t, exprs); p != nil {
		t.Errorf("0.0.0.0/0 needs no address match, got payload at offset %d", p.Offset)
	}
}

func TestOutAllowSkipsIPv6DestinationWhenIPv6Disabled(t *testing.T) {
	if exprs := buildOutAllowExprs(rule("2001:db8::1/128", 49152, 65534), false); exprs != nil {
		t.Errorf("v6 rule emitted while ipv6 is off, got %d exprs", len(exprs))
	}
}

func TestOutAllowSkipsUnparseableDestination(t *testing.T) {
	if exprs := buildOutAllowExprs(rule("not-an-ip", 49152, 65534), false); exprs != nil {
		t.Errorf("unparseable dst must emit no rule, got %d exprs", len(exprs))
	}
}

func TestOutAllowAcceptsAtEnd(t *testing.T) {
	exprs := buildOutAllowExprs(rule("203.0.113.155/32", 49152, 65534), false)
	v, ok := exprs[len(exprs)-1].(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictAccept {
		t.Fatalf("last expr = %#v, want accept verdict", exprs[len(exprs)-1])
	}
}
