//go:build linux

package firewall

import (
	"bytes"
	"testing"

	"github.com/google/nftables/expr"
)

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
