//go:build linux

package firewall

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// The Cloudflare whitelist accept rules live in the dual-stack inet table and
// load a raw IPv4 source (network-header offset 12, len 4). Without an
// NFPROTO==IPV4 guard that load also runs on IPv6 packets, where offset 12..15
// is bytes 4..7 of the 16-byte IPv6 source; an IPv6 address whose bytes 4..7
// collide with a Cloudflare v4 prefix would then be accepted on 80/443 ahead
// of the blocked/country/rate-limit rules. These tests pin the family guard
// on both the v4 and v6 rule builders.

func TestCFWhitelistV4RuleHasIPv4Guard(t *testing.T) {
	set := &nftables.Set{Name: "cf_whitelist", ID: 7}
	for _, port := range []uint16{80, 443} {
		exprs := cfWhitelistRuleExprs(set, false, port)
		assertIPv4NFProtoGuardPrefix(t, exprs)
		p, ok := exprs[2].(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != 12 || p.Len != 4 {
			t.Fatalf("port %d: exprs[2] = %#v, want v4 saddr load (network header offset 12 len 4) after guard", port, exprs[2])
		}
		lk, ok := exprs[3].(*expr.Lookup)
		if !ok || lk.SetName != "cf_whitelist" || lk.Invert {
			t.Fatalf("port %d: exprs[3] = %#v, want non-inverted cf_whitelist lookup", port, exprs[3])
		}
		v, ok := exprs[len(exprs)-1].(*expr.Verdict)
		if !ok || v.Kind != expr.VerdictAccept {
			t.Fatalf("port %d: last expr = %#v, want accept verdict", port, exprs[len(exprs)-1])
		}
	}
}

func TestCFWhitelistV6RuleHasIPv6Guard(t *testing.T) {
	set := &nftables.Set{Name: "cf_whitelist6", ID: 8}
	for _, port := range []uint16{80, 443} {
		exprs := cfWhitelistRuleExprs(set, true, port)
		if len(exprs) < 4 {
			t.Fatalf("port %d: expr list len = %d, want >= 4", port, len(exprs))
		}
		m, ok := exprs[0].(*expr.Meta)
		if !ok || m.Key != expr.MetaKeyNFPROTO || m.Register != 1 {
			t.Fatalf("port %d: exprs[0] = %#v, want NFPROTO meta load into register 1", port, exprs[0])
		}
		c, ok := exprs[1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq || c.Register != 1 || len(c.Data) != 1 || c.Data[0] != 10 {
			t.Fatalf("port %d: exprs[1] = %#v, want NFPROTO==IPV6 cmp", port, exprs[1])
		}
		p, ok := exprs[2].(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != 8 || p.Len != 16 {
			t.Fatalf("port %d: exprs[2] = %#v, want v6 saddr load (network header offset 8 len 16)", port, exprs[2])
		}
		lk, ok := exprs[3].(*expr.Lookup)
		if !ok || lk.SetName != "cf_whitelist6" || lk.Invert {
			t.Fatalf("port %d: exprs[3] = %#v, want non-inverted cf_whitelist6 lookup", port, exprs[3])
		}
		v, ok := exprs[len(exprs)-1].(*expr.Verdict)
		if !ok || v.Kind != expr.VerdictAccept {
			t.Fatalf("port %d: last expr = %#v, want accept verdict", port, exprs[len(exprs)-1])
		}
	}
}
