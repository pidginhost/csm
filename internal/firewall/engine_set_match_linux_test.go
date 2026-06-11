//go:build linux

package firewall

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestBuildSetMatchRuleExprsIPv4FiltersFamilyBeforeSourceLoad(t *testing.T) {
	set := &nftables.Set{Name: "country_blocked", ID: 42}

	exprs := buildSetMatchRuleExprs(set, expr.VerdictDrop, 2, 12, 4)

	nfprotoIndex := indexNFProtoFilter(exprs, 2)
	if nfprotoIndex < 0 {
		t.Fatal("IPv4 set match must restrict to NFPROTO_IPV4")
	}
	sourceIndex := indexSourceIPLoad(exprs, 12, 4)
	if sourceIndex < 0 {
		t.Fatal("IPv4 set match must load IPv4 source address")
	}
	if nfprotoIndex > sourceIndex {
		t.Fatal("IPv4 set match must restrict packet family before loading source address")
	}
	lookup := findLookup(exprs)
	if lookup == nil {
		t.Fatal("IPv4 set match must look up the source address")
	}
	if lookup.SetName != set.Name || lookup.SetID != set.ID {
		t.Fatalf("lookup set = %s/%d, want %s/%d", lookup.SetName, lookup.SetID, set.Name, set.ID)
	}
	if !endsWithDrop(exprs) {
		t.Fatal("IPv4 set match must end with drop verdict")
	}
}

func TestBuildSetMatchRuleExprsIPv6FiltersFamilyBeforeSourceLoad(t *testing.T) {
	set := &nftables.Set{Name: "country_blocked6", ID: 43}

	exprs := buildSetMatchRuleExprs(set, expr.VerdictDrop, 10, 8, 16)

	nfprotoIndex := indexNFProtoFilter(exprs, 10)
	if nfprotoIndex < 0 {
		t.Fatal("IPv6 set match must restrict to NFPROTO_IPV6")
	}
	sourceIndex := indexSourceIPLoad(exprs, 8, 16)
	if sourceIndex < 0 {
		t.Fatal("IPv6 set match must load IPv6 source address")
	}
	if nfprotoIndex > sourceIndex {
		t.Fatal("IPv6 set match must restrict packet family before loading source address")
	}
	lookup := findLookup(exprs)
	if lookup == nil {
		t.Fatal("IPv6 set match must look up the source address")
	}
	if lookup.SetName != set.Name || lookup.SetID != set.ID {
		t.Fatalf("lookup set = %s/%d, want %s/%d", lookup.SetName, lookup.SetID, set.Name, set.ID)
	}
	if !endsWithDrop(exprs) {
		t.Fatal("IPv6 set match must end with drop verdict")
	}
}

func TestBuildSetMatchRuleExprsNilSetReturnsNil(t *testing.T) {
	if exprs := buildSetMatchRuleExprs(nil, expr.VerdictDrop, 2, 12, 4); exprs != nil {
		t.Fatalf("nil set exprs = %d entries, want nil", len(exprs))
	}
}

func indexNFProtoFilter(exprs []expr.Any, nfproto byte) int {
	for i := 0; i < len(exprs)-1; i++ {
		m, ok := exprs[i].(*expr.Meta)
		if !ok || m.Key != expr.MetaKeyNFPROTO {
			continue
		}
		c, ok := exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq {
			continue
		}
		if len(c.Data) == 1 && c.Data[0] == nfproto {
			return i
		}
	}
	return -1
}

func indexSourceIPLoad(exprs []expr.Any, offset, length uint32) int {
	for i, e := range exprs {
		p, ok := e.(*expr.Payload)
		if !ok {
			continue
		}
		if p.Base == expr.PayloadBaseNetworkHeader && p.Offset == offset && p.Len == length {
			return i
		}
	}
	return -1
}

func findLookup(exprs []expr.Any) *expr.Lookup {
	for _, e := range exprs {
		l, ok := e.(*expr.Lookup)
		if ok {
			return l
		}
	}
	return nil
}
