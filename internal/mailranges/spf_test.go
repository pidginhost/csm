package mailranges

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// mapResolver is a fake Resolver for tests. It returns canned TXT records
// keyed by domain name. Domains not in the map return a "not found" error.
type mapResolver map[string][]string

func (m mapResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	v, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("no TXT record for %q", name)
	}
	return v, nil
}

// TestResolveSPF exercises ResolveSPF against a fake DNS resolver so no real
// network calls are made. Each subtest is fully self-contained.
func TestResolveSPF(t *testing.T) {
	// Core fixture: root includes child which redirects to more.
	// Collects: 8.8.8.0/24 (root), 2001:4860:4860::/48 (child), 1.1.1.0/24 (more).
	base := mapResolver{
		"root":  {"v=spf1 ip4:8.8.8.0/24 include:child -all"},
		"child": {"v=spf1 ip6:2001:4860:4860::/48 redirect=more"},
		"more":  {"v=spf1 ip4:1.1.1.0/24 -all"},
		"loopA": {"v=spf1 include:loopB -all"},
		"loopB": {"v=spf1 include:loopA -all"},
	}

	t.Run("collect", func(t *testing.T) {
		nets, err := ResolveSPF(context.Background(), base, "root")
		if err != nil || len(nets) != 3 {
			t.Fatalf("got %v err %v", nets, err)
		}
		want := map[string]bool{
			"8.8.8.0/24":          true,
			"2001:4860:4860::/48": true,
			"1.1.1.0/24":          true,
		}
		for _, n := range nets {
			if !want[n.String()] {
				t.Errorf("unexpected net %s", n)
			}
			delete(want, n.String())
		}
		for s := range want {
			t.Errorf("missing net %s", s)
		}
	})

	t.Run("loop", func(t *testing.T) {
		_, err := ResolveSPF(context.Background(), base, "loopA")
		if err == nil {
			t.Fatal("loop must return an error instead of silently publishing a partial provider set")
		}
	})

	t.Run("depth_cap", func(t *testing.T) {
		// Build a chain: d0 -> d1 -> ... -> d9 -> d10.
		// d10 is reached at depth 10, which exceeds the cap of 10 levels (0..9).
		deepFake := make(mapResolver)
		for i := 0; i < 10; i++ {
			deepFake[fmt.Sprintf("d%d", i)] = []string{
				fmt.Sprintf("v=spf1 include:d%d -all", i+1),
			}
		}
		deepFake["d10"] = []string{"v=spf1 ip4:8.8.8.0/24 -all"}
		_, err := ResolveSPF(context.Background(), deepFake, "d0")
		if err == nil {
			t.Fatal("depth cap must return an error")
		}
	})

	t.Run("lookup_fanout_cap", func(t *testing.T) {
		const includes = 70
		var root strings.Builder
		root.WriteString("v=spf1")
		r := make(mapResolver, includes+1)
		for i := 0; i < includes; i++ {
			name := fmt.Sprintf("fanout%d", i)
			root.WriteString(" include:")
			root.WriteString(name)
			r[name] = []string{"v=spf1 ip4:8.8.8.8 -all"}
		}
		root.WriteString(" -all")
		r["fanout-root"] = []string{root.String()}

		_, err := ResolveSPF(context.Background(), r, "fanout-root")
		if err == nil {
			t.Fatal("lookup fan-out above the cap must return an error")
		}
	})

	t.Run("malformed_txt", func(t *testing.T) {
		r := mapResolver{"bad": {"not an spf record at all"}}
		_, err := ResolveSPF(context.Background(), r, "bad")
		if err == nil {
			t.Fatal("missing v=spf1 must return an error")
		}
	})

	t.Run("non_public_rfc1918", func(t *testing.T) {
		r := mapResolver{"priv": {"v=spf1 ip4:10.0.0.0/8 -all"}}
		_, err := ResolveSPF(context.Background(), r, "priv")
		if err == nil {
			t.Fatal("RFC 1918 prefix must return an error")
		}
	})

	t.Run("documentation_ipv4_test_net_3", func(t *testing.T) {
		r := mapResolver{"doc": {"v=spf1 ip4:203.0.113.0/24 -all"}}
		_, err := ResolveSPF(context.Background(), r, "doc")
		if err == nil {
			t.Fatal("RFC 5737 TEST-NET-3 prefix must return an error")
		}
	})

	t.Run("documentation_ipv4_test_net_2", func(t *testing.T) {
		r := mapResolver{"doc": {"v=spf1 ip4:198.51.100.0/24 -all"}}
		_, err := ResolveSPF(context.Background(), r, "doc")
		if err == nil {
			t.Fatal("RFC 5737 TEST-NET-2 prefix must return an error")
		}
	})

	t.Run("documentation_ipv6", func(t *testing.T) {
		r := mapResolver{"doc6": {"v=spf1 ip6:2001:db8::/32 -all"}}
		_, err := ResolveSPF(context.Background(), r, "doc6")
		if err == nil {
			t.Fatal("RFC 3849 documentation prefix must return an error")
		}
	})

	t.Run("malformed_prefix", func(t *testing.T) {
		r := mapResolver{"malform": {"v=spf1 ip4:notacidr -all"}}
		_, err := ResolveSPF(context.Background(), r, "malform")
		if err == nil {
			t.Fatal("malformed CIDR must return an error")
		}
	})

	t.Run("bare_ip_mechanisms", func(t *testing.T) {
		r := mapResolver{"bare": {"v=spf1 ip4:8.8.8.8 ip6:2001:4860:4860::8888 -all"}}
		nets, err := ResolveSPF(context.Background(), r, "bare")
		if err != nil {
			t.Fatalf("bare SPF IP mechanisms must resolve, got error: %v", err)
		}
		want := map[string]bool{
			"8.8.8.8/32":               true,
			"2001:4860:4860::8888/128": true,
		}
		for _, n := range nets {
			if !want[n.String()] {
				t.Errorf("unexpected net %s", n)
			}
			delete(want, n.String())
		}
		for s := range want {
			t.Errorf("missing net %s", s)
		}
	})

	t.Run("explicit_pass_qualifier", func(t *testing.T) {
		r := mapResolver{
			"plus":  {"V=SPF1 +IP4:8.8.8.0/24 +include:child -all"},
			"child": {"v=spf1 +ip6:2001:4860:4860::/48 -all"},
		}
		nets, err := ResolveSPF(context.Background(), r, "plus")
		if err != nil {
			t.Fatalf("explicit pass qualifiers must resolve, got error: %v", err)
		}
		want := map[string]bool{
			"8.8.8.0/24":          true,
			"2001:4860:4860::/48": true,
		}
		for _, n := range nets {
			if !want[n.String()] {
				t.Errorf("unexpected net %s", n)
			}
			delete(want, n.String())
		}
		for s := range want {
			t.Errorf("missing net %s", s)
		}
	})

	t.Run("non_pass_qualifier_ignored", func(t *testing.T) {
		r := mapResolver{"negative": {"v=spf1 -ip4:8.8.8.0/24 ~include:child ?ip6:2001:4860:4860::/48 -all"}}
		nets, err := ResolveSPF(context.Background(), r, "negative")
		if err != nil {
			t.Fatalf("non-pass qualified mechanisms should be ignored, got error: %v", err)
		}
		if len(nets) != 0 {
			t.Fatalf("non-pass qualified mechanisms yielded nets: %v", nets)
		}
	})

	t.Run("wrong_ip_family", func(t *testing.T) {
		cases := map[string]string{
			"ip4v6": "v=spf1 ip4:2001:4860:4860::/48 -all",
			"ip6v4": "v=spf1 ip6:8.8.8.0/24 -all",
		}
		for name, txt := range cases {
			t.Run(name, func(t *testing.T) {
				r := mapResolver{name: {txt}}
				_, err := ResolveSPF(context.Background(), r, name)
				if err == nil {
					t.Fatal("wrong-family SPF mechanism must return an error")
				}
			})
		}
	})

	t.Run("default_route_ipv4", func(t *testing.T) {
		r := mapResolver{"def": {"v=spf1 ip4:0.0.0.0/0 -all"}}
		_, err := ResolveSPF(context.Background(), r, "def")
		if err == nil {
			t.Fatal("IPv4 default route must return an error")
		}
	})

	t.Run("default_route_ipv6", func(t *testing.T) {
		r := mapResolver{"def6": {"v=spf1 ip6:::/0 -all"}}
		_, err := ResolveSPF(context.Background(), r, "def6")
		if err == nil {
			t.Fatal("IPv6 default route must return an error")
		}
	})

	t.Run("dedup", func(t *testing.T) {
		// Two includes returning the same prefix must yield exactly one net.
		r := mapResolver{
			"dedup": {"v=spf1 include:dup1 include:dup2 -all"},
			"dup1":  {"v=spf1 ip4:8.8.8.0/24 -all"},
			"dup2":  {"v=spf1 ip4:8.8.8.0/24 -all"},
		}
		nets, err := ResolveSPF(context.Background(), r, "dedup")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nets) != 1 {
			t.Fatalf("expected 1 deduplicated net, got %d: %v", len(nets), nets)
		}
		if nets[0].String() != "8.8.8.0/24" {
			t.Fatalf("wrong net: %s", nets[0])
		}
	})

	t.Run("context_cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already canceled
		_, err := ResolveSPF(ctx, base, "root")
		if err == nil {
			t.Fatal("expected error when context is already canceled")
		}
	})

	// M1: a diamond (same sub-domain reached via two different include branches)
	// is NOT a cycle and must resolve successfully with deduplicated ranges.
	// A true ancestor cycle (loopA/loopB above) must still error.
	t.Run("diamond_resolves", func(t *testing.T) {
		r := mapResolver{
			"droot":   {"v=spf1 include:da include:db -all"},
			"da":      {"v=spf1 include:dshared -all"},
			"db":      {"v=spf1 include:dshared -all"},
			"dshared": {"v=spf1 ip4:8.8.8.0/24 -all"},
		}
		nets, err := ResolveSPF(context.Background(), r, "droot")
		if err != nil {
			t.Fatalf("diamond must resolve, got error: %v", err)
		}
		if len(nets) != 1 {
			t.Fatalf("expected 1 deduplicated net from diamond, got %d: %v", len(nets), nets)
		}
		if nets[0].String() != "8.8.8.0/24" {
			t.Fatalf("wrong net: %s", nets[0])
		}
	})

	// M2: a second redirect= must always error even when the first has an empty
	// value (the empty value must not bypass the multiple-redirect guard). The
	// second redirect target is a valid, resolvable record so the ONLY reason to
	// error is the multiple-redirect guard itself, not a failed target lookup.
	t.Run("multiple_redirect_first_empty", func(t *testing.T) {
		r := mapResolver{
			"mr":       {"v=spf1 redirect= redirect=mrtarget -all"},
			"mrtarget": {"v=spf1 ip4:8.8.8.0/24 -all"},
		}
		_, err := ResolveSPF(context.Background(), r, "mr")
		if err == nil {
			t.Fatal("multiple redirect= (first empty) must return an error")
		}
	})

	t.Run("empty_include_or_redirect", func(t *testing.T) {
		cases := map[string]string{
			"empty_include":  "v=spf1 ip4:8.8.8.0/24 include: -all",
			"empty_redirect": "v=spf1 ip4:8.8.8.0/24 redirect= -all",
		}
		for name, txt := range cases {
			t.Run(name, func(t *testing.T) {
				r := mapResolver{name: {txt}}
				_, err := ResolveSPF(context.Background(), r, name)
				if err == nil {
					t.Fatal("empty include/redirect must return an error")
				}
			})
		}
	})

	t.Run("multiple_spf_records", func(t *testing.T) {
		r := mapResolver{"multi": {
			"v=spf1 ip4:8.8.8.0/24 -all",
			"v=spf1 ip4:1.1.1.0/24 -all",
		}}
		_, err := ResolveSPF(context.Background(), r, "multi")
		if err == nil {
			t.Fatal("multiple v=spf1 records must return an error")
		}
	})

	// M3: record selection must not match v=spf1foo. A malformed v=spf1foo TXT
	// must be skipped in favor of a real later v=spf1 record.
	t.Run("v_spf1_boundary", func(t *testing.T) {
		r := mapResolver{"m3": {"v=spf1foo ip4:10.0.0.0/8 junk", "v=spf1 ip4:8.8.8.0/24 -all"}}
		nets, err := ResolveSPF(context.Background(), r, "m3")
		if err != nil {
			t.Fatalf("real v=spf1 record must be used, got error: %v", err)
		}
		if len(nets) != 1 || nets[0].String() != "8.8.8.0/24" {
			t.Fatalf("expected only 8.8.8.0/24 from real record, got %v", nets)
		}
	})

	// M4: RFC 5737 TEST-NET-1 documentation prefix must be rejected.
	t.Run("documentation_ipv4_test_net_1", func(t *testing.T) {
		r := mapResolver{"doc1": {"v=spf1 ip4:192.0.2.0/24 -all"}}
		_, err := ResolveSPF(context.Background(), r, "doc1")
		if err == nil {
			t.Fatal("RFC 5737 TEST-NET-1 prefix must return an error")
		}
	})
}
