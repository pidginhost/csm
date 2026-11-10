package emailspool

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestBuiltInProxyProvidersReturnsIndependentSnapshots(t *testing.T) {
	for name, mutate := range map[string]func([]ProxyProvider){
		"provider name": func(providers []ProxyProvider) {
			providers[0].Name = "Example caller"
		},
		"prefix entry": func(providers []ProxyProvider) {
			providers[0].Prefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
		},
		"prefix slice": func(providers []ProxyProvider) {
			providers[0].Prefixes = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			want := mustProxyProviders(defaultProxyRanges)
			// Keep a failing ownership check from corrupting later tests.
			t.Cleanup(func() { builtInProxyProviders = want })
			before := BuiltInProxyProviders()
			mutate(BuiltInProxyProviders())
			if !reflect.DeepEqual(before, want) {
				t.Error("mutating one result changed an earlier snapshot")
			}
			if !reflect.DeepEqual(BuiltInProxyProviders(), want) {
				t.Error("mutating one result changed the built-in snapshot")
			}
		})
	}
}

// Every built-in entry belongs to exactly the provider block it is listed
// under, so callers can select providers by name.
func TestBuiltInProxyProvidersPartitionTheList(t *testing.T) {
	providers := BuiltInProxyProviders()
	total := 0
	names := map[string]bool{}
	for _, p := range providers {
		if p.Name == "" || len(p.Prefixes) == 0 || names[p.Name] {
			t.Fatalf("provider %+v: want a unique name and at least one range", p)
		}
		names[p.Name] = true
		total += len(p.Prefixes)
		for _, prefix := range p.Prefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() {
				t.Errorf("%s: %v is not a canonical range", p.Name, prefix)
			}
		}
	}
	if total != len(builtInProxyRanges.CIDRs) {
		t.Fatalf("providers hold %d ranges, the list %d", total, len(builtInProxyRanges.CIDRs))
	}
	for _, want := range []string{"Cloudflare (IPv4)", "Cloudflare (IPv6)", "QUIC.cloud", "Sucuri firewall"} {
		if !names[want] {
			t.Errorf("no %q provider block", want)
		}
	}
	first := providers[0].Prefixes[0]
	if !first.Contains(first.Addr()) || !netip.MustParsePrefix(first.String()).IsValid() {
		t.Fatalf("first range %v does not round-trip", first)
	}
}

// The list's schema lets a bare address stand for its single-address range,
// so a block may mix both spellings.
func TestProxyProviderEntriesReadBareAddresses(t *testing.T) {
	got := mustProxyProviders([]byte("version: 1\ncidrs:\n  # Provider: Example\n  # source: https://example.com/ips (retrieved 2026-11-10)\n  - 192.0.2.10\n  - \"2001:db8::7\"\n  - 198.51.100.0/24\n"))
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32"), netip.MustParsePrefix("2001:db8::7/128"), netip.MustParsePrefix("198.51.100.0/24")}
	if len(got) != 1 || got[0].Name != "Example" || len(got[0].Prefixes) != len(want) {
		t.Fatalf("providers = %+v, want one Example block with %d ranges", got, len(want))
	}
	for i, p := range want {
		if got[0].Prefixes[i] != p {
			t.Errorf("range %d = %v, want %v", i, got[0].Prefixes[i], p)
		}
	}
}

func TestProxyProviderEntriesStayWithTheirHeadings(t *testing.T) {
	got := mustProxyProviders([]byte(`version: 1
cidrs:
  # Provider: Example edge
  - 192.0.2.0/24
  - 2001:db8:1::/48
  # Provider: Example caller
  - 198.51.100.7
  - 2001:db8:2::7
`))
	want := []ProxyProvider{
		{Name: "Example edge", Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:1::/48")}},
		{Name: "Example caller", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("2001:db8:2::7/128")}},
	}
	if len(got) != len(want) {
		t.Fatalf("provider count = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Name != w.Name || len(got[i].Prefixes) != len(w.Prefixes) {
			t.Fatalf("provider %d = %+v, want %+v", i, got[i], w)
		}
		for j, prefix := range w.Prefixes {
			if got[i].Prefixes[j] != prefix {
				t.Errorf("provider %d entry %d = %v, want %v", i, j, got[i].Prefixes[j], prefix)
			}
		}
	}
}

func TestProxyProviderEntriesRejectMalformedEmbeddedData(t *testing.T) {
	for name, data := range map[string]string{
		"missing heading": "cidrs:\n  - 192.0.2.7\n",
		"invalid entry":   "cidrs:\n  # Provider: Example\n  - not-an-address\n",
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("malformed embedded data was accepted")
				}
			}()
			mustProxyProviders([]byte(data))
		})
	}
}

func TestBuiltInProxyProvidersPreserveSnapshotEntries(t *testing.T) {
	var got []netip.Prefix
	for _, p := range BuiltInProxyProviders() {
		got = append(got, p.Prefixes...)
	}
	if len(got) != len(builtInProxyRanges.CIDRs) {
		t.Fatalf("entry count = %d, want %d", len(got), len(builtInProxyRanges.CIDRs))
	}
	for i, raw := range builtInProxyRanges.CIDRs {
		if raw == nil {
			t.Fatalf("snapshot entry %d is null", i)
		}
		var want netip.Prefix
		if a, err := netip.ParseAddr(*raw); err == nil {
			a = a.Unmap()
			want = netip.PrefixFrom(a, a.BitLen())
		} else {
			prefix, err := netip.ParsePrefix(*raw)
			if err != nil {
				t.Fatalf("snapshot entry %d: %v", i, err)
			}
			want = prefix.Masked()
		}
		if got[i] != want {
			t.Errorf("snapshot entry %d = %v, want %v", i, got[i], want)
		}
	}
}
