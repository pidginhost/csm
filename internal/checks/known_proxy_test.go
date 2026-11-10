package checks

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailspool"
)

// withKnownProxyPrefixes replaces the built-in CDN edges with documentation
// ranges for the test.
func withKnownProxyPrefixes(t *testing.T, prefixes ...string) {
	t.Helper()
	var set []netip.Prefix
	for _, p := range prefixes {
		set = append(set, netip.MustParsePrefix(p))
	}
	prev := knownProxyPrefixes
	prevLookup := CurrentASNLookup()
	knownProxyPrefixes = set
	t.Cleanup(func() {
		knownProxyPrefixes = prev
		SetASNLookup(prevLookup)
	})
}

// The built-in CDN and website-firewall blocks are known proxies; the list's
// payment webhook senders are callers, not proxies.
func TestKnownProxyPeerSelectsTheCDNBlocks(t *testing.T) {
	prevLookup := CurrentASNLookup()
	t.Cleanup(func() { SetASNLookup(prevLookup) })
	SetASNLookup(nil)
	byName := map[string]emailspool.ProxyProvider{}
	for _, p := range emailspool.BuiltInProxyProviders() {
		byName[p.Name] = p
	}
	for _, name := range knownProxyProviders {
		p, ok := byName[name]
		if !ok {
			t.Fatalf("no built-in %q block; a renamed heading must not drop a CDN", name)
		}
		for _, prefix := range p.Prefixes {
			if !KnownProxyPeer(prefix.Addr().String(), nil) {
				t.Errorf("%s range %v is not a known proxy", name, prefix)
			}
		}
	}
	for name, p := range byName {
		if slices.Contains(knownProxyProviders, name) {
			continue
		}
		for _, prefix := range p.Prefixes {
			if KnownProxyPeer(prefix.Addr().String(), nil) {
				t.Errorf("%s range %v (not a proxy) is a known proxy", name, prefix)
			}
		}
	}
}

func TestKnownProxyPeerReadsBareAddresses(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24", "2001:db8:1::/48")
	SetASNLookup(nil)
	for addr, want := range map[string]bool{
		"198.51.100.7":        true,
		"::ffff:198.51.100.7": true,
		"2001:db8:1::5":       true,
		"203.0.113.9":         false,
		"198.51.100.7:443":    false,
		"2001:db8:1::5%eth0":  false,
		"proxy.example":       false,
		"":                    false,
	} {
		if got := KnownProxyPeer(addr, nil); got != want {
			t.Errorf("KnownProxyPeer(%q) = %v, want %v", addr, got, want)
		}
	}
}

// A network in thresholds.http_asn_crawl_reverse_proxy_asns is a known proxy
// when the ASN database can name it; without the database, only the built-in
// ranges count.
func TestKnownProxyPeerReadsTheReverseProxyASNs(t *testing.T) {
	withKnownProxyPrefixes(t)
	SetASNLookup(func(ip string) (uint, string) {
		if ip == "203.0.113.9" {
			return 64512, "Edge"
		}
		return 64513, "Other"
	})
	cfg := &config.Config{}
	cfg.Thresholds.HTTPASNCrawlReverseProxyASNs = []uint{64512}
	if !KnownProxyPeer("203.0.113.9", cfg) {
		t.Fatal("an address in a reverse-proxy ASN is not a known proxy")
	}
	if KnownProxyPeer("198.51.100.7", cfg) {
		t.Fatal("an address outside the reverse-proxy ASNs is a known proxy")
	}
	if KnownProxyPeer("203.0.113.9", &config.Config{}) || KnownProxyPeer("203.0.113.9", nil) {
		t.Fatal("an empty or absent ASN list names a known proxy")
	}
	SetASNLookup(nil)
	if KnownProxyPeer("203.0.113.9", cfg) {
		t.Fatal("without the ASN database an ASN-only address is a known proxy")
	}
}

func TestKnownProxyPeerPinsProviderRoles(t *testing.T) {
	prev := CurrentASNLookup()
	SetASNLookup(nil)
	t.Cleanup(func() { SetASNLookup(prev) })
	wantEdges := []string{"Cloudflare (IPv4)", "Cloudflare (IPv6)", "QUIC.cloud", "Sucuri firewall"}
	if !slices.Equal(knownProxyProviders, wantEdges) {
		t.Fatalf("selected providers = %v, want %v", knownProxyProviders, wantEdges)
	}
	roles := map[string]bool{
		"Cloudflare (IPv4)": true,
		"Cloudflare (IPv6)": true,
		"QUIC.cloud":        true,
		"Sucuri firewall":   true,
		"Stripe webhooks":   false,
		"PayPal (server endpoints, live and sandbox)": false,
		"Braintree webhooks (production outbound)":    false,
		"PayU Europe notifications (production)":      false,
		"Revolut Merchant webhooks (production)":      false,
		"Mollie":                                      false,
	}
	seen := map[string]bool{}
	for _, p := range emailspool.BuiltInProxyProviders() {
		want, ok := roles[p.Name]
		if !ok || seen[p.Name] || len(p.Prefixes) == 0 {
			t.Fatalf("unreviewed, duplicate or empty provider %q", p.Name)
		}
		seen[p.Name] = true
		for _, prefix := range p.Prefixes {
			if got := KnownProxyPeer(prefix.Addr().String(), nil); got != want {
				t.Errorf("provider %q range %v: proxy = %v, want %v", p.Name, prefix, got, want)
			}
		}
	}
	for name := range roles {
		if !seen[name] {
			t.Errorf("reviewed provider %q is missing or renamed", name)
		}
	}
}

func TestKnownProxyPeerRejectsDecoratedASNAddresses(t *testing.T) {
	for _, raw := range []string{
		"198.51.100.7", "::ffff:198.51.100.7", "2001:db8:1::5",
		" 198.51.100.7 ", "2001:db8:1::5%eth0", "::ffff:198.51.100.7%eth0",
		"198.51.100.7:443", "[2001:db8:1::5]", "[2001:db8:1::5]:443",
		"198.51.100.7, 203.0.113.9", "proxy.example", "",
	} {
		t.Run(raw, func(t *testing.T) { checkKnownProxyAddressBoundary(t, raw) })
	}
}

func checkKnownProxyAddressBoundary(t *testing.T, raw string) {
	t.Helper()
	withKnownProxyPrefixes(t)
	calls := 0
	SetASNLookup(func(string) (uint, string) {
		calls++
		return 64512, "Edge"
	})
	cfg := &config.Config{}
	cfg.Thresholds.HTTPASNCrawlReverseProxyASNs = []uint{64512}
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	want := err == nil && a.Zone() == ""
	if got := KnownProxyPeer(raw, cfg); got != want {
		t.Fatalf("KnownProxyPeer(%q) = %v, want %v", raw, got, want)
	}
	if !want && calls != 0 {
		t.Fatalf("decorated or invalid address reached ASN lookup %d times", calls)
	}
}
