package checks

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailspool"
)

// knownProxyProviders names the built-in blocks of CDN and website-firewall
// edges. The same list's payment webhook senders are callers, not proxies.
var knownProxyProviders = []string{"Cloudflare (IPv4)", "Cloudflare (IPv6)", "QUIC.cloud", "Sucuri firewall"}

// knownProxyPrefixes is the edge ranges of knownProxyProviders, read once.
var knownProxyPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range emailspool.BuiltInProxyProviders() {
		if slices.Contains(knownProxyProviders, p.Name) {
			out = append(out, p.Prefixes...)
		}
	}
	return out
}()

// KnownProxyPeer reports whether addr, a bare address, is a known CDN or
// website-firewall edge: inside a built-in edge range, or, when the ASN
// database names it, in a network cfg lists under
// thresholds.http_asn_crawl_reverse_proxy_asns. Such an address carries many
// visitors, so it is never the attacker an HTTP, cPanel or reputation finding
// names, whether or not cloudflare.enabled is set.
func KnownProxyPeer(addr string, cfg *config.Config) bool {
	// ASN readers use address bytes and can discard a zone.
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil || a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	for _, p := range knownProxyPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	lookup := CurrentASNLookup()
	if lookup == nil || cfg == nil {
		return false
	}
	asn, _ := lookup(a.String())
	return asn != 0 && slices.Contains(cfg.Thresholds.HTTPASNCrawlReverseProxyASNs, asn)
}
