package emailspool

import (
	"net/netip"
	"strings"
)

// ProxyProvider is one block of the built-in shared-caller list, named by its
// "# Provider:" heading.
type ProxyProvider struct {
	Name     string
	Prefixes []netip.Prefix
}

// BuiltInProxyProviders returns the built-in http_proxy_ranges.yaml blocks
// in file order, so a caller can select providers by name. A bare address
// is a single-address range. An operator's replacement file is not read:
// it carries no provider headings the loader could trust.
func BuiltInProxyProviders() []ProxyProvider {
	return builtInProxyProviders
}

var builtInProxyProviders = mustProxyProviders(defaultProxyRanges)

func mustProxyProviders(data []byte) []ProxyProvider {
	var out []ProxyProvider
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(l, "# Provider:"); ok {
			out = append(out, ProxyProvider{Name: strings.TrimSpace(name)})
			continue
		}
		entry, ok := strings.CutPrefix(l, "- ")
		if !ok {
			continue
		}
		if len(out) == 0 {
			panic("embedded http_proxy_ranges.yaml: range before any provider heading")
		}
		prefix, err := parseProviderEntry(strings.Trim(strings.TrimSpace(entry), `"'`))
		if err != nil {
			panic("embedded http_proxy_ranges.yaml: " + err.Error())
		}
		out[len(out)-1].Prefixes = append(out[len(out)-1].Prefixes, prefix)
	}
	return out
}

func parseProviderEntry(s string) (netip.Prefix, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}
