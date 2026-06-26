package firewall

import "net"

// EffectiveDOSExemptNets returns the union of operator ranges and (when enabled)
// provider ranges, split into IPv4 and IPv6 *net.IPNet slices. providerNets may
// be nil. Invalid operator entries are skipped (validation already rejected them
// at load; this is defense in depth).
func EffectiveDOSExemptNets(cfg *FirewallConfig, providerNets []*net.IPNet) (v4, v6 []*net.IPNet) {
	var all []*net.IPNet

	if cfg != nil {
		for _, s := range cfg.DOSExemptRanges {
			n := parseExemptNet(s)
			if n != nil {
				all = append(all, n)
			}
		}
	}

	// nil cfg treats ExemptKnownMailProviders as true (safe default).
	if cfg == nil || cfg.ExemptKnownMailProviders() {
		all = append(all, providerNets...)
	}

	// Split and copy. To4() returns non-nil for IPv4, including
	// IPv4-mapped-in-IPv6 addresses, so it correctly classifies both.
	// Copies ensure callers cannot mutate the returned slices back into
	// any shared state held by the caller or this package.
	for _, n := range all {
		if n == nil {
			continue
		}
		ip := make(net.IP, len(n.IP))
		copy(ip, n.IP)
		mask := make(net.IPMask, len(n.Mask))
		copy(mask, n.Mask)
		c := &net.IPNet{IP: ip, Mask: mask}
		if n.IP.To4() != nil {
			v4 = append(v4, c)
		} else {
			v6 = append(v6, c)
		}
	}
	return v4, v6
}

// parseExemptNet parses s as a CIDR or a bare IP (becomes /32 or /128).
// Returns nil for invalid input.
func parseExemptNet(s string) *net.IPNet {
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
}
