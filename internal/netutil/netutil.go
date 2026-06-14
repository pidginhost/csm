// Package netutil holds the shared public-range guard used to validate
// operator- and vendor-supplied IP ranges. It lives in its own package so the
// special-use CIDR list and the public-IP predicate have a single definition
// instead of being copy-pasted across internal/config and internal/threatintel.
package netutil

import (
	"net"
	"strings"
)

// nonPublicSpecialUseNets are address blocks that are routable-looking but must
// never be treated as public crawler space: an allowlist entry inside any of
// them would let an attacker claim addresses CSM should always scan.
var nonPublicSpecialUseNets = mustParseCIDRs(
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // carrier-grade NAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"240.0.0.0/4",     // reserved
	"100::/64",        // discard-only
	"2001:2::/48",     // benchmarking
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4
	"64:ff9b::/96",    // IPv4/IPv6 translation
	"64:ff9b:1::/48",  // IPv4/IPv6 translation
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// IPInAnyNet reports whether ip is contained in any of nets.
func IPInAnyNet(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPublicIP reports whether ip is a public, globally-routable unicast address:
// not private, link-local, multicast, or in any non-public special-use block
// (CGNAT, documentation, benchmarking, reserved, IPv6 special-use). A nil IP is
// never public.
func IsPublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() &&
		!IPInAnyNet(ip, nonPublicSpecialUseNets)
}

// ParseCIDROrIP parses a CIDR or a bare IP, returning the normalized network. A
// bare IPv4 becomes a /32 and a bare IPv6 a /128. Returns nil on garbage.
func ParseCIDROrIP(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if _, n, err := net.ParseCIDR(s); err == nil {
		return NormalizeIPNet(n)
	}
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}
	return nil
}

// NormalizeIPNet returns n with its IP masked to the network address and IPv4
// kept in 4-byte form. An IPv4-mapped IPv6 CIDR is reduced to its effective
// IPv4 prefix so Contains matches on the IPv4 form. Returns nil for a malformed
// mask/IP combination.
func NormalizeIPNet(n *net.IPNet) *net.IPNet {
	if n == nil {
		return nil
	}
	if v4 := n.IP.To4(); v4 != nil {
		mask := n.Mask
		if len(mask) == net.IPv6len {
			if _, bits := mask.Size(); bits != net.IPv6len*8 {
				return nil
			}
			// Go treats IPv4-mapped IPv6 CIDRs as IPv4 ranges for Contains.
			// Keep validation and matching on that same effective prefix.
			mask = net.IPMask(mask[12:])
		}
		if _, bits := mask.Size(); bits != net.IPv4len*8 {
			return nil
		}
		return &net.IPNet{IP: v4.Mask(mask), Mask: mask}
	}
	ip := n.IP.To16()
	if ip == nil {
		return nil
	}
	if _, bits := n.Mask.Size(); bits != net.IPv6len*8 {
		return nil
	}
	return &net.IPNet{IP: ip.Mask(n.Mask), Mask: n.Mask}
}
