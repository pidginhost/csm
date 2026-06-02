package firewall

import (
	"net"
	"os"
)

// subnetCovering returns the first CIDR in entries that contains ip, if any.
// Pure helper for BlockedSubnetCovering so the containment logic is testable
// without a kernel-attached engine.
func subnetCovering(entries []SubnetEntry, ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	for _, entry := range entries {
		_, network, err := net.ParseCIDR(entry.CIDR)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return entry.CIDR, true
		}
	}
	return "", false
}

// nextIP returns the IP address immediately following the given IP.
// When ip is the all-ones address for its family, nextIP clamps to ip
// instead of wrapping to all-zeros. Callers that construct nftables
// interval ranges should use nextIPSafe so saturated ends can be
// skipped rather than encoded as a wrapped interval.
func nextIP(ip net.IP) net.IP {
	next, _ := nextIPSafe(ip)
	return next
}

// nextIPSafe returns the successor of ip plus whether the successor
// exists in the same address family.
func nextIPSafe(ip net.IP) (net.IP, bool) {
	next := canonicalIPBytes(ip)
	if next == nil {
		return nil, false
	}

	for i := len(next) - 1; i >= 0; i-- {
		if next[i] != 0xff {
			next[i]++
			return next, true
		}
		next[i] = 0
	}

	return canonicalIPBytes(ip), false
}

func canonicalIPBytes(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		out := make(net.IP, net.IPv4len)
		copy(out, ip4)
		return out
	}
	if ip16 := ip.To16(); ip16 != nil {
		out := make(net.IP, net.IPv6len)
		copy(out, ip16)
		return out
	}
	return nil
}

// lastIPInRange returns the last IP address in a CIDR range.
func lastIPInRange(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	if ip == nil {
		ip = network.IP.To16()
	}
	if ip == nil {
		return nil
	}
	mask := network.Mask
	last := make(net.IP, len(ip))
	for i := range ip {
		if i < len(mask) {
			last[i] = ip[i] | ^mask[i]
		} else {
			last[i] = ip[i]
		}
	}
	return last
}

// fileExistsFirewall checks if a file exists.
func fileExistsFirewall(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
