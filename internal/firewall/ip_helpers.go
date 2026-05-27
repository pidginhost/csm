package firewall

import (
	"net"
	"os"
)

// nextIP returns the IP address immediately following the given IP,
// used for nftables interval-set end markers. When ip is the all-ones
// address for its family (255.255.255.255 or ffff:...:ffff) the
// successor wraps to all-zeros, which would silently widen an
// interval set to the entire address space. nextIP clamps in that
// case so the end marker equals the input; the resulting [start,
// start) range is empty, which is the safe failure mode (rule
// matches nothing instead of everything).
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	if isAllZeroIP(next) && !isAllZeroIP(ip) {
		copy(next, ip)
	}
	return next
}

// nextIPSafe is nextIP plus an explicit ok flag so callers that want
// to *skip* emitting an IntervalEnd marker on saturation (rather than
// emit an empty range) can do so.
func nextIPSafe(ip net.IP) (net.IP, bool) {
	if len(ip) == 0 {
		return nil, false
	}
	allOnes := true
	for _, b := range ip {
		if b != 0xff {
			allOnes = false
			break
		}
	}
	if allOnes {
		clamp := make(net.IP, len(ip))
		copy(clamp, ip)
		return clamp, false
	}
	return nextIP(ip), true
}

func isAllZeroIP(ip net.IP) bool {
	for _, b := range ip {
		if b != 0 {
			return false
		}
	}
	return len(ip) > 0
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
