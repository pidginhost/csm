package firewall

import (
	"net"
	"os"
)

// nextIP returns the IP address immediately following the given IP.
// Used for nftables interval set end markers.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
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
