//go:build linux

package firewall

import (
	"fmt"
	"net"
	"os"

	"github.com/google/nftables"
)

// UpdateCloudflareSet flushes and repopulates the Cloudflare nftables sets.
func (e *Engine) UpdateCloudflareSet(ipv4, ipv6 []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.setCFWhitelist == nil {
		return fmt.Errorf("cf_whitelist set not initialized")
	}

	// Flush existing entries
	e.conn.FlushSet(e.setCFWhitelist)
	e.conn.FlushSet(e.setCFWhitelist6)

	// Populate IPv4 CIDRs
	var elems4 []nftables.SetElement
	for _, cidr := range ipv4 {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		start := network.IP.To4()
		end := lastIPInRange(network)
		if start == nil || end == nil {
			continue
		}
		elems4 = append(elems4,
			nftables.SetElement{Key: start},
			nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
		)
	}
	if len(elems4) > 0 {
		if err := e.conn.SetAddElements(e.setCFWhitelist, elems4); err != nil {
			return fmt.Errorf("adding CF IPv4 elements: %w", err)
		}
	}

	// Populate IPv6 CIDRs
	var elems6 []nftables.SetElement
	for _, cidr := range ipv6 {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		start := network.IP.To16()
		end := lastIPInRange(network)
		if start == nil || end == nil {
			continue
		}
		elems6 = append(elems6,
			nftables.SetElement{Key: start},
			nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
		)
	}
	if len(elems6) > 0 {
		if err := e.conn.SetAddElements(e.setCFWhitelist6, elems6); err != nil {
			return fmt.Errorf("adding CF IPv6 elements: %w", err)
		}
	}

	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing CF whitelist: %w", err)
	}

	fmt.Fprintf(os.Stderr, "firewall: cloudflare whitelist updated: %d IPv4, %d IPv6 CIDRs\n",
		len(ipv4), len(ipv6))
	return nil
}

// CloudflareIPs returns the currently configured Cloudflare CIDRs from the cached state.
func (e *Engine) CloudflareIPs() (ipv4, ipv6 []string) {
	return LoadCFState(e.statePath)
}
