package config

import (
	"net"
	"strings"

	"github.com/pidginhost/csm/internal/firewall"
)

// EffectiveFirewallConfig returns the copied configuration handed to the
// firewall engine. Keeping these derived values in one place prevents status
// surfaces from describing the persisted sections instead of the live policy.
func EffectiveFirewallConfig(cfg *Config) *firewall.FirewallConfig {
	if cfg == nil {
		return nil
	}

	effective := firewall.FirewallConfig{}
	if cfg.Firewall != nil {
		effective = *cfg.Firewall
	}
	effective.InfraIPs = firewall.MergeInfraIPs(cfg.InfraIPs, effective.InfraIPs)

	if !cfg.Challenge.Enabled || !cfg.Challenge.PortGate.Enabled ||
		cfg.Challenge.ListenPort <= 0 || challengeListenAddrIsLoopback(cfg.Challenge.ListenAddr) {
		return &effective
	}
	effective.TCPIn = appendUniquePort(effective.TCPIn, cfg.Challenge.ListenPort)
	effective.RestrictedTCP = removePort(effective.RestrictedTCP, cfg.Challenge.ListenPort)
	return &effective
}

func challengeListenAddrIsLoopback(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return true
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func appendUniquePort(ports []int, port int) []int {
	for _, existing := range ports {
		if existing == port {
			return ports
		}
	}
	out := append([]int(nil), ports...)
	return append(out, port)
}

func removePort(ports []int, port int) []int {
	out := make([]int, 0, len(ports))
	for _, existing := range ports {
		if existing != port {
			out = append(out, existing)
		}
	}
	return out
}
