//go:build linux

package firewall

import "net"

func countRuleEntries(state FirewallState, ipv6Enabled bool) RuleCounts {
	return RuleCounts{
		Blocked:     countBlockedRules(state.Blocked, ipv6Enabled),
		Allowed:     countAllowedRules(state.Allowed, ipv6Enabled),
		Subnets:     countSubnetRules(state.BlockedNet, ipv6Enabled),
		PortAllowed: countPortAllowRules(state.PortAllowed, ipv6Enabled),
	}
}

func countBlockedRules(entries []BlockedEntry, ipv6Enabled bool) int {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key, ok := ruleIPKey(entry.IP, ipv6Enabled)
		if !ok {
			continue
		}
		seen[key] = struct{}{}
	}
	return len(seen)
}

func countAllowedRules(entries []AllowedEntry, ipv6Enabled bool) int {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key, ok := ruleIPKey(entry.IP, ipv6Enabled)
		if !ok {
			continue
		}
		seen[key] = struct{}{}
	}
	return len(seen)
}

func countSubnetRules(entries []SubnetEntry, ipv6Enabled bool) int {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		_, network, err := net.ParseCIDR(entry.CIDR)
		if err != nil {
			continue
		}
		if network.IP.To4() == nil && !ipv6Enabled {
			continue
		}
		seen[network.String()] = struct{}{}
	}
	return len(seen)
}

func countPortAllowRules(entries []PortAllowEntry, ipv6Enabled bool) int {
	count := 0
	for _, entry := range entries {
		if _, ok := ruleIPKey(entry.IP, ipv6Enabled); !ok {
			continue
		}
		count++
	}
	return count
}

func ruleIPKey(raw string, ipv6Enabled bool) (string, bool) {
	parsed := net.ParseIP(raw)
	if parsed == nil {
		return "", false
	}
	if ip4 := parsed.To4(); ip4 != nil {
		return "4:" + net.IP(ip4).String(), true
	}
	if !ipv6Enabled {
		return "", false
	}
	ip16 := parsed.To16()
	if ip16 == nil {
		return "", false
	}
	return "6:" + net.IP(ip16).String(), true
}
