package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckDNSConnections looks for established connections to port 53 on
// DNS servers that are NOT in /etc/resolv.conf. This catches DNS
// tunneling, GSocket relay discovery, and malware using hardcoded resolvers.
func CheckDNSConnections(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Parse configured resolvers
	resolvers := parseResolvers()
	if len(resolvers) == 0 {
		return nil
	}

	// Also allow infra IPs and localhost
	allowed := make(map[string]bool)
	allowed["127.0.0.1"] = true
	allowed["0.0.0.0"] = true
	for _, r := range resolvers {
		allowed[r] = true
	}

	// Parse /proc/net/tcp for connections to port 53
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "sl" {
			continue
		}

		// State 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}

		remoteIP, remotePort := parseHexAddr(fields[2])
		if remotePort != 53 {
			continue
		}

		if allowed[remoteIP] {
			continue
		}

		// Check if it's an infra IP
		if isInfraIP(remoteIP, cfg.InfraIPs) {
			continue
		}

		_, localPort := parseHexAddr(fields[1])
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "dns_connection",
			Message:  fmt.Sprintf("DNS connection to non-configured resolver: %s", remoteIP),
			Details:  fmt.Sprintf("Local port: %d, Remote: %s:53\nConfigured resolvers: %s", localPort, remoteIP, strings.Join(resolvers, ", ")),
		})
	}

	return findings
}

func parseResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var resolvers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver ") {
			ip := strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
			if ip != "" {
				resolvers = append(resolvers, ip)
			}
		}
	}
	return resolvers
}
