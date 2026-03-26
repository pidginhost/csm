package firewall

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MigrateFromCSF reads CSF configuration files and converts them
// to a CSM FirewallConfig + state (blocked/allowed IPs).
func MigrateFromCSF() (*FirewallConfig, *FirewallState, error) {
	cfg := DefaultConfig()
	state := &FirewallState{}

	// Parse csf.conf for ports and settings
	if err := parseCSFConf(cfg); err != nil {
		return nil, nil, fmt.Errorf("parsing csf.conf: %w", err)
	}

	// Parse csf.allow for allowed IPs
	allowed, err := parseCSFAllow()
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: warning parsing csf.allow: %v\n", err)
	}
	state.Allowed = allowed

	// Parse csf.deny for blocked IPs
	blocked, err := parseCSFDeny()
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: warning parsing csf.deny: %v\n", err)
	}
	state.Blocked = blocked

	// Parse csf.ignore for infra IPs
	ignoreIPs := parseCSFIgnore()
	for _, ip := range ignoreIPs {
		// Add to infra if not already there
		found := false
		for _, existing := range cfg.InfraIPs {
			if existing == ip {
				found = true
				break
			}
		}
		if !found {
			cfg.InfraIPs = append(cfg.InfraIPs, ip)
		}
	}

	cfg.Enabled = true

	return cfg, state, nil
}

func parseCSFConf(cfg *FirewallConfig) error {
	f, err := os.Open("/etc/csf/csf.conf")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), "\"")

		switch key {
		case "TCP_IN":
			cfg.TCPIn = parsePorts(val)
		case "TCP_OUT":
			cfg.TCPOut = parsePorts(val)
		case "UDP_IN":
			cfg.UDPIn = parsePorts(val)
		case "UDP_OUT":
			cfg.UDPOut = parsePorts(val)
		case "SYNFLOOD":
			cfg.SYNFloodProtection = val == "1"
		case "CONNLIMIT":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				cfg.ConnRateLimit = n
			}
		case "DROP_LOGGING":
			cfg.LogDropped = val == "1"
		}
	}

	return nil
}

func parsePorts(val string) []int {
	var ports []int
	for _, p := range strings.Split(val, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Handle port ranges like 49152:65534
		if strings.Contains(p, ":") {
			rangeParts := strings.SplitN(p, ":", 2)
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
				if start > 0 && end > start {
					// Don't expand large ranges — store as range
					ports = append(ports, start, end)
				}
			}
			continue
		}
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			ports = append(ports, n)
		}
	}
	return ports
}

func parseCSFAllow() ([]AllowedEntry, error) {
	f, err := os.Open("/etc/csf/csf.allow")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var entries []AllowedEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Include") {
			continue
		}

		// Format: ip # comment  OR  tcp|in|d=port|s=ip # comment
		reason := ""
		if idx := strings.Index(line, "#"); idx > 0 {
			reason = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}

		// Port-specific rules: tcp|in|d=2325|s=1.2.3.4
		if strings.Contains(line, "|") {
			parts := strings.Split(line, "|")
			var ip string
			var port int
			for _, p := range parts {
				if strings.HasPrefix(p, "s=") {
					ip = p[2:]
				}
				if strings.HasPrefix(p, "d=") {
					port, _ = strconv.Atoi(p[2:])
				}
			}
			if ip != "" {
				entries = append(entries, AllowedEntry{IP: ip, Reason: reason, Port: port})
			}
			continue
		}

		// Plain IP
		ip := strings.Fields(line)[0]
		entries = append(entries, AllowedEntry{IP: ip, Reason: reason})
	}

	return entries, nil
}

func parseCSFDeny() ([]BlockedEntry, error) {
	f, err := os.Open("/etc/csf/csf.deny")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var entries []BlockedEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		reason := ""
		if idx := strings.Index(line, "#"); idx > 0 {
			reason = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}

		ip := strings.Fields(line)[0]
		ip = strings.Split(ip, "/")[0] // strip CIDR

		entries = append(entries, BlockedEntry{
			IP:     ip,
			Reason: reason,
		})
	}

	return entries, nil
}

func parseCSFIgnore() []string {
	f, err := os.Open("/etc/csf/csf.ignore")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Include") {
			continue
		}
		ip := strings.Fields(line)[0]
		ips = append(ips, ip)
	}
	return ips
}

// FormatMigrationReport returns a human-readable summary of what would be migrated.
func FormatMigrationReport(cfg *FirewallConfig, state *FirewallState) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CSF → CSM Firewall Migration Report\n")
	fmt.Fprintf(&b, "====================================\n\n")
	fmt.Fprintf(&b, "TCP In ports:  %d ports\n", len(cfg.TCPIn))
	fmt.Fprintf(&b, "TCP Out ports: %d ports\n", len(cfg.TCPOut))
	fmt.Fprintf(&b, "UDP In ports:  %d ports\n", len(cfg.UDPIn))
	fmt.Fprintf(&b, "UDP Out ports: %d ports\n", len(cfg.UDPOut))
	fmt.Fprintf(&b, "Infra IPs:     %d entries\n", len(cfg.InfraIPs))
	fmt.Fprintf(&b, "Allowed IPs:   %d entries\n", len(state.Allowed))
	fmt.Fprintf(&b, "Blocked IPs:   %d entries\n", len(state.Blocked))
	fmt.Fprintf(&b, "SYN flood:     %v\n", cfg.SYNFloodProtection)
	fmt.Fprintf(&b, "Drop logging:  %v\n", cfg.LogDropped)
	return b.String()
}
