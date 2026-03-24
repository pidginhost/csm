package checks

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

func CheckOutboundConnections(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Parse /proc/net/tcp for established connections
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip header
		if fields[0] == "sl" {
			continue
		}

		// State 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}

		remoteAddr := fields[2]
		ip, port := parseHexAddr(remoteAddr)
		if ip == "" {
			continue
		}

		// Skip localhost
		if ip == "127.0.0.1" || ip == "0.0.0.0" {
			continue
		}

		// Check against C2 blocklist
		for _, blocked := range cfg.C2Blocklist {
			if ip == blocked {
				// Get PID info from /proc/net/tcp uid field
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "c2_connection",
					Message:  fmt.Sprintf("Connection to known C2 IP: %s:%d", ip, port),
				})
			}
		}

		// Check for backdoor ports
		for _, bp := range cfg.BackdoorPorts {
			if port == bp {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "backdoor_port",
					Message:  fmt.Sprintf("Connection on known backdoor port: %s:%d", ip, port),
				})
			}
		}
	}

	return findings
}

func parseHexAddr(hexAddr string) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	hexIP := parts[0]
	hexPort := parts[1]

	if len(hexIP) != 8 {
		return "", 0
	}

	// Parse little-endian hex IP
	var octets [4]byte
	for i := 0; i < 4; i++ {
		val := hexToByte(hexIP[6-2*i : 8-2*i])
		octets[i] = val
	}
	ip := net.IPv4(octets[0], octets[1], octets[2], octets[3]).String()

	port := 0
	for _, c := range hexPort {
		port = port*16 + hexVal(byte(c))
	}

	return ip, port
}

func hexToByte(s string) byte {
	if len(s) != 2 {
		return 0
	}
	return byte(hexVal(s[0])<<4 | hexVal(s[1]))
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return 0
}
