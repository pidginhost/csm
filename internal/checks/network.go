package checks

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func CheckOutboundConnections(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Parse /proc/net/tcp for established connections
	// Format: sl local_address rem_address st ...
	// local_address = IP:port we are listening/connecting from
	// rem_address = IP:port of the remote end
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		if fields[0] == "sl" {
			continue
		}

		// State 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}

		localAddr := fields[1]
		remoteAddr := fields[2]

		_, localPort := parseHexAddr(localAddr)
		remoteIP, remotePort := parseHexAddr(remoteAddr)

		if remoteIP == "" || remoteIP == "127.0.0.1" || remoteIP == "0.0.0.0" {
			continue
		}

		// Check remote IP against C2 blocklist
		for _, blocked := range cfg.C2Blocklist {
			if remoteIP == blocked {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "c2_connection",
					Message:  fmt.Sprintf("Connection to known C2 IP: %s:%d", remoteIP, remotePort),
					Details:  fmt.Sprintf("Local port: %d", localPort),
				})
			}
		}

		// Check if OUR LOCAL port is a backdoor port (we're listening on it)
		// This catches backdoor listeners, not clients connecting from high ports
		for _, bp := range cfg.BackdoorPorts {
			if localPort == bp {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "backdoor_port",
					Message:  fmt.Sprintf("Listening on known backdoor port %d, connected from %s:%d", localPort, remoteIP, remotePort),
				})
			}
		}

		// Also check if we're connecting OUT to a backdoor port on a remote host
		// (e.g. reverse shell calling back to attacker's listener)
		// Skip if our local port is a known service (the remote port is just
		// the client's ephemeral port, not a backdoor listener)
		knownServicePorts := map[int]bool{
			21: true, 25: true, 26: true, 53: true, 80: true, 110: true,
			143: true, 443: true, 465: true, 587: true, 993: true, 995: true,
			2082: true, 2083: true, 2086: true, 2087: true, 2095: true, 2096: true,
			3306: true, 4190: true,
		}
		if knownServicePorts[localPort] {
			continue
		}
		for _, bp := range cfg.BackdoorPorts {
			if remotePort == bp {
				if isInfraIP(remoteIP, cfg.InfraIPs) {
					continue
				}
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "backdoor_port_outbound",
					Message:  fmt.Sprintf("Outbound connection to backdoor port: %s:%d", remoteIP, remotePort),
					Details:  fmt.Sprintf("Local port: %d", localPort),
				})
			}
		}
	}

	return findings
}

func isInfraIP(ip string, infraNets []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range infraNets {
		// Try CIDR first (e.g. "10.0.0.0/8")
		_, network, err := net.ParseCIDR(entry)
		if err == nil {
			if network.Contains(parsed) {
				return true
			}
			continue
		}
		// Fall back to plain IP match (e.g. "1.2.3.4")
		if net.ParseIP(entry) != nil && entry == ip {
			return true
		}
	}
	// Also check Cloudflare IPs - these must never be blocked/challenged
	// because blocking a CF edge IP blocks thousands of legitimate users.
	// The detection/alert still fires; only the nftables action is skipped.
	if isCloudflareIP(parsed) {
		return true
	}
	return false
}

var (
	cfNets   []*net.IPNet
	cfNetsMu sync.RWMutex
)

// SetCloudflareNets updates the cached Cloudflare IP ranges.
// Called by the daemon after fetching CF IPs.
func SetCloudflareNets(cidrs []string) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, network)
		}
	}
	cfNetsMu.Lock()
	cfNets = nets
	cfNetsMu.Unlock()
}

func isCloudflareIP(ip net.IP) bool {
	cfNetsMu.RLock()
	defer cfNetsMu.RUnlock()
	for _, network := range cfNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
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
