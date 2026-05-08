package checks

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// safeRemotePorts and safeUsers are package-level so both legacy polling and
// the BPF live coordinator share one source of truth.
var safeRemotePorts = map[uint16]bool{
	53: true, 80: true, 443: true, 25: true, 587: true, 465: true,
	993: true, 995: true, 110: true, 143: true,
}

var safeUsers = map[string]bool{
	"imunify360-webshield": true,
	"named":                true,
	"mysql":                true,
	"memcached":            true,
	"icinga":               true,
	"dovecot":              true,
	"mailman":              true,
}

var serverLocalPorts = map[uint16]bool{
	21: true, 25: true, 26: true, 53: true, 80: true, 110: true,
	143: true, 443: true, 465: true, 587: true, 993: true, 995: true,
	2082: true, 2083: true, 2086: true, 2087: true, 2095: true, 2096: true,
	3306: true, 4190: true,
	52223: true, 52224: true, 52227: true, 52228: true,
	52229: true, 52230: true, 52231: true, 52232: true,
}

// EvaluateConnection returns a populated alert.Finding and true when the
// connection should be reported, or a zero finding and false when it should
// be ignored. Pure function: no IO, no clock. Used by the BPF live backend
// (per-event) and the polling backend (per row of /proc/net/tcp[6]).
func EvaluateConnection(
	cfg *config.Config,
	uid uint32,
	dstIP net.IP,
	dstPort uint16,
	localPort uint16,
	proto string,
	user string,
) (alert.Finding, bool) {
	if uid == 0 {
		return alert.Finding{}, false
	}
	if dstIP == nil || dstIP.IsLoopback() || dstIP.IsUnspecified() {
		return alert.Finding{}, false
	}
	if serverLocalPorts[localPort] {
		return alert.Finding{}, false
	}
	if safeRemotePorts[dstPort] {
		return alert.Finding{}, false
	}
	if isInfraIP(dstIP.String(), cfg.InfraIPs) {
		return alert.Finding{}, false
	}
	if safeUsers[user] {
		return alert.Finding{}, false
	}

	dst := dstIP.String()
	if dstIP.To4() == nil {
		dst = "[" + dst + "]"
	}
	return alert.Finding{
		Severity: alert.High,
		Check:    "user_outbound_connection",
		Message:  fmt.Sprintf("Non-root user connecting to unusual destination: %s:%d", dst, dstPort),
		Details:  fmt.Sprintf("UID: %d (%s), Local port: %d, Proto: %s", uid, user, localPort, proto),
	}, true
}

// CheckOutboundUserConnections looks for non-root user processes making
// outbound connections to IPs that aren't infra or well-known services.
// Catches compromised accounts phoning home.
func CheckOutboundUserConnections(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	if data, err := osFS.ReadFile("/proc/net/tcp"); err == nil {
		findings = append(findings, scanProcNetTCP(cfg, data, false)...)
	} else {
		// Preserve historical behaviour: if /proc/net/tcp is unreadable,
		// return nil rather than continuing to tcp6.
		return nil
	}

	if tcp6Data, err := osFS.ReadFile("/proc/net/tcp6"); err == nil {
		findings = append(findings, scanProcNetTCP(cfg, tcp6Data, true)...)
	}

	return findings
}

// scanProcNetTCP parses one /proc/net/tcp[6] dump and returns findings for
// every ESTABLISHED row that EvaluateConnection flags.
//
// A first pass collects local sockets in LISTEN state so that an ESTABLISHED
// row whose local address and port have a listener is recognised as the
// accept side of an inbound connection (e.g. pure-ftpd PASV data channels,
// user-owned daemons listening on high ports) and not an outbound connect().
// Wildcard listeners match every local address for that port.
func scanProcNetTCP(cfg *config.Config, data []byte, ipv6 bool) []alert.Finding {
	var findings []alert.Finding
	proto := "tcp"
	if ipv6 {
		proto = "tcp6"
	}

	lines := strings.Split(string(data), "\n")
	listeners := collectListenSockets(lines, ipv6)

	// Resolve MTA identities once per scan; legacy poller has no per-PID context,
	// so the EvaluateDirectSMTPEgress UID/user gate carries the load.
	mta := platform.LocalMTAIdentities(platform.Detect())

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] == "sl" {
			continue
		}

		// State 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}

		uidStr := fields[7]
		uidU64, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil || uidU64 == 0 {
			continue
		}
		uidU32 := uint32(uidU64)

		var (
			localIP   net.IP
			dstIP     net.IP
			dstPort   int
			localPort int
		)
		if ipv6 {
			localIP, localPort = parseHex6Addr(fields[1])
			dstIP, dstPort = parseHex6Addr(fields[2])
		} else {
			localAddr, parsedLocalPort := parseHexAddr(fields[1])
			localIP = net.ParseIP(localAddr)
			localPort = parsedLocalPort
			remoteIP, remotePort := parseHexAddr(fields[2])
			dstIP = net.ParseIP(remoteIP)
			dstPort = remotePort
		}

		if listeners.has(localIP, localPort) {
			continue
		}

		user := LookupUser(uidU32)
		// #nosec G115 -- ports parsed from /proc/net/tcp[6] are bounded by uint16.
		if f, ok := EvaluateConnection(cfg, uidU32, dstIP, uint16(dstPort), uint16(localPort), proto, user); ok {
			f.Timestamp = time.Now()
			findings = append(findings, f)
		}
		// #nosec G115 -- ports parsed from /proc/net/tcp[6] are bounded by uint16.
		if f, ok := EvaluateDirectSMTPEgress(cfg, DirectSMTPEgressInput{
			UID:     uidU32,
			User:    user,
			DstIP:   dstIP,
			DstPort: uint16(dstPort),
			MTA:     mta,
		}); ok {
			f.Timestamp = time.Now()
			findings = append(findings, f)
		}
	}
	return findings
}

type listenSocket struct {
	address string
	port    int
}

type listenSocketSet struct {
	wildcardPorts map[int]bool
	sockets       map[listenSocket]bool
}

func (s listenSocketSet) has(ip net.IP, port int) bool {
	if port <= 0 {
		return false
	}
	if s.wildcardPorts[port] {
		return true
	}
	if ip == nil {
		return false
	}
	return s.sockets[listenSocket{address: normalizeListenIP(ip), port: port}]
}

// collectListenSockets scans /proc/net/tcp[6] rows for state 0A (LISTEN) and
// returns the set of local sockets a process is bound to.
func collectListenSockets(lines []string, ipv6 bool) listenSocketSet {
	listeners := listenSocketSet{
		wildcardPorts: make(map[int]bool),
		sockets:       make(map[listenSocket]bool),
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] == "sl" {
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		var (
			localIP   net.IP
			localPort int
		)
		if ipv6 {
			localIP, localPort = parseHex6Addr(fields[1])
		} else {
			localAddr, parsedLocalPort := parseHexAddr(fields[1])
			localIP = net.ParseIP(localAddr)
			localPort = parsedLocalPort
		}
		if localIP == nil || localPort <= 0 {
			continue
		}
		if localIP.IsUnspecified() {
			listeners.wildcardPorts[localPort] = true
			continue
		}
		listeners.sockets[listenSocket{address: normalizeListenIP(localIP), port: localPort}] = true
	}
	return listeners
}

func normalizeListenIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return net.IP(v4).String()
	}
	return ip.String()
}

// parseHex6Addr parses an IPv6 address:port from /proc/net/tcp6 format.
// IPv6 addresses are 32 hex chars (128 bits) in little-endian 4-byte groups.
func parseHex6Addr(s string) (net.IP, int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0
	}
	hexIP := parts[0]
	hexPort := parts[1]
	if len(hexIP) != 32 {
		return nil, 0
	}

	port, _ := strconv.ParseInt(hexPort, 16, 32)

	// Parse as 4 little-endian 32-bit words
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		word := hexIP[i*8 : (i+1)*8]
		b, _ := hex.DecodeString(word)
		if len(b) != 4 {
			return nil, 0
		}
		// Reverse bytes within each 32-bit word (little-endian to big-endian)
		ip[i*4+0] = b[3]
		ip[i*4+1] = b[2]
		ip[i*4+2] = b[1]
		ip[i*4+3] = b[0]
	}
	return ip, int(port)
}

// CheckSSHDConfig monitors sshd_config for dangerous changes.
func CheckSSHDConfig(ctx context.Context, _ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	hash, err := hashFileContent(sshdConfigPath)
	if err != nil {
		return nil
	}

	current := currentSSHDSettings()

	hashKey := "_sshd_config_hash"
	passKey := "_sshd_passwordauthentication"
	rootKey := "_sshd_permitrootlogin"

	prevHash, exists := store.GetRaw(hashKey)
	prevPass, _ := store.GetRaw(passKey)
	prevRoot, _ := store.GetRaw(rootKey)
	if exists && prevHash != hash {
		// Only alert when the effective setting changed into a dangerous value.
		// This avoids false positives from commented defaults or Match blocks.
		if current.PasswordAuthentication == "yes" && prevPass != "yes" {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "sshd_config_change",
				Message:  "PasswordAuthentication changed to 'yes' in sshd_config",
				Details:  "This allows password-based SSH login - high risk if passwords are compromised",
			})
		}
		if current.PermitRootLogin == "yes" && prevRoot != "yes" {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "sshd_config_change",
				Message:  "PermitRootLogin changed to 'yes' in sshd_config",
			})
		}

		// Generic change alert if no specific dangerous setting found
		if len(findings) == 0 {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "sshd_config_change",
				Message:  "sshd_config modified",
			})
		}
	}
	store.SetRaw(hashKey, hash)
	store.SetRaw(passKey, current.PasswordAuthentication)
	store.SetRaw(rootKey, current.PermitRootLogin)

	return findings
}

// CheckNulledPlugins scans WordPress plugin directories for signs of
// nulled/pirated plugins: missing licenses, known crack patterns, GPL
// bypass code, and plugins not found on wordpress.org.
func CheckNulledPlugins(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Known crack/null signatures in PHP files
	crackSignatures := []string{
		"nulled by", "cracked by", "gpl-club", "gpldl.com",
		"developer license", "remove license check",
		"license_key_bypass", "activation_bypass",
		"@remove_license", "null_license",
	}

	homeDirs, _ := osFS.ReadDir("/home")
	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		pluginsDir := filepath.Join("/home", homeEntry.Name(), "public_html", "wp-content", "plugins")
		plugins, err := osFS.ReadDir(pluginsDir)
		if err != nil {
			continue
		}

		for _, plugin := range plugins {
			if !plugin.IsDir() {
				continue
			}
			pluginDir := filepath.Join(pluginsDir, plugin.Name())

			// Check main plugin PHP file for crack signatures
			mainFiles, _ := osFS.Glob(filepath.Join(pluginDir, "*.php"))
			for _, mainFile := range mainFiles {
				// Only read the first 10KB of each file
				data := readFileHead(mainFile, 10*1024)
				if data == nil {
					continue
				}
				contentLower := strings.ToLower(string(data))

				for _, sig := range crackSignatures {
					if strings.Contains(contentLower, sig) {
						findings = append(findings, alert.Finding{
							Severity: alert.High,
							Check:    "nulled_plugin",
							Message:  fmt.Sprintf("Possible nulled plugin: %s/%s", homeEntry.Name(), plugin.Name()),
							Details:  fmt.Sprintf("File: %s\nSignature: %s", mainFile, sig),
						})
						break
					}
				}
			}
		}
	}

	return findings
}

// readFileHead reads the first N bytes of a file.
func readFileHead(path string, maxBytes int) []byte {
	f, err := osFS.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	if n == 0 {
		return nil
	}
	return buf[:n]
}
