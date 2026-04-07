package checks

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckOutboundUserConnections looks for non-root user processes making
// outbound connections to IPs that aren't infra or well-known services.
// Catches compromised accounts phoning home.
func CheckOutboundUserConnections(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Known service ports that are always OK for outbound
	safeRemotePorts := map[int]bool{
		53: true, 80: true, 443: true, 25: true, 587: true, 465: true,
		993: true, 995: true, 110: true, 143: true,
	}

	// Known safe service users - system daemons that make outbound connections
	safeUsers := map[string]bool{
		"imunify360-webshield": true,
		"named":                true,
		"mysql":                true,
		"memcached":            true,
		"icinga":               true,
		"dovecot":              true,
		"mailman":              true,
	}

	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] == "sl" {
			continue
		}

		// State 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}

		// Get UID (field 7)
		uid := fields[7]
		if uid == "0" {
			continue // skip root
		}

		// Parse local and remote addresses
		_, localPort := parseHexAddr(fields[1])
		remoteIP, remotePort := parseHexAddr(fields[2])

		if remoteIP == "127.0.0.1" || remoteIP == "0.0.0.0" {
			continue
		}

		// Skip if local port is a known service (we're the server)
		knownLocalPorts := map[int]bool{
			21: true, 25: true, 26: true, 53: true, 80: true, 110: true,
			143: true, 443: true, 465: true, 587: true, 993: true, 995: true,
			2082: true, 2083: true, 2086: true, 2087: true, 2095: true, 2096: true,
			3306: true, 4190: true,
			// Imunify360 webshield ports
			52223: true, 52224: true, 52227: true, 52228: true,
			52229: true, 52230: true, 52231: true, 52232: true,
		}
		if knownLocalPorts[localPort] {
			continue
		}

		// Skip safe remote ports
		if safeRemotePorts[remotePort] {
			continue
		}

		// Skip infra IPs
		if isInfraIP(remoteIP, cfg.InfraIPs) {
			continue
		}

		// Check if this is a known safe service user
		user := uidToUser(uid)
		if safeUsers[user] {
			continue
		}

		// This is a non-root user process connecting to a non-standard
		// port on a non-infra IP - suspicious
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "user_outbound_connection",
			Message:  fmt.Sprintf("Non-root user connecting to unusual destination: %s:%d", remoteIP, remotePort),
			Details:  fmt.Sprintf("UID: %s (%s), Local port: %d", uid, user, localPort),
		})
	}

	// Parse /proc/net/tcp6 for IPv6 connections
	tcp6Data, err := os.ReadFile("/proc/net/tcp6")
	if err == nil {
		for _, line := range strings.Split(string(tcp6Data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 8 || fields[0] == "sl" {
				continue
			}

			// State 01 = ESTABLISHED
			if fields[3] != "01" {
				continue
			}

			uid := fields[7]
			if uid == "0" {
				continue
			}

			_, localPort6 := parseHex6Addr(fields[1])
			remoteIP6, remotePort6 := parseHex6Addr(fields[2])

			if remoteIP6 == nil || remoteIP6.IsLoopback() || remoteIP6.IsUnspecified() {
				continue
			}

			// Skip if local port is a known service (we're the server)
			knownLocalPorts6 := map[int]bool{
				21: true, 25: true, 26: true, 53: true, 80: true, 110: true,
				143: true, 443: true, 465: true, 587: true, 993: true, 995: true,
				2082: true, 2083: true, 2086: true, 2087: true, 2095: true, 2096: true,
				3306: true, 4190: true,
				52223: true, 52224: true, 52227: true, 52228: true,
				52229: true, 52230: true, 52231: true, 52232: true,
			}
			if knownLocalPorts6[localPort6] {
				continue
			}

			if safeRemotePorts[remotePort6] {
				continue
			}

			remoteIPStr := remoteIP6.String()
			if isInfraIP(remoteIPStr, cfg.InfraIPs) {
				continue
			}

			user := uidToUser(uid)
			if safeUsers[user] {
				continue
			}

			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "user_outbound_connection",
				Message:  fmt.Sprintf("Non-root user connecting to unusual destination: [%s]:%d", remoteIPStr, remotePort6),
				Details:  fmt.Sprintf("UID: %s (%s), Local port: %d, Proto: tcp6", uid, user, localPort6),
			})
		}
	}

	return findings
}

// uidToUser tries to resolve a UID to username from /etc/passwd.
func uidToUser(uid string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return uid
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == uid {
			return fields[0]
		}
	}
	return uid
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
func CheckSSHDConfig(_ *config.Config, store *state.Store) []alert.Finding {
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
func CheckNulledPlugins(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Known crack/null signatures in PHP files
	crackSignatures := []string{
		"nulled by", "cracked by", "gpl-club", "gpldl.com",
		"developer license", "remove license check",
		"license_key_bypass", "activation_bypass",
		"@remove_license", "null_license",
	}

	homeDirs, _ := os.ReadDir("/home")
	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		pluginsDir := filepath.Join("/home", homeEntry.Name(), "public_html", "wp-content", "plugins")
		plugins, err := os.ReadDir(pluginsDir)
		if err != nil {
			continue
		}

		for _, plugin := range plugins {
			if !plugin.IsDir() {
				continue
			}
			pluginDir := filepath.Join(pluginsDir, plugin.Name())

			// Check main plugin PHP file for crack signatures
			mainFiles, _ := filepath.Glob(filepath.Join(pluginDir, "*.php"))
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
	f, err := os.Open(path)
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
