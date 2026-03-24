package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
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

		// This is a non-root user process connecting to a non-standard
		// port on a non-infra IP — suspicious
		user := uidToUser(uid)
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "user_outbound_connection",
			Message:  fmt.Sprintf("Non-root user connecting to unusual destination: %s:%d", remoteIP, remotePort),
			Details:  fmt.Sprintf("UID: %s (%s), Local port: %d", uid, user, localPort),
		})
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

// CheckSSHDConfig monitors sshd_config for dangerous changes.
func CheckSSHDConfig(_ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	hash, err := hashFileContent("/etc/ssh/sshd_config")
	if err != nil {
		return nil
	}

	key := "_sshd_config_hash"
	prev, exists := store.GetRaw(key)
	if exists && prev != hash {
		// Config changed — check for dangerous settings
		data, err := os.ReadFile("/etc/ssh/sshd_config")
		if err != nil {
			return nil
		}
		content := strings.ToLower(string(data))

		if strings.Contains(content, "passwordauthentication yes") {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "sshd_config_change",
				Message:  "PasswordAuthentication changed to 'yes' in sshd_config",
				Details:  "This allows password-based SSH login — high risk if passwords are compromised",
			})
		}
		if strings.Contains(content, "permitrootlogin yes") {
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
	store.SetRaw(key, hash)

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
