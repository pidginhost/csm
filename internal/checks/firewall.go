package checks

import (
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

func CheckFirewall(cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	// CSF config integrity
	csfFiles := map[string]string{
		"/etc/csf/csf.conf":  "_csf_conf_hash",
		"/etc/csf/csf.allow": "_csf_allow_hash",
	}

	for file, key := range csfFiles {
		hash, err := hashFileContent(file)
		if err != nil {
			continue
		}
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "csf_integrity",
				Message:  fmt.Sprintf("CSF config modified: %s", file),
			})
		}
		store.SetRaw(key, hash)
	}

	// Check for suspicious ports in TCP_IN
	data, err := os.ReadFile("/etc/csf/csf.conf")
	if err != nil {
		return findings
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "TCP_IN") {
			continue
		}

		// Check for port 22 (should not be globally open)
		ports := extractPorts(line)
		for _, p := range ports {
			if p == "22" {
				findings = append(findings, alert.Finding{
					Severity: alert.Warning,
					Check:    "csf_ports",
					Message:  "Port 22 found in TCP_IN (SSH default port should not be globally open)",
				})
			}
			for _, bp := range cfg.BackdoorPorts {
				if p == fmt.Sprintf("%d", bp) {
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "csf_ports",
						Message:  fmt.Sprintf("Known backdoor port %s found in TCP_IN", p),
					})
				}
			}
		}
	}

	return findings
}

func extractPorts(line string) []string {
	// TCP_IN = "20,21,22,..."
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return nil
	}
	portStr := strings.Trim(strings.TrimSpace(parts[1]), "\"")
	return strings.Split(portStr, ",")
}
