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

// CheckDNSZoneChanges monitors named zone files for modifications.
// Zone file tampering can redirect traffic or enable phishing.
func CheckDNSZoneChanges(_ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	// cPanel stores zone files in /var/named/
	zoneDir := "/var/named"
	zones, err := os.ReadDir(zoneDir)
	if err != nil {
		return nil
	}

	for _, zone := range zones {
		if zone.IsDir() {
			continue
		}
		name := zone.Name()
		// Only check .db zone files
		if !strings.HasSuffix(name, ".db") {
			continue
		}

		fullPath := filepath.Join(zoneDir, name)
		hash, err := hashFileContent(fullPath)
		if err != nil {
			continue
		}

		key := "_dns_zone:" + name
		prev, exists := store.GetRaw(key)
		store.SetRaw(key, hash)

		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "dns_zone_change",
				Message:  fmt.Sprintf("DNS zone file modified: %s", name),
				Details:  fmt.Sprintf("File: %s\nThis could indicate DNS hijacking or unauthorized domain changes", fullPath),
			})
		}
	}

	return findings
}

// CheckSSLCertIssuance monitors AutoSSL logs for new certificate issuance.
// Attackers may issue certificates for phishing domains using compromised accounts.
func CheckSSLCertIssuance(_ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Check AutoSSL log
	logPath := "/var/cpanel/logs/autossl"
	entries, err := os.ReadDir(logPath)
	if err != nil {
		return nil
	}

	// Track the count of log files as a simple change indicator
	currentCount := len(entries)
	key := "_ssl_autossl_count"
	prev, exists := store.GetRaw(key)
	store.SetRaw(key, fmt.Sprintf("%d", currentCount))

	if !exists {
		return nil
	}

	prevCount := 0
	fmt.Sscanf(prev, "%d", &prevCount)

	if currentCount > prevCount {
		// New AutoSSL activity — check the latest log
		var latestLog string
		var latestTime int64
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Unix() > latestTime {
				latestTime = info.ModTime().Unix()
				latestLog = filepath.Join(logPath, entry.Name())
			}
		}

		if latestLog != "" {
			// Read the tail of the latest log for certificate issuance
			lines := tailFile(latestLog, 50)
			for _, line := range lines {
				lineLower := strings.ToLower(line)
				if strings.Contains(lineLower, "installed") || strings.Contains(lineLower, "issued") {
					findings = append(findings, alert.Finding{
						Severity: alert.Warning,
						Check:    "ssl_cert_issued",
						Message:  "New SSL certificate issued via AutoSSL",
						Details:  truncate(line, 300),
					})
				}
			}
		}
	}

	return findings
}
