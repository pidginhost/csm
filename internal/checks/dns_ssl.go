package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// maxBulkDNSChanges is the threshold above which zone changes are considered
// a cPanel bulk operation (AutoSSL, serial bump, DNSSEC rotation) and suppressed.
// Only 1-5 zone changes at once are reported - likely targeted modifications.
const maxBulkDNSChanges = 5

// CheckDNSZoneChanges monitors named zone files for modifications.
// Suppresses bulk changes (>5 zones at once = cPanel maintenance).
// Only alerts on targeted changes (1-5 zones) which may indicate tampering.
func CheckDNSZoneChanges(_ *config.Config, store *state.Store) []alert.Finding {
	// cPanel stores zone files in /var/named/
	zoneDir := "/var/named"
	zones, err := os.ReadDir(zoneDir)
	if err != nil {
		return nil
	}

	// First pass: count how many zones changed
	var changedZones []string
	for _, zone := range zones {
		if zone.IsDir() {
			continue
		}
		name := zone.Name()
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
			changedZones = append(changedZones, name)
		}
	}

	// If many zones changed at once, it's cPanel maintenance - suppress
	if len(changedZones) > maxBulkDNSChanges {
		return nil
	}

	// Only alert on targeted changes (1-5 zones)
	var findings []alert.Finding
	for _, name := range changedZones {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "dns_zone_change",
			Message:  fmt.Sprintf("DNS zone file modified: %s", name),
			Details:  fmt.Sprintf("File: %s\nThis could indicate DNS hijacking or unauthorized domain changes", filepath.Join(zoneDir, name)),
		})
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
		// New AutoSSL activity - check the latest log
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
