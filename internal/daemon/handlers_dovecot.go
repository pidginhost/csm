package daemon

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/store"
)

const (
	geoHistoryMaxAge  = 30 * 24 * 60 * 60 // 30 days in seconds
	geoMinLoginCount  = 5                 // minimum logins before alerting on new country
	geoAlertCooldownH = 24                // hours between alerts per account
)

// parseDovecotLogLine handles Dovecot login lines from /var/log/maillog.
// It tracks per-mailbox login countries and alerts on new-country logins.
func parseDovecotLogLine(line string, cfg *config.Config) []alert.Finding {
	// Only process successful login lines
	if !strings.Contains(line, "Login: user=<") {
		return nil
	}
	if !strings.Contains(line, "dovecot:") {
		return nil
	}

	user, ip := parseDovecotLoginFields(line)
	if user == "" || ip == "" {
		return nil
	}

	// Skip private/loopback IPs
	if isPrivateOrLoopback(ip) {
		return nil
	}

	// Skip infra IPs
	if isInfraIPDaemon(ip, cfg.InfraIPs) {
		return nil
	}

	// GeoIP lookup
	db := getGeoIPDB()
	if db == nil {
		return nil
	}
	info := db.Lookup(ip)
	country := info.Country
	if country == "" {
		return nil
	}

	// Skip trusted countries
	for _, tc := range cfg.Suppressions.TrustedCountries {
		if strings.EqualFold(country, tc) {
			return nil
		}
	}

	// Load history from bbolt
	boltDB := store.Global()
	if boltDB == nil {
		return nil
	}

	now := time.Now().Unix()

	history, _ := boltDB.GetGeoHistory(user)
	if history.Countries == nil {
		history.Countries = make(map[string]int64)
	}

	// Prune old country entries
	history.Countries = pruneOldCountries(history.Countries, now, geoHistoryMaxAge)

	// Increment login count
	history.LoginCount++

	// Check if this is a new country
	_, countryKnown := history.Countries[country]
	isNewCountry := !countryKnown && history.LoginCount >= geoMinLoginCount

	// Update country timestamp
	history.Countries[country] = now

	// Persist updated history
	if err := boltDB.SetGeoHistory(user, history); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: failed to save geo history for %s: %v\n",
			time.Now().Format("2006-01-02 15:04:05"), user, err)
	}

	if !isNewCountry {
		return nil
	}

	// Rate limit: max 1 alert per account per 24h
	alertKey := "email:geo_alert:" + user
	lastAlertStr := boltDB.GetMetaString(alertKey)
	if lastAlertStr != "" {
		if lastAlert, err := time.Parse(time.RFC3339, lastAlertStr); err == nil {
			if time.Since(lastAlert) < time.Duration(geoAlertCooldownH)*time.Hour {
				return nil
			}
		}
	}

	// Record alert time
	_ = boltDB.SetMetaString(alertKey, time.Now().Format(time.RFC3339))

	// Build "previously seen" country list
	var knownCountries []string
	for c := range history.Countries {
		if c != country {
			knownCountries = append(knownCountries, c)
		}
	}
	previousList := "none"
	if len(knownCountries) > 0 {
		previousList = strings.Join(knownCountries, ", ")
	}

	countryName := info.CountryName
	if countryName == "" {
		countryName = country
	}

	return []alert.Finding{{
		Severity: alert.High,
		Check:    "email_suspicious_geo",
		Message: fmt.Sprintf("Suspicious email login for %s from %s (%s) — previously seen: %s",
			user, countryName, ip, previousList),
		Details: fmt.Sprintf("Country: %s (%s)\nIP: %s\nLogin count: %d\nPreviously seen countries: %s",
			country, countryName, ip, history.LoginCount, previousList),
	}}
}

// parseDovecotLoginFields extracts user and remote IP from a Dovecot login line.
// Expected format: "... Login: user=<user@domain>, ... rip=1.2.3.4, ..."
func parseDovecotLoginFields(line string) (user, ip string) {
	// Extract user from user=<...>
	userIdx := strings.Index(line, "user=<")
	if userIdx < 0 {
		return "", ""
	}
	rest := line[userIdx+6:]
	endIdx := strings.IndexByte(rest, '>')
	if endIdx < 0 {
		return "", ""
	}
	user = rest[:endIdx]

	// Extract remote IP from rip=...
	ripIdx := strings.Index(line, "rip=")
	if ripIdx < 0 {
		return "", ""
	}
	rest = line[ripIdx+4:]
	endIdx = strings.IndexAny(rest, ", \t\n")
	if endIdx < 0 {
		ip = rest
	} else {
		ip = rest[:endIdx]
	}

	if user == "" || ip == "" {
		return "", ""
	}
	return user, ip
}

// isPrivateOrLoopback returns true if the IP is loopback or RFC1918 private.
func isPrivateOrLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // invalid = skip
	}

	if ip.IsLoopback() {
		return true
	}

	// RFC1918 checks
	private10 := net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}
	private172 := net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)}
	private192 := net.IPNet{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)}

	return private10.Contains(ip) || private172.Contains(ip) || private192.Contains(ip)
}

// pruneOldCountries removes country entries older than maxAge seconds.
func pruneOldCountries(countries map[string]int64, now, maxAge int64) map[string]int64 {
	pruned := make(map[string]int64, len(countries))
	cutoff := now - maxAge
	for c, ts := range countries {
		if ts >= cutoff {
			pruned[c] = ts
		}
	}
	return pruned
}
