package daemon

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/store"
)

const (
	geoHistoryMaxAge  = 30 * 24 * 60 * 60 // 30 days in seconds
	geoMinLoginCount  = 5                 // minimum logins before alerting on new country
	geoAlertCooldownH = 24                // hours between alerts per account
)

// geoLookup resolves an IP through the daemon's GeoIP database, returning an
// empty Info when no database is loaded. A variable so tests can drive the geo
// detector without an mmdb file.
var geoLookup = func(ip string) geoip.Info {
	db := getGeoIPDB()
	if db == nil {
		return geoip.Info{}
	}
	return db.Lookup(ip)
}

// parseDovecotLogLine handles Dovecot login lines from /var/log/maillog.
// It tracks per-mailbox login countries and alerts on new-country logins.
func parseDovecotLogLine(line string, cfg *config.Config, trusted bool) []alert.Finding {
	// Only process successful login lines. dovecotLoginSucceeded accepts both
	// the classic "Login: user=<" and the production "Logged in: user=<"
	// formats so this detector is not silently dead on whichever one the host
	// emits.
	if !dovecotLoginSucceeded(line) {
		return nil
	}

	user, ip := parseDovecotLoginFields(line)
	if user == "" || ip == "" {
		return nil
	}
	return observeMailboxLoginGeo(cfg, user, ip, customerLoginTime(line, time.Now()), false, trusted)
}

// webmailLogin reads a webmail login from a session_log line. A session a
// reseller opened or the panel created through the API does not locate
// the mailbox owner.
func webmailLogin(line string) (user, ip string, at time.Time, ok bool) {
	r, ok := checks.ParseSessionRecord(line)
	if !ok || r.Service != "webmaild" || r.Event != "NEW" || r.CreatedByAPI() || r.Attr("possessed") == "1" {
		return "", "", time.Time{}, false
	}
	addr, ok := r.ClientAddr()
	if !ok {
		return "", "", time.Time{}, false
	}
	return r.Account, addr.String(), r.At, true
}

// observeMailboxLoginGeo records a mailbox login's country. A country new
// for the mailbox is compromise evidence and a summary-class
// email_suspicious_geo finding. A webmail login is also kept as the
// mailbox's last one, so the loopback sends webmail makes can be placed.
func observeMailboxLoginGeo(cfg *config.Config, user, ip string, at time.Time, webmail, record bool) []alert.Finding {
	db := store.Global()
	if db == nil {
		return nil
	}
	var info geoip.Info
	if !isPrivateOrLoopback(ip) && !isInfraIPDaemon(ip, cfg.InfraIPs) {
		info = geoLookup(ip)
	}
	country := info.Country
	if country == "" && !webmail {
		return nil
	}
	now := time.Now()
	if at.After(now) {
		at = now
	}
	if at.IsZero() {
		at, country = now, ""
	}
	trusted := countryTrusted(country, cfg.Suppressions.TrustedCountries)
	var novel bool
	apply := db.UpdateGeoLogin
	if !record {
		// A line any local user could have written gets the verdict the
		// history gives, but changes nothing and counts as no evidence.
		apply = func(account string, _ time.Time, _ time.Duration, update func(*store.GeoHistory) bool) (store.GeoLoginResult, error) {
			h, _ := db.GetGeoHistory(account)
			return store.GeoLoginResult{History: h, Notify: update(&h)}, nil
		}
	}
	result, err := apply(user, now, geoAlertCooldownH*time.Hour, func(h *store.GeoHistory) bool {
		if country != "" {
			h.Countries = pruneOldCountries(h.Countries, at.Unix(), geoHistoryMaxAge)
			seenAt, known := h.Countries[country]
			h.Countries[country] = max(seenAt, at.Unix())
			h.LoginCount++
			novel = !trusted && !known && h.LoginCount >= geoMinLoginCount
		}
		// A newer unlocated session invalidates the last webmail origin.
		if webmail && (h.Webmail == nil || !at.Before(h.Webmail.At)) {
			h.Webmail = &store.WebmailLogin{IP: ip, Country: country, At: at, New: novel}
		}
		return novel
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: failed to record geo login for %s: %v\n", ts(), user, err)
		return nil
	}
	if !novel {
		return nil
	}
	countryName := info.CountryName
	if countryName == "" {
		countryName = country
	}
	via := "email"
	if webmail {
		via = "webmail"
	}
	var findings []alert.Finding
	if record {
		findings = observeMailboxSignal(cfg, user, mailboxSignal{
			kind: signalNewCountry, key: country, at: at,
			detail: fmt.Sprintf("%s login from %s (%s)", via, countryName, ip),
		})
	}
	if !result.Notify {
		return findings
	}
	history := result.History

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

	mailbox, domain, _ := splitMailAccount(user)
	tenant := mailAccountOwner(user)
	return append(findings, alert.Finding{
		Severity: alert.High,
		Check:    "email_suspicious_geo",
		Message: fmt.Sprintf("Suspicious %s login for %s from %s (%s) - previously seen: %s",
			via, user, countryName, ip, previousList),
		Details: fmt.Sprintf("Country: %s (%s)\nIP: %s\nLogin count: %d\nPreviously seen countries: %s",
			country, countryName, ip, history.LoginCount, previousList),
		SourceIP:  ip,
		Mailbox:   mailbox,
		Domain:    domain,
		TenantID:  tenant,
		Timestamp: now,
	})
}

// parseDovecotLoginFields extracts user and remote IP from a Dovecot login line.
// Expected format: "... Login: user=<user@example.com>, ... rip=203.0.113.5, ..."
func parseDovecotLoginFields(line string) (user, ip string) {
	user, _ = checks.DovecotLoginFields(line)
	ip = checks.DovecotRemoteIP(line)
	if user == "" || ip == "" {
		return "", ""
	}
	return user, ip
}

// isPrivateOrLoopback returns true if the IP is loopback, RFC1918 private or
// an IPv6 unique local address.
func isPrivateOrLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // invalid = skip
	}
	return ip.IsLoopback() || ip.IsPrivate()
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
