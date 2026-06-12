package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckDNSZoneChanges monitors named zone files for tampering.
//
// A raw file-hash watch over /var/named is too coarse: every cPanel serial
// bump, AutoSSL DCV TXT record, DKIM rotation, and customer Zone Editor edit
// rewrites the file, so hashing the whole zone alerts on routine activity and
// buries real hijacks. This check instead compares only the security-relevant
// records and weighs the change against cPanel provenance:
//
//   - The "security fingerprint" covers delegation (NS), mail (MX), and apex/
//     wildcard address records -- the records an attacker rewrites to take over
//     a domain. Serial, TXT/DKIM/SPF/DCV, and ordinary subdomain A records are
//     ignored, so legitimate churn stays quiet.
//   - cPanel stamps each zone it writes with an "(update_time):" header. A
//     security change with no advance of that stamp means the file was edited
//     out of band (direct file write, or a non-cPanel path) -- the signature of
//     a hijack -- and is reported High. A security change that did go through
//     cPanel is trusted more: an NS/MX move still surfaces as a Warning (could
//     be a compromised account), while an apex/wildcard address repoint by the
//     authenticated owner is routine and stays quiet.
//
// There is deliberately no bulk-suppression gate: a mass out-of-band NS rewrite
// across every hosted domain is exactly the incident operators must see, and
// the per-record/provenance model already keeps benign mass operations quiet.
func CheckDNSZoneChanges(_ context.Context, _ *config.Config, store *state.Store) []alert.Finding {
	// cPanel stores zone files in /var/named/
	zoneDir := "/var/named"
	zones, err := osFS.ReadDir(zoneDir)
	if err != nil {
		return nil
	}

	var findings []alert.Finding
	for _, zone := range zones {
		if zone.IsDir() {
			continue
		}
		name := zone.Name()
		if !strings.HasSuffix(name, ".db") {
			continue
		}

		fullPath := filepath.Join(zoneDir, name)
		data, err := osFS.ReadFile(fullPath)
		if err != nil {
			continue
		}

		secHash, delegHash := parseZoneSecurity(data, zoneOrigin(name))
		cur := dnsZoneState{
			File:  hashBytes(data),
			Sec:   secHash,
			Deleg: delegHash,
			Prov:  zoneUpdateTime(data),
		}

		key := "_dns_zone:" + name
		rawPrev, exists := store.GetRaw(key)
		store.SetRaw(key, cur.encode())

		if !exists {
			continue // first sight: baseline only
		}
		prev, ok := decodeDNSZoneState(rawPrev)
		if !ok {
			continue // legacy bare-hash state: re-baseline silently, no alert
		}
		if prev.File == cur.File {
			continue // file unchanged
		}
		if prev.Sec == cur.Sec {
			continue // only non-security content changed (serial, TXT, subdomain A)
		}

		// A security-relevant record changed. Weigh it against cPanel provenance.
		if cur.Prov <= prev.Prov {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "dns_zone_change",
				Message:  fmt.Sprintf("DNS records changed outside cPanel: %s", name),
				Details:  fmt.Sprintf("File: %s\nDelegation, mail, or apex address records changed with no matching cPanel zone edit. A direct edit to a zone file that bypasses cPanel is the signature of DNS hijacking.", fullPath),
			})
			continue
		}
		if prev.Deleg == cur.Deleg {
			continue // cPanel-applied apex/wildcard address repoint: routine owner action
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "dns_zone_change",
			Message:  fmt.Sprintf("DNS delegation or mail records changed: %s", name),
			Details:  fmt.Sprintf("File: %s\nNS or MX records were changed through cPanel. Confirm this was an authorized account action and not a compromised login redirecting the domain or its mail.", fullPath),
		})
	}

	return findings
}

// dnsZoneState is the per-zone watch state persisted under "_dns_zone:<name>".
// File is the whole-file hash (cheap "did anything change" gate); Sec is the
// hash of the security-relevant record set (NS, MX, apex/wildcard A/AAAA);
// Deleg is the hash of the delegation/mail subset (NS, MX); Prov is the cPanel
// "(update_time):" stamp, 0 when the zone carries no cPanel header.
type dnsZoneState struct {
	File  string `json:"f"`
	Sec   string `json:"s"`
	Deleg string `json:"d"`
	Prov  int64  `json:"p"`
}

func (z dnsZoneState) encode() string {
	b, _ := json.Marshal(z)
	return string(b)
}

// decodeDNSZoneState parses persisted state. It returns ok=false for the legacy
// bare-hash format (a 64-char hex string written by earlier versions) so the
// caller re-baselines instead of treating the upgrade as a zone change.
func decodeDNSZoneState(s string) (dnsZoneState, bool) {
	if !strings.HasPrefix(s, "{") {
		return dnsZoneState{}, false
	}
	var z dnsZoneState
	if err := json.Unmarshal([]byte(s), &z); err != nil || z.File == "" {
		return dnsZoneState{}, false
	}
	return z, true
}

// zoneOrigin derives the zone apex (FQDN, trailing dot) from a zone file name,
// e.g. "example.com.db" -> "example.com.".
func zoneOrigin(filename string) string {
	return ensureTrailingDot(strings.TrimSuffix(filename, ".db"))
}

// zoneUpdateTime extracts the epoch from cPanel's "(update_time):<n>" zone
// header. Returns 0 when absent (manually managed or non-cPanel zone).
func zoneUpdateTime(data []byte) int64 {
	const marker = "(update_time):"
	s := string(data)
	i := strings.Index(s, marker)
	if i < 0 {
		return 0
	}
	rest := s[i+len(marker):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(rest[:j], 10, 64)
	return n
}

// parseZoneSecurity parses a BIND zone file and returns two hashes: the
// security fingerprint (NS, MX, apex/wildcard A and AAAA) and the delegation
// subset (NS, MX only). Records are canonicalized and sorted so reordering or
// whitespace changes do not register as a difference. SOA, ordinary subdomain
// addresses, and all TXT/DKIM/SPF/DCV records are excluded by design.
func parseZoneSecurity(data []byte, origin string) (secHash, delegHash string) {
	var secRecs, delegRecs []string

	lastOwner := ""
	curOrigin := origin
	parenDepth := 0

	for _, raw := range strings.Split(string(data), "\n") {
		if parenDepth > 0 {
			// Inside a multi-line record (typically SOA); just track depth.
			l := stripZoneComment(raw)
			parenDepth += strings.Count(l, "(") - strings.Count(l, ")")
			if parenDepth < 0 {
				parenDepth = 0
			}
			continue
		}

		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "$") {
			f := strings.Fields(trimmed)
			if len(f) >= 2 && strings.EqualFold(f[0], "$ORIGIN") {
				curOrigin = ensureTrailingDot(f[1])
			}
			continue
		}

		line := stripZoneComment(raw)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// A leading blank means "same owner as the previous record".
		owner := lastOwner
		rest := fields
		if r := []rune(raw); len(r) > 0 && r[0] != ' ' && r[0] != '\t' {
			owner = fields[0]
			rest = fields[1:]
		}
		lastOwner = owner

		typ, rdata := zoneRecordType(rest)

		// Account for parentheses opened on this line (inline SOA, etc.).
		parenDepth += strings.Count(line, "(") - strings.Count(line, ")")
		if parenDepth < 0 {
			parenDepth = 0
		}
		if typ == "" {
			continue
		}

		fqdn := toFQDN(owner, curOrigin)
		switch typ {
		case "NS":
			if len(rdata) >= 1 {
				rec := "NS " + fqdn + " " + strings.ToLower(toFQDN(rdata[0], curOrigin))
				delegRecs = append(delegRecs, rec)
				secRecs = append(secRecs, rec)
			}
		case "MX":
			if len(rdata) >= 2 {
				rec := "MX " + fqdn + " " + rdata[0] + " " + strings.ToLower(toFQDN(rdata[1], curOrigin))
				delegRecs = append(delegRecs, rec)
				secRecs = append(secRecs, rec)
			}
		case "A", "AAAA":
			if len(rdata) >= 1 && isApexOrWildcard(owner, fqdn, curOrigin) {
				rec := typ + " " + fqdn + " " + strings.ToLower(rdata[0])
				secRecs = append(secRecs, rec)
			}
		}
	}

	return hashSortedRecords(secRecs), hashSortedRecords(delegRecs)
}

// zoneRecordType skips leading TTL and class tokens and returns the record type
// (upper-cased) plus its rdata tokens. Returns "" when no type is present.
func zoneRecordType(tokens []string) (string, []string) {
	i := 0
	for i < len(tokens) && (isZoneTTL(tokens[i]) || isZoneClass(tokens[i])) {
		i++
	}
	if i >= len(tokens) {
		return "", nil
	}
	return strings.ToUpper(tokens[i]), tokens[i+1:]
}

func isZoneClass(t string) bool {
	switch strings.ToUpper(t) {
	case "IN", "CH", "HS", "CS":
		return true
	}
	return false
}

// isZoneTTL reports whether a token is a BIND TTL: pure digits, optionally with
// a single time-unit suffix (s/m/h/d/w).
func isZoneTTL(t string) bool {
	if t == "" {
		return false
	}
	end := len(t)
	switch t[end-1] {
	case 's', 'S', 'm', 'M', 'h', 'H', 'd', 'D', 'w', 'W':
		end--
	}
	if end == 0 {
		return false
	}
	for i := 0; i < end; i++ {
		if t[i] < '0' || t[i] > '9' {
			return false
		}
	}
	return true
}

func isApexOrWildcard(owner, fqdn, origin string) bool {
	return owner == "@" || owner == "*" || strings.HasPrefix(owner, "*.") ||
		fqdn == origin || strings.HasPrefix(fqdn, "*.")
}

func toFQDN(name, origin string) string {
	if name == "" || name == "@" {
		return origin
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "." + origin
}

func ensureTrailingDot(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

func stripZoneComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

func hashSortedRecords(recs []string) string {
	sort.Strings(recs)
	return hashBytes([]byte(strings.Join(recs, "\n")))
}

// CheckSSLCertIssuance monitors AutoSSL logs for new certificate issuance.
// Attackers may issue certificates for phishing domains using compromised accounts.
func CheckSSLCertIssuance(ctx context.Context, _ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Check AutoSSL log
	logPath := "/var/cpanel/logs/autossl"
	entries, err := osFS.ReadDir(logPath)
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
