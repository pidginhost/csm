package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
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

		key := "_dns_zone:" + name
		rawPrev, exists := store.GetRaw(key)
		var prev dnsZoneState
		prevOK := false
		if exists {
			prev, prevOK = decodeDNSZoneState(rawPrev)
		}

		secHash, delegHash := parseZoneSecurity(data, zoneOrigin(name))
		cur := dnsZoneState{
			File:  hashBytes(data),
			Sec:   secHash,
			Deleg: delegHash,
			Prov:  zoneUpdateTime(data),
		}
		cur.Panel = cur.Prov > 0
		if exists && prevOK && !prev.Panel {
			cur.Panel = false
			cur.Prov = 0
		}
		if !cur.Panel {
			cur.Prov = 0
		} else if exists && prevOK && prev.Panel && cur.Prov < prev.Prov {
			cur.Prov = prev.Prov
		}
		store.SetRaw(key, cur.encode())

		if !exists {
			continue // first sight: baseline only
		}
		if !prevOK {
			continue // legacy bare-hash state: re-baseline silently, no alert
		}
		if prev.File == cur.File {
			continue // file unchanged
		}
		if prev.Sec == cur.Sec {
			continue // only non-security content changed (serial, TXT, subdomain A)
		}

		// A security-relevant record changed. Weigh it against cPanel provenance.
		if !prev.Panel || !cur.Panel || cur.Prov <= prev.Prov {
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
// Deleg is the hash of the delegation/mail subset (NS, MX). Panel records
// whether the zone was already known as cPanel-managed; manually managed zones
// cannot become trusted just by adding a cPanel-looking file header later. Prov
// is the cPanel "(update_time):" stamp, 0 when Panel is false.
type dnsZoneState struct {
	File  string `json:"f"`
	Sec   string `json:"s"`
	Deleg string `json:"d"`
	Prov  int64  `json:"p"`
	Panel bool   `json:"c,omitempty"`
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
	var raw struct {
		File  string `json:"f"`
		Sec   string `json:"s"`
		Deleg string `json:"d"`
		Prov  int64  `json:"p"`
		Panel *bool  `json:"c"`
	}
	if err := json.Unmarshal([]byte(s), &raw); err != nil || raw.File == "" {
		return dnsZoneState{}, false
	}
	z := dnsZoneState{
		File:  raw.File,
		Sec:   raw.Sec,
		Deleg: raw.Deleg,
		Prov:  raw.Prov,
		Panel: raw.Prov > 0,
	}
	if raw.Panel != nil {
		z.Panel = *raw.Panel
	}
	if !z.Panel {
		z.Prov = 0
	}
	return z, true
}

// zoneOrigin derives the zone apex (FQDN, trailing dot) from a zone file name,
// e.g. "example.com.db" -> "example.com.".
func zoneOrigin(filename string) string {
	return canonicalZoneName(strings.TrimSuffix(filename, ".db"))
}

// zoneUpdateTime extracts the epoch from cPanel's "(update_time):<n>" zone
// header. Returns 0 when absent (manually managed or non-cPanel zone).
func zoneUpdateTime(data []byte) int64 {
	const marker = "(update_time):"
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, ";") {
			return 0
		}
		if !strings.HasPrefix(line, "; cPanel ") ||
			!strings.Contains(line, "Cpanel::ZoneFile::VERSION:") ||
			!strings.Contains(line, marker) {
			continue
		}
		rest := line[strings.Index(line, marker)+len(marker):]
		j := 0
		for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		if j == 0 {
			return 0
		}
		n, err := strconv.ParseInt(rest[:j], 10, 64)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// parseZoneSecurity parses a BIND zone file and returns two hashes: the
// security fingerprint (NS, MX, apex/wildcard A and AAAA) and the delegation
// subset (NS, MX only). Records are canonicalized and sorted so reordering or
// whitespace changes do not register as a difference. SOA, ordinary subdomain
// addresses, and all TXT/DKIM/SPF/DCV records are excluded by design.
func parseZoneSecurity(data []byte, origin string) (secHash, delegHash string) {
	var secRecs, delegRecs []string

	lastOwnerFQDN := ""
	zoneOrigin := canonicalZoneName(origin)
	curOrigin := zoneOrigin
	parenDepth := 0
	pendingRaw := ""
	pendingLine := ""

	processRecord := func(raw, line string) {
		fields := zoneRecordFields(line)
		if len(fields) == 0 {
			return
		}

		// A leading blank means "same owner as the previous record".
		fqdn := lastOwnerFQDN
		rest := fields
		if r := []rune(raw); len(r) > 0 && r[0] != ' ' && r[0] != '\t' {
			fqdn = toFQDN(fields[0], curOrigin)
			lastOwnerFQDN = fqdn
			rest = fields[1:]
		}

		typ, rdata := zoneRecordType(rest)
		if typ == "" || fqdn == "" {
			return
		}
		malformedParenSuffix := zoneMalformedParenSuffix(line)

		switch typ {
		case "NS":
			if len(rdata) >= 1 {
				rec := "NS " + fqdn + " " + toFQDN(rdata[0], curOrigin) + malformedParenSuffix
				delegRecs = append(delegRecs, rec)
				secRecs = append(secRecs, rec)
			}
		case "MX":
			if len(rdata) >= 2 {
				rec := "MX " + fqdn + " " + canonicalMXPreference(rdata[0]) + " " + toFQDN(rdata[1], curOrigin) + malformedParenSuffix
				delegRecs = append(delegRecs, rec)
				secRecs = append(secRecs, rec)
			}
		case "A", "AAAA":
			if len(rdata) >= 1 && isApexOrWildcard(fqdn, zoneOrigin) {
				rec := typ + " " + fqdn + " " + canonicalIPLiteral(typ, rdata[0]) + malformedParenSuffix
				secRecs = append(secRecs, rec)
			}
		}
	}

	lines := strings.Split(string(data), "\n")
	pendingCloses := false
	for i, raw := range lines {
		line := stripZoneComment(raw)
		trimmed := strings.TrimSpace(line)
		if parenDepth > 0 {
			if !pendingCloses && continuationStartsZoneEntry(raw, line) {
				processRecord(pendingRaw, pendingLine)
				pendingRaw = ""
				pendingLine = ""
				parenDepth = 0
			} else {
				if trimmed != "" {
					pendingLine += " " + trimmed
				}
				parenDepth += zoneParenDelta(line)
				if parenDepth > 0 {
					continue
				}
				parenDepth = 0
				processRecord(pendingRaw, pendingLine)
				pendingRaw = ""
				pendingLine = ""
				pendingCloses = false
				continue
			}
		}

		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "$") {
			f := strings.Fields(trimmed)
			if len(f) == 0 {
				continue
			}
			if len(f) >= 2 && strings.EqualFold(f[0], "$ORIGIN") {
				curOrigin = toFQDN(f[1], curOrigin)
				continue
			}
			if rec, ok := zoneDirectiveFingerprint(f); ok {
				delegRecs = append(delegRecs, rec)
				secRecs = append(secRecs, rec)
			}
			continue
		}

		parenDepth = zoneParenDelta(line)
		if parenDepth > 0 {
			pendingRaw = raw
			pendingLine = trimmed
			pendingCloses = zoneContinuationCloses(parenDepth, lines[i+1:])
			continue
		}
		if parenDepth < 0 {
			parenDepth = 0
		}
		processRecord(raw, line)
	}
	if pendingLine != "" {
		processRecord(pendingRaw, pendingLine)
	}

	return hashSortedRecords(secRecs), hashSortedRecords(delegRecs)
}

func zoneContinuationCloses(depth int, lines []string) bool {
	for _, raw := range lines {
		depth += zoneParenDelta(stripZoneComment(raw))
		if depth <= 0 {
			return true
		}
	}
	return false
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

// isZoneTTL reports whether a token is a BIND TTL. BIND accepts plain seconds
// and compact unit sequences such as 1h30m.
func isZoneTTL(t string) bool {
	if t == "" {
		return false
	}
	i := 0
	for i < len(t) {
		start := i
		for i < len(t) && t[i] >= '0' && t[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
		if i == len(t) {
			return true
		}
		switch t[i] {
		case 's', 'S', 'm', 'M', 'h', 'H', 'd', 'D', 'w', 'W':
			i++
		default:
			return false
		}
	}
	return true
}

func zoneRecordFields(line string) []string {
	var b strings.Builder
	b.Grow(len(line))
	inQuote := false
	escaped := false
	for i := 0; i < len(line); i++ {
		if escaped {
			escaped = false
			b.WriteByte(line[i])
			continue
		}
		switch line[i] {
		case '\\':
			if inQuote {
				escaped = true
			}
			b.WriteByte(line[i])
		case '"':
			inQuote = !inQuote
			b.WriteByte(line[i])
		case '(', ')':
			if inQuote {
				b.WriteByte(line[i])
			} else {
				b.WriteByte(' ')
			}
		default:
			b.WriteByte(line[i])
		}
	}
	return strings.Fields(b.String())
}

func zoneDirectiveFingerprint(fields []string) (string, bool) {
	switch strings.ToUpper(fields[0]) {
	case "$INCLUDE", "$GENERATE":
		return "DIRECTIVE " + strings.ToUpper(fields[0]) + " " + strings.Join(fields[1:], " "), true
	}
	return "", false
}

func continuationStartsZoneEntry(raw, line string) bool {
	if raw == "" || raw[0] == ' ' || raw[0] == '\t' {
		return false
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, "$") {
		return true
	}
	fields := zoneRecordFields(line)
	if len(fields) < 2 {
		return false
	}
	typ, _ := zoneRecordType(fields[1:])
	return isZoneRecordType(typ)
}

func isZoneRecordType(typ string) bool {
	switch typ {
	case "A", "AAAA", "CAA", "CNAME", "DNAME", "DNSKEY", "DS", "HTTPS",
		"LOC", "MX", "NAPTR", "NS", "PTR", "SOA", "SPF", "SRV", "SSHFP",
		"SVCB", "TLSA", "TXT":
		return true
	}
	if !strings.HasPrefix(typ, "TYPE") {
		return false
	}
	_, err := strconv.ParseUint(strings.TrimPrefix(typ, "TYPE"), 10, 16)
	return err == nil
}

func canonicalMXPreference(s string) string {
	if !isDecimalUint16(s) {
		return s
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return s
	}
	return strconv.FormatUint(n, 10)
}

func isDecimalUint16(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 16)
	return err == nil
}

func canonicalIPLiteral(typ, s string) string {
	if strings.Contains(s, "%") {
		return s
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	switch typ {
	case "A":
		if !addr.Is4() {
			return s
		}
	case "AAAA":
		if !addr.Is6() {
			return s
		}
	default:
		return s
	}
	return addr.String()
}

func isApexOrWildcard(fqdn, origin string) bool {
	return fqdn == origin || strings.HasPrefix(fqdn, "*.")
}

func toFQDN(name, origin string) string {
	name = strings.TrimSpace(name)
	origin = canonicalZoneName(origin)
	if name == "" || name == "@" {
		return origin
	}
	if strings.HasSuffix(name, ".") {
		return canonicalZoneName(name)
	}
	if origin == "." {
		return canonicalZoneName(name)
	}
	return canonicalZoneName(name + "." + origin)
}

func canonicalZoneName(s string) string {
	s = strings.TrimSpace(s)
	if s == "." {
		return "."
	}
	if strings.HasSuffix(s, ".") {
		s = strings.TrimSuffix(s, ".")
		if s == "" {
			return "."
		}
		return lowerASCII(s) + "."
	}
	if s == "" {
		return "."
	}
	return lowerASCII(s) + "."
}

func lowerASCII(s string) string {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if !changed {
				b.Grow(len(s))
				b.WriteString(s[:i])
				changed = true
			}
			c += 'a' - 'A'
		}
		if changed {
			b.WriteByte(c)
		}
	}
	if !changed {
		return s
	}
	return b.String()
}

func stripZoneComment(line string) string {
	inQuote := false
	escaped := false
	for i := 0; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch line[i] {
		case '\\':
			if inQuote {
				escaped = true
			}
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

func zoneParenDelta(line string) int {
	inQuote := false
	escaped := false
	delta := 0
	for i := 0; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch line[i] {
		case '\\':
			if inQuote {
				escaped = true
			}
		case '"':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				delta++
			}
		case ')':
			if !inQuote {
				delta--
			}
		}
	}
	return delta
}

func zoneMalformedParenSuffix(line string) string {
	if !zoneParensMalformed(line) {
		return ""
	}
	return " MALFORMED_PARENS " + strings.TrimSpace(line)
}

func zoneParensMalformed(line string) bool {
	inQuote := false
	escaped := false
	depth := 0
	for i := 0; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch line[i] {
		case '\\':
			if inQuote {
				escaped = true
			}
		case '"':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				if zoneParenAttachedToToken(line, i) {
					return true
				}
				depth++
			}
		case ')':
			if !inQuote {
				if zoneParenAttachedToToken(line, i) {
					return true
				}
				depth--
				if depth < 0 {
					return true
				}
			}
		}
	}
	return depth != 0
}

func zoneParenAttachedToToken(line string, i int) bool {
	return (i > 0 && !isZoneSpace(line[i-1])) || (i+1 < len(line) && !isZoneSpace(line[i+1]))
}

func isZoneSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n':
		return true
	}
	return false
}

func hashSortedRecords(recs []string) string {
	sort.Strings(recs)
	n := 0
	for _, rec := range recs {
		if n == 0 || rec != recs[n-1] {
			recs[n] = rec
			n++
		}
	}
	return hashBytes([]byte(strings.Join(recs[:n], "\n")))
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
