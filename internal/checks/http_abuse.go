// HTTP abuse detection (Task 1: aggregator + parser only).
//
// This file holds the access-log line parser, the per-scan aggregator
// struct (domlogStats), and the bot-classifier interface used by tests
// and (later) by the rDNS verify path. The new check kinds
// http_request_flood and http_ua_spoof are wired in later tasks.
package checks

import (
	"net"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// accessLogRecord is the parsed shape of one access-log line. Combined
// Log Format plus the cPanel final-vhost extension:
//
//	IP - - [time] "METHOD URI PROTO" status bytes "referer" "ua" "vhost"
//
// The parser tolerates either the 9-field plain CLF or the 10-field
// cPanel variant. Bad lines return ok=false; callers must skip them.
type accessLogRecord struct {
	RemoteIP  string
	Time      time.Time
	Method    string
	URI       string
	Status    int
	UserAgent string
	XFF       string // optional; only trusted when RemoteIP is a trusted proxy
}

// uaKind is the User-Agent classification used by domlogStats.scan and
// by the http_ua_spoof emit logic. Defined here so the type signature
// of botClassifier is stable across tasks. Task 4 wires these into scan
// and emit; the linter sees them as unused until then.
type uaKind int

//nolint:unused // wired in Task 4 UA classifier
const (
	uaKindBrowser uaKind = iota
	uaKindClaimedBot
	uaKindClaimedBotNegative
	uaKindKnownScanner
	uaKindWPSpoofPingback
	uaKindScriptingLang
	uaKindHeadless
	uaKindEmpty
)

// botClassifier decides whether the source IP is a known verified bot
// the detector should NOT count or flag. Returns true to skip. The
// real implementation lives in internal/threatintel; tests use the
// nopBotClassifier below.
type botClassifier interface {
	IsVerifiedBot(ip string, ua string) bool
}

type nopBotClassifier struct{}

func (nopBotClassifier) IsVerifiedBot(string, string) bool { return false }

// httpSample is one representative request kept per IP for forensic
// display in the finding Details field. First-seen wins; subsequent
// requests increment counters only.
type httpSample struct {
	Method string
	URI    string
	UA     string
}

// domlogStats is the per-scan aggregator. One instance per CheckWPBruteForce
// invocation. Every counter is map[ip] -> int so emit can produce findings
// per source IP without a second pass.
type domlogStats struct {
	wpLogin  map[string]int
	xmlrpc   map[string]int
	userEnum map[string]int
	httpReqs map[string]int            // Task 3
	uaCat    map[string]map[uaKind]int // Task 4
	samples  map[string]httpSample
	scanTime time.Time
}

func newDomlogStats() *domlogStats {
	return newDomlogStatsAt(time.Now())
}

func newDomlogStatsAt(t time.Time) *domlogStats {
	return &domlogStats{
		wpLogin:  make(map[string]int),
		xmlrpc:   make(map[string]int),
		userEnum: make(map[string]int),
		httpReqs: make(map[string]int),
		uaCat:    make(map[string]map[uaKind]int),
		samples:  make(map[string]httpSample),
		scanTime: t,
	}
}

// scan updates counters for one parsed record. cfg is allowed to be nil
// at Task 1 (parity tests pass nil); later tasks read thresholds from
// it. bot is consulted before any count so a verified Googlebot does
// not contribute to either legacy or new metrics.
func (s *domlogStats) scan(rec accessLogRecord, cfg *config.Config, bot botClassifier) {
	ip := clientIPForRecord(rec, cfg)
	if ip == "" || ip == "-" || ip == "127.0.0.1" || ip == "::1" {
		return
	}
	if cfg != nil && isInfraIP(ip, cfg.InfraIPs) {
		return
	}
	if bot != nil && bot.IsVerifiedBot(ip, rec.UserAgent) {
		return
	}

	if rec.Method == "POST" {
		if strings.Contains(rec.URI, "wp-login.php") {
			s.wpLogin[ip]++
		}
		if strings.Contains(rec.URI, "xmlrpc.php") {
			s.xmlrpc[ip]++
		}
	}
	if strings.Contains(rec.URI, "?author=") {
		s.userEnum[ip]++
	} else if strings.Contains(rec.URI, "/wp-json/wp/v2/users") &&
		!strings.Contains(rec.URI, "/users/me") {
		s.userEnum[ip]++
	}

	if _, ok := s.samples[ip]; !ok {
		s.samples[ip] = httpSample{Method: rec.Method, URI: rec.URI, UA: rec.UserAgent}
	}
}

// emitLegacy returns the three pre-existing finding kinds. Kept
// separate from the new emit() (Tasks 3/4) so the parity test can
// assert "no new findings yet".
func (s *domlogStats) emitLegacy(_ *config.Config) []alert.Finding {
	var out []alert.Finding
	for ip, count := range s.wpLogin {
		if count >= wpLoginThreshold {
			out = append(out, alert.Finding{
				Severity: alert.Critical,
				Check:    "wp_login_bruteforce",
				Message:  formatLegacyMessage("WordPress login brute force", ip, count, "attempts"),
				Details:  "Aggregated across per-vhost access logs",
			})
		}
	}
	for ip, count := range s.xmlrpc {
		if count >= xmlrpcThreshold {
			out = append(out, alert.Finding{
				Severity: alert.Critical,
				Check:    "xmlrpc_abuse",
				Message:  formatLegacyMessage("XML-RPC abuse", ip, count, "requests"),
				Details:  "Aggregated across per-vhost access logs",
			})
		}
	}
	for ip, count := range s.userEnum {
		if count >= 5 {
			out = append(out, alert.Finding{
				Severity: alert.High,
				Check:    "wp_user_enumeration",
				Message:  formatLegacyMessage("WordPress user enumeration", ip, count, "requests"),
				Details:  "Requests to /wp-json/wp/v2/users or ?author=",
			})
		}
	}
	return out
}

func formatLegacyMessage(kind, ip string, n int, unit string) string {
	return kind + " from " + ip + ": " + itoa(n) + " " + unit
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// parseAccessLogRecord parses one Combined Log Format line into an
// accessLogRecord. It does NOT use strings.Fields because quoted
// request/referer/user-agent fields can contain spaces.
//
// Format:
//
//	<ip> <ident> <user> [<time>] "<method> <uri> <proto>" <status> <bytes> "<ref>" "<ua>" ["<vhost>"]
//
// Returns ok=false for any line that cannot be parsed. Never panics.
func parseAccessLogRecord(line string) (accessLogRecord, bool) {
	const maxUALen = 512
	const maxURILen = 4096

	var rec accessLogRecord
	// IP is everything up to the first space.
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return rec, false
	}
	rec.RemoteIP = line[:sp]
	rest := line[sp+1:]

	// Skip ident, user (two single-token fields). Loose: we just need to
	// land at the [time] bracket.
	br := strings.IndexByte(rest, '[')
	if br < 0 {
		return rec, false
	}
	rest = rest[br+1:]
	closeBr := strings.IndexByte(rest, ']')
	if closeBr < 0 {
		return rec, false
	}
	timeStr := rest[:closeBr]
	rest = rest[closeBr+1:]
	// time format: 02/Jan/2006:15:04:05 -0700
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeStr)
	if err == nil {
		rec.Time = t
	}

	// Request quoted field.
	q1 := strings.IndexByte(rest, '"')
	if q1 < 0 {
		return rec, false
	}
	rest = rest[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return rec, false
	}
	request := rest[:q2]
	rest = rest[q2+1:]
	parts := strings.SplitN(request, " ", 3)
	if len(parts) >= 1 {
		rec.Method = parts[0]
	}
	if len(parts) >= 2 {
		uri := parts[1]
		if len(uri) > maxURILen {
			uri = uri[:maxURILen]
		}
		rec.URI = uri
	}

	// status (skip leading spaces)
	rest = strings.TrimLeft(rest, " ")
	end := strings.IndexByte(rest, ' ')
	if end > 0 {
		rec.Status = atoiSafe(rest[:end])
		rest = rest[end+1:]
	}

	// bytes field -- skip leading spaces then advance past the token
	rest = strings.TrimLeft(rest, " ")
	end = strings.IndexByte(rest, ' ')
	if end > 0 {
		rest = rest[end+1:]
	} else {
		// no more fields after bytes
		return rec, true
	}

	// referer quoted field (skipped).
	q1 = strings.IndexByte(rest, '"')
	if q1 < 0 {
		return rec, false
	}
	rest = rest[q1+1:]
	q2 = strings.IndexByte(rest, '"')
	if q2 < 0 {
		return rec, false
	}
	rest = rest[q2+1:]

	// UA quoted field.
	q1 = strings.IndexByte(rest, '"')
	if q1 < 0 {
		return rec, true // no UA present is fine
	}
	rest = rest[q1+1:]
	q2 = strings.IndexByte(rest, '"')
	if q2 < 0 {
		return rec, false
	}
	ua := rest[:q2]
	if len(ua) > maxUALen {
		ua = ua[:maxUALen]
	}
	rec.UserAgent = ua
	rest = rest[q2+1:]

	// Optional quoted extensions. cPanel may append a quoted vhost after
	// UA. Custom proxy formats may append an X-Forwarded-For value. Only
	// retain a quoted extension that parses as an IP list; clientIPForRecord
	// still ignores it unless RemoteIP is a configured trusted proxy.
	for {
		q1 = strings.IndexByte(rest, '"')
		if q1 < 0 {
			break
		}
		rest = rest[q1+1:]
		q2 = strings.IndexByte(rest, '"')
		if q2 < 0 {
			return rec, false
		}
		extra := rest[:q2]
		if looksLikeXFF(extra) {
			rec.XFF = extra
		}
		rest = rest[q2+1:]
	}

	return rec, true
}

func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func clientIPForRecord(rec accessLogRecord, cfg *config.Config) string {
	if cfg == nil || len(cfg.WebServer.TrustedProxies) == 0 || rec.XFF == "" {
		return rec.RemoteIP
	}
	if !isTrustedProxy(rec.RemoteIP, cfg.WebServer.TrustedProxies) {
		return rec.RemoteIP
	}
	for _, part := range strings.Split(rec.XFF, ",") {
		ip := strings.TrimSpace(part)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return rec.RemoteIP
}

// isTrustedProxy returns true when addr matches any entry in proxies (exact
// IP or CIDR). Entries that fail to parse are skipped.
func isTrustedProxy(addr string, proxies []string) bool {
	parsed := net.ParseIP(addr)
	if parsed == nil {
		return false
	}
	for _, entry := range proxies {
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			if cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if net.ParseIP(entry) != nil && entry == addr {
			return true
		}
	}
	return false
}

func looksLikeXFF(raw string) bool {
	for _, part := range strings.Split(raw, ",") {
		if net.ParseIP(strings.TrimSpace(part)) != nil {
			return true
		}
	}
	return false
}
