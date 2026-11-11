package checks

import (
	"net"
	"strings"
	"time"
)

// CpanelAccessRecord is one line of cpsrvd's access_log:
// `<ip> <ident> <user> [01/02/2006:15:04:05 -0700] "<method> <target> <proto>" <status> <size>`,
// where ident is "-" or "proxy",
// then up to four quoted fields and an optional listener port.
type CpanelAccessRecord struct {
	IP     string // the leading address: the connecting peer unless Proxy
	User   string // client text; "-" when the request named no user
	Method string
	Target string // the raw request target, log escapes kept
	Status string
	// Port served the request: the trailing field, or the port of a final
	// quoted "host:port" on lines written without one.
	Port string
	// At is zero when the line holds a second timestamp candidate: the
	// client may then have written the time it would be dated by.
	At time.Time
	// Proxy marks the "proxy" ident cpsrvd writes on service-subdomain
	// requests. Its address is unverified and must never act as a peer.
	Proxy bool
}

// ParseCpanelAccessRecord reads line by cpsrvd's grammar and rejects any
// other line. The client chooses the user, which may hold spaces, brackets,
// quotes and a whole forged record, so the request is the one after the only
// cpsrvd timestamp whose suffix parses through the end of the line: a forged
// suffix always runs into the real timestamp. A line whose time is not in
// cpsrvd's form is still read, undated, from the bracketed field whose suffix
// parses through the end: client text must not hide its request.
func ParseCpanelAccessRecord(line string) (CpanelAccessRecord, bool) {
	peer, rest, ok := strings.Cut(line, " ")
	if !ok || net.ParseIP(peer) == nil {
		return CpanelAccessRecord{}, false
	}
	// cpsrvd writes "proxy" as the ident on service-subdomain requests.
	ident, rest, ok := strings.Cut(rest, " ")
	if !ok || ident != "-" && ident != "proxy" {
		return CpanelAccessRecord{}, false
	}
	rec := CpanelAccessRecord{IP: peer, Proxy: ident == "proxy"}
	candidates, matches := 0, 0
	// Candidates never overlap, so one pass bounds the work by the line.
	for i := 0; i < len(rest); i++ {
		j := strings.IndexByte(rest[i:], '[')
		if j < 0 {
			break
		}
		i += j
		end := i + 1 + cpanelStampLen
		if end >= len(rest) || rest[end] != ']' || !cpanelStampShape(rest[i+1:end]) {
			continue
		}
		after := strings.TrimLeft(rest[end+1:], " \t")
		if len(after) == len(rest)-end-1 || after == "" || after[0] != '"' {
			continue
		}
		candidates++
		r := CpanelAccessRecord{IP: peer, Proxy: rec.Proxy}
		if r.parseFrom(rest, i, after) {
			matches++
			r.At, _ = time.Parse("01/02/2006:15:04:05 -0700", rest[i+1:end])
			rec = r
		}
		i = end
	}
	switch {
	case matches == 1 && candidates == 1:
		return rec, true
	case matches == 1:
		rec.At = time.Time{}
		return rec, true
	case matches == 0 && rec.parseUndated(rest):
		return rec, true
	}
	return CpanelAccessRecord{}, false
}

// parseUndated applies the same complete-suffix check to other time forms.
// Keep the opening bracket while moving forward: searching the whole prefix
// again at each closing bracket would make crafted user fields quadratic.
func (r *CpanelAccessRecord) parseUndated(rest string) bool {
	open, matches := -1, 0
	for i := 0; i < len(rest); i++ {
		if rest[i] == '[' {
			open = i
		}
		if rest[i] != ']' {
			continue
		}
		after := strings.TrimLeft(rest[i+1:], " \t")
		if len(after) == len(rest)-i-1 || after == "" || after[0] != '"' {
			continue
		}
		candidate := CpanelAccessRecord{IP: r.IP, Proxy: r.Proxy}
		if candidate.parseFrom(rest, open, after) {
			matches++
			if matches > 1 {
				return false
			}
			*r = candidate
		}
	}
	return matches == 1
}

// parseFrom reads the user ending before rest[open] and the suffix after.
func (r *CpanelAccessRecord) parseFrom(rest string, open int, after string) bool {
	if open < 2 || (rest[open-1] != ' ' && rest[open-1] != '\t') || !r.parseSuffix(after) {
		return false
	}
	r.User = rest[:open-1]
	return true
}

// cpanelAccessLogTime reads the time cpsrvd stamped on an access_log line.
// A user holding its own timestamp followed by a quote leaves the line with
// no time, never the time the client wrote.
func cpanelAccessLogTime(line string) (time.Time, bool) {
	rec, ok := ParseCpanelAccessRecord(line)
	at := rec.evidenceTime()
	return at, ok && !at.IsZero()
}

// evidenceTime is the time a scan may date an observation by. Only direct
// records are dated: a proxy record's leading address is unverified.
func (r CpanelAccessRecord) evidenceTime() time.Time {
	if r.Proxy {
		return time.Time{}
	}
	return r.At
}

// WebmailLogin reports whether the record is a login POST to webmail.
func (r CpanelAccessRecord) WebmailLogin() bool {
	if r.Port != "2095" && r.Port != "2096" || !strings.EqualFold(r.Method, "POST") {
		return false
	}
	target := strings.ToLower(r.Target)
	return strings.Contains(target, "login") || strings.Contains(target, "auth")
}

// cpanelStampLen is the length of cpsrvd's `01/02/2006:15:04:05 -0700`.
const cpanelStampLen = 25

// cpanelStampShape reports whether s has the shape of cpsrvd's timestamp.
func cpanelStampShape(s string) bool {
	const shape = "00/00/0000:00:00:00 +0000"
	if len(s) != len(shape) {
		return false
	}
	for i := range len(shape) {
		switch c := s[i]; shape[i] {
		case '0':
			if c < '0' || c > '9' {
				return false
			}
		case '+':
			if c != '+' && c != '-' {
				return false
			}
		default:
			if c != shape[i] {
				return false
			}
		}
	}
	return true
}

// parseSuffix reads what cpsrvd writes after its timestamp, through the end
// of the line.
func (r *CpanelAccessRecord) parseSuffix(s string) bool {
	request, s, ok := patternQuotedField(s)
	if !ok {
		return false
	}
	method, afterMethod, hasMethod := strings.Cut(request, " ")
	target, proto, hasProto := strings.Cut(afterMethod, " ")
	// Method tokens have no fixed length. Rejecting a long one would hide
	// the whole request, including checks that do not depend on its method.
	method, _ = patternDecodeField(method, len(method))
	if !hasMethod || !hasProto || !patternValidMethod(method) ||
		!patternValidRawTarget(target) || !patternHTTPVersion(proto) {
		return false
	}
	status, s := patternToken(s)
	if len(status) != 3 || !patternDigitsOnly(status) || status[0] < '1' || status[0] > '5' {
		return false
	}
	size, s := patternToken(s)
	if size != "-" && !patternDigitsOnly(size) {
		return false
	}
	var last string
	quoted := 0
	for ; ; quoted++ {
		s = strings.TrimLeft(s, " \t")
		if s == "" || s[0] != '"' {
			break
		}
		if quoted == 4 {
			return false
		}
		if last, s, ok = patternQuotedField(s); !ok {
			return false
		}
	}
	r.Method, r.Target, r.Status = method, target, status
	if s == "" {
		// Referer and user agent come first; only a third field names the host.
		if quoted >= 3 {
			r.Port = hostPort(last)
		}
		return true
	}
	port, tail := patternToken(s)
	if strings.TrimLeft(tail, " \t") != "" || !validPort(port) {
		return false
	}
	r.Port = port
	return true
}

// hostPort returns the valid port ending "host:port", or "".
func hostPort(s string) string {
	i := strings.LastIndexByte(s, ':')
	if i < 0 || !validPort(s[i+1:]) {
		return ""
	}
	return s[i+1:]
}

func validPort(s string) bool {
	if s == "" || len(s) > 5 || !patternDigitsOnly(s) {
		return false
	}
	n := atoiSafe(s)
	return n > 0 && n <= 65535
}
