package checks

import (
	"iter"
	"net"
	"strings"
	"time"
)

// CpanelAccessRecord is one line of cpsrvd's access_log:
// `<ip> <ident> <user> [01/02/2006:15:04:05 -0700] "<method> <target> <proto>" <status> <size>`,
// then quoted fields and the listener port, where ident is "-" or "proxy".
// cpsrvd escapes no quotes, so the user, request, referer and user agent
// are client text that may hold raw quotes and whole forged records. Client
// text can add a possible request or status to a record, never hide the one
// cpsrvd wrote; it never supplies the peer, the port or the time.
type CpanelAccessRecord struct {
	IP   string // the leading address: the connecting peer unless Proxy
	User string // text before the first request; "-" when none was named
	// Status is the response code when the line holds one request and one
	// status, "" when client text makes it ambiguous.
	Status string
	// Port served the request: the bare last field after a quoted field, or
	// the host:port of the last quoted field when a request's suffix parses
	// strictly through the end of the line.
	Port string
	// At is the time cpsrvd stamped, zero unless cpanelAccessLogTime dates
	// the line.
	At time.Time
	// Proxy marks the "proxy" ident cpsrvd writes on service-subdomain
	// requests. Its address is unverified and must never act as a peer.
	Proxy bool
	// rest is the line after the ident, read again for each request so a
	// line full of forged requests costs no memory.
	rest string
	// first is the text from the first request's opening quote.
	first string
}

// CpanelRequest is one request a cpsrvd access_log line may hold. The
// method and the start of the target are read from just after the opening
// quote; raw quotes later on cannot move them.
type CpanelRequest struct {
	Method string
	Target string // raw, up to the first blank; may hold raw quotes
}

// ParseCpanelAccessRecord reads line as cpsrvd writes it and rejects lines
// with no request after a bracketed field.
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
	rec := CpanelAccessRecord{IP: peer, Proxy: ident == "proxy", rest: rest}
	requests := 0
	for open, after := range cpanelRequestStarts(rest) {
		if _, ok := parseCpanelRequest(after[1:]); !ok {
			continue
		}
		if requests++; requests > 1 {
			break
		}
		if open >= 2 && (rest[open-1] == ' ' || rest[open-1] == '\t') {
			rec.User = rest[:open-1]
		}
		rec.first = after
	}
	if requests == 0 {
		return CpanelAccessRecord{}, false
	}
	if requests == 1 {
		if codes := cpanelStatuses(rec.first, 2); len(codes) == 1 {
			rec.Status = codes[0]
		}
	}
	rec.Port = cpanelServedPort(line)
	if rec.Port == "" {
		// A writer without the bare port names the served host in a third
		// or later quoted field. Only a strict parse through the end of the
		// line tells that field from a user agent; a start forged in the
		// user runs into the real timestamp and fails it.
		for _, after := range cpanelRequestStarts(rest) {
			if vhost, ok := strictCpanelSuffix(after); ok && vhost != "" {
				rec.Port = vhost
				break
			}
		}
	}
	rec.At, _ = cpanelAccessLogTime(line)
	return rec, true
}

// cpanelRequestStarts yields, for each bracketed field followed by blanks
// and a quote, the index of the last opening bracket before it (-1 when
// none) and the text from the quote on. Client text adds starts; the
// request cpsrvd wrote is always one of them.
func cpanelRequestStarts(rest string) iter.Seq2[int, string] {
	return func(yield func(int, string) bool) {
		open := -1
		for i := 0; i < len(rest); i++ {
			if rest[i] == '[' {
				open = i
				continue
			}
			if rest[i] != ']' {
				continue
			}
			after := strings.TrimLeft(rest[i+1:], " \t")
			if len(after) == len(rest)-i-1 || after == "" || after[0] != '"' {
				continue
			}
			if !yield(open, after) {
				return
			}
		}
	}
}

// Requests yields every request the line may hold, in line order.
func (r CpanelAccessRecord) Requests() iter.Seq[CpanelRequest] {
	return func(yield func(CpanelRequest) bool) {
		for _, after := range cpanelRequestStarts(r.rest) {
			if q, ok := parseCpanelRequest(after[1:]); ok && !yield(q) {
				return
			}
		}
	}
}

// Any reports whether any request the line may hold matches.
func (r CpanelAccessRecord) Any(match func(CpanelRequest) bool) bool {
	for q := range r.Requests() {
		if match(q) {
			return true
		}
	}
	return false
}

// TargetContains reports whether any request target on the line contains
// one of words, ignoring case.
func (r CpanelAccessRecord) TargetContains(words ...string) bool {
	return r.Any(func(q CpanelRequest) bool {
		target := strings.ToLower(q.Target)
		for _, w := range words {
			if strings.Contains(target, strings.ToLower(w)) {
				return true
			}
		}
		return false
	})
}

// MayHaveStatus reports whether any status-shaped field after the first
// request is one of codes. Only use it where a forged status can count only
// against the client that sent it.
func (r CpanelAccessRecord) MayHaveStatus(codes ...string) bool {
	for _, s := range cpanelStatuses(r.first, -1) {
		for _, c := range codes {
			if s == c {
				return true
			}
		}
	}
	return false
}

// WebmailLogin reports whether the record is a login POST to webmail.
func (r CpanelAccessRecord) WebmailLogin() bool {
	if r.Port != "2095" && r.Port != "2096" {
		return false
	}
	return r.Any(func(q CpanelRequest) bool {
		target := strings.ToLower(q.Target)
		return strings.EqualFold(q.Method, "POST") &&
			(strings.Contains(target, "login") || strings.Contains(target, "auth"))
	})
}

// parseCpanelRequest reads the method and target from just after a
// request's opening quote.
func parseCpanelRequest(s string) (CpanelRequest, bool) {
	method, rest, ok := strings.Cut(s, " ")
	if !ok {
		return CpanelRequest{}, false
	}
	// Method tokens have no fixed length. Rejecting a long one would hide
	// the whole request.
	method, _ = patternDecodeField(method, len(method))
	target, _, _ := strings.Cut(rest, " ")
	if !patternValidMethod(method) || !patternValidRawTarget(target) {
		return CpanelRequest{}, false
	}
	return CpanelRequest{Method: method, Target: target}, true
}

// cpanelStatuses returns up to limit (all when negative) `" <code> ` fields
// in s: the status cpsrvd wrote after the request, and any a client wrote
// into its own text.
func cpanelStatuses(s string, limit int) []string {
	var codes []string
	for i := 0; i < len(s) && len(codes) != limit; i++ {
		j := strings.IndexByte(s[i:], '"')
		if j < 0 {
			break
		}
		i += j
		rest := s[i+1:]
		if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		code, tail := patternToken(rest)
		if len(code) == 3 && patternDigitsOnly(code) && code[0] >= '1' && code[0] <= '5' &&
			tail != "" && (tail[0] == ' ' || tail[0] == '\t') {
			codes = append(codes, code)
		}
	}
	return codes
}

// cpanelServedPort reads the port cpsrvd ends its line with, after its
// last quoted field. Client text sits inside quotes before it.
func cpanelServedPort(line string) string {
	line = strings.TrimRight(line, " \t\r\n")
	i := strings.LastIndexAny(line, " \t")
	if i < 0 || !strings.HasSuffix(strings.TrimRight(line[:i], " \t"), `"`) || !validPort(line[i+1:]) {
		return ""
	}
	return line[i+1:]
}

// cpanelAccessLogTime reads the time cpsrvd stamped on an access_log line
// with ident "-". The client chooses the user, which may hold spaces,
// brackets and quotes, so only one complete parse dates the line: a user
// holding its own timestamp followed by a quote leaves the line with no
// time, never the time the client wrote. A line with raw quotes in its
// quoted fields does not parse strictly and stays undated.
func cpanelAccessLogTime(line string) (time.Time, bool) {
	peer, rest, ok := strings.Cut(line, " ")
	if !ok || net.ParseIP(peer) == nil {
		return time.Time{}, false
	}
	rest, ok = strings.CutPrefix(rest, "- ")
	if !ok {
		return time.Time{}, false
	}
	stamp, suffix, ok := cpanelUniqueStamp(rest)
	if !ok {
		return time.Time{}, false
	}
	if _, ok := strictCpanelSuffix(suffix); !ok {
		return time.Time{}, false
	}
	at, err := time.Parse("01/02/2006:15:04:05 -0700", stamp)
	return at, err == nil
}

// cpanelStampLen is the length of cpsrvd's `01/02/2006:15:04:05 -0700`.
const cpanelStampLen = 25

// cpanelUniqueStamp finds the bracketed timestamp, followed by blanks and a
// quote, that ends a nonempty user field. Any second such timestamp anywhere
// in the line, valid date or not, makes the split ambiguous. Candidates never
// overlap, so one pass bounds the work by the line.
func cpanelUniqueStamp(s string) (stamp, rest string, ok bool) {
	found, at := 0, -1
	for i := 0; i < len(s); i++ {
		j := strings.IndexByte(s[i:], '[')
		if j < 0 {
			break
		}
		i += j
		end := i + 1 + cpanelStampLen
		if end >= len(s) || s[end] != ']' || !cpanelStampShape(s[i+1:end]) {
			continue
		}
		after := strings.TrimLeft(s[end+1:], " \t")
		if len(after) == len(s)-end-1 || after == "" || after[0] != '"' {
			continue
		}
		found++
		at, stamp, rest = i, s[i+1:end], after
		i = end
	}
	if found != 1 || at < 2 || (s[at-1] != ' ' && s[at-1] != '\t') {
		return "", "", false
	}
	return stamp, rest, true
}

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

// strictCpanelSuffix parses what follows a timestamp through the end of the
// line, reading quoted fields with escapes. It returns the port the line
// names: its bare last field, or the host:port of a third or later quoted
// field. cpsrvd writes raw quotes, so its lines with quotes in client text
// fail here; use this only to date a line or to trust a quoted host.
func strictCpanelSuffix(s string) (port string, ok bool) {
	request, s, ok := patternQuotedField(s)
	if !ok {
		return "", false
	}
	method, afterMethod, hasMethod := strings.Cut(request, " ")
	target, proto, hasProto := strings.Cut(afterMethod, " ")
	method, _ = patternDecodeField(method, len(method))
	if !hasMethod || !hasProto || !patternValidMethod(method) ||
		!patternValidRawTarget(target) || !patternHTTPVersion(proto) {
		return "", false
	}
	status, s := patternToken(s)
	if len(status) != 3 || !patternDigitsOnly(status) || status[0] < '1' || status[0] > '5' {
		return "", false
	}
	size, s := patternToken(s)
	if size != "-" && !patternDigitsOnly(size) {
		return "", false
	}
	var last string
	quoted := 0
	for ; ; quoted++ {
		s = strings.TrimLeft(s, " \t")
		if s == "" || s[0] != '"' {
			break
		}
		if quoted == 4 {
			return "", false
		}
		if last, s, ok = patternQuotedField(s); !ok {
			return "", false
		}
	}
	if s == "" {
		// Referer and user agent come first; only a third field names the host.
		if quoted >= 3 {
			return hostPort(last), true
		}
		return "", true
	}
	port, tail := patternToken(s)
	if strings.TrimLeft(tail, " \t") != "" || !validPort(port) {
		return "", false
	}
	return port, true
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
