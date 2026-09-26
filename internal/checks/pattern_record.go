package checks

import (
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// These are parser resource bounds, not qualified server acceptance limits.
// A caller must bound the raw line, including log-escape expansion, separately.
const (
	patternMaxTarget    = 8192
	patternMaxUA        = 512
	patternMaxReferer   = 2048
	patternMaxHost      = 253
	patternMaxExtension = 256
	patternMaxMethod    = 32
)

type refererState uint8

const (
	refererMissing refererState = iota
	refererDash
	refererEmpty
	refererMalformed
	refererValid
)

// Target and RefererHost are transient: derive identity/evidence and discard
// them before persistence. Query values and raw Referer must never be stored.
type patternRecord struct {
	RemoteIP       string
	Time           time.Time
	TimeOK         bool
	Method         string
	Target         string
	TargetOverflow bool
	TargetInvalid  bool
	Status         int
	Referer        refererState
	RefererHost    string
	UserAgent      string
	UAOverflow     bool
	XFF            string
	XFFUnusable    bool
}

// parsePatternRecord accepts common/combined logs with optional quoted
// extensions. Unsupported structure is a coverage gap, not a quiet record.
func parsePatternRecord(line string) (patternRecord, bool) {
	var rec patternRecord
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return rec, false
	}
	rec.RemoteIP = line[:sp]
	rest := line[sp+1:]
	br := strings.IndexByte(rest, '[')
	if br < 0 {
		return rec, false
	}
	rest = rest[br+1:]
	cb := strings.IndexByte(rest, ']')
	if cb < 0 {
		return rec, false
	}
	if stamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", rest[:cb]); err == nil {
		rec.Time, rec.TimeOK = stamp, true
	}
	rest = rest[cb+1:]

	request, rest, ok := patternQuotedField(rest)
	if !ok {
		return rec, false
	}
	// Split log-level separators first: a decoded \x20 belongs to the target,
	// not to request-line framing. Never reinterpret a target prefix as whole.
	method, afterMethod, hasMethod := strings.Cut(request, " ")
	target, proto, hasProto := strings.Cut(afterMethod, " ")
	var methodOver bool
	rec.Method, methodOver = patternDecodeField(method, patternMaxMethod)
	if !hasMethod || !hasProto || method == "" || target == "" || methodOver || !patternHTTPVersion(proto) {
		rec.TargetInvalid = true
	} else {
		rec.Target, rec.TargetOverflow = patternDecodeField(target, patternMaxTarget)
		if rec.TargetOverflow {
			rec.Target = ""
		} else if !strings.HasPrefix(rec.Target, "/") {
			rec.Target, rec.TargetInvalid = "", true
		}
	}

	statusTok, rest := patternToken(rest)
	if len(statusTok) != 3 || !patternDigitsOnly(statusTok) || statusTok[0] < '1' || statusTok[0] > '5' {
		return rec, false
	}
	rec.Status = atoiSafe(statusTok)
	bytesTok, rest := patternToken(rest)
	if bytesTok != "-" && !patternDigitsOnly(bytesTok) {
		return rec, false
	}
	if strings.TrimSpace(rest) == "" {
		return rec, true
	}

	refRaw, rest, ok := patternQuotedField(rest)
	if !ok {
		return rec, false
	}
	ref, refOver := patternDecodeField(refRaw, patternMaxReferer)
	if !patternRefererSyntax(refRaw) {
		rec.Referer = refererMalformed
	} else {
		rec.Referer, rec.RefererHost = patternRefererFromValue(ref, refOver)
	}
	if strings.TrimSpace(rest) == "" {
		return rec, true
	}
	ua, uaOver, rest, ok := scanPatternQuoted(rest, patternMaxUA)
	if !ok {
		return rec, false
	}
	rec.UserAgent, rec.UAOverflow = ua, uaOver
	for strings.TrimSpace(rest) != "" {
		value, over, tail, fieldOK := scanPatternQuoted(rest, patternMaxExtension)
		if !fieldOK {
			return rec, false
		}
		// An oversized extension could hide the proxy-appended address.
		// A duplicate or partly malformed IP list has no unique authority.
		if over {
			rec.XFFUnusable = true
		} else if looksLikeXFF(value) {
			if rec.XFF != "" || !patternValidXFF(value) {
				rec.XFFUnusable = true
			}
			rec.XFF = value
		}
		rest = tail
	}
	if rec.XFFUnusable {
		rec.XFF = ""
	}
	return rec, true
}

func patternHTTPVersion(s string) bool {
	if !strings.HasPrefix(s, "HTTP/") || len(s) > 16 {
		return false
	}
	major, minor, dot := strings.Cut(s[5:], ".")
	return patternDigitsOnly(major) && (!dot || patternDigitsOnly(minor))
}

func patternToken(s string) (string, string) {
	s = strings.TrimLeft(s, " \t")
	at := strings.IndexAny(s, " \t")
	if at < 0 {
		return s, ""
	}
	return s[:at], s[at:]
}

// patternQuotedField retains encoded bytes so decoded delimiters cannot
// change request framing. It never searches past unexpected unquoted text.
func patternQuotedField(s string) (raw, rest string, ok bool) {
	s = strings.TrimLeft(s, " \t")
	if len(s) == 0 || s[0] != '"' {
		return "", s, false
	}
	for i := 1; i < len(s); {
		if s[i] == '"' {
			if i+1 < len(s) && s[i+1] != ' ' && s[i+1] != '\t' {
				return "", s, false
			}
			return s[1:i], s[i+1:], true
		}
		_, i = patternLogByte(s, i)
	}
	return "", s, false
}

// patternLogByte decodes one log escape; percent escapes are untouched.
// Unknown/incomplete log escapes remain literal bytes.
func patternLogByte(s string, i int) (byte, int) {
	if s[i] == '\\' && i+1 < len(s) {
		switch s[i+1] {
		case '"', '\\':
			return s[i+1], i + 2
		case 'b':
			return '\b', i + 2
		case 'f':
			return '\f', i + 2
		case 'n':
			return '\n', i + 2
		case 'r':
			return '\r', i + 2
		case 't':
			return '\t', i + 2
		case 'v':
			return '\v', i + 2
		case 'x':
			if i+3 < len(s) && patternIsHex(s[i+2]) && patternIsHex(s[i+3]) {
				return hexToByte(s[i+2 : i+4]), i + 4
			}
		}
	}
	return s[i], i + 1
}

func patternDecodeField(raw string, limit int) (string, bool) {
	var out strings.Builder
	over := false
	for i := 0; i < len(raw); {
		var c byte
		c, i = patternLogByte(raw, i)
		if out.Len() < limit {
			out.WriteByte(c)
		} else {
			over = true
		}
	}
	return out.String(), over
}

func scanPatternQuoted(s string, limit int) (val string, overflow bool, rest string, ok bool) {
	raw, rest, ok := patternQuotedField(s)
	if !ok {
		return "", false, rest, false
	}
	val, overflow = patternDecodeField(raw, limit)
	return val, overflow, rest, true
}

// Validate all decoded Referer bytes even beyond the retained host prefix.
// An overlong path is fine; an illegal URL byte or escape is not evidence.
func patternRefererSyntax(raw string) bool {
	hexLeft := 0
	for i := 0; i < len(raw); {
		var c byte
		c, i = patternLogByte(raw, i)
		if c <= ' ' || c == 0x7f || c == '"' || c == '\\' {
			return false
		}
		if hexLeft > 0 {
			if !patternIsHex(c) {
				return false
			}
			hexLeft--
		} else if c == '%' {
			hexLeft = 2
		}
	}
	return hexLeft == 0
}

func patternRefererFromValue(v string, overflow bool) (refererState, string) {
	switch {
	case v == "-" && !overflow:
		return refererDash, ""
	case v == "" && !overflow:
		return refererEmpty, ""
	}
	host, ok := patternRefererHost(v, overflow)
	if !ok {
		return refererMalformed, ""
	}
	return refererValid, host
}

func patternRefererHost(v string, overflow bool) (string, bool) {
	var after string
	switch {
	case len(v) >= 8 && strings.EqualFold(v[:8], "https://"):
		after = v[8:]
	case len(v) >= 7 && strings.EqualFold(v[:7], "http://"):
		after = v[7:]
	default:
		return "", false
	}
	end := strings.IndexAny(after, "/?#")
	if end < 0 {
		if overflow {
			return "", false
		}
		end = len(after)
	}
	authority := after[:end]
	// Parse only the complete authority: a truncated path may end mid-escape.
	parsed, err := url.Parse("http://" + authority)
	if err != nil {
		return "", false
	}
	authority = parsed.Host
	if strings.HasPrefix(authority, "[") {
		rb := strings.IndexByte(authority, ']')
		if rb < 0 {
			return "", false
		}
		addr, addrErr := netip.ParseAddr(authority[1:rb])
		if addrErr != nil || !addr.Is6() || addr.Zone() != "" || !patternValidPortSuffix(authority[rb+1:]) {
			return "", false
		}
		return addr.Unmap().String(), true
	}
	host, port, hasPort := strings.Cut(authority, ":")
	if hasPort && !patternValidPortSuffix(":"+port) {
		return "", false
	}
	host = strings.TrimSuffix(patternASCIILower(host), ".")
	if host == "" || len(host) > patternMaxHost {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := range len(label) {
			c := label[i]
			valid := ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-'
			if !valid {
				return "", false
			}
		}
	}
	return host, true
}

func patternValidPortSuffix(s string) bool {
	if s == "" {
		return true
	}
	if s[0] != ':' || len(s) < 2 || len(s) > 6 {
		return false
	}
	n := 0
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n <= 65535
}

func patternValidXFF(s string) bool {
	for _, part := range strings.Split(s, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || addr.Zone() != "" {
			return false
		}
	}
	return true
}

func patternASCIILower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func patternIsHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func patternDigitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

type refererClass uint8

const (
	refClassNone refererClass = iota
	refClassMalformed
	refClassCrossSite
	refClassSameSite
)

// isSiteHost comes from verified inventory, never from request headers.
// Consumers discard RefererHost after this call; same-site is not a bypass.
func classifyReferer(r patternRecord, isSiteHost func(string) bool) refererClass {
	switch r.Referer {
	case refererValid:
		if isSiteHost(r.RefererHost) {
			return refClassSameSite
		}
		return refClassCrossSite
	case refererMalformed:
		return refClassMalformed
	default:
		return refClassNone
	}
}
