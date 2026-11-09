package modsec

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrorLogMessage requires the module marker directly after the server header.
// Other modules can log request text containing a complete ModSecurity message.
func ErrorLogMessage(line string) (string, bool) {
	at, marker, isLiteSpeed := errorLogMarker(line)
	if at < 0 {
		return "", false
	}
	message := strings.TrimSpace(line[at+len(marker):])
	if isLiteSpeed {
		message = strings.TrimSpace(strings.TrimPrefix(message, modsecApacheMarker))
	}
	return message, isLiteSpeed
}

const (
	modsecApacheMarker    = "ModSecurity:"
	modsecLiteSpeedMarker = "[MODSEC]"
)

// Each marker has its own header grammar. Message text cannot change which
// server wrote the header or extend it with another module's bracketed fields.
var (
	errorLogPrefix = regexp.MustCompile(`^(?:` +
		`[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[[a-z]+\] [0-9]+#[0-9]+: (?:\*[0-9]+ )?|` +
		`(?:\[[A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9]?[0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)? [0-9]{4}\][ \t]*)?` +
		`(?:\[(?:security[23]:)?(?:emerg|alert|crit|error|warn|notice|info|debug|trace[1-8])\][ \t]*)?` +
		`(?:\[pid [0-9]+(?::tid [0-9]+)?\][ \t]*)?` +
		`)(?:\[client (?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\][ \t]*)*$`)
	liteSpeedErrorLogPrefix = regexp.MustCompile(`^` +
		`(?:[0-9]{4}-[0-9]{2}-[0-9]{2}(?: [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?)? )?` +
		`(?:\[(?:DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRIT|ALERT|EMERG)\][ \t]*)?` +
		`(?:\[[0-9]+\][ \t]*)?(?:\[T[0-9]+\][ \t]*)?` +
		`\[(?:[^\[\]\s:]+|\[[^\[\]\r\n]+\]):[^\[\]\s#]+#[^\[\]\r\n]+\][ \t]*$`)
)

// errorLogMarker finds the module marker that ends the server-written prefix
// of a ModSecurity log line, or -1.
func errorLogMarker(line string) (at int, marker string, isLiteSpeed bool) {
	a := strings.Index(line, modsecApacheMarker)
	l := strings.Index(line, modsecLiteSpeedMarker)
	if l >= 0 && (a < 0 || l < a) {
		at, marker, isLiteSpeed = l, modsecLiteSpeedMarker, true
	} else {
		at, marker = a, modsecApacheMarker
	}
	if at >= 0 {
		prefix := errorLogPrefix
		if isLiteSpeed {
			prefix = liteSpeedErrorLogPrefix
		}
		if !prefix.MatchString(line[:at]) {
			return -1, "", false
		}
	}
	return at, marker, isLiteSpeed
}

// The time each server writes at the start of its error-log prefix.
var (
	apacheErrorLogTime    = regexp.MustCompile(`^\[([A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9]?[0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)? [0-9]{4})\]`)
	nginxErrorLogTime     = regexp.MustCompile(`^([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) `)
	liteSpeedErrorLogTime = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?) `)
)

// ErrorLogTime reads the time the server wrote at the start of a ModSecurity
// log line's prefix, in the server's local time. A line without a validated
// prefix, or whose prefix has no time, has none.
func ErrorLogTime(line string) (time.Time, bool) {
	at, _, isLiteSpeed := errorLogMarker(line)
	if at < 0 {
		return time.Time{}, false
	}
	prefix := line[:at]
	re, layout := nginxErrorLogTime, "2006/01/02 15:04:05"
	switch {
	case isLiteSpeed:
		re, layout = liteSpeedErrorLogTime, "2006-01-02 15:04:05"
	case strings.HasPrefix(prefix, "["):
		re, layout = apacheErrorLogTime, "Mon Jan 2 15:04:05 2006"
	}
	m := re.FindStringSubmatch(prefix)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation(layout, m[1], time.Local)
	return t, err == nil
}

// ErrorLogClientIP reads the client address from the server-written prefix
// of a ModSecurity log line. Rule data, the URI and the message after the
// marker are client text and never name the client.
func ErrorLogClientIP(line string) string {
	at, _, isLiteSpeed := errorLogMarker(line)
	if at < 0 {
		return ""
	}
	prefix := line[:at]
	if isLiteSpeed {
		return liteSpeedClientIP(prefix)
	}
	beforeClient, rest, ok := strings.Cut(prefix, "[client ")
	if !ok {
		return ""
	}
	if strings.HasPrefix(rest, "[") {
		// Bracketed IPv6 with a port: [client [2001:db8::5]:5555].
		raw, _, closed := strings.Cut(rest, "] ")
		if !closed {
			raw, closed = strings.CutSuffix(rest, "]")
		}
		host, port, err := net.SplitHostPort(raw)
		if !closed || err != nil {
			return ""
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return ""
		}
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return ""
	}
	raw, _, ok := strings.Cut(rest, "]")
	if !ok {
		return ""
	}
	// Apache 2.4's module-qualified prefix identifies its unbracketed
	// IP:port format. Legacy Apache and libmodsecurity log a bare IP;
	// stripping a numeric IPv6 tail there would name a different host.
	ip := net.ParseIP(raw)
	apachePort := strings.Contains(beforeClient, "[security2:") || strings.Contains(beforeClient, "[security3:")
	if ip != nil && (!apachePort || ip.To4() != nil) {
		return ip.String()
	}
	if i := strings.LastIndexByte(raw, ':'); i > 0 {
		if _, err := strconv.ParseUint(raw[i+1:], 10, 16); err == nil {
			if hostIP := net.ParseIP(raw[:i]); hostIP != nil {
				return hostIP.String()
			}
		}
	}
	if ip != nil {
		return ip.String()
	}
	return ""
}

// liteSpeedClientIP accepts only the known IPv4 connection field. An unknown
// connection format must not let a later field choose another address.
func liteSpeedClientIP(prefix string) string {
	for {
		_, rest, ok := strings.Cut(prefix, "[")
		if !ok {
			return ""
		}
		field, tail, ok := strings.Cut(rest, "]")
		if !ok {
			return ""
		}
		prefix = tail
		if !strings.ContainsAny(field, ":[#") {
			continue
		}
		host, connection, ok := strings.Cut(field, ":")
		if !ok {
			return ""
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			return ""
		}
		port, connection, ok := strings.Cut(connection, "-")
		if !ok {
			return ""
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return ""
		}
		id, vhost, ok := strings.Cut(connection, "#")
		if !ok || id == "" || vhost == "" {
			return ""
		}
		return ip.String()
	}
}
