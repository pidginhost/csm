package modsec

import (
	"net"
	"strconv"
	"strings"
)

// ErrorLogMessage uses the first module marker so request text cannot change
// the server format or supply an action by embedding another marker later.
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

// errorLogMarker finds the module marker that ends the server-written prefix
// of a ModSecurity log line, or -1.
func errorLogMarker(line string) (at int, marker string, isLiteSpeed bool) {
	a := strings.Index(line, modsecApacheMarker)
	l := strings.Index(line, modsecLiteSpeedMarker)
	if l >= 0 && (a < 0 || l < a) {
		return l, modsecLiteSpeedMarker, true
	}
	return a, modsecApacheMarker, false
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
	// Apache 2.4 writes [client IP:port], also for IPv6 ("2001:db8::5:5555").
	_, rest, ok := strings.Cut(prefix, "[client ")
	if !ok {
		return ""
	}
	if strings.HasPrefix(rest, "[") {
		// Bracketed IPv6 with a port: [client [2001:db8::5]:5555].
		raw, _, ok := strings.Cut(rest, "] ")
		if !ok {
			raw, ok = strings.CutSuffix(rest, "]")
		}
		host, port, err := net.SplitHostPort(raw)
		if !ok || err != nil {
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
	if i := strings.LastIndexByte(raw, ':'); i > 0 {
		if _, err := strconv.ParseUint(raw[i+1:], 10, 16); err == nil {
			if ip := net.ParseIP(raw[:i]); ip != nil {
				return ip.String()
			}
		}
	}
	if ip := net.ParseIP(raw); ip != nil {
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
