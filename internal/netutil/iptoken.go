package netutil

import (
	"net"
	"strings"
)

// ParseIPToken extracts an IP address from one whitespace-delimited log or
// message token: surrounding brackets and trailing punctuation are removed,
// and a trailing ':' separator is dropped only when the token does not
// already parse as an address, so the "::" that ends many IPv6 addresses
// survives. The result is the canonical text form; ok is false when no
// address is left. It replaces per-caller TrimRight cutsets that contained
// ':' and cut IPv6 addresses short without re-validating the remnant.
func ParseIPToken(token string) (string, bool) {
	t := strings.Trim(strings.TrimSpace(token), ",;()[]")
	if ip := net.ParseIP(t); ip != nil {
		return ip.String(), true
	}
	for strings.HasSuffix(t, ":") {
		t = strings.TrimSuffix(t, ":")
		if ip := net.ParseIP(strings.Trim(t, ",;()[]")); ip != nil {
			return ip.String(), true
		}
	}
	return "", false
}
