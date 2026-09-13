// Package eximlog extracts the connecting client from Exim main log lines.
//
// Exim renders the peer as `hostname (HELO) [IP]:port`, prefixed with `H=`
// in most records but bare in a few (authenticator failures, TLS errors).
// Everything before the bracketed address is attacker-influenced. The HELO
// may be an RFC 5321 address literal such as `[203.0.113.9]`, and servers that
// accept junk HELO values can log delimiter-like text there. The message
// Subject can carry brackets too. Every consumer that turns a log line into
// an IP for blocking or reputation scoring must therefore go through this
// package rather than grabbing the first bracketed token.
package eximlog

import (
	"net"
	"strings"
)

// ClientIP returns the connecting client's IP from an Exim log line, or ""
// when the line carries none. It reads either a real H= field or one of the
// known records that Exim writes through host_and_ident without an H= prefix.
func ClientIP(line string) string {
	hStart, hasHField := HFieldStart(line)
	bareStart, bareMarker := unprefixedClientStart(line)
	if bareMarker >= 0 && (!hasHField || bareMarker < hFieldMarkerStart(line, hStart)) {
		return hostAndIdentClientIP(line[bareStart:])
	}
	if hasHField {
		return HFieldClientIP(line[hStart:])
	}
	return ""
}

func hFieldMarkerStart(line string, valueStart int) int {
	if strings.HasPrefix(line, "H=") {
		return 0
	}
	return valueStart - len(" H=")
}

// unprefixedClientStart recognizes the Exim records that render
// host_and_ident(FALSE) directly. A marker inside T= is message data, not a
// peer field. markerStart is returned separately so ClientIP can prefer a
// genuine H= field that occurs earlier on the line.
func unprefixedClientStart(line string) (start, markerStart int) {
	markerStart = -1
	t := strings.Index(line, " T=")
	for _, marker := range []string{
		"authenticator failed for ",
		"TLS error on connection from ",
		"SMTP connection from ",
	} {
		idx := strings.Index(line, marker)
		if idx < 0 || (t >= 0 && t < idx) {
			continue
		}
		if markerStart < 0 || idx < markerStart {
			markerStart = idx
			start = idx + len(marker)
		}
	}
	return start, markerStart
}

// HFieldStart returns the offset just past the H= marker and true when the
// line carries a real H= field. An H= that appears after T= is inside the
// Subject and is ignored.
func HFieldStart(line string) (int, bool) {
	if strings.HasPrefix(line, "H=") {
		return len("H="), true
	}
	if h := strings.Index(line, " H="); h >= 0 {
		if t := strings.Index(line, " T="); t >= 0 && t < h {
			return 0, false
		}
		return h + len(" H="), true
	}
	return 0, false
}

// HFieldClientIP returns the connecting address inside an H= value.
func HFieldClientIP(s string) string {
	ip, _ := HFieldClientIPAndEnd(s)
	return ip
}

// HFieldClientIPAndEnd returns the connecting address and the byte offset
// immediately after its closing bracket. The offset lets callers discard the
// entire attacker-controlled H= value before parsing later Exim fields. A
// candidate must be followed by a real H= boundary, and a second plausible
// candidate makes the field ambiguous instead of letting junk HELO text win.
func HFieldClientIPAndEnd(s string) (string, int) {
	// Remote ident follows the peer. A U= marker before a candidate means
	// greeting delimiters hid the real peer and ident boundary. Text after
	// the peer is not checked this way: subjects, addresses and login names
	// placed there by any sender must not remove the connecting address.
	identStart := strings.Index(s, " U=")
	parenDepth := 0
	quoted := false
	client := ""
	clientEnd := 0
	for i := 0; i < len(s); i++ {
		if quoted {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if s[i] == '"' {
				quoted = false
			}
			continue
		}
		switch s[i] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth == 0 {
				return "", 0
			}
			parenDepth--
		case '"':
			if parenDepth == 0 {
				quoted = true
			}
		case '[':
			end := strings.IndexByte(s[i+1:], ']')
			if end < 0 {
				return "", 0
			}
			if parenDepth == 0 && !interfaceAddressAt(s, i) {
				candidate := s[i+1 : i+1+end]
				after := s[i+1+end+1:]
				if net.ParseIP(candidate) != nil && hFieldClientIPTerminated(after) {
					if client != "" || (identStart >= 0 && identStart < i) {
						return "", 0
					}
					client = candidate
					clientEnd = i + end + 2
				}
			}
			i += end + 1
		}
	}
	if parenDepth != 0 || quoted {
		return "", 0
	}
	return client, clientEnd
}

func beginsNextField(s string) bool {
	if len(s) == 0 || (s[0] != ' ' && s[0] != '\t') {
		return false
	}
	rest := strings.TrimLeft(s, " \t")
	if strings.HasPrefix(rest, "for ") {
		return true
	}
	eq := strings.IndexByte(rest, '=')
	if eq <= 0 || eq > 3 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := rest[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func hFieldClientIPTerminated(s string) bool {
	rest := withoutLoggedPort(s)
	return rest == "" || beginsNextField(rest) ||
		strings.HasPrefix(rest, " authenticator failed") ||
		strings.HasPrefix(rest, " rejected RCPT")
}

func hostAndIdentClientIPTerminated(s string) bool {
	rest := withoutLoggedPort(s)
	if rest == "" || beginsNextField(rest) || strings.HasPrefix(rest, ": ") {
		return true
	}
	for _, suffix := range []string{" (", " lost", " D=", " closed"} {
		if strings.HasPrefix(rest, suffix) {
			return true
		}
	}
	return false
}

func withoutLoggedPort(s string) string {
	if len(s) < 2 || s[0] != ':' || s[1] < '0' || s[1] > '9' {
		return s
	}
	i := 2
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[i:]
}

// hostAndIdentClientIP returns the connecting address from Exim's unprefixed
// host_and_ident output. Exim encloses the HELO in parentheses before the
// client, so an address literal inside that group is attacker text. More than
// one plausible peer or malformed parentheses are rejected; otherwise a junk
// HELO could make CSM block an address supplied by the peer.
func hostAndIdentClientIP(s string) string {
	// host_and_ident writes remote U= after the peer, as in an H= record.
	identStart := strings.Index(s, " U=")
	parenDepth := 0
	quoted := false
	client := ""
	for i := 0; i < len(s); i++ {
		if quoted {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if s[i] == '"' {
				quoted = false
			}
			continue
		}
		switch s[i] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth == 0 {
				return ""
			}
			parenDepth--
		case '"':
			if parenDepth == 0 {
				quoted = true
			}
		case '[':
			end := strings.IndexByte(s[i+1:], ']')
			if end < 0 {
				return ""
			}
			if parenDepth == 0 && !interfaceAddressAt(s, i) {
				candidate := s[i+1 : i+1+end]
				after := s[i+1+end+1:]
				if net.ParseIP(candidate) != nil && hostAndIdentClientIPTerminated(after) {
					if client != "" || (identStart >= 0 && identStart < i) {
						return ""
					}
					client = candidate
				}
			}
			i += end + 1
		}
	}
	if parenDepth != 0 || quoted {
		return ""
	}
	return client
}

func interfaceAddressAt(s string, bracket int) bool {
	return bracket >= len(" I=") && s[bracket-len(" I="):bracket] == " I="
}
