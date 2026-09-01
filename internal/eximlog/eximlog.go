// Package eximlog extracts the connecting client from Exim main log lines.
//
// Exim renders the peer as `hostname (HELO) [IP]:port`, prefixed with `H=`
// in most records but bare in a few (authenticator failures, TLS errors).
// Everything before the bracketed address is attacker-influenced: the HELO
// is free text and may itself be an RFC 5321 address literal such as
// `[203.0.113.9]`, and the message Subject can carry brackets too. Every
// consumer that turns a log line into an IP for blocking or reputation
// scoring must therefore go through this package rather than grabbing the
// first bracketed token.
package eximlog

import (
	"net"
	"strings"
)

// ClientIP returns the connecting client's IP from an Exim log line, or ""
// when the line carries none. It prefers the `[IP]:port` token inside the H=
// field; on lines without H= it takes the first bracketed IP outside any
// parenthesised group, which is where Exim keeps the HELO.
func ClientIP(line string) string {
	if start, ok := HFieldStart(line); ok {
		return HFieldClientIP(line[start:])
	}
	if strings.HasPrefix(line, "H=") || strings.Contains(line, " H=") {
		return ""
	}
	return firstBracketedIP(line)
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
// entire attacker-controlled H= value before parsing later Exim fields.
func HFieldClientIPAndEnd(s string) (string, int) {
	parenDepth := 0
	for i := 0; i < len(s); i++ {
		if parenDepth == 0 && beginsNextField(s[i:]) {
			return "", 0
		}
		switch s[i] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			if parenDepth > 0 {
				continue
			}
			end := strings.IndexByte(s[i+1:], ']')
			if end < 0 {
				return "", 0
			}
			candidate := s[i+1 : i+1+end]
			after := s[i+1+end+1:]
			if net.ParseIP(candidate) != nil && clientIPTerminated(after) {
				return candidate, i + end + 2
			}
			i += end + 1
		}
	}
	return "", 0
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

func clientIPTerminated(s string) bool {
	if s == "" {
		return true
	}
	switch s[0] {
	case ':', ' ', '\t', '\n':
		return true
	default:
		return false
	}
}

// firstBracketedIP returns the contents of the first `[...]` token in s that
// parses as an IP address and sits outside any parenthesised group, or "" if
// none. A bracketed IP inside parentheses is the HELO the peer announced,
// never the client. Validating each remaining candidate with net.ParseIP also
// skips bracketed non-IP tokens such as a Subject that happens to contain
// square brackets (e.g. T="Order [20260701-123]").
func firstBracketedIP(s string) string {
	parenDepth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			end := strings.IndexByte(s[i+1:], ']')
			if end < 0 {
				return ""
			}
			if parenDepth == 0 {
				if candidate := s[i+1 : i+1+end]; net.ParseIP(candidate) != nil {
					return candidate
				}
			}
			i += end + 1
		}
	}
	return ""
}
