// Package stalwartlog parses the text log Stalwart mail server 1.0 writes:
// one event per line, "<RFC3339> <LEVEL> <description> (<event.name>)
// key = value, ...". Values are quoted strings, lists of them, (null) or bare
// tokens. Session keys (listenerId, localPort, remoteIp, remotePort) come
// before any client-supplied value, and the first occurrence of a key wins,
// so a quoted value cannot supply an address.
package stalwartlog

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Event is one parsed log line. Fields holds scalar values with quotes
// removed and escapes decoded; Lists holds list values. A (null) value
// leaves its key absent from both.
type Event struct {
	Time   time.Time
	Level  string
	Name   string
	Fields map[string]string
	Lists  map[string][]string
}

// Session is the connection an event happened on.
type Session struct {
	Listener   string
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
}

// Parse reads one log line. It reports false for anything that is not a
// complete event in Stalwart's layout.
func Parse(line string) (Event, bool) {
	stamp, rest, ok := strings.Cut(line, " ")
	if !ok {
		return Event{}, false
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return Event{}, false
	}
	level, rest, ok := strings.Cut(rest, " ")
	if !ok || !isLevel(level) {
		return Event{}, false
	}
	name, tail, ok := eventName(rest)
	if !ok {
		return Event{}, false
	}
	ev := Event{Time: at, Level: level, Name: name, Fields: map[string]string{}, Lists: map[string][]string{}}
	if !parseFields(tail, &ev) {
		return Event{}, false
	}
	return ev, true
}

// Session returns the event's connection, or false when a port or the
// client address is missing or malformed.
func (e Event) Session() (Session, bool) {
	local, ok := port(e.Fields["localPort"])
	if !ok {
		return Session{}, false
	}
	remote, ok := port(e.Fields["remotePort"])
	if !ok {
		return Session{}, false
	}
	ip, err := netip.ParseAddr(e.Fields["remoteIp"])
	if err != nil || ip.Zone() != "" {
		return Session{}, false
	}
	return Session{Listener: e.Fields["listenerId"], LocalPort: local, RemoteIP: ip.Unmap(), RemotePort: remote}, true
}

func port(s string) (uint16, bool) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint16(n), true
}

func isLevel(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// eventName finds the first "(name)" after the description whose name is a
// dotted event name followed by a space or the end of the line. The
// description is Stalwart's fixed text, never client data.
func eventName(rest string) (name, tail string, ok bool) {
	for i := 0; i < len(rest); i++ {
		if rest[i] != '(' || (i > 0 && rest[i-1] != ' ') {
			continue
		}
		end := strings.IndexByte(rest[i:], ')')
		if end < 0 {
			return "", "", false
		}
		end += i
		candidate := rest[i+1 : end]
		if !isEventName(candidate) {
			continue
		}
		after := rest[end+1:]
		if after == "" {
			return candidate, "", true
		}
		if after[0] == ' ' {
			return candidate, after[1:], true
		}
	}
	return "", "", false
}

func isEventName(s string) bool {
	dots := 0
	prev := byte('.')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if prev == '.' {
				return false
			}
			dots++
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
		prev = c
	}
	return dots > 0 && prev != '.'
}

// parseFields reads "key = value" pairs separated by ", ".
func parseFields(s string, ev *Event) bool {
	seen := map[string]bool{}
	for s != "" {
		key := keyLen(s)
		if key == 0 || !strings.HasPrefix(s[key:], " = ") {
			return false
		}
		name := s[:key]
		s = s[key+len(" = "):]
		var (
			scalar string
			list   []string
			isList bool
			null   bool
			ok     bool
		)
		switch {
		case strings.HasPrefix(s, `"`):
			scalar, s, ok = quoted(s)
		case strings.HasPrefix(s, "["):
			list, s, ok = listValue(s)
			isList = true
		case strings.HasPrefix(s, "(null)"):
			s, null, ok = s[len("(null)"):], true, true
		default:
			scalar, s, ok = bare(s, ", ")
		}
		if !ok {
			return false
		}
		if !seen[name] {
			seen[name] = true
			switch {
			case null:
			case isList:
				ev.Lists[name] = list
			default:
				ev.Fields[name] = scalar
			}
		}
		if s == "" {
			return true
		}
		var more bool
		s, more = strings.CutPrefix(s, ", ")
		if !more {
			return false
		}
	}
	return true
}

func keyLen(s string) int {
	n := 0
	for n < len(s) {
		c := s[n]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			n++
			continue
		}
		break
	}
	return n
}

// quoted reads a double-quoted string. A backslash escapes the next
// character; \n, \t, \r, \0 and \u{...} decode, others stand for themselves.
func quoted(s string) (value, rest string, ok bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b.String(), s[i+1:], true
		case '\\':
			i++
			if i >= len(s) {
				return "", "", false
			}
			switch e := s[i]; e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0':
				b.WriteByte(0)
			case 'u':
				r, n := unicodeEscape(s[i+1:])
				if n == 0 {
					b.WriteByte(e)
					continue
				}
				b.WriteRune(r)
				i += n
			default:
				b.WriteByte(e)
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

// unicodeEscape decodes "{hex}" after a \u, returning the rune and the bytes
// consumed, or 0 consumed when s does not start with a valid escape.
func unicodeEscape(s string) (rune, int) {
	if !strings.HasPrefix(s, "{") {
		return 0, 0
	}
	end := strings.IndexByte(s, '}')
	if end < 2 || end > 7 {
		return 0, 0
	}
	v, err := strconv.ParseUint(s[1:end], 16, 32)
	if err != nil || !utf8.ValidRune(rune(v)) {
		return 0, 0
	}
	return rune(v), end + 1
}

// listValue reads ["a", "b"]. Elements are quoted strings or bare tokens.
func listValue(s string) (list []string, rest string, ok bool) {
	s = s[1:]
	if after, empty := strings.CutPrefix(s, "]"); empty {
		return []string{}, after, true
	}
	for {
		var v string
		if strings.HasPrefix(s, `"`) {
			v, s, ok = quoted(s)
		} else {
			v, s, ok = bare(s, ", ", "]")
		}
		if !ok {
			return nil, "", false
		}
		list = append(list, v)
		if after, done := strings.CutPrefix(s, "]"); done {
			return list, after, true
		}
		var more bool
		s, more = strings.CutPrefix(s, ", ")
		if !more {
			return nil, "", false
		}
	}
}

// bare reads an unquoted token up to the first stop sequence or the end.
// It must be non-empty and contain no quote.
func bare(s string, stops ...string) (value, rest string, ok bool) {
	end := len(s)
	for _, stop := range stops {
		if i := strings.Index(s, stop); i >= 0 && i < end {
			end = i
		}
	}
	value = s[:end]
	if value == "" || strings.ContainsRune(value, '"') {
		return "", "", false
	}
	return value, s[end:], true
}
