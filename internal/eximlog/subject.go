package eximlog

import "strings"

// Subject returns the T= subject of an Exim arrival record. It reads only
// the arrival's own fields, so a T=" inside the sender, HELO or message ID
// is skipped. Exim writes a quote or backslash in the subject as \" or \\.
// A subject cut off by a truncated line is returned as far as it goes.
func Subject(line string) (string, bool) {
	accept := strings.Index(line, " <= ")
	if accept < 0 || !arrivalPrefix(line[:accept]) {
		return "", false
	}
	rest := line[accept+len(" <= "):]
	end := envelopeEnd(rest)
	if end <= 0 {
		return "", false
	}
	rest = rest[end:]
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" || strings.HasPrefix(rest, "for ") {
			return "", false
		}
		if strings.HasPrefix(rest, "H=") {
			_, clientEnd := HFieldClientIPAndEnd(rest[len("H="):])
			if clientEnd == 0 {
				return "", false
			}
			rest = rest[len("H=")+clientEnd:]
			continue
		}
		if quoted, ok := strings.CutPrefix(rest, `T="`); ok {
			return unescapeSubject(quoted), true
		}
		rest = rest[fieldEnd(rest):]
	}
}

func unescapeSubject(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"':
			return b.String()
		case s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\'):
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
