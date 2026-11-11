package eximlog

import "strings"

// Subject returns the T= subject of an Exim arrival record. It reads only
// the arrival's own fields, so a T=" inside the sender, HELO or message ID
// is skipped. Records with unquoted remote ident or MAIL AUTH text are
// ambiguous and return no subject. Quote and backslash escapes are decoded;
// escapes for non-printing bytes stay as written.
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
	remote := false
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
			remote = true
			rest = rest[len("H=")+clientEnd:]
			continue
		}
		if quoted, ok := strings.CutPrefix(rest, `T="`); ok {
			return unescapeSubject(quoted), true
		}
		end := fieldEnd(rest)
		field := rest[:end]
		// These values are logged without quoting spaces, so their text
		// can imitate every later field, including the size and subject.
		if (remote && strings.HasPrefix(field, "U=")) ||
			(strings.HasPrefix(field, "A=") && strings.Count(field, ":") >= 2) {
			return "", false
		}
		rest = rest[end:]
	}
}

// unescapeSubject undoes only the \" and \\ quoting receive.c adds. The
// non-printing escapes stay as text rather than becoming terminal controls
// or line breaks in a finding. Literal tabs pass through as Exim logs them.
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
