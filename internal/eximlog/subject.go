package eximlog

import "strings"

// Subject returns the T= subject of an Exim arrival record. It reads only
// the arrival's own fields, so a T=" inside the sender, HELO or message ID
// is skipped. Records with unquoted remote ident or MAIL AUTH text are
// ambiguous and return no subject. Exim escapes subject quotes, backslashes
// and non-printing bytes; literal escape text is decoded only once.
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

func unescapeSubject(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			return b.String()
		}
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"', '\\':
				i++
				c = s[i]
			case 'n', 'r', 'b', 'v', 'f', 't':
				i++
				c = "\n\r\b\v\f\t"[strings.IndexByte("nrbvft", s[i])]
			case '0', '1', '2', '3':
				// string_printing writes exactly three octal digits per byte.
				// Keep incomplete or unknown escapes in truncated logs intact.
				if i+3 < len(s) && s[i+2] >= '0' && s[i+2] <= '7' && s[i+3] >= '0' && s[i+3] <= '7' {
					c = (s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0')
					i += 3
				}
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}
