package eximlog

import (
	"strings"
	"time"
)

// AuthenticatedUser reads the Dovecot authentication identity on an Exim
// arrival record. The envelope sender, HELO and quoted fields are not proof
// of authentication. The complete mainlog prefix must identify an arrival.
func AuthenticatedUser(line string) string {
	fields, ok := submissionFields(line)
	if !ok {
		return ""
	}
	return fields.auth
}

// Submitter returns an authenticated identity, or the local Exim caller on
// a non-network P=local arrival. A remote U= is an RFC 1413 identity and is
// never treated as a local account. The caller must resolve this identity
// against the local account inventory before assigning a tenant.
func Submitter(line string) string {
	fields, ok := submissionFields(line)
	if !ok {
		return ""
	}
	if fields.auth != "" {
		return fields.auth
	}
	if !fields.remote && !fields.authSeen && fields.protocol == "local" {
		return fields.user
	}
	return ""
}

type submitFields struct {
	auth, user, protocol string
	remote, authSeen     bool
}

func submissionFields(line string) (submitFields, bool) {
	var out submitFields
	accept := strings.Index(line, " <= ")
	if accept < 0 || !arrivalPrefix(line[:accept]) {
		return out, false
	}
	rest := line[accept+len(" <= "):]
	end := envelopeEnd(rest)
	if end <= 0 || end == len(rest) {
		return out, false
	}
	rest = rest[end:]
	if hStart, ok := HFieldStart(rest); ok {
		_, clientEnd := HFieldClientIPAndEnd(rest[hStart:])
		if clientEnd == 0 {
			return out, false
		}
		out.remote = true
		rest = rest[hStart+clientEnd:]
	}
	seen := map[string]bool{}
	for rest != "" {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" || strings.HasPrefix(rest, "T=") || strings.HasPrefix(rest, "for ") {
			break
		}
		end := fieldEnd(rest)
		field := rest[:end]
		key, value, hasValue := strings.Cut(field, "=")
		if hasValue && (key == "A" || key == "U" || key == "P") {
			if seen[key] {
				return submitFields{}, false
			}
			seen[key] = true
			switch key {
			case "A":
				out.authSeen = true
				authenticator, identity, ok := strings.Cut(value, ":")
				if ok && (authenticator == "dovecot_login" || authenticator == "dovecot_plain") {
					// smtp_mailauth can append an envelope identity after the
					// authenticated identity. Only the second A= item is trusted.
					out.auth, _, _ = strings.Cut(identity, ":")
					if strings.Count(out.auth, "@") > 1 || strings.HasPrefix(out.auth, "@") ||
						strings.HasSuffix(out.auth, "@") || strings.ContainsAny(out.auth, " \t\r\n\"\\") {
						return submitFields{}, false
					}
				}
			case "U":
				out.user = value
			case "P":
				out.protocol = value
			}
		}
		rest = rest[end:]
	}
	return out, true
}

// An arrival must start with a date, time, optional zone/PID and message ID.
// A <= fragment in a delivery reply or subject cannot supply an identity.
func arrivalPrefix(prefix string) bool {
	fields := strings.Fields(prefix)
	if len(fields) < 3 {
		return false
	}
	if _, err := time.Parse("2006-01-02 15:04:05", fields[0]+" "+fields[1]); err != nil {
		return false
	}
	fields = fields[2:]
	if _, err := time.Parse("-0700", fields[0]); err == nil {
		fields = fields[1:]
	}
	if len(fields) > 0 && strings.HasPrefix(fields[0], "[") {
		pid := fields[0]
		if len(pid) < 3 || pid[len(pid)-1] != ']' || strings.Trim(pid[1:len(pid)-1], "0123456789") != "" {
			return false
		}
		fields = fields[1:]
	}
	if len(fields) != 1 {
		return false
	}
	id := strings.Split(fields[0], "-")
	if len(id) != 3 {
		return false
	}
	for _, part := range id {
		if part == "" || strings.Trim(part, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return false
		}
	}
	return true
}

func envelopeEnd(s string) int {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch {
		case quoted && s[i] == '\\' && i+1 < len(s):
			i++
		case s[i] == '"':
			quoted = !quoted
		case !quoted && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n'):
			return i
		}
	}
	return len(s)
}

// fieldEnd consumes quoted values together so their contents cannot
// masquerade as authentication or local-user metadata.
func fieldEnd(s string) int {
	eq := strings.IndexByte(s, '=')
	space := strings.IndexAny(s, " \t\n")
	if eq < 0 || (space >= 0 && eq > space) || eq+1 >= len(s) || (s[eq+1] != '\'' && s[eq+1] != '"') {
		if space < 0 {
			return len(s)
		}
		return space
	}
	quote := s[eq+1]
	escaped := false
	for i := eq + 2; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\':
			escaped = true
		case s[i] == quote:
			return i + 1
		}
	}
	return len(s)
}
