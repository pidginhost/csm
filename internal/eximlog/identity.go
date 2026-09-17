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
// a non-network P=local arrival. Records containing a remote U= identity
// are ambiguous and cannot prove a submitter. The caller must resolve the
// returned identity against the local inventory before assigning a tenant.
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
	seen := map[string]bool{}
metadata:
	for rest != "" {
		rest = strings.TrimLeft(rest, " \t\r\n")
		// Exim writes submission metadata before the message size. Later
		// fields contain message data, including addr-spec message IDs with
		// quoted words that can resemble authentication or local-user fields.
		if rest == "" || strings.HasPrefix(rest, "S=") || strings.HasPrefix(rest, "T=") || strings.HasPrefix(rest, "for ") {
			break
		}
		// Only a top-level host field establishes a network submission.
		// Searching ahead would mistake H= inside message data for metadata.
		if strings.HasPrefix(rest, "H=") {
			_, clientEnd := HFieldClientIPAndEnd(rest[len("H="):])
			if out.remote || clientEnd == 0 {
				return submitFields{}, false
			}
			out.remote = true
			rest = rest[len("H=")+clientEnd:]
			continue
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
					auth, _, mailauth := strings.Cut(identity, ":")
					out.auth = auth
					if strings.Count(out.auth, "@") > 1 || strings.HasPrefix(out.auth, "@") ||
						strings.HasSuffix(out.auth, "@") || strings.ContainsAny(out.auth, " \t\r\n\"\\") {
						return submitFields{}, false
					}
					if mailauth {
						// The optional envelope is client-supplied xtext,
						// not additional submission metadata.
						break metadata
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
	// Exim appends remote RFC 1413 ident text without quoting spaces. It
	// can therefore imitate all following metadata, including A= and S=.
	// Neither an apparent authentication field nor its order proves an
	// identity on such a record. Local U= still comes from the server.
	if out.remote && seen["U"] {
		return submitFields{}, false
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
// masquerade as authentication or local-user metadata. Quotes can begin
// within a value, including an optional mailbox appended to an A= field.
func fieldEnd(s string) int {
	eq := strings.IndexByte(s, '=')
	var quote byte
	for i := 0; i < len(s); i++ {
		if quote != 0 {
			switch {
			case s[i] == '\\' && i+1 < len(s):
				i++
			case s[i] == quote:
				quote = 0
			}
			continue
		}
		switch {
		case s[i] == '"' || (s[i] == '\'' && eq >= 0 && i == eq+1):
			quote = s[i]
		case s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n':
			return i
		}
	}
	return len(s)
}
