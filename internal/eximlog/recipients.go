package eximlog

import "strings"

// Recipients returns the envelope recipients Exim logged after the top-level
// "for" of an arrival record. Quoted subjects, HELO text and quoted envelope
// senders can carry the same word, so fields are consumed with the quoting
// rules of the submission metadata. Nil when the record is not an arrival or
// logs no recipient list.
func Recipients(line string) []string {
	accept := strings.Index(line, " <= ")
	if accept < 0 || !arrivalPrefix(line[:accept]) {
		return nil
	}
	rest := line[accept+len(" <= "):]
	end := envelopeEnd(rest)
	if end <= 0 || end == len(rest) {
		return nil
	}
	rest = rest[end:]
	remote := false
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" {
			return nil
		}
		if strings.HasPrefix(rest, "H=") {
			_, clientEnd := HFieldClientIPAndEnd(rest[len("H="):])
			if clientEnd == 0 {
				return nil
			}
			remote = true
			rest = rest[len("H=")+clientEnd:]
			continue
		}
		end := fieldEnd(rest)
		field := rest[:end]
		// Remote ident and the optional MAIL AUTH envelope are logged as
		// unquoted client text. Neither can prove where the list begins.
		if (remote && strings.HasPrefix(field, "U=")) ||
			(strings.HasPrefix(field, "A=") && strings.Count(field, ":") >= 2) {
			return nil
		}
		if field == "for" {
			return recipientAddresses(rest[end:])
		}
		rest = rest[end:]
	}
}

// A quoted local part is one recipient even when it contains whitespace.
// Reject incomplete quoting instead of counting fragments of an address.
func recipientAddresses(rest string) []string {
	var recipients []string
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" {
			return recipients
		}
		end := envelopeEnd(rest)
		address := rest[:end]
		quoted := false
		for i := 0; i < len(address); i++ {
			if quoted && address[i] == '\\' && i+1 < len(address) {
				i++
			} else if address[i] == '"' {
				quoted = !quoted
			}
		}
		if quoted {
			return nil
		}
		recipients = append(recipients, address)
		rest = rest[end:]
	}
}
