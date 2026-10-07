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
			rest = rest[len("H=")+clientEnd:]
			continue
		}
		end := fieldEnd(rest)
		if rest[:end] == "for" {
			recipients := strings.Fields(rest[end:])
			if len(recipients) == 0 {
				return nil
			}
			return recipients
		}
		rest = rest[end:]
	}
}
