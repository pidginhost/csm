package eximlog

import "strings"

// Arrival returns the message ID and envelope sender of an Exim arrival
// ("<=") record. The marker counts only after the complete mainlog prefix,
// so a "<=" inside a delivery reply or subject is not an arrival. A bounce
// has the sender "<>".
func Arrival(line string) (id, sender string, ok bool) {
	accept := strings.Index(line, " <= ")
	if accept < 0 || !arrivalPrefix(line[:accept]) {
		return "", "", false
	}
	prefix := strings.Fields(line[:accept])
	rest := line[accept+len(" <= "):]
	end := envelopeEnd(rest)
	if end <= 0 {
		return "", "", false
	}
	return prefix[len(prefix)-1], rest[:end], true
}
