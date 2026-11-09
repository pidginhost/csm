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

// IsSubmission reports whether an arrival was submitted by a local process
// or authenticated SMTP client. Unlike Submitter, it does not require a
// tenant identity: Exim can authenticate without logging one, and local
// processes can submit SMTP on stdin instead of using P=local.
func IsSubmission(line string) bool {
	fields, ok := submissionFields(line)
	if !ok {
		return false
	}
	return (!fields.remote && fields.user != "") ||
		fields.protocol == "esmtpa" || fields.protocol == "esmtpsa"
}
