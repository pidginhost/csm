package eximlog

import (
	"regexp"
	"strings"
)

// Only the record prefix can establish a failure. Searching the whole line
// would accept an authenticator marker in HELO, a subject or an SMTP command.
var authFailurePrefix = regexp.MustCompile(`^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: [+-]\d{4})?(?: \[\d+\])? )?([A-Za-z0-9_]+) authenticator failed for `)

type AuthFailureRecord struct {
	Authenticator string
	ClientIP      string
	Code          string
	Account       string
}

// AuthFailure reads one Exim authentication failure. Missing or unreadable
// reply codes remain empty; callers must not treat them as credential checks.
func AuthFailure(line string) AuthFailureRecord {
	match := authFailurePrefix.FindStringSubmatchIndex(line)
	if match == nil {
		return AuthFailureRecord{}
	}
	ip, details := hostAndIdentClient(line[match[1]:])
	out := AuthFailureRecord{Authenticator: line[match[2]:match[3]], ClientIP: ip}
	// The attempted identity follows the reply, never the greeting. Preserve
	// its complete spelling so a delimiter in the name cannot alias trust.
	if _, account, ok := strings.Cut(details, " (set_id="); ok {
		if account, ok = strings.CutSuffix(account, ")"); ok {
			out.Account = account
		}
	}
	if len(details) < 4 || details[3] != ' ' {
		return out
	}
	for i := 0; i < 3; i++ {
		if details[i] < '0' || details[i] > '9' {
			return out
		}
	}
	out.Code = details[:3]
	return out
}
