package daemon

import (
	"strings"
	"unicode/utf8"
)

// maxSprayMailboxBytes is the longest mailbox name kept as a spray key. It
// matches the longest address SMTP allows.
const maxSprayMailboxBytes = 254

// normalizeSprayMailbox is the one spelling of a mailbox name for both failed
// and successful logins, so trust earned by a login matches the failures
// logged for that mailbox. Names are client-chosen, so the key is bounded.
func normalizeSprayMailbox(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) <= maxSprayMailboxBytes {
		return s
	}
	n := maxSprayMailboxBytes
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
