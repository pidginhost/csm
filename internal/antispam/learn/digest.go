// Package learn turns Spam folder reports and operator requests into anchor
// values in rspamd's local fuzzy storage (spec 7.4): a strict controller
// client, the ledger, anchor bodies, assignment, publication and audits.
package learn

import (
	"errors"
	"strings"
)

// Digest is a full fuzzy digest: 128 lowercase hex digits.
type Digest string

// ParseDigest accepts only a full digest; a prefix never names a hash.
func ParseDigest(s string) (Digest, error) {
	if len(s) != 128 || strings.ContainsFunc(s, func(r rune) bool { return (r < '0' || r > '9') && (r < 'a' || r > 'f') }) {
		return "", errors.New("not a 128-digit lowercase hex digest")
	}
	return Digest(s), nil
}
