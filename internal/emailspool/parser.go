package emailspool

import (
	"strings"

	"golang.org/x/net/idna"
)

// ExtractDomain returns the lowercased, IDN-normalised domain portion of an
// RFC 5322 address or display-name form. Returns "" on parse failure.
//
// Quoted local parts ("a@b"@example.com) are handled by treating the address
// as the substring after the LAST unquoted '@'.
func ExtractDomain(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.LastIndex(s, ">"); j > i {
			s = s[i+1 : j]
		}
	}
	at := lastUnquotedAt(s)
	if at < 0 {
		return ""
	}
	domain := strings.TrimSpace(s[at+1:])
	domain = strings.ToLower(domain)
	if ascii, err := idna.ToASCII(domain); err == nil {
		domain = ascii
	}
	return domain
}

// lastUnquotedAt returns the index of the rightmost '@' character that is not
// inside a double-quoted segment, or -1 if none.
func lastUnquotedAt(s string) int {
	inQuote := false
	last := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			i++ // skip the next byte (quoted-pair)
		case '"':
			inQuote = !inQuote
		case '@':
			if !inQuote {
				last = i
			}
		}
	}
	return last
}

// IsSubdomainOrEqual reports whether candidate is base or a subdomain of base.
// Both inputs are case-insensitive. Empty inputs return false.
func IsSubdomainOrEqual(candidate, base string) bool {
	if candidate == "" || base == "" {
		return false
	}
	c := strings.ToLower(strings.TrimSuffix(candidate, "."))
	b := strings.ToLower(strings.TrimSuffix(base, "."))
	if c == b {
		return true
	}
	return strings.HasSuffix(c, "."+b)
}
