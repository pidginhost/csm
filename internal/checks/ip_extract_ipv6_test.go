package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// An IPv6 source ending in "::" (a common shape for a /64 holder's first
// address) must survive extraction intact: the old cutset trimmed the
// trailing colons, the remnant was neither a valid address nor blockable.
func TestExtractIPAfterKeywordKeepsTrailingIPv6Groups(t *testing.T) {
	line := "Sep  2 04:12:33 host dovecot: imap-login: Aborted login (auth failed, 1 attempts): user=<x@y>, method=PLAIN, rip=2a01:4f8:1c17:abcd::, lip=203.0.113.1, TLS"
	if got := extractIPAfterKeyword(line, "rip="); got != "2a01:4f8:1c17:abcd::" {
		t.Fatalf("rip= extraction = %q, want the full address", got)
	}
	if got := extractIPAfterKeyword("Accepted publickey for root from 198.51.100.7 port 22", "from"); got != "198.51.100.7" {
		t.Fatalf("IPv4 extraction changed: %q", got)
	}
}

func TestExtractIPFromFindingKeepsTrailingIPv6Groups(t *testing.T) {
	f := alert.Finding{Check: "wp_login_bruteforce", Message: "WordPress brute force from 2a01:4f8:1c17:abcd::"}
	if got := extractIPFromFinding(f); got != "2a01:4f8:1c17:abcd::" {
		t.Fatalf("message fallback = %q, want the full address", got)
	}
}
