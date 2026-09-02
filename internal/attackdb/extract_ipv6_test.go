package attackdb

import "testing"

func TestExtractIPKeepsTrailingIPv6Groups(t *testing.T) {
	if got := extractIP("SMTP brute force from 2a01:4f8:1c17:abcd::"); got != "2a01:4f8:1c17:abcd::" {
		t.Fatalf("extractIP = %q, want the full address", got)
	}
	if got := extractIP("IP reputation hit: 203.0.113.5 (AbuseIPDB score 100)"); got != "203.0.113.5" {
		t.Fatalf("IPv4 with score suffix = %q", got)
	}
}
