package modsec

import "testing"

func TestExtractLiteSpeedIP_Standard(t *testing.T) {
	line := `2026-04-01 [NOTICE] [203.0.113.57:41920-13#APVH_*_server.example.com] [MODSEC] triggered!`
	got := liteSpeedClientIP(line)
	if got != "203.0.113.57" {
		t.Errorf("got %q, want 203.0.113.57", got)
	}
}

func TestExtractLiteSpeedIP_NoMatch(t *testing.T) {
	if got := liteSpeedClientIP("no bracketed IP here"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractLiteSpeedIP_BracketButNotLiteSpeed(t *testing.T) {
	// A bracket without the #-conn pattern should not match.
	if got := liteSpeedClientIP("[plain text] more text"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractLiteSpeedIP_NoCloseBracket(t *testing.T) {
	if got := liteSpeedClientIP("[203.0.113.57:41920-13#APVH_*_server.example.com"); got != "" {
		t.Errorf("unclosed bracket should return empty, got %q", got)
	}
}

func TestExtractLiteSpeedIP_IPv6NotMatched(t *testing.T) {
	// The IPv6 connection format is not supported.
	line := `[2001:db8::1:41920-13#APVH_*_host] [MODSEC] triggered!`
	if got := liteSpeedClientIP(line); got != "" {
		t.Errorf("Unsupported IPv6 should not name a client, got %q", got)
	}
}

func TestErrorLogClientIP(t *testing.T) {
	for _, tt := range []struct{ name, line, want string }{
		{"apache_legacy", `[client 203.0.113.5] ModSecurity: Access denied`, "203.0.113.5"},
		{"apache_port", `[client 203.0.113.5:65535] ModSecurity: Access denied`, "203.0.113.5"},
		{"apache_ipv6", `[client 2001:db8::5:5555] ModSecurity: Access denied`, "2001:db8::5"},
		{"apache_ipv6_full", `[client 2001:db8:1:2:3:4:5:6:65535] ModSecurity: Access denied`, "2001:db8:1:2:3:4:5:6"},
		{"apache_ipv6_compressed_tail", `[client 2001:db8:::5555] ModSecurity: Access denied`, "2001:db8::"},
		{"apache_mapped", `[client ::ffff:192.0.2.5:5555] ModSecurity: Access denied`, "192.0.2.5"},
		{"apache_invalid_port", `[client 203.0.113.5:invalid] ModSecurity: Access denied`, ""},
		{"apache_missing_close", `[client 203.0.113.5 ModSecurity: [client 198.51.100.7]`, ""},
		{"apache_invalid_first", `[client invalid] [client 198.51.100.7] ModSecurity: Access denied`, ""},
		{"no_marker", `[client 203.0.113.5]`, ""},
		{"litespeed_h3", `[NOTICE] [1] [T4] [203.0.113.5:5555-H3:A-1#APVH_example.test:443] [MODSEC] triggered!`, "203.0.113.5"},
		{"litespeed_invalid_ip", `[203.0.113.999:5555-1#APVH_example.test] [198.51.100.7:5555-1#APVH_forged] [MODSEC] triggered!`, ""},
		{"litespeed_invalid_port", `[203.0.113.5:invalid-1#APVH_example.test] [MODSEC] triggered!`, ""},
		{"litespeed_missing_id", `[203.0.113.5:5555-#APVH_example.test] [MODSEC] triggered!`, ""},
		{"litespeed_missing_vhost", `[203.0.113.5:5555-1#] [MODSEC] triggered!`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ErrorLogClientIP(tt.line); got != tt.want {
				t.Fatalf("client = %q, want %q", got, tt.want)
			}
		})
	}
}
