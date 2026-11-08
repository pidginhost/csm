package webui

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestModSecClientUsesTrustedFields(t *testing.T) {
	for _, tt := range []struct {
		name    string
		finding alert.Finding
		want    string
	}{
		{"structured_ipv6", alert.Finding{SourceIP: "2001:db8::5", Message: "ModSecurity blocked request from 198.51.100.7"}, "2001:db8::5"},
		{"message_payload", alert.Finding{Message: "ModSecurity blocked request: rule 900115 uri=/probe from 198.51.100.7"}, ""},
		{"nginx_file_error", alert.Finding{Details: `2026/11/08 08:40:00 [error] 123#123: *1 open() "/srv/www/[client 198.51.100.7] ModSecurity: Access denied with code 403" failed (2: No such file or directory), client: 203.0.113.50`}, ""},
		{"apache_ipv6", alert.Finding{Details: `[security2:error] [client 2001:db8::5:5555] ModSecurity: Access denied`}, "2001:db8::5"},
		{"portless_ipv6", alert.Finding{Details: `2026/11/08 08:40:00 [error] 123#123: *1 [client 2001:db8::5:1234] ModSecurity: Access denied`}, "2001:db8::5:1234"},
		{"apache_missing", alert.Finding{Details: `ModSecurity: Access denied [data "[client 198.51.100.7]"]`}, ""},
		{"litespeed_ipv6", alert.Finding{Details: `[2001:db8::5:5555-1#APVH_example.test] [MODSEC] Access denied [uri "/[client 198.51.100.7]"]`}, ""},
		{"structured_raw", alert.Finding{Details: "Rule: 900115\nMessage: [client 198.51.100.7]\nHostname: example.test\nURI: /probe\nRaw: [client 203.0.113.50:5555] ModSecurity: Access denied"}, "203.0.113.50"},
		{"structured_without_raw", alert.Finding{Details: "Rule: 900115\nMessage: [client 198.51.100.7] ModSecurity: Access denied\nURI: /probe"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractModSecIP(tt.finding); got != tt.want {
				t.Fatalf("client = %q, want %q", got, tt.want)
			}
		})
	}
}
