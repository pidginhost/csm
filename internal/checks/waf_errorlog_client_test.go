package checks

import (
	"strings"
	"testing"
)

func TestModSecErrorLogClientAttribution(t *testing.T) {
	for _, tt := range []struct {
		name, prefix, want string
	}{
		{"apache", `[client 203.0.113.50:5555] ModSecurity: `, "203.0.113.50"},
		{"apache_ipv6", `[security2:error] [client 2001:db8::5:5555] ModSecurity: `, "2001:db8::5"},
		{"apache_missing", `[security2:error] ModSecurity: `, ""},
		{"apache_invalid", `[client invalid] ModSecurity: `, ""},
		{"litespeed", `[NOTICE] [1] [T1] [203.0.113.50:5555-1#APVH_example.test] [MODSEC] `, "203.0.113.50"},
		{"litespeed_ipv6", `[NOTICE] [1] [T1] [2001:db8::5:5555-1#APVH_example.test] [MODSEC] `, ""},
		{"litespeed_missing", `[NOTICE] [1] [T1] [MODSEC] `, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			line := tt.prefix + `Access denied with code 403 [id "900115"] [data "[client 198.51.100.7]"] [uri "/[198.51.100.7:5555-1#APVH_forged]"]`
			got := auditFindingIPs(t, strings.Repeat(line+"\n", 25))
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("untrusted client produced findings: %v", got)
				}
			} else if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("findings for %v, want only %s", got, tt.want)
			}
		})
	}
}

func TestModSecErrorLogCannotBecomeAuditIndex(t *testing.T) {
	for _, marker := range []string{"ModSecurity:", "[MODSEC]"} {
		line := marker + ` 198.51.100.7 - - [02/Jan/2026:03:04:05 +0000] "GET / HTTP/1.1" 403`
		if got := countModSecDenials([]string{line}); len(got) != 0 {
			t.Errorf("error-log message became an audit index: %v", got)
		}
		index := modsecIndexLine("example.test", "203.0.113.50", "GET /"+marker+" HTTP/1.1", "probe", 403)
		if got := countModSecDenials([]string{index}); len(got) != 1 || got["203.0.113.50"] != 1 {
			t.Errorf("audit-index request changed the client: %v", got)
		}
	}
}

func TestModSecAuditErrorLogPreservesPortlessIPv6(t *testing.T) {
	line := `2026/11/08 08:40:00 [error] 123#123: *1 [client 2001:db8::5:1234] ModSecurity: Access denied with code 403 [id "900115"]`
	got := auditFindingIPs(t, strings.Repeat(line+"\n", 25))
	if len(got) != 1 || got[0] != "2001:db8::5:1234" {
		t.Fatalf("audit findings = %v, want only the complete IPv6 client", got)
	}
}
