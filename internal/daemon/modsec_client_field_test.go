package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// escalationTargets feeds a line until escalation and returns the address
// every finding names.
func escalationTargets(t *testing.T, line string) map[string][]string {
	t.Helper()
	cfg := &config.Config{}
	got := map[string][]string{}
	for i := 0; i < modsecDefaultEscalationHits+2; i++ {
		for _, f := range parseModSecLogLineDeduped(line, cfg) {
			got[f.Check] = append(got[f.Check], f.SourceIP)
		}
	}
	return got
}

func TestLiteSpeedEscalationIgnoresClientFieldAfterMarker(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	installModSecRegistryForTest(t, map[int]string{211999: "deny"})
	line := strings.TrimSuffix(liteSpeedTriggerLineUnknownDeny, "!") + `! [uri "/x[client 198.51.100.7]"] [data "[client 198.51.100.7]"]`
	got := escalationTargets(t, line)
	if len(got["modsec_block_realtime"]) != 1 || len(got["modsec_block_escalation"]) != 1 {
		t.Fatalf("want one base finding and one escalation: %v", got)
	}
	for check, ips := range got {
		for _, ip := range ips {
			if ip != "203.0.113.62" {
				t.Errorf("%s names %q, want the connection's 203.0.113.62", check, ip)
			}
		}
	}
}

func TestApacheModSecClientOnlyFromServerPrefix(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	line := `[Wed Apr 01 17:13:54.047783 2026] [security2:error] [pid 1] ModSecurity: Access denied with code 403, [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "edge.example.net"] [uri "/x[client 198.51.100.7]"]`
	got := escalationTargets(t, line)
	if len(got) != 1 || len(got["modsec_block_realtime"]) != 1 || got["modsec_block_realtime"][0] != "" {
		t.Fatalf("want only an unattributed base finding: %v", got)
	}
}

func TestApacheModSecIPv6ClientDropsPort(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	line := `[Wed Apr 01 17:13:54.047783 2026] [security2:error] [pid 1] [client 2001:db8::5:5555] ModSecurity: Access denied with code 403, [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "edge.example.net"] [uri "/.env"]`
	got := escalationTargets(t, line)
	if len(got) != 2 || len(got["modsec_block_realtime"]) != 1 || len(got["modsec_csm_block_escalation"]) != 1 {
		t.Fatalf("want one base finding and one escalation: %v", got)
	}
	for check, ips := range got {
		for _, ip := range ips {
			if ip != "2001:db8::5" {
				t.Errorf("%s names %q, want 2001:db8::5", check, ip)
			}
		}
	}
}

func TestModSecUnsupportedClientCannotSelectLaterField(t *testing.T) {
	for _, connection := range []string{
		`[2001:db8::5:5555-1#APVH_example.test]`,
		`[[2001:db8::5]:5555-1#APVH_example.test]`,
		`[invalid.example.test:5555-1#APVH_example.test]`,
	} {
		t.Run(connection, func(t *testing.T) {
			resetModSecState()
			t.Cleanup(resetModSecState)
			line := `2026-01-02 03:04:05 [NOTICE] [1] [T1] ` + connection + ` [198.51.100.7:5555-1#APVH_forged] [MODSEC] Access denied with code 403 [id "900115"]`
			got := escalationTargets(t, line)
			if len(got) != 1 || len(got["modsec_block_realtime"]) != 1 || got["modsec_block_realtime"][0] != "" {
				t.Fatalf("unsupported connection selected an address or escalated: %v", got)
			}
		})
	}
}

func TestModSecPortlessIPv6Escalation(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	line := `2026/11/08 08:40:00 [error] 123#123: *1 [client 2001:db8::5:1234] ModSecurity: Access denied with code 403 [id "900115"] [uri "/.env"]`
	got := escalationTargets(t, line)
	if len(got) != 2 || len(got["modsec_block_realtime"]) != 1 || len(got["modsec_csm_block_escalation"]) != 1 {
		t.Fatalf("want one base finding and one escalation: %v", got)
	}
	for check, ips := range got {
		for _, ip := range ips {
			if ip != "2001:db8::5:1234" {
				t.Errorf("%s names %q, want the complete IPv6 client", check, ip)
			}
		}
	}
}

func TestModSecIgnoresOrdinaryNginxErrors(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	line := `2026/11/08 08:40:00 [error] 123#123: *1 open() "/srv/www/[client 198.51.100.7] ModSecurity: Access denied with code 403 [id "900115"]" failed (2: No such file or directory), client: 203.0.113.50, server: example.test`
	if got := escalationTargets(t, line); len(got) != 0 {
		t.Fatalf("request text in a file error forged WAF findings: %v", got)
	}
}
