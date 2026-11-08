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
	installModSecRegistryForTest(t, map[int]string{211999: "deny"})
	line := strings.TrimSuffix(liteSpeedTriggerLineUnknownDeny, "!") + `! [uri "/x[client 198.51.100.7]"] [data "[client 198.51.100.7]"]`
	got := escalationTargets(t, line)
	if len(got["modsec_block_escalation"]) == 0 {
		t.Fatalf("no escalation: %v", got)
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
	line := `[Wed Apr 01 17:13:54.047783 2026] [security2:error] [pid 1] ModSecurity: Access denied with code 403, [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "edge.example.net"] [uri "/x[client 198.51.100.7]"]`
	for check, ips := range escalationTargets(t, line) {
		for _, ip := range ips {
			if ip == "198.51.100.7" {
				t.Errorf("%s took the address from the URI", check)
			}
		}
	}
}

func TestApacheModSecIPv6ClientDropsPort(t *testing.T) {
	resetModSecState()
	line := `[Wed Apr 01 17:13:54.047783 2026] [security2:error] [pid 1] [client 2001:db8::5:5555] ModSecurity: Access denied with code 403, [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "edge.example.net"] [uri "/.env"]`
	got := escalationTargets(t, line)
	if len(got) == 0 {
		t.Fatalf("no findings: %v", got)
	}
	for check, ips := range got {
		for _, ip := range ips {
			if ip != "2001:db8::5" {
				t.Errorf("%s names %q, want 2001:db8::5", check, ip)
			}
		}
	}
}

func FuzzModSecClientIPIgnoresTextAfterMarker(f *testing.F) {
	f.Add(`[client 198.51.100.7]`, `[198.51.100.7:1-1#APVH_x]`)
	f.Add(`ModSecurity: [client 198.51.100.7:80]`, `[MODSEC] [198.51.100.7:5-H3:A-1#v]`)
	f.Fuzz(func(t *testing.T, apacheTail, liteSpeedTail string) {
		apache := `[Wed Apr 01 17:13:54.047783 2026] [security2:error] [pid 1] [client 203.0.113.50:5555] ModSecurity: ` + apacheTail
		liteSpeed := `2026-05-09 09:07:53.866619 [NOTICE] [1800848] [T4] [203.0.113.62:62060-H3:1FDA31C803B1F23A-44#APVH_test.example.com:443] [MODSEC] ` + liteSpeedTail
		if got := modsecClientIP(apache); got != "203.0.113.50" {
			t.Fatalf("Apache tail %q chose %q", apacheTail, got)
		}
		if got := modsecClientIP(liteSpeed); got != "203.0.113.62" {
			t.Fatalf("LiteSpeed tail %q chose %q", liteSpeedTail, got)
		}
	})
}
