package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
)

// With AddressEvidence wired as the daemon wires it, a C2 connection joins
// its account's incident and completes the webshell plus C2 rule, but its
// address is never the incident's attacker. An attacker finding for the
// same address still is.
func TestC2IncidentIsNoAttackerEvidence(t *testing.T) {
	const ip = "203.0.113.9"
	run := func(t *testing.T, findings ...alert.Finding) (incident.Incident, []string) {
		t.Helper()
		var blocked []string
		c := incident.NewCorrelator(incident.CorrelatorConfig{
			OpenThreshold:   1,
			AutoBlock:       incident.IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"},
			AddressEvidence: AddressEvidence,
			OnIncidentBlock: func(ip, _ string, _ time.Duration, _ string, _ incident.PreparedRoot) bool {
				blocked = append(blocked, ip)
				return true
			},
		})
		var id string
		for _, f := range findings {
			f.Timestamp = time.Now()
			got, _, err := c.OnFinding(f)
			if err != nil {
				t.Fatal(err)
			}
			if got != "" {
				id = got
			}
		}
		inc, ok := c.Get(id)
		if !ok {
			t.Fatalf("no incident %q", id)
		}
		return inc, blocked
	}
	webshell := alert.Finding{Check: "webshell", Severity: alert.Critical, TenantID: "acct"}
	c2 := alert.Finding{Check: "c2_connection", Severity: alert.Critical, TenantID: "acct", SourceIP: ip, Message: "Connection to known C2 IP: " + ip + ":443"}
	for _, order := range [][]alert.Finding{{webshell, c2}, {c2, webshell}} {
		inc, blocked := run(t, order...)
		if inc.Kind != incident.KindPostExploitProcess || !inc.CompoundFlags.C2 {
			t.Fatalf("kind %s flags %+v, want the webshell plus C2 rule", inc.Kind, inc.CompoundFlags)
		}
		if inc.RemoteIPEvidence || len(blocked) != 0 {
			t.Fatalf("evidence %v, blocks %v; a C2 address is no attacker", inc.RemoteIPEvidence, blocked)
		}
	}
	attacker := alert.Finding{Check: "ftp_bruteforce", Severity: alert.High, TenantID: "acct", SourceIP: ip}
	if _, blocked := run(t, webshell, c2, attacker); len(blocked) != 1 || blocked[0] != ip {
		t.Fatalf("blocks = %v, want the attacker address once", blocked)
	}
}
