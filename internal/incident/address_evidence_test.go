package incident

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// registryEvidence stands in for checks.AddressEvidence, which this package
// cannot import: checks depends on incident.
func registryEvidence(check string, sev alert.Severity) bool {
	switch check {
	case "xmlrpc_abuse", "wp_login_bruteforce", "modsec_csm_block_escalation", "c2_connection", "email_compromised_account":
		return true
	case "mail_account_compromised":
		return sev == alert.Critical
	}
	return false
}

func evidenceCorrelator(t *testing.T, atSeverity string) (*Correlator, *blockCapture, *time.Time) {
	t.Helper()
	cap := &blockCapture{}
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold:   1,
		AutoBlock:       IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: atSeverity},
		AddressEvidence: registryEvidence,
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	return c, cap, &now
}

func feed(t *testing.T, c *Correlator, now *time.Time, findings ...alert.Finding) string {
	t.Helper()
	var id string
	for _, f := range findings {
		*now = now.Add(time.Second)
		f.Timestamp = *now
		got, _, err := c.OnFinding(f)
		if err != nil {
			t.Fatalf("OnFinding(%s): %v", f.Check, err)
		}
		if got == "" {
			t.Fatalf("OnFinding(%s) opened or joined no incident", f.Check)
		}
		if id != "" && got != id {
			t.Fatalf("OnFinding(%s) joined incident %s, want %s", f.Check, got, id)
		}
		id = got
	}
	return id
}

// Outbound checks report the remote end of a local connection as SourceIP.
// That address is a destination, not an attacker, so an incident must not
// block it, whichever way the incident picked it up.
func TestAutoBlockRefusesAddressWithoutEvidence(t *testing.T) {
	const dest = "203.0.113.7"
	for _, tc := range []struct {
		name     string
		findings []alert.Finding
	}{
		{"correlation key", []alert.Finding{
			{Check: "backdoor_port_outbound", Severity: alert.Critical, SourceIP: dest},
		}},
		{"host timeline", []alert.Finding{
			{Check: "uid0_account", Severity: alert.Critical},
			{Check: "bad_asn_outbound", Severity: alert.High, SourceIP: dest},
		}},
		{"account timeline", []alert.Finding{
			{Check: "webshell", Severity: alert.Critical, TenantID: "acct1"},
			{Check: "backdoor_port_outbound", Severity: alert.High, TenantID: "acct1", SourceIP: dest},
		}},
		// Evidence about the mailbox that names no address does not
		// attest the owner's own login address.
		{"mailbox owner login", []alert.Finding{
			{Check: "email_compromised_account", Severity: alert.Critical, Mailbox: "owner@example.com"},
			{Check: "email_suspicious_geo", Severity: alert.High, Mailbox: "owner@example.com", SourceIP: dest},
		}},
		{"account timeline below the severity floor", []alert.Finding{
			{Check: "webshell", Severity: alert.Critical, TenantID: "acct3"},
			{Check: "mail_account_compromised", Severity: alert.High, TenantID: "acct3", SourceIP: dest},
		}},
		{"evidence below its severity floor", []alert.Finding{
			{Check: "mail_account_compromised", Severity: alert.High, SourceIP: dest},
			{Check: "email_php_relay_abuse", Severity: alert.Critical, SourceIP: dest},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cap, now := evidenceCorrelator(t, "high")
			id := feed(t, c, now, tc.findings...)
			inc, ok := c.Get(id)
			if !ok || inc.Severity != alert.Critical || incidentBlockCandidate(&inc) != dest {
				t.Fatalf("precondition: incident %+v should be Critical with block candidate %s", inc, dest)
			}
			if got := cap.len(); got != 0 {
				t.Fatalf("blocked %d times on an address no evidence named", got)
			}
		})
	}
}

func TestAutoBlockKeepsAddressWithEvidence(t *testing.T) {
	const ip = "198.51.100.9"
	for _, tc := range []struct {
		name     string
		findings []alert.Finding
	}{
		{"correlation key", []alert.Finding{
			{Check: "email_php_relay_abuse", Severity: alert.Critical, SourceIP: ip},
			{Check: "xmlrpc_abuse", Severity: alert.High, SourceIP: ip},
		}},
		{"account timeline", []alert.Finding{
			{Check: "webshell", Severity: alert.Critical, TenantID: "acct2"},
			// The listed C2 server is a destination whose block is the
			// reviewed response.
			{Check: "c2_connection", Severity: alert.High, TenantID: "acct2", SourceIP: ip},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cap, now := evidenceCorrelator(t, "critical")
			feed(t, c, now, tc.findings...)
			if got := cap.len(); got != 1 || cap.calls[0].IP != ip {
				t.Fatalf("calls = %+v, want one block of the attested address", cap.calls)
			}
		})
	}
}

// A long incident trims the middle of its timeline. The finding that named
// the correlation key's address as evidence may be trimmed away; the
// incident must still remember it.
func TestAutoBlockEvidenceSurvivesTimelineTrimming(t *testing.T) {
	const ip = "198.51.100.10"
	c, cap, now := evidenceCorrelator(t, "critical")
	filler := alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, SourceIP: ip}
	var findings []alert.Finding
	for range maxIncidentTimeline / 2 {
		findings = append(findings, filler)
	}
	findings = append(findings, alert.Finding{Check: "xmlrpc_abuse", Severity: alert.High, SourceIP: ip})
	for range maxIncidentTimeline {
		findings = append(findings, filler)
	}
	id := feed(t, c, now, findings...)
	inc, _ := c.Get(id)
	truncated := false
	for _, ev := range inc.Timeline {
		if ev.Check == "xmlrpc_abuse" {
			t.Fatal("precondition: the evidence event is still in the timeline")
		}
		truncated = truncated || ev.Kind == incidentTimelineTruncatedKind
	}
	if !truncated || cap.len() != 0 {
		t.Fatalf("precondition: truncated=%v blocks=%d", truncated, cap.len())
	}
	feed(t, c, now, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.Critical, SourceIP: ip})
	if got := cap.len(); got != 1 || cap.calls[0].IP != ip {
		t.Fatalf("calls = %+v, want one block of the key address", cap.calls)
	}
}

// The remembered evidence is part of the stored incident, so a restart
// that reloads it keeps blocking the address.
func TestIncidentAddressEvidenceIsPersisted(t *testing.T) {
	c, _, now := evidenceCorrelator(t, "critical")
	id := feed(t, c, now, alert.Finding{Check: "xmlrpc_abuse", Severity: alert.High, SourceIP: "198.51.100.11"})
	inc, _ := c.Get(id)
	raw, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	var back Incident
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !inc.RemoteIPEvidence || !back.RemoteIPEvidence {
		t.Fatalf("evidence remembered %v, after reload %v", inc.RemoteIPEvidence, back.RemoteIPEvidence)
	}
}
