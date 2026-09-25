package incident

import (
	"encoding/json"
	"strconv"
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

func TestAddressEvidencePendingFindingsSurviveImmediateOpen(t *testing.T) {
	const ip = "198.51.100.12"
	for _, tc := range []struct {
		name    string
		pending alert.Finding
		opener  alert.Finding
	}{
		{"key", alert.Finding{Check: "xmlrpc_abuse", Severity: alert.High, SourceIP: ip},
			alert.Finding{Check: "email_php_relay_abuse", Severity: alert.Critical, SourceIP: ip}},
		{"account", alert.Finding{Check: "c2_connection", Severity: alert.High, TenantID: "acct", SourceIP: ip},
			alert.Finding{Check: "webshell", Severity: alert.Critical, TenantID: "acct"}},
	} {
		for _, stale := range []bool{false, true} {
			t.Run(tc.name+"/stale="+strconv.FormatBool(stale), func(t *testing.T) {
				c, cap, now := evidenceCorrelator(t, "critical")
				c.openThreshold = 2
				tc.pending.Timestamp = *now
				if id, created, err := c.OnFinding(tc.pending); id != "" || created || err != nil {
					t.Fatalf("pending finding: id=%q created=%v err=%v", id, created, err)
				}
				if stale {
					*now = now.Add(incidentMergeWindow)
				}
				id := feed(t, c, now, tc.opener)
				inc, _ := c.Get(id)
				wantEvents, wantBlocks := 2, 1
				if stale {
					wantEvents, wantBlocks = 1, 0
				}
				if got := cap.len(); got != wantBlocks {
					t.Errorf("blocks = %d, want %d", got, wantBlocks)
				}
				if len(inc.Timeline) != wantEvents || c.PendingCount() != 0 {
					t.Fatalf("timeline=%d pending=%d, want %d events and no pending findings", len(inc.Timeline), c.PendingCount(), wantEvents)
				}
				if !stale && (inc.Timeline[0].FindingID != alert.FindingID(tc.pending) || cap.len() != 1 || cap.calls[0].IP != ip) {
					t.Fatal("pending evidence or block address was not preserved")
				}
			})
		}
	}
}

func TestAddressEvidenceTransitionPersistsBeforeReload(t *testing.T) {
	const ip = "198.51.100.13"
	c, cap, now := evidenceCorrelator(t, "critical")
	var stored []byte
	writes := 0
	c.cfg.Persist = func(inc Incident) error {
		var err error
		stored, err = json.Marshal(inc)
		writes++
		return err
	}
	id := feed(t, c, now,
		alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, SourceIP: ip},
		alert.Finding{Check: "c2_connection", Severity: alert.High, SourceIP: ip},
	)
	if cap.len() != 0 || writes != 2 {
		t.Errorf("blocks=%d writes=%d, want no blocks and immediate persistence of new evidence", cap.len(), writes)
	}
	feed(t, c, now, alert.Finding{Check: "c2_connection", Severity: alert.High, SourceIP: ip})
	if writes != 2 {
		t.Errorf("repeated attestation bypassed bookkeeping debounce: writes=%d, want 2", writes)
	}
	var restored Incident
	if err := json.Unmarshal(stored, &restored); err != nil {
		t.Fatal(err)
	}
	if !restored.RemoteIPEvidence {
		t.Error("stored incident lost the new attestation")
	}
	c, cap, _ = evidenceCorrelator(t, "critical")
	c.now = func() time.Time { return *now }
	c.Restore([]Incident{restored})
	if got := feed(t, c, now, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.Critical, SourceIP: ip}); got != id {
		t.Fatalf("reload opened %s, want %s", got, id)
	}
	if cap.len() != 1 || cap.calls[0].IP != ip {
		t.Fatalf("blocks after reload = %+v, want one block", cap.calls)
	}
}

func TestAddressEvidenceLegacyRestoreSurvivesTrimming(t *testing.T) {
	const ip = "2001:db8::14"
	c, cap, now := evidenceCorrelator(t, "critical")
	legacy := Incident{
		ID: "legacy", Kind: KindWebAttack, Status: StatusOpen, Severity: alert.High,
		CorrelationKey: &Key{RemoteIP: ip}, CreatedAt: *now, UpdatedAt: *now,
	}
	for range maxIncidentTimeline {
		legacy.Timeline = append(legacy.Timeline, IncidentEvent{
			Kind: "finding", Check: "email_php_relay_abuse", Severity: "HIGH", RemoteIP: ip,
		})
	}
	legacy.Timeline[maxIncidentTimeline/2] = IncidentEvent{
		Kind: "finding", Check: "xmlrpc_abuse", Severity: "HIGH", RemoteIP: "[2001:db8::14]:443",
	}
	c.Restore([]Incident{legacy})
	feed(t, c, now, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, SourceIP: ip})
	inc, _ := c.Get(legacy.ID)
	for _, ev := range inc.Timeline {
		if ev.Check == "xmlrpc_abuse" {
			t.Fatal("precondition: evidence event was not trimmed")
		}
	}
	if !inc.RemoteIPEvidence {
		t.Error("legacy key evidence was not retained")
	}
	feed(t, c, now, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.Critical, SourceIP: ip})
	if cap.len() != 1 || cap.calls[0].IP != ip {
		t.Fatalf("blocks = %+v, want one block after legacy evidence was trimmed", cap.calls)
	}
}

func TestAddressEvidenceLegacySeverity(t *testing.T) {
	const ip = "198.51.100.15"
	for _, tc := range []struct {
		name, check, severity, address string
		want                           bool
	}{
		{"no floor", "xmlrpc_abuse", "", ip, true},
		{"floor unknown", "mail_account_compromised", "", ip, false},
		{"floor unmet", "mail_account_compromised", "HIGH", ip, false},
		{"floor met", "mail_account_compromised", "CRITICAL", ip, true},
		{"invalid severity", "xmlrpc_abuse", "invalid", ip, false},
		{"different address", "xmlrpc_abuse", "HIGH", "198.51.100.16", false},
		{"no address", "xmlrpc_abuse", "HIGH", "", false},
		{"no evidence", "backdoor_port_outbound", "CRITICAL", ip, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cap, now := evidenceCorrelator(t, "critical")
			legacy := Incident{
				ID: "legacy", Kind: KindWebAttack, Status: StatusOpen, Severity: alert.Critical,
				CorrelationKey: &Key{RemoteIP: ip}, CreatedAt: *now, UpdatedAt: *now,
				Timeline: []IncidentEvent{{Kind: "finding", Check: tc.check, Severity: tc.severity, RemoteIP: tc.address}},
			}
			c.Restore([]Incident{legacy})
			feed(t, c, now, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, SourceIP: ip})
			wantBlocks := 0
			if tc.want {
				wantBlocks = 1
			}
			if got := cap.len(); got != wantBlocks {
				t.Errorf("blocks=%d, want evidence=%v", got, tc.want)
			}
			inc, _ := c.Get(legacy.ID)
			if inc.RemoteIPEvidence != tc.want {
				t.Errorf("remembered evidence=%v, want %v", inc.RemoteIPEvidence, tc.want)
			}
		})
	}
}

func TestAddressEvidenceReopenAndNewIncident(t *testing.T) {
	const ip = "198.51.100.17"
	c, cap, now := evidenceCorrelator(t, "critical")
	id := feed(t, c, now, alert.Finding{Check: "xmlrpc_abuse", Severity: alert.Critical, SourceIP: ip})
	if cap.len() != 1 {
		t.Fatal("attested incident did not block")
	}
	if err := c.SetStatus(id, StatusResolved, "resolved"); err != nil {
		t.Fatal(err)
	}
	closed, _ := c.Get(id)
	c = NewCorrelator(c.cfg)
	c.now = func() time.Time { return *now }
	c.Restore([]Incident{closed})
	if err := c.SetStatus(id, StatusOpen, "reopened"); err != nil {
		t.Fatal(err)
	}
	if got := feed(t, c, now, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, SourceIP: ip}); got != id {
		t.Fatalf("reopened incident id = %s, want %s", got, id)
	}
	if cap.len() != 2 || cap.calls[1].IP != ip {
		t.Fatalf("reopened incident lost evidence: blocks=%+v", cap.calls)
	}
	if err := c.SetStatus(id, StatusDismissed, "dismissed"); err != nil {
		t.Fatal(err)
	}
	newID := feed(t, c, now, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.Critical, SourceIP: ip})
	inc, _ := c.Get(newID)
	if newID == id || inc.RemoteIPEvidence || cap.len() != 2 {
		t.Fatal("new incident inherited a closed incident's evidence")
	}
}

func TestAddressEvidenceDoesNotOverrideSprayOwnership(t *testing.T) {
	for _, check := range []string{"email_auth_failure_realtime", "mail_account_compromised"} {
		t.Run(check, func(t *testing.T) {
			generic, spray := &blockCapture{}, &blockCapture{}
			cfg := sprayTestConfig(true, false)
			cfg.PerCheck = map[string]bool{check: true}
			cfg.BlockAtSeverity = "high"
			c := NewCorrelator(CorrelatorConfig{
				AddressEvidence:  registryEvidence,
				AutoBlock:        IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "high"},
				SpraySuppression: cfg, OnIncidentBlock: generic.recordOK, OnSprayBlock: spray.recordOK,
			})
			now := time.Unix(1_700_000_000, 0)
			c.now = func() time.Time { return now }
			for i := range cfg.DistinctMailboxes {
				feed(t, c, &now, alert.Finding{
					Check: check, Severity: alert.Critical, SourceIP: "198.51.100.18", Mailbox: "account" + strconv.Itoa(i),
				})
			}
			if generic.len() != 0 || spray.len() != 1 || spray.calls[0].IP != "198.51.100.18" {
				t.Fatalf("generic=%+v spray=%+v, want only the spray block", generic.calls, spray.calls)
			}
		})
	}
}

func TestAddressEvidenceNilLeavesGateDisabled(t *testing.T) {
	c, cap, now := evidenceCorrelator(t, "critical")
	c.cfg.AddressEvidence = nil
	feed(t, c, now, alert.Finding{Check: "backdoor_port_outbound", Severity: alert.Critical, SourceIP: "198.51.100.19"})
	if cap.len() != 1 || cap.calls[0].IP != "198.51.100.19" {
		t.Fatalf("nil evidence gate rejected block: %+v", cap.calls)
	}
}
