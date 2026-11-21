package daemon

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/store"
)

// incidentExclusionPinConfig arms the production incident auto-block for the
// exclusion pins and records every address handed to the firewall.
func incidentExclusionPinConfig(t *testing.T) *[]string {
	t.Helper()
	previousCorrelator := incidentCorrelator
	previousRegistry := incidentRegistry
	previousRetention := incidentRetentionCancel
	previousAutoClose := incidentAutoCloseCancel
	previousSource := globalCfgForIncidents
	previousBlocker := incidentSprayBlocker
	previousThreshold := incidentOpenThreshold
	previousStore := store.Global()
	store.SetGlobal(nil)
	// Detach the previous singleton without stopping its workers. Cleanup
	// stops only this pin's workers and restores the original instance.
	incidentRetentionCancel = nil
	incidentAutoCloseCancel = nil
	resetIncidentForTest()
	t.Cleanup(func() {
		resetIncidentForTest()
		incidentCorrelator = previousCorrelator
		if previousCorrelator != nil {
			incidentOnce.Do(func() {})
		}
		incidentRegistry = previousRegistry
		incidentRetentionCancel = previousRetention
		incidentAutoCloseCancel = previousAutoClose
		globalCfgForIncidents = previousSource
		incidentSprayBlocker = previousBlocker
		incidentOpenThreshold = previousThreshold
		store.SetGlobal(previousStore)
	})
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "15m"
	cfg.Incidents.AutoBlock.Enabled = true
	cfg.Incidents.AutoBlock.BlockAtSeverity = "high"
	SetIncidentConfigSource(func() *config.Config { return cfg })
	blocked := &[]string{}
	SetIncidentSprayBlocker(func(ip, _ string, _ time.Duration, _ string, _ incident.PreparedRoot, _ admission.Entry) (bool, error) {
		*blocked = append(*blocked, ip)
		return true, nil
	})
	return blocked
}

// Every check the incident exclusion list names is refused by the registry
// evidence gate of the production wiring as well. A finding of one of these
// checks alone never blocks its address; the list can go once the gate is
// the only guard.
func TestIncidentExclusionPinGateRefusesEachExcludedCheck(t *testing.T) {
	excluded := []alert.Finding{
		{Check: "cpanel_file_upload", Severity: alert.Critical},
		{Check: "cpanel_file_upload_realtime", Severity: alert.Critical},
		{Check: "cpanel_login", Severity: alert.Critical},
		{Check: "cpanel_login_realtime", Severity: alert.Critical},
		{Check: "ftp_login", Severity: alert.Critical},
		{Check: "ftp_login_realtime", Severity: alert.Critical},
		{Check: "webmail_login_realtime", Severity: alert.Critical},
		{Check: "pam_login", Severity: alert.Critical},
		{Check: "ftp_login_after_bruteforce", Severity: alert.Critical},
		{Check: "mail_bruteforce_suspected", Severity: alert.Critical},
		{Check: "modsec_classifier_gap", Severity: alert.Critical},
		{Check: "modsec_low_confidence_burst", Severity: alert.Critical},
		{Check: "mail_account_compromised", Severity: alert.High},
	}
	for i, f := range excluded {
		t.Run(fmt.Sprintf("%s/%s", f.Check, f.Severity), func(t *testing.T) {
			blocked := incidentExclusionPinConfig(t)
			f.SourceIP = fmt.Sprintf("203.0.113.%d", 10+i)
			f.Timestamp = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
			correlator := IncidentCorrelator()
			id, created, err := correlator.OnFinding(f)
			if err != nil {
				t.Fatalf("OnFinding: %v", err)
			}
			inc, ok := correlator.Get(id)
			if !created || !ok || inc.CorrelationKey == nil || inc.CorrelationKey.RemoteIP != f.SourceIP || len(inc.Timeline) != 1 {
				t.Fatalf("incident %+v, created %v, found %v, want the finding's address incident", inc, created, ok)
			}
			// The exclusion list can also prevent a block. Inspect attestation
			// to prove that the production registry gate refused the finding.
			if inc.RemoteIPEvidence {
				t.Fatalf("%s/%s attested its address despite the registry refusal", f.Check, f.Severity)
			}
			if len(*blocked) != 0 {
				t.Fatalf("blocked %v, want no block", *blocked)
			}
		})
	}
}

// The same wiring does block an attested attacker address, so the pin above
// observes the gate and not a disarmed correlator.
func TestIncidentExclusionPinGateBlocksAnAttestedAddress(t *testing.T) {
	blocked := incidentExclusionPinConfig(t)
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	// Stamped by a reader the daemon trusts: an unstamped finding of a check
	// a syslog file producer also emits attests nothing.
	f := alert.Finding{Check: "mail_account_compromised", Severity: alert.Critical, SourceIP: "198.51.100.30", Timestamp: at,
		Attribution: admission.AttributionPeer,
		Observation: alert.Observation{Producer: string(checks.ProducerEximLog), Stream: "f:1:2", Cursor: "0:0123456789abcdef", ObservedAt: at}}
	if _, _, err := IncidentCorrelator().OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !slices.Equal(*blocked, []string{"198.51.100.30"}) {
		t.Fatalf("blocked %v, want the attested address", *blocked)
	}
}

// A renamed check in an old snapshot needs the same producer proof as its
// current name, through cached attestation and retained timeline events.
func TestIncidentRestoredSSHProducerProof(t *testing.T) {
	for _, check := range []string{"ssh_login_realtime", "ssh_login_unknown_ip"} {
		for _, producer := range []string{"", string(checks.ProducerSSHLog), string(checks.ProducerSSHJournal)} {
			for _, timeline := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/timeline=%v", check, producer, timeline), func(t *testing.T) {
					blocked := incidentExclusionPinConfig(t)
					at := time.Now()
					inc := incident.Incident{
						ID: "restored", Kind: incident.KindWebAttack, Status: incident.StatusOpen, Severity: alert.Critical,
						CreatedAt: at, UpdatedAt: at, CorrelationKey: &incident.Key{RemoteIP: "192.0.2.77"},
					}
					if timeline {
						inc.Timeline = []incident.IncidentEvent{{Kind: "finding", Check: check, Severity: "CRITICAL",
							RemoteIP: "192.0.2.77", FindingID: "0123456789abcdef", Producer: producer}}
					} else {
						inc.RemoteIPEvidence = true
						inc.RemoteIPEvidenceFinding = "0123456789abcdef"
						inc.RemoteIPEvidenceCheck = check
						inc.RemoteIPEvidenceSeverity = "CRITICAL"
						inc.RemoteIPEvidenceProducer = producer
					}
					c := IncidentCorrelator()
					c.Restore([]incident.Incident{inc})
					want := producer == string(checks.ProducerSSHJournal)
					got, ok := c.Get(inc.ID)
					if !ok || got.RemoteIPEvidence != want {
						t.Errorf("restored evidence = %v (found %v), want %v", got.RemoteIPEvidence, ok, want)
					}
					// An advisory can trigger a response only if the restored
					// SSH evidence attests the address; it adds no proof itself.
					id, created, err := c.OnFinding(alert.Finding{
						Check: "ftp_login", Severity: alert.Warning, SourceIP: "192.0.2.77", Timestamp: at,
					})
					if err != nil || created || id != inc.ID {
						t.Fatalf("advisory did not join restored incident: id=%q created=%v err=%v", id, created, err)
					}
					wantBlocks := []string{}
					if want {
						wantBlocks = append(wantBlocks, "192.0.2.77")
					}
					if !slices.Equal(*blocked, wantBlocks) {
						t.Fatalf("blocked %v, want %v", *blocked, wantBlocks)
					}
				})
			}
		}
	}
}
