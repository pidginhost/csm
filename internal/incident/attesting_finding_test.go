package incident

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func attestingCorrelator(t *testing.T, captured *[]string) (*Correlator, *time.Time) {
	t.Helper()
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold:   1,
		AddressEvidence: func(check string, _ alert.Severity) bool { return check == "modsec_csm_block_escalation" },
		AutoBlock:       IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"},
		OnIncidentBlock: func(_, _ string, _ time.Duration, id string) bool {
			*captured = append(*captured, id)
			return true
		},
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	return c, &now
}

func attestingFinding(check string, sev alert.Severity, n int) alert.Finding {
	return alert.Finding{Check: check, Severity: sev, SourceIP: "192.0.2.77", Message: fmt.Sprintf("%s %d", check, n)}
}

// The block names the finding that attested the address, not the newest
// event: a later finding without address evidence can raise the severity
// that triggers the block, but it is not the block's evidence.
func TestIncidentBlockNamesTheAttestingFinding(t *testing.T) {
	var ids []string
	c, now := attestingCorrelator(t, &ids)
	feed(t, c, now, attestingFinding("modsec_csm_block_escalation", alert.High, 0))
	evidence := attestingFinding("modsec_csm_block_escalation", alert.High, 1)
	feed(t, c, now, evidence)
	evidence.Timestamp = *now
	feed(t, c, now, attestingFinding("wp_login_bruteforce", alert.Critical, 2))
	if len(ids) != 1 || ids[0] != alert.FindingID(evidence) {
		t.Fatalf("block named %q, want the newest attesting finding %s", ids, alert.FindingID(evidence))
	}
}

// Timeline trimming can drop the attesting event; the incident keeps its
// identity, so the block still names it.
func TestIncidentBlockNamesTheAttestingFindingAfterTrim(t *testing.T) {
	var ids []string
	c, now := attestingCorrelator(t, &ids)
	for i := 0; i < 260; i++ {
		feed(t, c, now, attestingFinding("wp_login_bruteforce", alert.High, i))
	}
	evidence := attestingFinding("modsec_csm_block_escalation", alert.High, 0)
	id := feed(t, c, now, evidence)
	evidence.Timestamp = *now
	for i := 260; i < 860; i++ {
		feed(t, c, now, attestingFinding("wp_login_bruteforce", alert.High, i))
	}
	inc, _ := c.Get(id)
	for _, ev := range inc.Timeline {
		if ev.FindingID == alert.FindingID(evidence) {
			t.Fatal("fixture did not trim the attesting event")
		}
	}
	if inc.RemoteIPEvidenceFinding != alert.FindingID(evidence) {
		t.Fatalf("incident evidence finding %q, want %s", inc.RemoteIPEvidenceFinding, alert.FindingID(evidence))
	}
	feed(t, c, now, attestingFinding("wp_login_bruteforce", alert.Critical, 9999))
	if len(ids) != 1 || ids[0] != alert.FindingID(evidence) {
		t.Fatalf("block named %q, want the attesting finding %s", ids, alert.FindingID(evidence))
	}
}

// An incident stored before the evidence finding was recorded learns it
// from its timeline on restore.
func TestRestoreLearnsTheAttestingFinding(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(fmt.Sprint(recorded), func(t *testing.T) {
			var ids []string
			c, now := attestingCorrelator(t, &ids)
			evidence := attestingFinding("modsec_csm_block_escalation", alert.High, 0)
			id := feed(t, c, now, evidence)
			evidence.Timestamp = *now
			inc, _ := c.Get(id)
			inc.RemoteIPEvidence, inc.RemoteIPEvidenceFinding = recorded, ""
			restored, _ := attestingCorrelator(t, &ids)
			restored.Restore([]Incident{inc})
			got, _ := restored.Get(id)
			if !got.RemoteIPEvidence || got.RemoteIPEvidenceFinding != alert.FindingID(evidence) {
				t.Fatalf("restored evidence %v finding %q, want %s", got.RemoteIPEvidence, got.RemoteIPEvidenceFinding, alert.FindingID(evidence))
			}
		})
	}
}

func TestLegacyIncidentLearnsLaterEvidenceBeforeTrim(t *testing.T) {
	for _, spray := range []bool{false, true} {
		t.Run(fmt.Sprintf("spray=%v", spray), func(t *testing.T) {
			var ids []string
			c, now := attestingCorrelator(t, &ids)
			if spray {
				c.cfg.SpraySuppression = SpraySuppressionConfig{
					Enabled: true, DistinctMailboxes: 2, BlockAtSeverity: "critical",
					SeverityEscalateAt: maxIncidentTimeline * 2,
					PerCheck:           map[string]bool{"modsec_csm_block_escalation": true, "wp_login_bruteforce": true},
				}
				c.spray = newSprayDetector(c.cfg.SpraySuppression, incidentMergeWindow, c.now, nil)
				c.cfg.OnSprayBlock = c.cfg.OnIncidentBlock
				c.cfg.OnIncidentBlock = nil
			}
			kind := KindWebAttack
			if spray {
				kind = KindCredentialSpray
			}
			c.Restore([]Incident{{
				ID: "legacy", Kind: kind, Status: StatusOpen, Severity: alert.High,
				CorrelationKey: &Key{RemoteIP: "192.0.2.77"}, RemoteIPEvidence: true,
				CreatedAt: *now, UpdatedAt: *now,
			}})
			var stored Incident
			writes := 0
			c.cfg.Persist = func(inc Incident) error {
				stored = inc
				writes++
				return nil
			}
			for i := range maxIncidentTimeline / 2 {
				feed(t, c, now, attestingFinding("wp_login_bruteforce", alert.High, i))
			}
			c.FlushPendingPersists()
			evidence := attestingFinding("modsec_csm_block_escalation", alert.High, 0)
			before := writes
			feed(t, c, now, evidence)
			evidence.Timestamp = *now
			if writes != before+1 || stored.RemoteIPEvidenceFinding != alert.FindingID(evidence) {
				t.Errorf("later evidence was not persisted immediately: writes %d -> %d, identity %q", before, writes, stored.RemoteIPEvidenceFinding)
			}
			inc, _ := c.Get("legacy")
			if inc.RemoteIPEvidenceFinding != alert.FindingID(evidence) {
				t.Errorf("later evidence identity = %q, want %s", inc.RemoteIPEvidenceFinding, alert.FindingID(evidence))
			}
			for i := range maxIncidentTimeline {
				feed(t, c, now, attestingFinding("wp_login_bruteforce", alert.High, i+maxIncidentTimeline))
			}
			inc, _ = c.Get("legacy")
			for _, ev := range inc.Timeline {
				if ev.FindingID == alert.FindingID(evidence) {
					t.Fatal("fixture did not trim the later attesting event")
				}
			}
			c.FlushPendingPersists()
			c.Restore([]Incident{stored})
			if len(ids) != 0 {
				t.Fatalf("blocked before the severity transition: %q", ids)
			}
			feed(t, c, now, attestingFinding("wp_login_bruteforce", alert.Critical, 9999))
			if len(ids) != 1 || ids[0] != alert.FindingID(evidence) {
				t.Fatalf("block named %q, want the later attesting finding %s", ids, alert.FindingID(evidence))
			}
		})
	}
}

func TestSprayBlockNamesTheAttestingFinding(t *testing.T) {
	var ids []string
	c := NewCorrelator(CorrelatorConfig{
		AddressEvidence: func(check string, _ alert.Severity) bool { return check == "pam_bruteforce" },
		SpraySuppression: SpraySuppressionConfig{
			Enabled: true, DistinctMailboxes: 2, BlockAtSeverity: "high",
		},
		OnSprayBlock: func(_, _ string, _ time.Duration, id string) bool {
			ids = append(ids, id)
			return true
		},
	})
	inc := &Incident{
		ID: "spray", Kind: KindCredentialSpray, Status: StatusOpen, Severity: alert.High,
		CorrelationKey: &Key{RemoteIP: "192.0.2.77"},
		Timeline: []IncidentEvent{
			{Kind: "finding", Check: "pam_bruteforce", Severity: "HIGH", RemoteIP: "192.0.2.77", FindingID: "0123456789abcdef"},
			{Kind: "finding", Check: "wp_login_bruteforce", Severity: "HIGH", RemoteIP: "192.0.2.77", FindingID: "fedcba9876543210"},
		},
	}
	c.mu.Lock()
	c.incidents[inc.ID] = inc
	callback := c.maybeBlockSprayLocked(inc, "192.0.2.77", 2, time.Now(), "threshold")
	c.mu.Unlock()
	if callback == nil {
		t.Fatal("attested spray did not reach its block callback")
	}
	callback()
	if len(ids) != 1 || ids[0] != "0123456789abcdef" {
		t.Fatalf("spray block names %v, want its attesting finding", ids)
	}
}
