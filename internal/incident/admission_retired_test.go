package incident

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A restored cache can authorize renewal only while the attesting check
// and severity still qualify. Old retained proof migrates; missing old
// proof waits for fresh evidence. New proof survives serialization and trim.
func TestRestoredIncidentRevalidatesItsAddressEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, cachedCheck, cachedSeverity, eventCheck string
		want                                          bool
	}{
		{"retired retained proof", "", "", "local_threat_score", false},
		{"missing old proof", "", "", "", false},
		{"active old retained proof", "", "", "modsec_csm_block_escalation", true},
		{"active new trimmed proof", "modsec_csm_block_escalation", "CRITICAL", "", true},
		{"retired new trimmed proof", "local_threat_score", "CRITICAL", "", false},
		{"unmet severity floor", "modsec_csm_block_escalation", "HIGH", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1_700_000_000, 0).UTC()
			calls := 0
			cfg := CorrelatorConfig{
				OpenThreshold: 1,
				AddressEvidence: func(check string, sev alert.Severity) bool {
					return check == "modsec_csm_block_escalation" && sev == alert.Critical
				},
				AutoBlock: IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"},
				OnIncidentBlock: func(_, _ string, _ time.Duration, _ string, _ PreparedRoot) bool {
					calls++
					return true
				},
			}
			inc := Incident{
				ID: "stored", Kind: KindWebAttack, Status: StatusOpen, Severity: alert.Critical,
				CreatedAt: now, UpdatedAt: now, CorrelationKey: &Key{RemoteIP: "192.0.2.77"},
				RemoteIPEvidence: true, RemoteIPEvidenceFinding: "0123456789abcdef",
				RemoteIPEvidenceCheck: tc.cachedCheck, RemoteIPEvidenceSeverity: tc.cachedSeverity,
				AutoBlock: AutoBlockState{Count: 1, ExpiresAt: now.Add(-time.Minute)},
			}
			if tc.eventCheck != "" {
				inc.Timeline = []IncidentEvent{{Kind: "finding", Check: tc.eventCheck, Severity: "CRITICAL", RemoteIP: "192.0.2.77", FindingID: inc.RemoteIPEvidenceFinding}}
			}
			c := NewCorrelator(cfg)
			c.now = func() time.Time { return now }
			c.Restore([]Incident{inc})
			stored, _ := c.Get(inc.ID)
			if stored.RemoteIPEvidence != tc.want {
				t.Fatalf("cached evidence=%v, want %v", stored.RemoteIPEvidence, tc.want)
			}
			if stored.AutoBlock != inc.AutoBlock {
				t.Fatalf("existing block changed: %+v, want %+v", stored.AutoBlock, inc.AutoBlock)
			}
			if tc.want {
				if stored.RemoteIPEvidenceCheck != "modsec_csm_block_escalation" || stored.RemoteIPEvidenceSeverity != "CRITICAL" {
					t.Fatalf("retained proof lacks policy identity: %+v", stored)
				}
				stored.Timeline = nil
			}
			raw, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			var back Incident
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatal(err)
			}
			c = NewCorrelator(cfg)
			c.now = func() time.Time { return now }
			c.Restore([]Incident{back})
			c.mu.Lock()
			callback := c.maybeBlockIncidentLocked(c.incidents[inc.ID], now, "renewal")
			c.mu.Unlock()
			if (callback != nil) != tc.want {
				t.Fatalf("renewal callback present=%v, want %v", callback != nil, tc.want)
			}
			if callback != nil {
				callback()
			}
			if tc.want && calls != 1 || !tc.want && calls != 0 {
				t.Fatalf("renewal calls=%d", calls)
			}
			if !tc.want {
				f := alert.Finding{Check: "modsec_csm_block_escalation", Severity: alert.Critical, SourceIP: "192.0.2.77", Timestamp: now}
				if _, _, err := c.OnFinding(f); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Fatalf("fresh active evidence produced %d blocks, want one", calls)
				}
			}
		})
	}
}
