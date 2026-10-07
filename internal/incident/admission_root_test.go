package incident

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// testRoots mints admission evidence for findings the way the daemon's
// root minter does, one observation per finding.
func testRoots(t *testing.T) func(alert.Finding, string) PreparedRoot {
	t.Helper()
	reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
		return check, admission.Policy{Family: admission.FamilyHTTP, Basis: admission.BasisLocal}, true
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(admission.ProducerSpec{ID: "access_log", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"modsec_csm_block_escalation", "wp_login_bruteforce"}})
	if err != nil {
		t.Fatal(err)
	}
	return func(f alert.Finding, target string) PreparedRoot {
		tg, err := admission.CanonicalAddress(target, admission.Caps{})
		if err != nil {
			t.Fatal(err)
		}
		e, err := p.Mint(admission.EvidenceInput{
			Check: f.Check, FindingID: alert.FindingID(f), Severity: admission.SeverityHigh, Target: tg,
			Observation: admission.ObservationRef{Stream: "access", Cursor: alert.FindingID(f), Version: 1},
			ObservedAt:  time.Unix(1_700_000_000, 0).UTC(), Parser: admission.ParserRef{Name: "access_log", Version: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		return PreparedRoot{Evidence: e, Finding: f}
	}
}

// An incident block answers the root of the finding that attested its
// address (spec 5.2: an incident is a derived wrapper that adds no root of
// its own); a finding without address evidence keeps no root.
func TestIncidentBlockCarriesItsAttestingRoot(t *testing.T) {
	roots := testRoots(t)
	var got []PreparedRoot
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold:   1,
		AddressEvidence: func(check string, _ alert.Severity) bool { return check == "modsec_csm_block_escalation" },
		AutoBlock:       IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"},
		Root:            roots,
		OnIncidentBlock: func(_, _ string, _ time.Duration, _ string, root PreparedRoot) bool {
			got = append(got, root)
			return true
		},
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	evidence := attestingFinding("modsec_csm_block_escalation", alert.High, 1)
	id := feed(t, c, &now, evidence)
	evidence.Timestamp = now
	feed(t, c, &now, attestingFinding("wp_login_bruteforce", alert.Critical, 2))
	if len(got) != 1 || !got[0].Equal(roots(evidence, evidence.SourceIP).Evidence) {
		t.Fatalf("roots = %+v", got)
	}
	inc, _ := c.Get(id)
	for _, ev := range inc.Timeline {
		if ev.Check == "wp_login_bruteforce" && !ev.root.Equal(admission.Evidence{}) {
			t.Fatalf("a finding without address evidence kept a root: %+v", ev)
		}
	}
}

// An incident restored from storage kept no root in memory: its block is
// handed over without one, and admission refuses it.
func TestRestoredIncidentBlockCarriesNoRoot(t *testing.T) {
	roots := testRoots(t)
	var got []PreparedRoot
	cfg := CorrelatorConfig{
		OpenThreshold:   1,
		AddressEvidence: func(check string, _ alert.Severity) bool { return check == "modsec_csm_block_escalation" },
		Root:            roots,
	}
	first := NewCorrelator(cfg)
	now := time.Unix(1_700_000_000, 0)
	first.now = func() time.Time { return now }
	id := feed(t, first, &now, attestingFinding("modsec_csm_block_escalation", alert.High, 1))
	inc, ok := first.Get(id)
	if !ok {
		t.Fatal("no incident")
	}
	data, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	var stored Incident
	if err = json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	cfg.AutoBlock = IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"}
	cfg.OnIncidentBlock = func(_, _ string, _ time.Duration, _ string, root PreparedRoot) bool {
		got = append(got, root)
		return true
	}
	second := NewCorrelator(cfg)
	second.now = func() time.Time { return now }
	second.Restore([]Incident{stored})
	feed(t, second, &now, attestingFinding("wp_login_bruteforce", alert.Critical, 2))
	if len(got) != 1 || !got[0].Equal(admission.Evidence{}) {
		t.Fatalf("roots = %+v", got)
	}
}
