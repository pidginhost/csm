package incident

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// testRoots mints admission evidence for findings the way the daemon's
// root minter does, one observation per finding.
func testRoots(t *testing.T) func(alert.Finding) PreparedRoot {
	t.Helper()
	reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
		return check, admission.Policy{Family: admission.FamilyHTTP, Basis: admission.BasisLocal, Attribution: admission.Attributions(admission.AttributionHTTPPeer, admission.AttributionTrustedHTTPChain)}, true
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(admission.ProducerSpec{ID: "access_log", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"modsec_csm_block_escalation", "wp_login_bruteforce"}, Attribution: admission.Attributions(admission.AttributionHTTPPeer)})
	if err != nil {
		t.Fatal(err)
	}
	return func(f alert.Finding) PreparedRoot {
		tg, err := admission.CanonicalAddress(f.SourceIP, admission.Caps{})
		if err != nil {
			t.Fatal(err)
		}
		e, err := p.Mint(admission.EvidenceInput{
			Check: f.Check, FindingID: alert.FindingID(f), Severity: admission.SeverityHigh, Target: tg, Attribution: admission.AttributionHTTPPeer,
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
// address (an incident is a derived wrapper that adds no root of
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
	if len(got) != 1 || !got[0].Equal(roots(evidence).Evidence) {
		t.Fatalf("roots = %+v", got)
	}
	inc, _ := c.Get(id)
	for _, ev := range inc.Timeline {
		if ev.Check == "wp_login_bruteforce" && ev.root != nil {
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

func TestIncidentRootUsesTheAttributedAddress(t *testing.T) {
	roots := testRoots(t)
	var got []PreparedRoot
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold:   1,
		AddressEvidence: func(check string, _ alert.Severity) bool { return check == "modsec_csm_block_escalation" },
		AutoBlock:       IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"},
		Root: func(f alert.Finding) PreparedRoot {
			if _, err := admission.CanonicalAddress(f.SourceIP, admission.Caps{}); err != nil {
				return PreparedRoot{Finding: f, Err: err}
			}
			return roots(f)
		},
		OnIncidentBlock: func(ip, _ string, _ time.Duration, _ string, root PreparedRoot) bool {
			if ip != "192.0.2.81" {
				t.Fatalf("legacy target=%q", ip)
			}
			got = append(got, root)
			return true
		},
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	f := attestingFinding("modsec_csm_block_escalation", alert.Critical, 1)
	// The legacy block normalizes the address; the root keeps what the
	// parser wrote and refuses an address it cannot attribute.
	f.SourceIP = "192.0.2.81:443"
	feed(t, c, &now, f)
	if len(got) != 1 || got[0].Err == nil || got[0].Finding.SourceIP != f.SourceIP {
		t.Fatalf("prepared roots=%+v", got)
	}
	if reason, _ := admission.ReasonOf(got[0].Err); reason != admission.ReasonInvalid || got[0].Check() != "" {
		t.Fatalf("malformed attributed address must produce no root and an invalid refusal: %+v", got[0])
	}
}

// Timelines are copied on every read and persist snapshot, so an event
// keeps its in-memory admission root behind a pointer and stays small.
func TestIncidentEventsStaySmall(t *testing.T) {
	if size := reflect.TypeOf(IncidentEvent{}).Size(); size > 256 {
		t.Fatalf("an incident event takes %d bytes", size)
	}
}

// A writable-log refusal must outlive its in-memory root: neither a
// restart nor timeline trimming can turn it into address evidence.
func TestWritableLogIncidentEvidenceSurvivesRestoreAndTrim(t *testing.T) {
	for _, trim := range []bool{false, true} {
		t.Run(fmt.Sprint(trim), func(t *testing.T) {
			calls := 0
			cfg := CorrelatorConfig{
				OpenThreshold:     1,
				AddressEvidence:   func(check string, _ alert.Severity) bool { return check == "modsec_csm_block_escalation" },
				UnverifiedAddress: func(_, producer string) bool { return producer != "journal" },
				Root: func(f alert.Finding) PreparedRoot {
					if f.Observation.Producer == "journal" {
						return PreparedRoot{Finding: f}
					}
					return PreparedRoot{Finding: f, Err: &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseWritableLog}}
				},
				AutoBlock:       IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"},
				OnIncidentBlock: func(_, _ string, _ time.Duration, _ string, _ PreparedRoot) bool { calls++; return false },
			}
			c := NewCorrelator(cfg)
			now := time.Unix(1_700_000_000, 0)
			c.now = func() time.Time { return now }
			if trim {
				for i := 0; i < 260; i++ {
					feed(t, c, &now, attestingFinding("wp_login_bruteforce", alert.High, i))
				}
			}
			id := feed(t, c, &now, attestingFinding("modsec_csm_block_escalation", alert.High, 1))
			if trim {
				for i := 260; i < 860; i++ {
					feed(t, c, &now, attestingFinding("wp_login_bruteforce", alert.High, i))
				}
			}
			inc, ok := c.Get(id)
			if !ok {
				t.Fatal("missing incident")
			}
			if inc.RemoteIPEvidence {
				t.Error("writable finding was retained as address evidence")
			}
			if trim {
				for _, ev := range inc.Timeline {
					if ev.Check == "modsec_csm_block_escalation" {
						t.Fatal("fixture did not trim the refused finding")
					}
				}
			}
			data, err := json.Marshal(inc)
			if err != nil {
				t.Fatal(err)
			}
			var stored Incident
			if err := json.Unmarshal(data, &stored); err != nil {
				t.Fatal(err)
			}
			second := NewCorrelator(cfg)
			second.now = func() time.Time { return now }
			second.Restore([]Incident{stored})
			feed(t, second, &now, attestingFinding("wp_login_bruteforce", alert.Critical, 9999))
			if calls != 0 {
				t.Fatalf("writable evidence requested %d blocks", calls)
			}
			trusted := attestingFinding("modsec_csm_block_escalation", alert.Critical, 10000)
			trusted.Observation.Producer = "journal"
			feed(t, second, &now, trusted)
			if calls != 1 {
				t.Fatalf("independent trusted evidence requested %d blocks, want one", calls)
			}
		})
	}
}
