package daemon

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// Isolate parser state without discarding entries another test installed.
func producerAcceptanceState(t *testing.T) {
	t.Helper()
	withOwnerTable(t)
	for _, windows := range []*sync.Map{&emailRateWindows, &cloudRelayWindows} {
		previous := make(map[any]any)
		windows.Range(func(key, value any) bool {
			previous[key] = value
			return true
		})
		windows.Clear()
		t.Cleanup(func() {
			windows.Clear()
			for key, value := range previous {
				windows.Store(key, value)
			}
		})
	}
	emailRateSuppressed.mu.Lock()
	previousSuppressed := emailRateSuppressed.domains
	emailRateSuppressed.domains = make(map[string]time.Time)
	emailRateSuppressed.mu.Unlock()
	t.Cleanup(func() {
		emailRateSuppressed.mu.Lock()
		emailRateSuppressed.domains = previousSuppressed
		emailRateSuppressed.mu.Unlock()
	})
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previousStore := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(previousStore)
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
}

// producerAcceptanceMint mints a finding the way a producer adapter will:
// the check and severity from the finding, the target from SourceIP. The
// observation and parser are fixtures here; these tests prove classification
// of what the parsers emit, not provenance.
func producerAcceptanceMint(t *testing.T, f alert.Finding) (admission.Assessment, error) {
	t.Helper()
	reg, err := admission.NewRegistry(checks.AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(admission.ProducerSpec{
		ID: "acceptance", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"email_cloud_relay_abuse", "email_compromised_account", "mail_account_compromised"},
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := admission.CanonicalAddress(f.SourceIP, admission.Caps{IPv6: true})
	if err != nil {
		return admission.Assessment{}, err
	}
	sev := admission.SeverityHigh
	if f.Severity == alert.Critical {
		sev = admission.SeverityCritical
	}
	observed := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	e, err := p.Mint(admission.EvidenceInput{
		Check: f.Check, FindingID: "0123456789abcdef", Severity: sev,
		Observation: admission.ObservationRef{Stream: "fixture", Cursor: "1", Version: 1},
		ObservedAt:  observed, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: target,
	})
	if err != nil {
		return admission.Assessment{}, err
	}
	return admission.Assess(target, []admission.Evidence{e}, observed)
}

func onlyCheck(t *testing.T, findings []alert.Finding, check string) alert.Finding {
	t.Helper()
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("got %d %s findings, want 1: %+v", len(out), check, findings)
	}
	return out[0]
}

// The outgoing-mail hold and the bulk-mail match name a mailbox, never an
// address, so neither can become address evidence.
func TestProducerAcceptanceMailHeuristicsWithoutAddress(t *testing.T) {
	producerAcceptanceState(t)
	cfg := cloudRelayTestConfig()
	for _, c := range []struct {
		name, line, mailbox, domain string
	}{
		{"hold", `2026-10-02 12:00:00 Sender office@example.com has an outgoing mail hold`, "office@example.com", "example.com"},
		{"bulk", `2026-10-02 12:00:00 1abc23 <= bulk@example.org H=truelist.io [192.0.2.5] P=esmtpsa A=dovecot_login:bulk@example.org S=500 T="news"`, "bulk@example.org", "example.org"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := onlyCheck(t, parseEximLogLine(c.line, cfg), "email_compromised_account")
			if f.Severity != alert.Critical || f.SourceIP != "" || f.CIDRs != nil || f.Mailbox != c.mailbox || f.Domain != c.domain {
				t.Fatalf("finding %+v, want Critical naming mailbox %s and domain %s with no address", f, c.mailbox, c.domain)
			}
			if _, err := producerAcceptanceMint(t, f); err == nil {
				t.Fatalf("finding without an address minted evidence: %+v", f)
			} else if reason, ok := admission.ReasonOf(err); !ok || reason != admission.ReasonInvalid {
				t.Fatalf("mint error %v, want an invalid address refusal", err)
			}
		})
	}
}

// Realtime and retrospective cloud relay findings name the newest relay
// client and stay local C2 evidence at Critical.
func TestProducerAcceptanceCloudRelayIsLocal(t *testing.T) {
	producerAcceptanceState(t)
	cfg := cloudRelayTestConfig()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var realtime []alert.Finding
	for i := 10; i < 13; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		ptr := fmt.Sprintf("%d.2.0.192.bc.googleusercontent.com", i)
		realtime = append(realtime, parseEximLogLine(eximLine(now, "info@example.com", ptr, ip, "notice"), cfg)...)
	}
	base := now.Add(-2 * time.Hour)
	var lines []string
	for i := 0; i < 18; i++ {
		ip := fmt.Sprintf("198.51.100.%d", 7+i%3)
		lines = append(lines, eximLine(base.Add(time.Duration(i)*2*time.Minute), "news@example.net", "relay.googleusercontent.com", ip, "notice"))
	}
	retro := ScanEximHistoryForCloudRelay(&config.Config{}, writeEximFixture(t, lines), now, 24*time.Hour)
	for _, c := range []struct {
		name, address string
		findings      []alert.Finding
	}{
		{"realtime", "192.0.2.12", realtime},
		{"retrospective", "198.51.100.9", retro},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := onlyCheck(t, c.findings, "email_cloud_relay_abuse")
			if f.Severity != alert.Critical || f.SourceIP != c.address || len(f.CIDRs) != 0 {
				t.Fatalf("finding %+v, want Critical naming %s", f, c.address)
			}
			a, err := producerAcceptanceMint(t, f)
			if err != nil {
				t.Fatal(err)
			}
			if a.Tier.Class != admission.ClassC2 || a.DirectC3 || a.Corroborated || a.Reserved() {
				t.Fatalf("%s: assessment %+v, want local C2", c.address, a)
			}
		})
	}
}

// A successful mail login from an address that was failing is direct C3
// evidence; from an established multi-mailbox source it is High and refused.
func TestProducerAcceptanceMailCompromise(t *testing.T) {
	producerAcceptanceState(t)
	clock := &staticClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 3; i++ {
		tr.Record("192.0.2.20", "alice@example.com")
	}
	critical := onlyCheck(t, tr.RecordSuccess("192.0.2.20", "alice@example.com"), "mail_account_compromised")
	if critical.Severity != alert.Critical || critical.SourceIP != "192.0.2.20" || critical.Mailbox != "alice@example.com" {
		t.Fatalf("Critical compromise finding %+v, want the successful client's address and mailbox", critical)
	}
	if a, err := producerAcceptanceMint(t, critical); err != nil || !a.DirectC3 || a.Tier.Class != admission.ClassC3 {
		t.Fatalf("Critical compromise: assessment %+v err %v, want direct C3", a, err)
	}

	establishOfficeStanding(tr, clock, "192.0.2.21", "office1@example.com", "office2@example.com")
	tr.Record("192.0.2.21", "victim@example.com")
	tr.Record("192.0.2.21", "victim@example.com")
	high := onlyCheck(t, tr.RecordSuccess("192.0.2.21", "victim@example.com"), "mail_account_compromised")
	if high.Severity != alert.High || high.SourceIP != "192.0.2.21" || high.Mailbox != "victim@example.com" {
		t.Fatalf("established source compromise %+v, want High naming the successful client and mailbox", high)
	}
	if _, err := producerAcceptanceMint(t, high); err == nil {
		t.Fatal("High compromise minted evidence")
	} else if reason, ok := admission.ReasonOf(err); !ok || reason != admission.ReasonPolicy {
		t.Fatalf("High compromise error %v, want a policy refusal", err)
	}
}
