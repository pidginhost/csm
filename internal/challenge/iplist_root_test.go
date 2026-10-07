package challenge

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

func testRoot(t *testing.T) admission.Evidence {
	t.Helper()
	reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
		return check, admission.Policy{Family: admission.FamilyHTTP, Basis: admission.BasisLocal}, check == "http_brute"
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(admission.ProducerSpec{ID: "access_log", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"http_brute"}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := admission.CanonicalAddress("203.0.113.70", admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := p.Mint(admission.EvidenceInput{
		Check: "http_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh, Target: target,
		Observation: admission.ObservationRef{Stream: "access", Cursor: "offset=1", Version: 1},
		ObservedAt:  time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), Parser: admission.ParserRef{Name: "access_log", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A challenge keeps the admission root it was routed with, and its timeout
// returns it for the escalation to answer; one routed without a root
// returns none.
func TestExpiredEntriesReturnTheirRoots(t *testing.T) {
	l := NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	root := testRoot(t)
	l.AddWithRoot("203.0.113.70", "brute force", -time.Second, "0123456789abcdef", root)
	l.AddWithFindingID("203.0.113.71", "brute force", -time.Second, "fedcba9876543210")
	got := map[string]ExpiredEntry{}
	for _, e := range l.ExpiredEntries() {
		got[e.IP] = e
	}
	if e := got["203.0.113.70"]; e.FindingID != "0123456789abcdef" || !e.Root.Equal(root) {
		t.Fatalf("rooted entry = %+v", e)
	}
	if e := got["203.0.113.71"]; e.FindingID != "fedcba9876543210" || !e.Root.Equal(admission.Evidence{}) {
		t.Fatalf("an entry without a root = %+v", e)
	}
}
