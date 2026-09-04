package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// buildAdminOverlapFindings sorts its account list so "the dedup layer
// downstream treats two identical overlaps emitted across scans as the same
// finding". The LastSeen timestamp written into Details defeated exactly that:
// Finding.Key() hashes Details, so every scan minted a new key for an unchanged
// overlap. On cluster6 that added 18 duplicate findings per scan cycle -- 163
// findings covering 19 real overlaps within a day, growing every hour.

func TestAdminOverlapFindingKeyIsStableAcrossScans(t *testing.T) {
	overlapAt := func(seen time.Time) map[string][]store.AdminEmailEntry {
		return map[string][]store.AdminEmailEntry{
			"shared@example.com": {
				{Account: "acctone", Schema: "acctone_wp", LastSeen: seen},
				{Account: "accttwo", Schema: "accttwo_wp", LastSeen: seen},
			},
		}
	}

	first := buildAdminOverlapFindings(overlapAt(time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC)))
	second := buildAdminOverlapFindings(overlapAt(time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)))
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected one finding per scan, got %d and %d", len(first), len(second))
	}
	if first[0].Key() != second[0].Key() {
		t.Fatalf("an unchanged overlap must keep one identity across scans:\n first  = %s\n second = %s",
			first[0].Key(), second[0].Key())
	}
}

func TestAdminOverlapFindingKeyDistinguishesDifferentOverlaps(t *testing.T) {
	seen := time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC)
	one := buildAdminOverlapFindings(map[string][]store.AdminEmailEntry{
		"first@example.com": {
			{Account: "acctone", Schema: "acctone_wp", LastSeen: seen},
			{Account: "accttwo", Schema: "accttwo_wp", LastSeen: seen},
		},
	})
	two := buildAdminOverlapFindings(map[string][]store.AdminEmailEntry{
		"second@example.com": {
			{Account: "acctone", Schema: "acctone_wp", LastSeen: seen},
			{Account: "accttwo", Schema: "accttwo_wp", LastSeen: seen},
		},
	})
	if one[0].Key() == two[0].Key() {
		t.Fatalf("two different overlapping emails collapsed to one identity: %s", one[0].Key())
	}
}

// The account set is the substance of the finding: an email that spreads to a
// third account is a different situation from the same email on two, and must
// not be silently folded into the existing finding.
func TestAdminOverlapFindingKeyChangesWhenAccountSetGrows(t *testing.T) {
	seen := time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC)
	two := buildAdminOverlapFindings(map[string][]store.AdminEmailEntry{
		"shared@example.com": {
			{Account: "acctone", Schema: "acctone_wp", LastSeen: seen},
			{Account: "accttwo", Schema: "accttwo_wp", LastSeen: seen},
		},
	})
	three := buildAdminOverlapFindings(map[string][]store.AdminEmailEntry{
		"shared@example.com": {
			{Account: "acctone", Schema: "acctone_wp", LastSeen: seen},
			{Account: "accttwo", Schema: "accttwo_wp", LastSeen: seen},
			{Account: "acctthree", Schema: "acctthree_wp", LastSeen: seen},
		},
	})
	if two[0].Key() == three[0].Key() {
		t.Fatalf("an overlap that spread to a third account kept the old identity: %s", two[0].Key())
	}
}

// The timestamp is still worth showing an operator; it just must not decide
// identity.
func TestAdminOverlapFindingStillReportsLastSeen(t *testing.T) {
	seen := time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC)
	got := buildAdminOverlapFindings(map[string][]store.AdminEmailEntry{
		"shared@example.com": {
			{Account: "acctone", Schema: "acctone_wp", LastSeen: seen},
			{Account: "accttwo", Schema: "accttwo_wp", LastSeen: seen},
		},
	})
	if !strings.Contains(got[0].Details, "last seen") {
		t.Fatalf("details should still carry last-seen context, got %q", got[0].Details)
	}
}
