package attackdb

import (
	"sort"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// MappedChecks hands out a fresh sorted slice; a caller that mutates it
// changes neither later listings nor what RecordFinding accepts.
func TestMappedChecksIsSortedCallerOwnedCopy(t *testing.T) {
	first := MappedChecks()
	if len(first) == 0 || !sort.StringsAreSorted(first) {
		t.Fatalf("MappedChecks() = %v, want a sorted non-empty list", first)
	}
	for _, name := range first {
		if _, ok := AttackTypeFor(name); !ok {
			t.Errorf("%s listed but AttackTypeFor reports unmapped", name)
		}
	}
	victim := first[0]
	first[0] = "mutated"
	second := MappedChecks()
	if second[0] != victim {
		t.Fatalf("second listing starts with %q, want %q", second[0], victim)
	}
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{Check: victim, Message: "fixture", Severity: alert.High, SourceIP: "203.0.113.7", Timestamp: time.Now()})
	if db.LookupIP("203.0.113.7") == nil {
		t.Fatalf("%s no longer recorded after a caller mutated the listing", victim)
	}
}

// A check outside the mapping records nothing, even with a source IP.
func TestRecordFindingIgnoresUnmappedCheck(t *testing.T) {
	db := newTestDB(t)
	for _, name := range []string{"php_dropper", "modsec_block", "waf_block", "made_up_check"} {
		if _, ok := AttackTypeFor(name); ok {
			t.Errorf("%s reported as mapped", name)
		}
		db.RecordFinding(alert.Finding{Check: name, Message: "fixture", Severity: alert.Critical, SourceIP: "203.0.113.8", Timestamp: time.Now()})
	}
	if rec := db.LookupIP("203.0.113.8"); rec != nil {
		t.Fatalf("unmapped checks created a record: %+v", rec)
	}
}
