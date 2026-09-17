package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

// The daemon's health provider mirrors the checks package's attribution
// state into the snapshot type, nil until the first active-set update.
func TestHealthProviderReportsCorrelationAttribution(t *testing.T) {
	checks.ResetAttributionHealthForTest()
	t.Cleanup(checks.ResetAttributionHealthForTest)
	d := &Daemon{}
	if got := d.CorrelationAttribution(); got != nil {
		t.Fatalf("before any merge = %+v, want nil", got)
	}
	checks.RecordUnattributedActiveSet(map[string]int{"db_rogue_admin": 2})
	got := d.CorrelationAttribution()
	if got == nil || got.Current["db_rogue_admin"] != 2 || got.Cumulative["db_rogue_admin"] != 2 || got.ActiveSetUpdates != 1 || got.Since.IsZero() {
		t.Fatalf("after merge = %+v", got)
	}
	checks.RecordUnattributedActiveSet(nil)
	got = d.CorrelationAttribution()
	if got == nil || len(got.Current) != 0 || got.Cumulative["db_rogue_admin"] != 2 {
		t.Fatalf("after recovery = %+v", got)
	}
}
