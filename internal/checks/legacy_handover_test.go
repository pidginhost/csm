package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Design C7: the live start reads the legacy hour as LegacyBlockSpend does
// and counts the pending entries legacy blocking would still retry. A stale
// entry, which its drain drops unblocked, is not counted; an entry from
// before queue times were kept is.
func TestLegacyHandoverCountsRetriablePending(t *testing.T) {
	now := time.Date(2026, 10, 4, 14, 20, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339Nano) }
	body := fmt.Sprintf(`{"ips":[],"pending":[`+
		`{"ip":"192.0.2.1","reason":"r","check":"ssh_brute","severity":3},`+
		`{"ip":"192.0.2.2","reason":"r","queued_at":%q},`+
		`{"ip":"192.0.2.3","reason":"r","queued_at":%q},`+
		`{"ip":"192.0.2.4","reason":"r","queued_at":%q}],`+
		`"blocks_this_hour":12,"hour_key":"2026-10-04T14"}`, stamp(time.Hour), stamp(PendingRetryAge), stamp(PendingRetryAge+time.Nanosecond))
	dir := writeLegacyState(t, body)
	h, err := LegacyHandover(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	spend, err := LegacyBlockSpend(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if h.Pending != 3 || h.Spend != spend || spend.Units != 12 {
		t.Fatalf("handover = %+v, want 3 pending and %+v", h, spend)
	}
}

// No file means no legacy state; a damaged one is an error, never zero.
func TestLegacyHandoverRefusesDamage(t *testing.T) {
	now := time.Date(2026, 10, 4, 14, 20, 0, 0, time.UTC)
	if h, err := LegacyHandover(t.TempDir(), now); err != nil || h != (admission.LegacyHandover{}) {
		t.Fatalf("no file = %+v, %v", h, err)
	}
	for _, body := range []string{
		`{"blocks_this_hour":1}`,
		`{"blocks_this_hour":0,"hour_key":"","pending":[{"ip":"not an address"}]}`,
		`{"blocks_this_hour":0,"hour_key":"","pending":[null]}`,
		`{"blocks_this_hour":2,"hour_key":"2026-10-06T14"}`,
	} {
		if h, err := LegacyHandover(writeLegacyState(t, body), now); err == nil {
			t.Errorf("%s read as %+v", body, h)
		}
	}
}
