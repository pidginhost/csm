package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// SnapshotPage is the server-side pagination + status filter primitive
// used by the /api/v1/incidents handler. The bare Snapshot() loads
// every record (CLI / control-socket consumers); SnapshotPage lets a
// busy host's web UI ship only the visible page.

func newPaginatedCorrelator(t *testing.T, n int) *Correlator {
	t.Helper()
	c := NewCorrelator(CorrelatorConfig{OpenThreshold: 1})
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < n; i++ {
		// Stagger UpdatedAt so the descending-time sort is deterministic.
		ts := base.Add(time.Duration(i) * time.Second)
		c.now = func() time.Time { return ts }
		f := alert.Finding{
			Check:     "wp_login_bruteforce",
			Severity:  alert.High,
			TenantID:  "acct" + itoa(i),
			Timestamp: ts,
		}
		if _, _, err := c.OnFinding(f); err != nil {
			t.Fatalf("OnFinding[%d]: %v", i, err)
		}
	}
	return c
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for n := i; n > 0; n /= 10 {
		digits = append([]byte{'0' + byte(n%10)}, digits...)
	}
	return string(digits)
}

func TestSnapshotPageRespectsOffsetAndLimit(t *testing.T) {
	c := newPaginatedCorrelator(t, 25)

	page, total := c.SnapshotPage("", 5, 10)
	if total != 25 {
		t.Errorf("total = %d, want 25", total)
	}
	if len(page) != 10 {
		t.Errorf("page len = %d, want 10", len(page))
	}
	// Items must come in UpdatedAt-desc order (same as Snapshot).
	for i := 1; i < len(page); i++ {
		if page[i].UpdatedAt.After(page[i-1].UpdatedAt) {
			t.Errorf("page out of order: %s after %s at index %d", page[i].UpdatedAt, page[i-1].UpdatedAt, i)
		}
	}
}

func TestSnapshotPageOrdersEqualTimestampsByID(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})
	at := time.Unix(1_700_000_000, 0)
	c.Restore([]Incident{
		pageIncident("inc_a", StatusOpen, at),
		pageIncident("inc_c", StatusOpen, at),
		pageIncident("inc_b", StatusOpen, at),
	})

	page, total := c.SnapshotPage("", 0, 3)
	if total != 3 || len(page) != 3 {
		t.Fatalf("page total/len = %d/%d, want 3/3", total, len(page))
	}
	want := []string{"inc_c", "inc_b", "inc_a"}
	for i, id := range want {
		if page[i].ID != id {
			t.Fatalf("page[%d].ID = %q, want %q", i, page[i].ID, id)
		}
	}
}

func TestSnapshotPageStatusesFiltersBeforePaging(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})
	at := time.Unix(1_700_000_000, 0)
	c.Restore([]Incident{
		pageIncident("inc_a", StatusOpen, at),
		pageIncident("inc_b", StatusOpen, at),
		pageIncident("inc_c", StatusContained, at),
		pageIncident("inc_d", StatusResolved, at),
	})

	page, total := c.SnapshotPageStatuses([]Status{StatusOpen, StatusContained}, 1, 1)
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if len(page) != 1 {
		t.Fatalf("page len = %d, want 1", len(page))
	}
	if page[0].ID != "inc_b" {
		t.Fatalf("page[0].ID = %q, want inc_b", page[0].ID)
	}
}

func TestSnapshotPageFiltersByStatus(t *testing.T) {
	c := newPaginatedCorrelator(t, 5)
	all := c.Snapshot()
	if err := c.SetStatus(all[0].ID, StatusResolved, "ack"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if err := c.SetStatus(all[1].ID, StatusDismissed, "fp"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	open, totalOpen := c.SnapshotPage(StatusOpen, 0, 100)
	if totalOpen != 3 {
		t.Errorf("open total = %d, want 3", totalOpen)
	}
	if len(open) != 3 {
		t.Errorf("open page len = %d, want 3", len(open))
	}
	for _, inc := range open {
		if inc.Status != StatusOpen {
			t.Errorf("page contains non-open incident: status=%s", inc.Status)
		}
	}

	resolved, totalResolved := c.SnapshotPage(StatusResolved, 0, 100)
	if totalResolved != 1 {
		t.Errorf("resolved total = %d, want 1", totalResolved)
	}
	if len(resolved) != 1 {
		t.Errorf("resolved page len = %d, want 1", len(resolved))
	}
}

func pageIncident(id string, status Status, at time.Time) Incident {
	account := "acct-" + id
	return Incident{
		ID:             id,
		Status:         status,
		Severity:       alert.High,
		Account:        account,
		CorrelationKey: &Key{Account: account},
		CreatedAt:      at,
		UpdatedAt:      at,
	}
}

func TestSnapshotPageEmptyStatusMatchesAll(t *testing.T) {
	c := newPaginatedCorrelator(t, 4)
	all := c.Snapshot()
	if err := c.SetStatus(all[0].ID, StatusDismissed, ""); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	page, total := c.SnapshotPage("", 0, 100)
	if total != 4 || len(page) != 4 {
		t.Errorf("empty-status page: total=%d len=%d, want 4/4", total, len(page))
	}
}

func TestSnapshotPageOffsetBeyondTotalReturnsEmpty(t *testing.T) {
	c := newPaginatedCorrelator(t, 3)
	page, total := c.SnapshotPage("", 100, 10)
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(page) != 0 {
		t.Errorf("page len = %d, want 0", len(page))
	}
}

// limit <= 0 returns the rest of the filtered set after offset. This
// matches the server-side handler contract where an unset limit means
// "no client-imposed page size; the server caps at its own ceiling".
func TestSnapshotPageLimitZeroReturnsRemainder(t *testing.T) {
	c := newPaginatedCorrelator(t, 5)
	page, total := c.SnapshotPage("", 2, 0)
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(page) != 3 {
		t.Errorf("page len = %d, want 3 (rest after offset)", len(page))
	}
}

// Negative offset is clamped to zero so a buggy caller cannot panic the
// slice operation. Limit semantics already handled (zero or negative ->
// remainder).
func TestSnapshotPageNegativeOffsetClamps(t *testing.T) {
	c := newPaginatedCorrelator(t, 4)
	page, total := c.SnapshotPage("", -10, 2)
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if len(page) != 2 {
		t.Errorf("page len = %d, want 2", len(page))
	}
}

func TestSnapshotPageItemsAreDeepCopies(t *testing.T) {
	c := newPaginatedCorrelator(t, 1)
	page, _ := c.SnapshotPage("", 0, 1)
	if len(page) != 1 {
		t.Fatalf("page len = %d, want 1", len(page))
	}
	page[0].Findings = append(page[0].Findings, "tamper")

	page2, _ := c.SnapshotPage("", 0, 1)
	for _, fp := range page2[0].Findings {
		if fp == "tamper" {
			t.Fatal("SnapshotPage leaked internal state to caller")
		}
	}
}
