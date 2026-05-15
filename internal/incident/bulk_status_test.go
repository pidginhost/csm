package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func seedBulkIncident(t *testing.T, c *Correlator, at time.Time, f alert.Finding) string {
	t.Helper()
	c.now = func() time.Time { return at }
	if f.Timestamp.IsZero() {
		f.Timestamp = at
	}
	if f.Message == "" {
		f.Message = "seed"
	}
	if f.Severity == 0 {
		f.Severity = alert.High
	}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created || id == "" {
		t.Fatalf("expected created incident, got id=%q created=%v", id, created)
	}
	return id
}

func TestBulkSetStatusDryRunFiltersAndDoesNotMutate(t *testing.T) {
	c := newTestCorrelator()
	base := time.Unix(1_700_000_000, 0)
	oldWeb := seedBulkIncident(t, c, base, alert.Finding{
		Check:    "wp_login_bruteforce",
		TenantID: "alice",
		Domain:   "Example.COM",
	})
	seedBulkIncident(t, c, base, alert.Finding{
		Check:   "email_auth_failure_realtime",
		Mailbox: "office@example.com",
	})
	seedBulkIncident(t, c, base.Add(23*time.Hour), alert.Finding{
		Check:    "wp_login_bruteforce",
		TenantID: "fresh",
		Domain:   "example.com",
	})

	res, err := c.BulkSetStatus(BulkStatusFilter{
		FromStatuses: []Status{StatusOpen, StatusContained},
		To:           StatusResolved,
		OlderThan:    24 * time.Hour,
		Kind:         KindWebAccountCompromise,
		Domain:       "example.com",
		Limit:        10,
		DryRun:       true,
		Now:          base.Add(25 * time.Hour),
	})
	if err != nil {
		t.Fatalf("BulkSetStatus: %v", err)
	}
	if res.Matched != 1 || res.Updated != 0 || len(res.Items) != 1 {
		t.Fatalf("result = %+v, want one dry-run match", res)
	}
	if res.Items[0].ID != oldWeb || res.Items[0].Status != string(StatusOpen) || res.Items[0].NewStatus != string(StatusResolved) {
		t.Fatalf("preview item = %+v, want old web incident", res.Items[0])
	}
	got, _ := c.Get(oldWeb)
	if got.Status != StatusOpen {
		t.Fatalf("dry run changed status to %s", got.Status)
	}
}

func TestBulkSetStatusAppliesOldestFirstAndUnbindsClosedIncident(t *testing.T) {
	var persisted []Incident
	c := NewCorrelator(CorrelatorConfig{
		Persist: func(inc Incident) {
			persisted = append(persisted, inc)
		},
	})
	base := time.Unix(1_700_000_000, 0)
	oldest := seedBulkIncident(t, c, base, alert.Finding{
		Check:    "wp_login_bruteforce",
		TenantID: "alice",
		Domain:   "example.com",
	})
	second := seedBulkIncident(t, c, base.Add(time.Hour), alert.Finding{
		Check:    "wp_login_bruteforce",
		TenantID: "bob",
		Domain:   "example.net",
	})
	third := seedBulkIncident(t, c, base.Add(2*time.Hour), alert.Finding{
		Check:    "wp_login_bruteforce",
		TenantID: "carol",
		Domain:   "example.org",
	})
	persisted = nil

	res, err := c.BulkSetStatus(BulkStatusFilter{
		FromStatuses: []Status{StatusOpen},
		To:           StatusResolved,
		OlderThan:    24 * time.Hour,
		Limit:        2,
		Details:      "operator batch",
		Now:          base.Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("BulkSetStatus: %v", err)
	}
	if res.Matched != 3 || res.Updated != 2 || len(res.Items) != 2 {
		t.Fatalf("result = %+v, want three matches and two updates", res)
	}
	if res.Items[0].ID != oldest || res.Items[1].ID != second {
		t.Fatalf("items = %+v, want oldest incidents first", res.Items)
	}
	for _, id := range []string{oldest, second} {
		got, _ := c.Get(id)
		if got.Status != StatusResolved || got.ClosedBy != "operator" || got.ClosedAt.IsZero() {
			t.Fatalf("closed incident %s = %+v", id, got)
		}
		if got.Actions[len(got.Actions)-1].Details != "open -> resolved: operator batch" {
			t.Fatalf("last action details = %q", got.Actions[len(got.Actions)-1].Details)
		}
	}
	gotThird, _ := c.Get(third)
	if gotThird.Status != StatusOpen {
		t.Fatalf("third status = %s, want open", gotThird.Status)
	}
	if len(persisted) != 2 {
		t.Fatalf("persisted %d incidents, want 2", len(persisted))
	}

	c.now = func() time.Time { return base.Add(49 * time.Hour) }
	newID, created, err := c.OnFinding(alert.Finding{
		Check:     "wp_login_bruteforce",
		Message:   "fresh",
		Severity:  alert.High,
		TenantID:  "alice",
		Domain:    "example.com",
		Timestamp: base.Add(49 * time.Hour),
	})
	if err != nil {
		t.Fatalf("OnFinding after close: %v", err)
	}
	if !created || newID == "" || newID == oldest {
		t.Fatalf("re-detection id=%q created=%v, want fresh incident", newID, created)
	}
}

func TestBulkSetStatusRequiresAgeGuardAndPositiveLimit(t *testing.T) {
	c := newTestCorrelator()
	if _, err := c.BulkSetStatus(BulkStatusFilter{
		FromStatuses: []Status{StatusOpen},
		To:           StatusResolved,
		Limit:        1,
	}); err == nil {
		t.Fatal("expected missing age guard error")
	}
	if _, err := c.BulkSetStatus(BulkStatusFilter{
		FromStatuses: []Status{StatusOpen},
		To:           StatusResolved,
		OlderThan:    time.Hour,
	}); err == nil {
		t.Fatal("expected missing limit error")
	}
}
