package incident

import (
	"fmt"
	"testing"
	"time"
)

var testClosedRetention = ClosedRetention{Operator: 30 * 24 * time.Hour, Auto: 7 * 24 * time.Hour}

func TestOperatorDecisionReplacesAutomaticCloseAttribution(t *testing.T) {
	for _, by := range []string{"auto:stale", "auto:age_cap", "auto:active_cap", ""} {
		for _, action := range []string{"resolve", "dismiss", "bulk", "block", "reopen"} {
			t.Run(by+"/"+action, func(t *testing.T) {
				now := time.Unix(1_700_000_000, 0)
				old := now.Add(-8 * 24 * time.Hour)
				var persisted []Incident
				c := NewCorrelator(CorrelatorConfig{Persist: func(inc Incident) error {
					persisted = append(persisted, inc)
					return nil
				}})
				c.now = func() time.Time { return now }
				c.Restore([]Incident{{ID: "inc_closed", Status: StatusResolved, ClosedBy: by, ClosedAt: old, UpdatedAt: old, CorrelationKey: &Key{RemoteIP: "192.0.2.10"}}})
				var err error
				switch action {
				case "resolve":
					err = c.SetStatus("inc_closed", StatusResolved, "confirmed")
				case "dismiss":
					err = c.SetStatus("inc_closed", StatusDismissed, "false positive")
				case "bulk":
					var result BulkStatusResult
					result, err = c.BulkSetStatus(BulkStatusFilter{FromStatuses: []Status{StatusResolved}, To: StatusResolved, OlderThan: time.Hour, Limit: 1})
					if result.Updated != 1 {
						t.Fatalf("bulk updated %d, want 1", result.Updated)
					}
				case "block":
					err = c.RecordOperatorBlock("inc_closed", "192.0.2.10", time.Hour)
				case "reopen":
					for _, status := range []Status{StatusOpen, StatusContained} {
						if err = c.SetStatus("inc_closed", status, "investigate"); err != nil {
							t.Fatal(err)
						}
						inc, _ := c.Get("inc_closed")
						if inc.ClosedBy != "" || !inc.ClosedAt.IsZero() {
							t.Fatalf("reopen kept closure attribution: %+v", inc)
						}
					}
					err = c.SetStatus("inc_closed", StatusResolved, "done")
				}
				if err != nil {
					t.Fatal(err)
				}
				inc, _ := c.Get("inc_closed")
				if inc.ClosedBy != "operator" || !inc.UpdatedAt.Equal(now) || !inc.ClosedAt.Equal(now) {
					t.Errorf("operator action left attribution=%q updated=%v closed=%v", inc.ClosedBy, inc.UpdatedAt, inc.ClosedAt)
				}
				if len(persisted) == 0 || persisted[len(persisted)-1].ClosedBy != "operator" {
					t.Error("operator attribution was not persisted")
				}
				if testClosedRetention.Expired(inc, now.Add(8*24*time.Hour)) {
					t.Error("operator decision expires before 30 days")
				}
				if !testClosedRetention.Expired(inc, now.Add(31*24*time.Hour)) {
					t.Error("operator decision survives beyond 30 days")
				}
			})
		}
	}
}

func TestAutomaticClosureAfterReopenUsesShortRetention(t *testing.T) {
	for _, by := range []string{"auto:stale", "auto:age_cap", "auto:active_cap"} {
		t.Run(by, func(t *testing.T) {
			var persisted Incident
			c := NewCorrelator(CorrelatorConfig{Persist: func(inc Incident) error {
				persisted = inc
				return nil
			}})
			now := time.Unix(1_700_000_000, 0)
			c.now = func() time.Time { return now }
			c.Restore([]Incident{{ID: "inc_closed", Kind: KindWebAttack, Status: StatusResolved, ClosedBy: "operator", ClosedAt: now, UpdatedAt: now}})
			if err := c.SetStatus("inc_closed", StatusContained, "investigate"); err != nil {
				t.Fatal(err)
			}
			closedAt := now.Add(2 * time.Hour)
			switch by {
			case "auto:stale":
				c.CloseStale(closedAt, map[Kind]time.Duration{KindWebAttack: time.Hour}, false)
			case "auto:age_cap":
				c.CloseStaleByAge(closedAt, time.Hour, 1)
			case "auto:active_cap":
				c.Restore([]Incident{{ID: "inc_fresh", Status: StatusOpen, UpdatedAt: closedAt}})
				c.EnforceActiveCap(closedAt, 1, 1)
			}
			if persisted.ID != "inc_closed" || persisted.Status != StatusResolved || persisted.ClosedBy != by || !persisted.ClosedAt.Equal(closedAt) || !persisted.UpdatedAt.Equal(closedAt) {
				t.Fatalf("incorrect automatic closure: %+v", persisted)
			}
			if testClosedRetention.Expired(persisted, closedAt.Add(7*24*time.Hour)) || !testClosedRetention.Expired(persisted, closedAt.Add(8*24*time.Hour)) {
				t.Error("automatic closure did not start a new 7-day period")
			}
		})
	}
}

func TestClosedRetentionBoundaries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, by := range []string{"auto:stale", "auto:age_cap", "auto:active_cap", "operator", "", "automation"} {
		keep := testClosedRetention.Operator
		if by == "auto:stale" || by == "auto:age_cap" || by == "auto:active_cap" {
			keep = testClosedRetention.Auto
		}
		for _, status := range []Status{StatusOpen, StatusContained, StatusResolved, StatusDismissed} {
			for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
				inc := Incident{Status: status, ClosedBy: by, UpdatedAt: now.Add(-keep).Add(delta)}
				want := (status == StatusResolved || status == StatusDismissed) && delta < 0
				if got := testClosedRetention.Expired(inc, now); got != want {
					t.Errorf("by=%q status=%s delta=%s: expired=%v, want %v", by, status, delta, got, want)
				}
			}
		}
	}
}

func TestClosedRetentionPreservesHistoricalOperatorDecisions(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	closed := now.Add(-20 * 24 * time.Hour)
	decided := now.Add(-8 * 24 * time.Hour)
	for _, action := range []string{"incident_status_changed", "operator_block"} {
		t.Run(action, func(t *testing.T) {
			// Older writers left auto attribution behind, and operator_block
			// did not advance UpdatedAt either.
			inc := Incident{Status: StatusResolved, ClosedBy: "auto:stale", ClosedAt: closed, UpdatedAt: closed, Actions: []IncidentAction{
				{Time: closed, Action: "incident_auto_closed"},
				{Time: decided, Action: action},
			}}
			if testClosedRetention.Expired(inc, now) {
				t.Error("historical operator decision gets automatic retention")
			}
			if testClosedRetention.Expired(inc, decided.Add(30*24*time.Hour)) {
				t.Error("historical operator decision expires before its own retention ends")
			}
			if !testClosedRetention.Expired(inc, decided.Add(31*24*time.Hour)) {
				t.Error("historical operator decision never expires")
			}
			// Reopening and a later automatic close starts a new episode.
			inc.ClosedAt = decided
			inc.UpdatedAt = decided
			inc.Actions = append(inc.Actions, IncidentAction{Time: decided, Action: "incident_auto_closed"})
			if !testClosedRetention.Expired(inc, now) {
				t.Error("an earlier operator action extended a later automatic closure")
			}
		})
	}
}

func BenchmarkPruneClosedUpgradeBacklog(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	rows := make([]Incident, 93000)
	for i := range rows {
		rows[i] = Incident{ID: fmt.Sprintf("inc_%06d", i), Status: StatusResolved, ClosedBy: "auto:stale", UpdatedAt: now.Add(-8 * 24 * time.Hour)}
		if i >= 58000 {
			rows[i].UpdatedAt = now
		}
		if i >= 88000 {
			rows[i].Status = StatusOpen
			rows[i].Account = rows[i].ID
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c := NewCorrelator(CorrelatorConfig{})
		c.Restore(rows)
		b.StartTimer()
		if got := c.PruneClosedOlderThan(now, testClosedRetention); got != 58000 {
			b.Fatalf("pruned=%d, want 58000", got)
		}
		if len(c.byKey) != 5000 || len(c.incidents) != 35000 {
			b.Fatalf("remaining active=%d total=%d", len(c.byKey), len(c.incidents))
		}
	}
}
