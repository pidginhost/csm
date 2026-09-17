package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// retentionCfg returns a Config with the retention block configured
// to the supplied values; unrelated fields stay at defaults.
func retentionCfg(enabled bool, findingsDays, historyDays, reputationDays int) *config.Config {
	cfg := &config.Config{}
	cfg.Retention.Enabled = enabled
	cfg.Retention.FindingsDays = findingsDays
	cfg.Retention.HistoryDays = historyDays
	cfg.Retention.ReputationDays = reputationDays
	cfg.Retention.CompactMinSizeMB = 128
	cfg.Retention.CompactFillRatio = 0.5
	return cfg
}

func TestRunRetentionOnce_DisabledIsNoop(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Put one old history entry in to confirm it's NOT swept.
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := db.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "c", Message: "old", Timestamp: old},
	}); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	cfg := retentionCfg(false /* disabled */, 90, 30, 180)
	result := RunRetentionOnce(db, cfg, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if result.Deleted() != 0 {
		t.Errorf("Deleted = %d, want 0 when retention is disabled", result.Deleted())
	}
	if db.HistoryCount() != 1 {
		t.Errorf("HistoryCount = %d, want 1 (nothing should have been swept)", db.HistoryCount())
	}
}

func TestRunRetentionOnce_NilDBIsNoop(t *testing.T) {
	cfg := retentionCfg(true, 90, 30, 180)
	result := RunRetentionOnce(nil, cfg, time.Now())
	if result.Deleted() != 0 {
		t.Errorf("Deleted = %d, want 0 with nil db", result.Deleted())
	}
}

func TestRunRetentionOnce_NilConfigIsNoop(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	result := RunRetentionOnce(db, nil, time.Now())
	if result.Deleted() != 0 {
		t.Errorf("Deleted = %d, want 0 with nil config", result.Deleted())
	}
}

func TestRunRetentionOnce_SweepsEachBucket(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	// history: one old, one fresh
	if err := db.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "c", Message: "old", Timestamp: old},
		{Severity: alert.Warning, Check: "c", Message: "fresh", Timestamp: fresh},
	}); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}
	// attacks:events: two old, one fresh
	for i, ts := range []time.Time{old, old.Add(time.Hour), fresh} {
		if err := db.RecordAttackEvent(store.AttackEvent{
			IP: "1.2.3.4", Timestamp: ts, AttackType: "t",
		}, i); err != nil {
			t.Fatalf("RecordAttackEvent: %v", err)
		}
	}
	// reputation: one old, one fresh
	if err := db.SetReputation("a", store.ReputationEntry{Score: 1, CheckedAt: old}); err != nil {
		t.Fatalf("SetReputation a: %v", err)
	}
	if err := db.SetReputation("b", store.ReputationEntry{Score: 2, CheckedAt: fresh}); err != nil {
		t.Fatalf("SetReputation b: %v", err)
	}

	// Retention: 30d history -> old-only swept; 30d findings -> both old
	// attack events swept; 30d reputation -> old reputation swept.
	cfg := retentionCfg(true, 30, 30, 30)
	result := RunRetentionOnce(db, cfg, now)

	if result.History != 1 {
		t.Errorf("History = %d, want 1", result.History)
	}
	if result.AttackEvents != 2 {
		t.Errorf("AttackEvents = %d, want 2", result.AttackEvents)
	}
	if result.Reputation != 1 {
		t.Errorf("Reputation = %d, want 1", result.Reputation)
	}
	if result.Deleted() != 4 {
		t.Errorf("Deleted = %d, want 4 (1+2+1)", result.Deleted())
	}

	// Surviving counts.
	if db.HistoryCount() != 1 {
		t.Errorf("HistoryCount = %d, want 1", db.HistoryCount())
	}
	if len(db.QueryAttackEvents("1.2.3.4", 10)) != 1 {
		t.Errorf("attack events survived = %d, want 1", len(db.QueryAttackEvents("1.2.3.4", 10)))
	}
	if _, ok := db.GetReputation("a"); ok {
		t.Error("a should be swept")
	}
	if _, ok := db.GetReputation("b"); !ok {
		t.Error("b should be kept")
	}
}

func TestRunRetentionOnce_ZeroDaysSkipsThatBucket(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	if err := db.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "c", Message: "old", Timestamp: old},
	}); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	// HistoryDays=0 → history sweep is a no-op.
	cfg := retentionCfg(true, 0, 0, 0)
	result := RunRetentionOnce(db, cfg, now)
	if result.Deleted() != 0 {
		t.Errorf("Deleted = %d, want 0 when all *Days are zero", result.Deleted())
	}
	if db.HistoryCount() != 1 {
		t.Errorf("HistoryCount = %d, want 1", db.HistoryCount())
	}
}

// firewallOutcomeFixture drives one durable firewall action to a delivered
// outcome so the sweep has a retained record to work on.
func firewallOutcomeFixture(t *testing.T, db *store.DB, id string, at time.Time) {
	t.Helper()
	state, revision, err := db.ReadFirewallState()
	if err != nil {
		if _, seedErr := db.ReplaceFirewallState(0, firewall.FirewallState{}); seedErr != nil {
			t.Fatalf("seed firewall state: %v", seedErr)
		}
		state, revision = firewall.FirewallState{}, 1
	}
	next := firewall.FirewallState{Blocked: append([]firewall.BlockedEntry(nil), state.Blocked...)}
	next.Blocked = append(next.Blocked, firewall.BlockedEntry{IP: "198.51.100." + id[len(id)-1:], Reason: "retention", BlockedAt: at})
	plan := firewall.FirewallAction{
		Request:   firewall.ActionRequest{ID: id, Operation: "block", Target: "198.51.100.1", Actor: "cli", Source: "manual"},
		Before:    state,
		After:     next,
		Revision:  revision,
		CreatedAt: at,
	}
	if _, _, admitErr := db.AdmitFirewallAction(plan); admitErr != nil {
		t.Fatalf("admit %s: %v", id, admitErr)
	}
	for _, phase := range []string{"executing", "applied", "verified"} {
		if _, transitionErr := db.TransitionFirewallAction(id, phase, "", at); transitionErr != nil {
			t.Fatalf("transition %s: %v", id, transitionErr)
		}
	}
	pending, err := db.FirewallAuditPending()
	if err != nil {
		t.Fatalf("audit pending: %v", err)
	}
	for _, a := range pending {
		if err := db.AcknowledgeFirewallAudit(a.Request.ID, a.AuditVersion); err != nil {
			t.Fatalf("acknowledge %s: %v", a.Request.ID, err)
		}
	}
}

func TestRunRetentionOnce_SweepsFirewallActionsWithHistoryDays(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	firewallOutcomeFixture(t, db, "action-1", old)
	firewallOutcomeFixture(t, db, "action-2", fresh)

	result := RunRetentionOnce(db, retentionCfg(true, 90, 30, 180), now)
	if len(result.Errors) != 0 {
		t.Fatalf("Errors = %v", result.Errors)
	}
	if result.FirewallActions != 1 {
		t.Fatalf("FirewallActions = %d, want 1", result.FirewallActions)
	}
	if _, err := db.ReadFirewallAction("action-1"); !errors.Is(err, firewall.ErrActionMissing) {
		t.Fatalf("swept action read = %v, want it gone", err)
	}
	if _, err := db.ReadFirewallAction("action-2"); err != nil {
		t.Fatalf("recent action must stay: %v", err)
	}
	if result.Deleted() < 1 {
		t.Fatalf("Deleted = %d, want the firewall sweep counted", result.Deleted())
	}
}

func TestRunRetentionOnce_DisabledKeepsFirewallActions(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	firewallOutcomeFixture(t, db, "action-1", old)
	result := RunRetentionOnce(db, retentionCfg(false, 90, 30, 180), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if result.FirewallActions != 0 {
		t.Fatalf("FirewallActions = %d, want 0 when retention is disabled", result.FirewallActions)
	}
	if _, err := db.ReadFirewallAction("action-1"); err != nil {
		t.Fatalf("action must stay when sweeps are off: %v", err)
	}
}
