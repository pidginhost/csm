package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// terminalActionFixture drives one admission through to a proven outcome so
// retention tests exercise the same records recovery and undo read.
func terminalActionFixture(t *testing.T, s firewall.ActionStore, id string, at time.Time, filler string) firewall.FirewallAction {
	t.Helper()
	state, revision, err := s.ReadFirewallState()
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	next := firewall.FirewallState{Blocked: append([]firewall.BlockedEntry(nil), state.Blocked...)}
	next.Blocked = append(next.Blocked, firewall.BlockedEntry{IP: fmt.Sprintf("198.51.100.%d", len(next.Blocked)+1), Reason: filler, BlockedAt: at})
	plan := firewall.FirewallAction{
		Request:   firewall.ActionRequest{ID: id, Operation: "block", Target: "198.51.100.1", Actor: "cli", Source: "manual"},
		Before:    state,
		After:     next,
		Revision:  revision,
		CreatedAt: at,
	}
	if _, _, admitErr := s.AdmitFirewallAction(plan); admitErr != nil {
		t.Fatalf("admit %s: %v", id, admitErr)
	}
	for _, phase := range []string{"executing", "applied", "verified"} {
		if _, transitionErr := s.TransitionFirewallAction(id, phase, "", at); transitionErr != nil {
			t.Fatalf("transition %s to %s: %v", id, phase, transitionErr)
		}
	}
	stored, err := s.ReadFirewallAction(id)
	if err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return stored
}

func acknowledgeAllFirewallAudit(t *testing.T, s firewall.ActionStore) {
	t.Helper()
	pending, err := s.FirewallAuditPending()
	if err != nil {
		t.Fatalf("audit pending: %v", err)
	}
	for _, a := range pending {
		if err := s.AcknowledgeFirewallAudit(a.Request.ID, a.AuditVersion); err != nil {
			t.Fatalf("acknowledge %s: %v", a.Request.ID, err)
		}
	}
}

func firewallActionExists(t *testing.T, s firewall.ActionStore, id string) bool {
	t.Helper()
	_, err := s.ReadFirewallAction(id)
	if err == nil {
		return true
	}
	if errors.Is(err, firewall.ErrActionMissing) {
		return false
	}
	t.Fatalf("read %s: %v", id, err)
	return false
}

func TestFirewallActionHistoryKeepsNewestWithinCountCap(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	if _, err := s.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
		t.Fatal(err)
	}
	previous := firewallActionRetention
	t.Cleanup(func() { firewallActionRetention = previous })
	firewallActionRetention = firewallActionRetentionCaps{Actions: 3, Bytes: previous.Bytes, BudgetWindows: previous.BudgetWindows}
	at := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	for i := range 5 {
		terminalActionFixture(t, s, fmt.Sprintf("action-%d", i), at.Add(time.Duration(i)*time.Minute), "cap")
		acknowledgeAllFirewallAudit(t, s)
	}
	for i := range 2 {
		if firewallActionExists(t, s, fmt.Sprintf("action-%d", i)) {
			t.Fatalf("action-%d survived the retained-action cap", i)
		}
	}
	for i := 2; i < 5; i++ {
		if !firewallActionExists(t, s, fmt.Sprintf("action-%d", i)) {
			t.Fatalf("action-%d was pruned inside the retained-action cap", i)
		}
	}
	state, revision, err := s.ReadFirewallState()
	if err != nil || revision != 6 || len(state.Blocked) != 5 {
		t.Fatalf("committed state = %#v, revision %d, %v", state, revision, err)
	}
}

func TestFirewallActionHistoryKeepsUndeliveredAndPendingRecords(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	if _, err := s.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
		t.Fatal(err)
	}
	previous := firewallActionRetention
	t.Cleanup(func() { firewallActionRetention = previous })
	firewallActionRetention = firewallActionRetentionCaps{Actions: 1, Bytes: previous.Bytes, BudgetWindows: previous.BudgetWindows}
	at := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	terminalActionFixture(t, s, "undelivered", at, "audit")
	terminalActionFixture(t, s, "newer", at.Add(time.Minute), "audit")
	if !firewallActionExists(t, s, "undelivered") {
		t.Fatal("an action with undelivered audit was pruned")
	}
	acknowledgeAllFirewallAudit(t, s)
	terminalActionFixture(t, s, "newest", at.Add(2*time.Minute), "audit")
	acknowledgeAllFirewallAudit(t, s)
	if firewallActionExists(t, s, "undelivered") {
		t.Fatal("a delivered action stayed beyond the cap")
	}
	if !firewallActionExists(t, s, "newest") {
		t.Fatal("the newest action was pruned")
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(firewallAuditBucket))
		if b == nil {
			return errors.New("audit bucket missing")
		}
		return b.ForEach(func(k, _ []byte) error {
			if strings.HasPrefix(string(k), "undelivered\x00") {
				return errors.New("pruned action left audit events behind")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallActionHistoryHonoursByteBudget(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	if _, err := s.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
		t.Fatal(err)
	}
	previous := firewallActionRetention
	t.Cleanup(func() { firewallActionRetention = previous })
	filler := strings.Repeat("e", 4096)
	firewallActionRetention = firewallActionRetentionCaps{Actions: previous.Actions, Bytes: 12 * 1024, BudgetWindows: previous.BudgetWindows}
	at := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	for i := range 6 {
		terminalActionFixture(t, s, fmt.Sprintf("bytes-%d", i), at.Add(time.Duration(i)*time.Minute), filler)
		acknowledgeAllFirewallAudit(t, s)
	}
	if !firewallActionExists(t, s, "bytes-5") {
		t.Fatal("the newest action was pruned by the byte budget")
	}
	if firewallActionExists(t, s, "bytes-0") {
		t.Fatal("the oldest action survived the byte budget")
	}
	// One record can exceed the budget on its own, so the newest outcome is
	// always kept. Everything older than it must be gone.
	var retained []firewallActionHistoryEntry
	var bytes uint64
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		retained, bytes, err = readFirewallActionHistory(tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || retained[0].id != "bytes-5" {
		t.Fatalf("retained = %#v, want only bytes-5", retained)
	}
	if bytes <= firewallActionRetention.Bytes {
		t.Fatalf("retained %d bytes; the fixture must exceed the %d byte budget to prove the cap", bytes, firewallActionRetention.Bytes)
	}
}

func TestFirewallActionSweepRemovesOnlyOlderTerminalRecords(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	if _, err := s.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	terminalActionFixture(t, s, "old", at, "sweep")
	acknowledgeAllFirewallAudit(t, s)
	// This one keeps an undelivered outcome, so the sweep must keep the record
	// its audit reference points at.
	terminalActionFixture(t, s, "kept-undelivered", at.Add(time.Minute), "sweep")
	terminalActionFixture(t, s, "recent", at.Add(48*time.Hour), "sweep")
	state, revision, err := s.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	pendingPlan := firewall.FirewallAction{
		Request:   firewall.ActionRequest{ID: "pending", Operation: "unblock", Target: "198.51.100.1", Actor: "cli", Source: "manual"},
		Before:    state,
		After:     firewall.FirewallState{},
		Revision:  revision,
		CreatedAt: at,
	}
	if _, _, admitErr := s.AdmitFirewallAction(pendingPlan); admitErr != nil {
		t.Fatal(admitErr)
	}
	deleted, err := db.SweepFirewallActionsOlderThan(at.Add(24 * time.Hour))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	if firewallActionExists(t, s, "old") {
		t.Fatal("an old terminal action survived the sweep")
	}
	for _, id := range []string{"kept-undelivered", "recent", "pending"} {
		if !firewallActionExists(t, s, id) {
			t.Fatalf("%s must survive the sweep", id)
		}
	}
	if _, err := db.SweepFirewallActionsOlderThan(at.Add(24 * time.Hour)); err != nil {
		t.Fatalf("repeat sweep: %v", err)
	}
}

func TestFirewallScanBudgetWindowsStayBounded(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	if _, err := s.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
		t.Fatal(err)
	}
	previous := firewallActionRetention
	t.Cleanup(func() { firewallActionRetention = previous })
	firewallActionRetention = firewallActionRetentionCaps{Actions: previous.Actions, Bytes: previous.Bytes, BudgetWindows: 2}
	at := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	windows := []string{"2026-02-03T01", "2026-02-03T02", "2026-02-03T03", "2026-02-03T04"}
	for i, window := range windows {
		state, revision, err := s.ReadFirewallState()
		if err != nil {
			t.Fatal(err)
		}
		next := firewall.FirewallState{Blocked: append([]firewall.BlockedEntry(nil), state.Blocked...)}
		next.Blocked = append(next.Blocked, firewall.BlockedEntry{IP: fmt.Sprintf("203.0.113.%d", i+1), Reason: "budget", BlockedAt: at})
		id := fmt.Sprintf("budget-%d", i)
		plan := firewall.FirewallAction{
			Request:   firewall.ActionRequest{ID: id, Operation: "block", Target: "203.0.113.1", Actor: "daemon", Source: "scan"},
			Before:    state,
			After:     next,
			Revision:  revision,
			CreatedAt: at,
			Budget:    &firewall.ScanAdmission{Window: window, Limit: 5},
		}
		if _, _, err := s.AdmitFirewallAction(plan); err != nil {
			t.Fatalf("admit %s: %v", id, err)
		}
		for _, phase := range []string{"executing", "applied", "verified"} {
			if _, err := s.TransitionFirewallAction(id, phase, "", at); err != nil {
				t.Fatal(err)
			}
		}
		acknowledgeAllFirewallAudit(t, s)
	}
	for _, window := range windows[:2] {
		count, err := s.ReadFirewallScanBudget(window)
		if err != nil || count != 0 {
			t.Fatalf("pruned window %s = %d, %v", window, count, err)
		}
	}
	for _, window := range windows[2:] {
		count, err := s.ReadFirewallScanBudget(window)
		if err != nil || count != 1 {
			t.Fatalf("retained window %s = %d, %v", window, count, err)
		}
	}
	var retainedWindows int
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		inventory, err := readFirewallBudgetInventory(tx)
		retainedWindows = len(inventory.Windows)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if retainedWindows != 2 {
		t.Fatalf("inventory windows = %d, want 2", retainedWindows)
	}
}

func TestFirewallActionHistoryCorruptionFailsClosed(t *testing.T) {
	for _, damage := range []string{"missing action", "invalid size"} {
		t.Run(damage, func(t *testing.T) {
			db := openSnapshotDB(t)
			s := actionStore(t, db)
			if _, err := s.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
				t.Fatal(err)
			}
			at := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
			terminalActionFixture(t, s, "damaged", at, "corrupt")
			acknowledgeAllFirewallAudit(t, s)
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				history := tx.Bucket([]byte(firewallActionHistoryBucket))
				key, _ := history.Cursor().First()
				switch damage {
				case "missing action":
					return tx.Bucket([]byte(firewallActionsBucket)).Delete([]byte("damaged"))
				case "invalid size":
					return history.Put(key, []byte("size"))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.SweepFirewallActionsOlderThan(at.Add(time.Hour)); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("sweep = %v, want corruption", err)
			}
			state, revision, err := s.ReadFirewallState()
			if err != nil {
				t.Fatal(err)
			}
			plan := firewall.FirewallAction{
				Request:   firewall.ActionRequest{ID: "after-damage", Operation: "block", Target: "198.51.100.9", Actor: "cli", Source: "manual"},
				Before:    state,
				After:     state,
				Revision:  revision,
				CreatedAt: at,
			}
			if _, _, err := s.AdmitFirewallAction(plan); err != nil {
				t.Fatalf("admission over damaged history = %v", err)
			}
			for _, phase := range []string{"executing", "applied"} {
				if _, err := s.TransitionFirewallAction("after-damage", phase, "", at); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.TransitionFirewallAction("after-damage", "verified", "", at); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("outcome over damaged history = %v", err)
			}
			if _, _, err := s.ReadFirewallState(); err != nil {
				t.Fatalf("committed state must stay readable: %v", err)
			}
		})
	}
}
