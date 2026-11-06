package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// deliver runs one delivery through the reservation API in which every
// eligible finding is sent, and returns what was sent.
func deliver(s *Store, findings ...alert.Finding) []alert.Finding {
	eligible, finish := s.BeginDelivery(findings)
	finish(eligible)
	return eligible
}

// offered returns what a delivery would send now, then sends nothing.
func offered(s *Store, findings ...alert.Finding) []alert.Finding {
	eligible, finish := s.BeginDelivery(findings)
	finish(nil)
	return eligible
}

func gateKeys(findings []alert.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.Key())
	}
	return keys
}

func TestFilterUnemailedSkipsDeliveredContent(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "shell in upload", Details: "first"}
	s.Update([]alert.Finding{f})
	deliver(s, f)
	if got := offered(s, f); len(got) != 0 {
		t.Fatalf("delivered content offered again: %v", gateKeys(got))
	}

	changed := f
	changed.Details = "second"
	if got := offered(s, changed); len(got) != 1 || got[0].Key() != changed.Key() {
		t.Fatalf("changed content held back: %v", gateKeys(got))
	}

	// The same identity with a different delivered fingerprint is new content.
	s.mu.Lock()
	s.entries[f.Key()].Emailed = "older content"
	s.mu.Unlock()
	if got := offered(s, f); len(got) != 1 {
		t.Fatalf("content delivered under an older fingerprint held back: %v", gateKeys(got))
	}
}

func TestFilterUnemailedKeepsUndelivered(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "shell in upload"}
	s.Update([]alert.Finding{f})
	if got := offered(s, f); len(got) != 1 {
		t.Fatalf("alerted but undelivered finding held back: %v", gateKeys(got))
	}
}

func TestFilterUnemailedBaselineAndDismissal(t *testing.T) {
	baseline := alert.Finding{Check: "webshell", Message: "baseline"}
	dismissed := alert.Finding{Check: "webshell", Message: "dismissed"}

	s := openTestStore(t)
	s.SetBaseline([]alert.Finding{baseline})
	s.Update([]alert.Finding{dismissed})
	s.DismissFinding(dismissed.Key())

	if got := offered(s, baseline, dismissed); len(got) != 0 {
		t.Fatalf("baseline or dismissed finding offered for email: %v", gateKeys(got))
	}
}

func TestFilterUnemailedRefreshesLastSeen(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.7"}
	deliver(s, f)
	old := time.Now().Add(-20 * time.Hour)
	s.mu.Lock()
	s.entries[f.Key()].LastSeen = old
	s.dirty = false
	s.mu.Unlock()

	if got := offered(s, f); len(got) != 0 {
		t.Fatalf("delivered finding offered again: %v", gateKeys(got))
	}
	entry, ok := s.EntryForKey(f.Key())
	if !ok || !entry.LastSeen.After(old) {
		t.Fatalf("dropped finding did not refresh LastSeen: %+v", entry)
	}
	s.mu.RLock()
	dirty := s.dirty
	s.mu.RUnlock()
	if !dirty {
		t.Fatal("LastSeen refresh left the state clean, so it would not persist")
	}
}

func TestDeliveryCreatesEntry(t *testing.T) {
	s := openTestStore(t)
	action := alert.Finding{Check: "auto_block", Severity: alert.High, Message: "AUTO-BLOCK: 203.0.113.9"}
	if _, ok := s.EntryForKey(action.Key()); ok {
		t.Fatal("setup: action already has an entry")
	}
	if got := deliver(s, action); len(got) != 1 {
		t.Fatalf("action with no entry held back: %v", gateKeys(got))
	}
	entry, ok := s.EntryForKey(action.Key())
	if !ok || entry.Hash != action.Fingerprint() || entry.Emailed != action.Fingerprint() ||
		entry.FirstSeen.IsZero() || entry.LastSeen.IsZero() || entry.AlertSent.IsZero() {
		t.Fatalf("delivered entry = %+v, ok=%t", entry, ok)
	}
	if got := offered(s, action); len(got) != 0 {
		t.Fatalf("delivered action offered again: %v", gateKeys(got))
	}

	s.mu.Lock()
	s.entries[action.Key()].LastSeen = time.Now().Add(-25 * time.Hour)
	s.mu.Unlock()
	s.Update(nil)
	if got := offered(s, action); len(got) != 1 {
		t.Fatalf("action unseen for 25h still held back: %v", gateKeys(got))
	}
}

func writeStateFile(t *testing.T, dir string, entries map[string]*Entry) {
	t.Helper()
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenMarksAlertedEntriesEmailed(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	a := alert.Finding{Check: "webshell", Message: "alerted before upgrade"}
	b := alert.Finding{Check: "webshell", Message: "never alerted"}
	baseline := alert.Finding{Check: "webshell", Message: "baseline"}
	writeStateFile(t, dir, map[string]*Entry{
		a.Key():         {Hash: a.Fingerprint(), FirstSeen: now, LastSeen: now, AlertSent: now},
		b.Key():         {Hash: b.Fingerprint(), FirstSeen: now, LastSeen: now},
		baseline.Key():  {Hash: baseline.Fingerprint(), FirstSeen: now, LastSeen: now, AlertSent: now, IsBaseline: true},
		"_throttle:any": {Hash: "raw", LastSeen: now, AlertSent: now},
	})

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := offered(s, a, b)
	if len(got) != 1 || got[0].Key() != b.Key() {
		t.Fatalf("after upgrade got %v, want only %s", gateKeys(got), b.Key())
	}
	if _, ok := s.GetRaw(emailGateMetaKey); !ok {
		t.Fatal("upgrade marker not set")
	}
	for _, key := range []string{baseline.Key(), "_throttle:any"} {
		if entry, _ := s.EntryForKey(key); entry.Emailed != "" {
			t.Errorf("%s migrated: %+v", key, entry)
		}
	}

	// Leave an alerted entry without a delivery and no delivered entry, so
	// only the persisted marker keeps the reopened store from migrating it.
	s.ForgetCleared([]alert.Finding{a})
	c := alert.Finding{Check: "webshell", Message: "alerted after upgrade"}
	s.Update([]alert.Finding{c})
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if !onDiskKeys(t, dir)[emailGateMetaKey] {
		t.Fatal("upgrade marker not persisted")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got = offered(reopened, b, c)
	if len(got) != 2 || got[0].Key() != b.Key() || got[1].Key() != c.Key() {
		t.Fatalf("after reopening got %v, want %s and %s", gateKeys(got), b.Key(), c.Key())
	}
}

func retiredKeys(retired []alert.Finding) map[string]bool {
	keys := make(map[string]bool, len(retired))
	for _, f := range retired {
		keys[f.Key()] = true
	}
	return keys
}

func TestPurgeAndMergeReturnsRetired(t *testing.T) {
	const gapPath = "/home/example/public_html/gap.php"
	cleared := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "cleared", FilePath: "/home/example/public_html/a.php"}
	gap := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "unexamined", FilePath: gapPath}
	demoted := alert.Finding{Check: "webshell", Severity: alert.Warning, DemotedFrom: alert.High, Message: "demoted"}
	reported := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "reported again"}
	other := alert.Finding{Check: "other_check", Severity: alert.Critical, Message: "not purged"}
	scoped := alert.Finding{Check: "db_scan", Severity: alert.High, Message: "scope done", CoverageScope: "db1"}
	derivedGone := alert.Finding{Check: "derived_check", Severity: alert.High, Message: "no longer derived"}
	derivedKept := alert.Finding{Check: "derived_check", Severity: alert.High, Message: "derived again"}
	// Purged by the first pass and derived again by the second.
	crossPass := alert.Finding{Check: "derived_purged", Severity: alert.High, Message: "both passes"}

	s := openTestStore(t)
	s.SetLatestFindings([]alert.Finding{cleared, gap, demoted, reported, other, scoped, derivedGone, derivedKept, crossPass})
	retired, kept := s.PurgeAndMergeFindingsDerivedWithCoverage(
		[]string{"webshell", "derived_purged"},
		[]alert.Finding{reported},
		&ScanCoverage{
			PreservePaths:   map[string]map[string]bool{"webshell": {gapPath: true}},
			CompletedScopes: map[string]map[string]bool{"db_scan": {"db1": true}},
		},
		[]string{"derived_check", "derived_purged"},
		func([]alert.Finding) []alert.Finding { return []alert.Finding{derivedKept, crossPass} },
	)
	got := retiredKeys(retired)
	want := map[string]bool{cleared.Key(): true, scoped.Key(): true, derivedGone.Key(): true}
	if len(got) != len(want) || len(retired) != len(want) {
		t.Fatalf("retired = %v, want %v", got, want)
	}
	for key := range want {
		if !got[key] {
			t.Fatalf("retired = %v, missing %s", got, key)
		}
	}
	// Every other current row is kept, still present.
	gotKept := make(map[string]bool, len(kept))
	for _, key := range kept {
		gotKept[key] = true
	}
	wantKept := []alert.Finding{gap, demoted, reported, other, derivedKept, crossPass}
	if len(kept) != len(wantKept) {
		t.Fatalf("kept = %v, want %d rows", kept, len(wantKept))
	}
	for _, f := range wantKept {
		if !gotKept[f.Key()] {
			t.Fatalf("kept = %v, missing %s", kept, f.Key())
		}
	}

	// A row the cap evicts was not cleared by any scan.
	evicted := alert.Finding{Check: "other_check", Severity: alert.Warning, Message: "evicted", Timestamp: time.Unix(1, 0)}
	capped := openTestStore(t)
	capped.SetLatestFindings([]alert.Finding{evicted})
	flood := make([]alert.Finding, latestFindingsCap)
	for i := range flood {
		flood[i] = alert.Finding{Check: "flood", Severity: alert.High, Message: fmt.Sprintf("row %d", i), Timestamp: time.Unix(1000, 0)}
	}
	retired, kept = capped.PurgeAndMergeFindingsDerivedWithCoverage([]string{"flood"}, flood, nil, nil, nil)
	if len(retired) != 0 {
		t.Fatalf("cap eviction reported as retired: %v", gateKeys(retired))
	}
	if len(kept) != 1 || kept[0] != evicted.Key() {
		t.Fatalf("cap-evicted row not kept as present: %v", kept)
	}
	for _, f := range capped.LatestFindings() {
		if f.Key() == evicted.Key() {
			t.Fatal("setup: the cap did not evict the low-priority row")
		}
	}
}

func TestForgetClearedKeepsBaseline(t *testing.T) {
	s := openTestStore(t)
	baseline := alert.Finding{Check: "webshell", Message: "baseline"}
	active := alert.Finding{Check: "webshell", Message: "active"}
	internal := alert.Finding{Check: "_throttle", Message: "probe"}
	s.SetBaseline([]alert.Finding{baseline})
	s.Update([]alert.Finding{active})
	deliver(s, active)
	s.SetRaw(internal.Key(), "raw")

	s.ForgetCleared([]alert.Finding{baseline, active, internal})

	if _, ok := s.EntryForKey(active.Key()); ok {
		t.Fatal("cleared entry kept")
	}
	if entry, ok := s.EntryForKey(baseline.Key()); !ok || !entry.IsBaseline {
		t.Fatalf("baseline entry forgotten: %+v ok=%t", entry, ok)
	}
	if _, ok := s.GetRaw(internal.Key()); !ok {
		t.Fatal("internal entry forgotten")
	}
	if got := offered(s, active); len(got) != 1 {
		t.Fatalf("cleared finding held back on return: %v", gateKeys(got))
	}
}

func TestEmailGateFreshStateKeepsUndeliveredOnRestart(t *testing.T) {
	for _, baseline := range []bool{false, true} {
		t.Run(fmt.Sprintf("baseline=%t", baseline), func(t *testing.T) {
			s := openTestStore(t)
			if baseline {
				s.SetBaseline([]alert.Finding{{Check: "baseline", Message: "accepted"}})
			}
			f := alert.Finding{Check: "webshell", Message: "delivery failed"}
			s.Update([]alert.Finding{f})
			s.MarkAlerted([]alert.Finding{f})
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if !onDiskKeys(t, s.path)[emailGateMetaKey] {
				t.Fatal("marker not persisted")
			}
			reopened, err := Open(s.path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			if got := offered(reopened, f); len(got) != 1 {
				t.Fatalf("undelivered finding lost across restart: %v", gateKeys(got))
			}
		})
	}
}

func TestFilterUnemailedExpiresWithoutSweep(t *testing.T) {
	for _, baseline := range []bool{false, true} {
		t.Run(fmt.Sprintf("baseline=%t", baseline), func(t *testing.T) {
			s := openTestStore(t)
			now := time.Now().Add(-25 * time.Hour)
			s.now = func() time.Time { return now }
			f := alert.Finding{Check: "webshell", Message: "returned"}
			deliver(s, f)
			if baseline {
				s.DismissFinding(f.Key())
			}
			now = now.Add(25 * time.Hour)
			want := 1
			if baseline {
				want = 0
			}
			if got := offered(s, f); len(got) != want {
				t.Fatalf("after 25h without a sweep: got %v, want %d findings", gateKeys(got), want)
			}
			// Observing the returned finding before delivery must not restore
			// the receipt from its previous occurrence.
			s.Update([]alert.Finding{f})
			if got := offered(s, f); len(got) != want {
				t.Fatalf("pending recurrence lost after Update: %v", gateKeys(got))
			}
		})
	}
}

func TestUpdateExpiresReceiptBeforeObservingReturn(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().Add(-24 * time.Hour)
	s.now = func() time.Time { return now }
	f := alert.Finding{Check: "webshell", Message: "returned with notifications disabled"}
	deliver(s, f)
	now = now.Add(24 * time.Hour)
	s.Update([]alert.Finding{f})
	if got := offered(s, f); len(got) != 1 {
		t.Fatal("observing a return restored its expired delivery receipt")
	}
}

// The findings page shows LastSeen as the last report. Merges that keep a
// listed row alive must not move it, while the gate and the Update sweep
// still treat the condition as present.
func TestKeptRowKeepsReportedLastSeen(t *testing.T) {
	s := openTestStore(t)
	reported := time.Now().Add(-40 * time.Hour)
	now := reported
	s.now = func() time.Time { return now }
	f := alert.Finding{Check: "email_weak_password", Message: "weak password for user@example.com"}
	s.PurgeAndMergeFindings([]string{f.Check}, []alert.Finding{f})
	s.Update([]alert.Finding{f})
	deliver(s, f)

	for i := 0; i < 2; i++ {
		now = now.Add(20 * time.Hour)
		_, kept := s.PurgeAndMergeFindingsDerivedWithCoverage([]string{"other_check"}, nil, nil, nil, nil)
		s.MarkKept(kept)
	}
	entry, ok := s.EntryForKey(f.Key())
	if !ok || !entry.LastSeen.Equal(reported) {
		t.Fatalf("merges moved the reported LastSeen: %+v, present=%t", entry, ok)
	}
	s.Update(nil)
	if _, ok := s.EntryForKey(f.Key()); !ok {
		t.Fatal("Update swept a row the merge keeps listed")
	}
	if got := offered(s, f); len(got) != 0 {
		t.Fatalf("kept row offered for delivery again: %v", gateKeys(got))
	}
}

// After more than 24h without any merge or report, as after downtime, a
// merge does not revive the receipt: the next report emails once.
func TestMarkKeptDoesNotReviveStaleEntry(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().Add(-25 * time.Hour)
	s.now = func() time.Time { return now }
	f := alert.Finding{Check: "email_weak_password", Message: "weak password for user@example.com"}
	s.PurgeAndMergeFindings([]string{f.Check}, []alert.Finding{f})
	s.Update([]alert.Finding{f})
	deliver(s, f)

	now = now.Add(25 * time.Hour)
	_, kept := s.PurgeAndMergeFindingsDerivedWithCoverage([]string{"other_check"}, nil, nil, nil, nil)
	s.MarkKept(kept)
	if got := offered(s, f); len(got) != 1 {
		t.Fatalf("merge revived a receipt stale for 25h: %v", gateKeys(got))
	}
}

func TestEmailExpiryBoundary(t *testing.T) {
	for _, kept := range []bool{false, true} {
		for _, age := range []time.Duration{24*time.Hour - time.Nanosecond, 24 * time.Hour, 24*time.Hour + time.Nanosecond} {
			for _, operation := range []string{"sweep", "delivery", "merge"} {
				t.Run(fmt.Sprintf("kept=%t/age=%s/%s", kept, age, operation), func(t *testing.T) {
					now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
					s := debounceStore(t, &now)
					f := alert.Finding{Check: "webshell", Message: "expiry boundary"}
					deliver(s, f)
					if kept {
						now = now.Add(time.Hour)
						s.MarkKept([]string{f.Key()})
					}
					lastAlive := now
					now = now.Add(age)
					expired := age >= 24*time.Hour
					switch operation {
					case "sweep":
						s.Update(nil)
						if _, present := s.EntryForKey(f.Key()); present == expired {
							t.Fatalf("entry present=%t, expired=%t", present, expired)
						}
					case "delivery":
						if got := offered(s, f); (len(got) == 1) != expired {
							t.Fatalf("offered %d findings, expired=%t", len(got), expired)
						}
					case "merge":
						s.MarkKept([]string{f.Key()})
						entry, present := s.EntryForKey(f.Key())
						wantAlive := now
						if expired {
							wantAlive = lastAlive
						}
						if !present || !entry.aliveAt().Equal(wantAlive) {
							t.Fatalf("last alive=%v, present=%t, want %v", entry.aliveAt(), present, wantAlive)
						}
					}
				})
			}
		}
	}
}

// An acknowledgment of a ruled event condition covers it while it is reported
// or kept listed, and lapses once it is unseen for 24h. Other baselines, as
// `csm baseline` writes them, and explicit identities of scan findings, whose
// producer may report less than daily, never lapse.
func TestExplicitIdentityAcknowledgmentLapsesWithCondition(t *testing.T) {
	identities := []struct {
		name   string
		f      alert.Finding
		lapses bool
	}{
		{"ruled event", alert.Finding{Check: "smtp_probe_abuse", Severity: alert.High, Message: "SMTP probe abuse from 203.0.113.5", DedupKey: "203.0.113.5"}, true},
		{"ordinary", alert.Finding{Check: "smtp_probe_abuse", Severity: alert.High, Message: "SMTP probe abuse from 203.0.113.5"}, false},
		{"scan identity", alert.Finding{Check: "db_post_injection", Severity: alert.High, Message: "Injected script in posts", DedupKey: "db=\"alice_wp\" prefix=\"wp_\""}, false},
	}
	for _, ack := range []string{"dismissal", "baseline"} {
		for _, refresh := range []string{"report", "kept"} {
			for _, id := range identities {
				t.Run(fmt.Sprintf("%s/%s/%s", ack, refresh, id.name), func(t *testing.T) {
					now := time.Now()
					s := debounceStore(t, &now)
					f := id.f
					s.Update([]alert.Finding{f})
					deliver(s, f)
					if ack == "dismissal" {
						s.DismissFinding(f.Key())
					} else {
						s.SetBaseline([]alert.Finding{f})
					}
					if got := offered(s, f); len(got) != 0 {
						t.Fatalf("acknowledged condition offered for email")
					}
					now = now.Add(23 * time.Hour)
					if refresh == "report" {
						s.Update([]alert.Finding{f})
					} else {
						s.MarkKept([]string{f.Key()})
					}
					// FilterNew and the sweep only read liveness; a delivery
					// attempt would count as another report.
					now = now.Add(23 * time.Hour)
					if got := s.FilterNew([]alert.Finding{f}); len(got) != 0 {
						t.Fatalf("condition refreshed by %s lost its %s", refresh, ack)
					}
					if s.Update(nil); !s.Acknowledged(f) {
						t.Fatalf("sweep dropped a condition refreshed by %s", refresh)
					}
					now = now.Add(2 * time.Hour)
					lapsed := id.lapses
					if got := s.FilterNew([]alert.Finding{f}); (len(got) == 1) != lapsed {
						t.Fatalf("history after 25h unseen: new=%d, want lapsed=%t", len(got), lapsed)
					}
					s.Update(nil)
					if _, present := s.EntryForKey(f.Key()); present == lapsed {
						t.Fatalf("sweep after 25h unseen: present=%t, want lapsed=%t", present, lapsed)
					}
					if got := offered(s, f); (len(got) == 1) != lapsed {
						t.Fatalf("email after 25h unseen: offered=%d, want lapsed=%t", len(got), lapsed)
					}
					if s.Update([]alert.Finding{f}); s.Acknowledged(f) == lapsed {
						t.Fatalf("re-report after 25h unseen: acknowledged=%t, want lapsed=%t", s.Acknowledged(f), lapsed)
					}
				})
			}
		}
	}
}
