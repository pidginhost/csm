package checks

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAttributionHealthPublishesWholeUpdates(t *testing.T) {
	r := newUnattributedReporter(func(string, ...any) {})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 2000 {
				r.RecordActiveSet(map[string]int{"webshell": 1})
			}
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	defer func() { <-done }()
	for {
		h := r.Health()
		if h.Cumulative["webshell"] != h.ActiveSetUpdates {
			t.Fatalf("partially published update: %+v", h)
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func TestAttributionHealthCountsFinalCappedSet(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	prev := defaultUnattributedReporter
	defaultUnattributedReporter = newUnattributedReporter(func(string, ...any) {})
	t.Cleanup(func() { defaultUnattributedReporter = prev })
	st := newTestStore(t)
	now := time.Now()
	rows := make([]alert.Finding, 0, 15000)
	for i := range 14997 {
		rows = append(rows, alert.Finding{Check: "db_rogue_admin", Severity: alert.Critical, TenantID: "alice", Message: fmt.Sprintf("row %d", i), Timestamp: now})
	}
	for _, account := range []string{"bob", "carol", ""} {
		rows = append(rows, alert.Finding{Check: "webshell", Severity: alert.Warning, TenantID: account, Message: "artifact " + account, Timestamp: now})
	}
	rows[len(rows)-1].Timestamp = now.Add(-time.Hour)
	StoreLatestScanFindings(st, []string{"db_rogue_admin", "webshell"}, rows)
	latest := st.LatestFindings()
	want := CorrelateFindings(latest).Unattributed
	if len(latest) != 15000 || len(want) != 0 {
		t.Fatalf("fixture did not evict the unattributed row: size=%d counts=%v", len(latest), want)
	}
	if got := AttributionHealth().Current; !reflect.DeepEqual(got, want) {
		t.Fatalf("health counts rows evicted by derived findings: got %v, want %v", got, want)
	}
}

func TestAttributionHealthConcurrentMergesMatchStore(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	prev := defaultUnattributedReporter
	defaultUnattributedReporter = newUnattributedReporter(func(string, ...any) {})
	t.Cleanup(func() { defaultUnattributedReporter = prev })
	st := newTestStore(t)
	for range 30 {
		var wg sync.WaitGroup
		for _, owner := range []string{"alice", ""} {
			wg.Go(func() {
				StoreLatestScanFindings(st, []string{"webshell"}, []alert.Finding{{Check: "webshell", Severity: alert.Critical, TenantID: owner, Message: "artifact"}})
			})
		}
		wg.Wait()
		if got, want := AttributionHealth().Current, CorrelateFindings(st.LatestFindings()).Unattributed; !reflect.DeepEqual(got, want) {
			t.Fatalf("older merge overwrote health: got %v, want %v", got, want)
		}
	}
}

func TestAttributionHealthLoggerCanMerge(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	prev := defaultUnattributedReporter
	defaultUnattributedReporter = newUnattributedReporter(func(string, ...any) {
		StoreLatestScanFindings(st, []string{"webshell"}, nil)
	})
	t.Cleanup(func() { defaultUnattributedReporter = prev })
	done := make(chan struct{})
	go func() {
		StoreLatestScanFindings(st, []string{"webshell"}, []alert.Finding{{Check: "webshell", Severity: alert.Critical}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("logger could not re-enter merge")
	}
	if h := AttributionHealth(); len(h.Current) != 0 || h.ActiveSetUpdates != 2 || h.Cumulative["webshell"] != 1 {
		t.Fatalf("logger merge lost: %+v", h)
	}
}

// The active-set snapshot answers "which checks are losing attribution on
// this host right now"; the cumulative count answers "how often has it
// happened since start". A batch report feeds only the latter.
func TestAttributionHealthDistinguishesActiveSetFromCumulative(t *testing.T) {
	rec := &warnRecorder{}
	r := newUnattributedReporter(rec.warn)
	if h := r.Health(); h.ActiveSetUpdates != 0 || len(h.Current) != 0 || len(h.Cumulative) != 0 || !h.Since.IsZero() {
		t.Fatalf("fresh reporter health = %+v", h)
	}

	r.RecordActiveSet(map[string]int{"db_rogue_admin": 2, "db_options_injection": 1, "ip_reputation": 7, "bogus": 3})
	h := r.Health()
	want := map[string]int{"db_rogue_admin": 2, "db_options_injection": 1}
	if !reflect.DeepEqual(h.Current, want) {
		t.Fatalf("current = %v, want eligible checks only %v", h.Current, want)
	}
	if !reflect.DeepEqual(h.Cumulative, want) || h.ActiveSetUpdates != 1 || h.Since.IsZero() {
		t.Fatalf("health after first active set = %+v", h)
	}

	// A per-batch report counts toward the cumulative total but never
	// changes what the active set says.
	r.Report(map[string]int{"webshell": 1, "db_rogue_admin": 5})
	h = r.Health()
	if !reflect.DeepEqual(h.Current, want) {
		t.Fatalf("batch report changed the active-set snapshot: %v", h.Current)
	}
	if h.Cumulative["webshell"] != 1 || h.Cumulative["db_rogue_admin"] != 7 || h.ActiveSetUpdates != 1 {
		t.Fatalf("cumulative after batch = %+v", h)
	}

	// Recovery: the next active set carries owners everywhere, so the
	// current snapshot clears while the history stays.
	r.RecordActiveSet(nil)
	h = r.Health()
	if len(h.Current) != 0 {
		t.Fatalf("current did not clear after an attributed active set: %v", h.Current)
	}
	if h.Cumulative["db_rogue_admin"] != 7 || h.ActiveSetUpdates != 2 {
		t.Fatalf("cumulative lost history on recovery: %+v", h)
	}

	// Returned maps are copies.
	h.Cumulative["db_rogue_admin"] = 0
	if r.Health().Cumulative["db_rogue_admin"] != 7 {
		t.Fatal("Health exposes its internal map")
	}
}

// Both entry points share the once-per-check warning: an active-set update
// after a batch report of the same check stays quiet, and vice versa.
func TestAttributionHealthWarnsOnceAcrossBothPaths(t *testing.T) {
	rec := &warnRecorder{}
	r := newUnattributedReporter(rec.warn)
	r.RecordActiveSet(map[string]int{"db_rogue_admin": 2})
	r.Report(map[string]int{"db_rogue_admin": 9})
	r.RecordActiveSet(map[string]int{"db_rogue_admin": 1})
	if calls := rec.snapshot(); len(calls) != 1 || argValue(calls[0].args, "rows") != 2 {
		t.Fatalf("warnings = %+v, want one from the first active set", calls)
	}
	r.RecordActiveSet(map[string]int{"webshell": 1})
	if len(rec.snapshot()) != 2 {
		t.Fatalf("a new check in the active set did not warn: %+v", rec.snapshot())
	}
}

// The latest-state merge is what defines the active set: rows it merges
// without an owner appear in the snapshot, and a later merge whose rows carry
// owners clears them. Per-tier batches do not touch the snapshot.
func TestAttributionHealthFollowsLatestStateMerge(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	rec := &warnRecorder{}
	prev := defaultUnattributedReporter
	defaultUnattributedReporter = newUnattributedReporter(rec.warn)
	t.Cleanup(func() { defaultUnattributedReporter = prev })
	st := newTestStore(t)

	unattributed := []alert.Finding{
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: alice)"},
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: bob)"},
	}
	StoreLatestScanFindings(st, purgeNamesFor("db_content"), unattributed)
	if h := AttributionHealth(); h.Current["db_rogue_admin"] != 2 || h.ActiveSetUpdates != 1 {
		t.Fatalf("health after unattributed merge = %+v", h)
	}

	// A batch with unattributed rows from another check leaves the active
	// set alone but is counted.
	ReportUnattributedCorrelation(map[string]int{"webshell": 3})
	if h := AttributionHealth(); h.Current["db_rogue_admin"] != 2 || len(h.Current) != 1 || h.Cumulative["webshell"] != 3 {
		t.Fatalf("health after batch report = %+v", h)
	}

	attributed := []alert.Finding{
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: alice)", TenantID: "alice"},
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: bob)", TenantID: "bob"},
	}
	StoreLatestScanFindings(st, purgeNamesFor("db_content"), attributed)
	h := AttributionHealth()
	if len(h.Current) != 0 {
		t.Fatalf("attributed merge did not clear the active set: %v", h.Current)
	}
	if h.Cumulative["db_rogue_admin"] != 2 || h.ActiveSetUpdates != 2 {
		t.Fatalf("cumulative after recovery = %+v", h)
	}
}
