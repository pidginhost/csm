package checks

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

func openStoreAt(t *testing.T, dir string) *state.Store {
	t.Helper()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func closeStore(t *testing.T, st *state.Store) {
	t.Helper()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func checksIn(findings []alert.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[f.Check]++
	}
	return out
}

func purgeNamesFor(owner string) []string {
	return append([]string(nil), runnerFindingNames[owner]...)
}

func stamped(check, tenant string, sev alert.Severity) alert.Finding {
	return alert.Finding{Severity: sev, Check: check, TenantID: tenant, Message: check + " on " + tenant, FilePath: "/home/" + tenant + "/public_html/" + check + ".php", Timestamp: time.Now()}
}

// Three merges from disjoint runners, each below the threshold on its own,
// aggregate through the persisted active set; the aggregate follows the
// evidence as runners replace their snapshots.
func TestLatestStateAggregatesAcrossMerges(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	t.Cleanup(func() {
		if st != nil {
			closeStore(t, st)
		}
	})

	StoreLatestScanFindings(st, purgeNamesFor("db_content"), []alert.Finding{stamped("db_rogue_admin", "alice", alert.Critical)})
	if got := checksIn(st.LatestFindings()); !reflect.DeepEqual(got, map[string]int{"db_rogue_admin": 1}) {
		t.Fatalf("after first merge: %v", got)
	}
	StoreLatestScanFindings(st, purgeNamesFor("file_index"), []alert.Finding{stamped("new_php_in_uploads", "bob", alert.Critical)})
	got := checksIn(st.LatestFindings())
	if got["coordinated_attack"] != 0 || got["db_rogue_admin"] != 1 || got["new_php_in_uploads"] != 1 || len(st.LatestFindings()) != 2 {
		t.Fatalf("after two merges: %v", got)
	}
	StoreLatestScanFindings(st, purgeNamesFor("yara_deep"), []alert.Finding{stamped("yara_match_scheduled", "carol", alert.Critical)})
	got = checksIn(st.LatestFindings())
	if got["coordinated_attack"] != 1 || len(st.LatestFindings()) != 4 {
		t.Fatalf("after three merges: %v", got)
	}
	for _, f := range st.LatestFindings() {
		if f.Check == "coordinated_attack" && (f.Timestamp.IsZero() || f.Details != "Affected accounts: alice, bob, carol") {
			t.Fatalf("persisted aggregate %+v", f)
		}
	}
	// Reload while the derived row and all three owners are still present.
	// Normalize time locations/monotonic clocks to compare persisted values.
	snapshot := func() map[string]alert.Finding {
		rows := make(map[string]alert.Finding)
		for _, f := range st.LatestFindings() {
			f.Timestamp = f.Timestamp.UTC()
			rows[f.Key()] = f
		}
		return rows
	}
	before := snapshot()
	closeStore(t, st)
	st = nil
	st = openStoreAt(t, dir)
	if after := snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("reload disagrees: before %+v after %+v", before, after)
	}

	// The same runner replacing its snapshot with a demoted row clears the
	// aggregate; an alternative Critical for that owner keeps it.
	StoreLatestScanFindings(st, purgeNamesFor("yara_deep"), []alert.Finding{stamped("yara_match_scheduled", "carol", alert.High)})
	if got := checksIn(st.LatestFindings()); got["coordinated_attack"] != 0 {
		t.Fatalf("aggregate survived demotion below Critical: %v", got)
	}
	alternative := stamped("yara_match_scheduled", "carol", alert.Critical)
	alternative.Message += " in another file"
	alternative.FilePath = "/home/carol/public_html/other.php"
	StoreLatestScanFindings(st, purgeNamesFor("yara_deep"), []alert.Finding{stamped("yara_match_scheduled", "carol", alert.High), alternative})
	if got := checksIn(st.LatestFindings()); got["coordinated_attack"] != 1 || got["yara_match_scheduled"] != 2 || len(st.LatestFindings()) != 5 {
		t.Fatalf("alternative Critical did not keep the aggregate: %v", got)
	}
	// Replacing a runner's complete snapshot drops owners absent from it.
	StoreLatestScanFindings(st, purgeNamesFor("yara_deep"), nil)
	if got := checksIn(st.LatestFindings()); got["coordinated_attack"] != 0 || got["yara_match_scheduled"] != 0 {
		t.Fatalf("empty replacement kept stale rows: %v", got)
	}

	// A seeded stale derived row is replaced, never used as evidence.
	st.SetLatestFindings([]alert.Finding{{Severity: alert.Critical, Check: "coordinated_attack", Message: "stale", Timestamp: time.Now()}})
	StoreLatestScanFindings(st, purgeNamesFor("db_content"), []alert.Finding{stamped("db_rogue_admin", "alice", alert.Critical)})
	if got := checksIn(st.LatestFindings()); got["coordinated_attack"] != 0 {
		t.Fatalf("stale derived row survived a merge: %v", got)
	}
}

func TestLatestStateRecomputesAfterEvidenceChanges(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	for _, change := range []string{"dismiss", "verified clear", "demote"} {
		t.Run(change, func(t *testing.T) {
			st := newTestStore(t)
			rows := []alert.Finding{stamped("db_rogue_admin", "alice", alert.Critical), stamped("db_rogue_admin", "bob", alert.Critical), stamped("db_rogue_admin", "carol", alert.Critical)}
			StoreLatestScanFindings(st, purgeNamesFor("db_content"), rows)
			wantRows := 2
			switch change {
			case "dismiss":
				st.DismissFinding(rows[2].Key())
				st.DismissLatestFinding(rows[2].Key())
			case "verified clear":
				if !st.DismissFindingIfLatest(rows[2]) {
					t.Fatal("verified snapshot was not removed")
				}
			case "demote":
				if !st.DemoteLatestFinding(rows[2], alert.Warning) {
					t.Fatal("verified snapshot was not demoted")
				}
				wantRows = 3
			}
			// A no-op must leave recomputation to the next real scan merge.
			StoreLatestScanFindings(st, nil, nil)
			if got := checksIn(st.LatestFindings()); !reflect.DeepEqual(got, map[string]int{"db_rogue_admin": wantRows, "coordinated_attack": 1}) {
				t.Fatalf("before recomputation: %v", got)
			}
			StoreLatestScanFindings(st, purgeNamesFor("file_index"), nil)
			if got := checksIn(st.LatestFindings()); !reflect.DeepEqual(got, map[string]int{"db_rogue_admin": wantRows}) {
				t.Fatalf("after recomputation: %v", got)
			}
		})
	}
}

func TestLatestStateMalwareAggregateAtLowerSeverity(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	StoreLatestScanFindings(st, purgeNamesFor("webshells"), []alert.Finding{stamped("webshell", "alice", alert.Warning), stamped("webshell", "bob", alert.Warning)})
	if got := checksIn(st.LatestFindings()); got["cross_account_malware"] != 1 || got["coordinated_attack"] != 0 {
		t.Fatalf("lower-severity malware aggregate: %v", got)
	}
	StoreLatestScanFindings(st, purgeNamesFor("webshells"), []alert.Finding{stamped("webshell", "alice", alert.Warning)})
	if got := checksIn(st.LatestFindings()); got["cross_account_malware"] != 0 {
		t.Fatalf("malware aggregate survived membership dropping below two: %v", got)
	}
}

func TestLatestStateCoverageGapKeepsEvidence(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	rows := []alert.Finding{stamped("db_rogue_admin", "alice", alert.Critical), stamped("db_rogue_admin", "bob", alert.Critical), stamped("db_rogue_admin", "carol", alert.Critical)}
	StoreLatestScanFindings(st, purgeNamesFor("db_content"), rows)
	if got := checksIn(st.LatestFindings()); got["coordinated_attack"] != 1 {
		t.Fatalf("seed: %v", got)
	}
	// A replacement that could not examine carol's file keeps her row and
	// the aggregate; a later fully covered replacement clears both.
	gaps := map[string]map[string]bool{"db_rogue_admin": {rows[2].FilePath: true}}
	StoreLatestScanFindingsWithGaps(st, purgeNamesFor("db_content"), rows[:2], gaps)
	if got := checksIn(st.LatestFindings()); got["db_rogue_admin"] != 3 || got["coordinated_attack"] != 1 {
		t.Fatalf("gap retention: %v", got)
	}
	StoreLatestScanFindingsWithGaps(st, purgeNamesFor("db_content"), rows[:2], map[string]map[string]bool{})
	if got := checksIn(st.LatestFindings()); got["db_rogue_admin"] != 2 || got["coordinated_attack"] != 0 {
		t.Fatalf("covered replacement: %v", got)
	}
}

func TestLatestStateNoOpPathsAndRace(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	StoreLatestScanFindings(nil, purgeNamesFor("db_content"), []alert.Finding{stamped("db_rogue_admin", "alice", alert.Critical)})
	st := newTestStore(t)
	StoreLatestScanFindings(st, nil, nil)
	if len(st.LatestFindings()) != 0 {
		t.Fatal("empty call changed state")
	}

	StoreLatestScanFindings(st, purgeNamesFor("db_content"), []alert.Finding{stamped("db_rogue_admin", "alice", alert.Critical)})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		StoreLatestScanFindings(st, purgeNamesFor("file_index"), []alert.Finding{stamped("new_php_in_uploads", "bob", alert.Critical)})
	}()
	go func() {
		defer wg.Done()
		StoreLatestScanFindings(st, purgeNamesFor("yara_deep"), []alert.Finding{stamped("yara_match_scheduled", "carol", alert.Critical)})
	}()
	wg.Wait()
	got := checksIn(st.LatestFindings())
	if len(st.LatestFindings()) != 4 {
		t.Fatalf("concurrent merges left extra or missing rows: %v", got)
	}
	for _, want := range []string{"db_rogue_admin", "new_php_in_uploads", "yara_match_scheduled", "coordinated_attack"} {
		if got[want] != 1 {
			t.Errorf("after concurrent merges %s = %d: %v", want, got[want], got)
		}
	}
	for _, f := range st.LatestFindings() {
		if f.Check == "coordinated_attack" && f.Details != "Affected accounts: alice, bob, carol" {
			t.Fatalf("concurrent aggregate has wrong owners: %+v", f)
		}
	}
}

// The store callback captures the unattributed snapshot and reports only
// after the merge returns; a logger that reads the store must not deadlock.
func TestLatestStateReportsUnattributedOutsideLock(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	rec := &warnRecorder{}
	prev := defaultUnattributedReporter
	defaultUnattributedReporter = newUnattributedReporter(func(msg string, args ...any) {
		_ = st.LatestFindings() // would deadlock if invoked under latestMu
		rec.warn(msg, args...)
	})
	t.Cleanup(func() { defaultUnattributedReporter = prev })
	done := make(chan struct{})
	go func() {
		defer close(done)
		StoreLatestScanFindings(st, purgeNamesFor("db_content"), []alert.Finding{{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: alice)", Timestamp: time.Now()}})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("merge did not return; reporter ran under the store lock")
	}
	calls := rec.snapshot()
	if len(calls) != 1 || argValue(calls[0].args, "check") != "db_rogue_admin" || argValue(calls[0].args, "rows") != 1 {
		t.Fatalf("warnings %+v", calls)
	}
}
