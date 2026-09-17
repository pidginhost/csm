package checks

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func criticalAt(account, check string, at time.Time) alert.Finding {
	return alert.Finding{
		Severity:  alert.Critical,
		Check:     check,
		Message:   "finding for " + account,
		TenantID:  account,
		Timestamp: at,
	}
}

func TestCorrelationWindowIgnoresDerivedTimestamps(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	at := time.Now().Add(-2 * time.Hour)
	rows := []alert.Finding{
		criticalAt("one", "webshell", at),
		criticalAt("two", "webshell", at),
		criticalAt("three", "db_rogue_admin", at),
		criticalAt("", "db_rogue_admin", at),
	}
	want := CorrelateFindings(rows)
	for _, check := range DerivedCorrelationChecks() {
		withDerived := append(append([]alert.Finding(nil), rows...), criticalAt("", check, time.Now()))
		if got := CorrelateFindings(withDerived); !reflect.DeepEqual(got, want) {
			t.Fatalf("derived %s changed correlation: got %+v, want %+v", check, got, want)
		}
	}
}

func TestCorrelationWindowBoundaryAndUnattributed(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	at := time.Now()
	rows := []alert.Finding{
		criticalAt("one", "webshell", at.Add(-time.Hour)),
		criticalAt("two", "webshell", at),
		criticalAt("three", "db_rogue_admin", time.Time{}),
		criticalAt("", "webshell", at.Add(-time.Hour)),
		criticalAt("", "webshell", time.Time{}),
		criticalAt("", "webshell", at.Add(-time.Hour-time.Nanosecond)),
	}
	got := CorrelateFindings(rows)
	if !raised(got, "coordinated_attack") || !raised(got, "cross_account_malware") || got.Unattributed["webshell"] != 2 {
		t.Fatalf("window boundary or legacy input lost: %+v", got)
	}
}

func TestLatestStateWindowExpiresOnEmptyScan(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	prev := defaultUnattributedReporter
	defaultUnattributedReporter = newUnattributedReporter(func(string, ...any) {})
	t.Cleanup(func() { defaultUnattributedReporter = prev })
	at := time.Now().Add(-2 * time.Hour)
	rows := []alert.Finding{
		criticalAt("one", "webshell", at),
		criticalAt("two", "webshell", at),
		criticalAt("three", "db_rogue_admin", at),
		criticalAt("", "db_rogue_admin", at),
		criticalAt("", "webshell", time.Time{}),
	}
	RecordUnattributedActiveSet(map[string]int{"db_rogue_admin": 1, "webshell": 1})
	st.SetLatestFindings(rows)
	StoreLatestScanFindings(st, []string{"file_index"}, nil)
	if got := checksIn(st.LatestFindings()); got["coordinated_attack"] != 0 || got["cross_account_malware"] != 0 || len(st.LatestFindings()) != len(rows) {
		t.Fatalf("empty scan did not expire aggregates while retaining sources: %v", got)
	}
	h := AttributionHealth()
	if !reflect.DeepEqual(h.Current, map[string]int{"webshell": 1}) || h.Cumulative["db_rogue_admin"] != 1 || h.Cumulative["webshell"] != 2 {
		t.Fatalf("expiry must clear current loss, preserve history and count unstamped rows: %+v", h)
	}
}

func raised(res CorrelationResult, check string) bool {
	for _, d := range res.Derived {
		if d.Check == check {
			return true
		}
	}
	return false
}

// A coordinated attack means several accounts were hit around the same time.
// The persisted active set holds months of findings, so without a bound the
// aggregate latches on the first three accounts that ever had a critical and
// never clears. On one recorded host it stayed raised for 76% of a 100-day
// recording, and for 99% of a two-day one.
func TestCorrelateFindingsIgnoresAccountsOutsideTheWindow(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	stale := []alert.Finding{
		criticalAt("one", "webshell", now.Add(-30*24*time.Hour)),
		criticalAt("two", "phishing_php", now.Add(-20*24*time.Hour)),
		criticalAt("three", "webshell", now),
	}
	if raised(CorrelateFindings(stale), "coordinated_attack") {
		t.Fatal("accounts attacked weeks apart raised a coordinated attack")
	}

	together := []alert.Finding{
		criticalAt("one", "webshell", now.Add(-30*time.Minute)),
		criticalAt("two", "phishing_php", now.Add(-10*time.Minute)),
		criticalAt("three", "webshell", now),
	}
	if !raised(CorrelateFindings(together), "coordinated_attack") {
		t.Fatal("three accounts attacked within the window did not correlate")
	}
}

// The same bound applies to the malware aggregate: the same webshell found on
// two accounts months apart is not one campaign.
func TestCorrelateFindingsWindowsCrossAccountMalware(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	apart := []alert.Finding{
		{Severity: alert.High, Check: "webshell", TenantID: "one", Timestamp: now.Add(-30 * 24 * time.Hour)},
		{Severity: alert.High, Check: "webshell", TenantID: "two", Timestamp: now},
	}
	if raised(CorrelateFindings(apart), "cross_account_malware") {
		t.Fatal("the same malware found a month apart raised a cross-account finding")
	}

	together := []alert.Finding{
		{Severity: alert.High, Check: "webshell", TenantID: "one", Timestamp: now.Add(-time.Minute)},
		{Severity: alert.High, Check: "webshell", TenantID: "two", Timestamp: now},
	}
	if !raised(CorrelateFindings(together), "cross_account_malware") {
		t.Fatal("the same malware on two accounts in one window did not correlate")
	}
}

// A batch carries findings stamped moments ago, so the bound is inert there:
// the realtime and scan paths must behave exactly as before.
func TestCorrelateFindingsWindowIsInertWithinOneBatch(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	batch := []alert.Finding{
		criticalAt("one", "webshell", now),
		criticalAt("two", "phishing_php", now.Add(time.Millisecond)),
		criticalAt("three", "wp_core_integrity", now.Add(2*time.Millisecond)),
	}
	if !raised(CorrelateFindings(batch), "coordinated_attack") {
		t.Fatal("a single dispatch batch stopped correlating")
	}
}

// A finding with no timestamp predates the fix that stamps every finding.
// It must keep counting rather than silently dropping out of correlation.
func TestCorrelateFindingsCountsUnstampedFindings(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", TenantID: "one"},
		criticalAt("two", "phishing_php", now),
		criticalAt("three", "webshell", now),
	}
	if !raised(CorrelateFindings(findings), "coordinated_attack") {
		t.Fatal("an unstamped finding was dropped from correlation")
	}
}

// The defect the window alone could not fix: a scan re-emits every finding it
// still sees with a fresh timestamp, so long-lived conditions kept re-entering
// the window on every cycle. On one production host 98.8% of correlation input
// was a re-report, and the aggregate named 75 accounts. Correlation must judge
// a finding by when the condition started, not by when it was last reported.
func TestCorrelateFindingsJudgesAccountsByFirstObservation(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)
	old := now.Add(-30 * 24 * time.Hour)

	// Three long-standing conditions, all re-reported by the scan that just
	// ran. Their Timestamp is current; their FirstSeen is a month old.
	restamped := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", TenantID: "one", Timestamp: now, FirstSeen: old},
		{Severity: alert.Critical, Check: "webshell", TenantID: "two", Timestamp: now, FirstSeen: old},
		{Severity: alert.Critical, Check: "phishing_php", TenantID: "three", Timestamp: now, FirstSeen: old},
	}
	if raised(CorrelateFindings(restamped), "coordinated_attack") {
		t.Fatal("a scan re-reporting month-old conditions raised a coordinated attack")
	}

	// The same three accounts, newly compromised, must still correlate.
	fresh := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", TenantID: "one", Timestamp: now, FirstSeen: now.Add(-20 * time.Minute)},
		{Severity: alert.Critical, Check: "webshell", TenantID: "two", Timestamp: now, FirstSeen: now.Add(-10 * time.Minute)},
		{Severity: alert.Critical, Check: "phishing_php", TenantID: "three", Timestamp: now, FirstSeen: now},
	}
	if !raised(CorrelateFindings(fresh), "coordinated_attack") {
		t.Fatal("three accounts first seen inside the window did not correlate")
	}
}

// A finding with no FirstSeen (a batch that never reached the merge, or a row
// stored before the field existed) falls back to its Timestamp rather than
// dropping out of correlation.
func TestCorrelateFindingsFallsBackToTimestampWithoutFirstSeen(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", TenantID: "one", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", TenantID: "two", Timestamp: now.Add(-time.Minute)},
		{Severity: alert.Critical, Check: "phishing_php", TenantID: "three", Timestamp: now.Add(-2 * time.Minute)},
	}
	if !raised(CorrelateFindings(findings), "coordinated_attack") {
		t.Fatal("findings without FirstSeen stopped correlating")
	}
}
