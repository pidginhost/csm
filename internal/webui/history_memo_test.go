package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func withMemoAges(t *testing.T, minAge, maxAge time.Duration) {
	t.Helper()
	oldMin, oldMax := memoMinAge, memoMaxAge
	memoMinAge, memoMaxAge = minAge, maxAge
	t.Cleanup(func() { memoMinAge, memoMaxAge = oldMin, oldMax })
}

func TestHistoryMemoReusesAResultUntilHistoryChanges(t *testing.T) {
	var m historyMemo
	calls := 0
	compute := func() any { calls++; return calls }

	withMemoAges(t, 0, time.Hour)
	m.get("a", compute)
	m.get("a", compute)
	if calls != 1 {
		t.Fatalf("unchanged history computed %d times, want 1", calls)
	}
	m.get("b", compute)
	if calls != 2 {
		t.Fatalf("changed history computed %d times in total, want 2", calls)
	}

	// A busy host changes history constantly; the minimum age bounds the work.
	withMemoAges(t, time.Hour, time.Hour)
	m.get("c", compute)
	if calls != 2 {
		t.Fatalf("a change inside the minimum age recomputed (%d)", calls)
	}

	// Time windows move even on a quiet host.
	withMemoAges(t, time.Hour, 0)
	m.get("c", compute)
	if calls != 3 {
		t.Fatalf("an expired result was reused (%d)", calls)
	}
}

func TestHistoryMemosDropTheOldestKey(t *testing.T) {
	var ms historyMemos
	first := ms.memo("k0")
	for i := 1; i <= historyMemosMax; i++ {
		ms.memo(string(rune('a' + i)))
	}
	if ms.memo("k0") == first {
		t.Fatal("the oldest memo was kept past the limit")
	}
	if len(ms.items) > historyMemosMax {
		t.Fatalf("%d memos kept, limit %d", len(ms.items), historyMemosMax)
	}
}

// The dashboard polls /api/v1/stats and loads the page from the same 24h
// summary; repeated polls while history is unchanged do not walk it again.
func TestStatsAndDashboardShareOneSummary(t *testing.T) {
	withMemoAges(t, 0, time.Hour)
	s := newTestServerWithTemplates(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{{Check: "webshell", Severity: alert.Critical, Message: "one", Timestamp: now.Add(-time.Minute)}})

	for i := 0; i < 3; i++ {
		s.apiStats(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil))
	}
	s.handleDashboard(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got := s.statsMemo.computes; got != 1 {
		t.Fatalf("summary computed %d times, want 1", got)
	}

	// New history is reflected.
	s.store.AppendHistory([]alert.Finding{{Check: "webshell", Severity: alert.Critical, Message: "two", Timestamp: now}})
	w := httptest.NewRecorder()
	s.apiStats(w, httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil))
	if s.statsMemo.computes != 2 || !strings.Contains(w.Body.String(), `"critical":2`) {
		t.Fatalf("computes=%d body=%s", s.statsMemo.computes, w.Body.String())
	}
}

func TestTimelineReusesItsResultWhileHistoryIsUnchanged(t *testing.T) {
	withMemoAges(t, 0, time.Hour)
	s := newTestServerWithBbolt(t, "tok")
	for i := 0; i < 3; i++ {
		s.apiStatsTimeline(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/stats/timeline", nil))
	}
	if got := s.timelineMemo.computes; got != 1 {
		t.Fatalf("timeline computed %d times, want 1", got)
	}
}

func TestEmailGroupsReuseResultsPerRange(t *testing.T) {
	withMemoAges(t, 0, time.Hour)
	s := newTestServerWithBbolt(t, "tok")
	get := func(q string) {
		s.apiEmailGroups(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/email/groups?"+q, nil))
	}
	from := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	get("from=" + from + "&limit=50")
	get("from=" + from + "&limit=50")
	get("from=" + from + "&limit=10")
	if got := len(s.emailMemos.items); got != 2 {
		t.Fatalf("%d memos for two distinct queries", got)
	}
	for key, m := range s.emailMemos.items {
		if m.computes != 1 {
			t.Errorf("%s computed %d times, want 1", key, m.computes)
		}
	}
}
