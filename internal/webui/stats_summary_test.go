package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

type statsRiskAccount struct {
	Account  string `json:"account"`
	Severity string `json:"severity"`
	Findings int    `json:"findings"`
}

type statsRiskResponse struct {
	AccountsAtRisk []statsRiskAccount `json:"accounts_at_risk"`
	Last24h        map[string]int     `json:"last_24h"`
}

func getStatsRisk(t *testing.T, s *Server) statsRiskResponse {
	t.Helper()
	w := httptest.NewRecorder()
	s.apiStats(w, httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var body statsRiskResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if body.AccountsAtRisk == nil {
		t.Fatal("accounts_at_risk must be an array, even when empty")
	}
	return body
}

// Accounts at risk are the accounts with an active high or critical finding.
// A fixed finding leaves the dashboard as soon as it leaves the account page,
// even though history still holds it and the 24h summary is cached.
func TestAccountsAtRiskFollowActiveFindings(t *testing.T) {
	withMemoAges(t, time.Hour, time.Hour)
	s := newTestServer(t, "tok")
	now := time.Now()
	fixed := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "Webshell: /home/alice/public_html/x.php", Timestamp: now}
	high := alert.Finding{Check: "obfuscated_php", Severity: alert.High, Message: "Obfuscated PHP: /home/bob/public_html/a.php", Timestamp: now}
	warning := alert.Finding{Check: "world_writable_php", Severity: alert.Warning, Message: "World-writable PHP: /home/bob/public_html/b.php", Timestamp: now}
	suppressed := alert.Finding{Check: "backdoor_binary", Severity: alert.Critical, Message: "Backdoor: /home/carol/.config/x", Timestamp: now}
	internal := alert.Finding{Check: "auto_response", Severity: alert.Critical, Message: "Quarantined /home/dave/public_html/y.php", Timestamp: now}
	all := []alert.Finding{fixed, high, warning, suppressed, internal}
	s.store.AppendHistory(all)
	s.store.SetLatestFindings(all)
	if err := s.store.SaveSuppressions([]state.SuppressionRule{{ID: "sup-1", Check: "backdoor_binary", CreatedAt: now}}); err != nil {
		t.Fatal(err)
	}

	want := []statsRiskAccount{{"alice", "CRITICAL", 1}, {"bob", "HIGH", 2}}
	if got := getStatsRisk(t, s).AccountsAtRisk; !reflect.DeepEqual(got, want) {
		t.Fatalf("before fix: got %+v, want %+v", got, want)
	}

	s.store.DismissLatestFinding(fixed.Key())
	want = []statsRiskAccount{{"bob", "HIGH", 2}}
	if got := getStatsRisk(t, s).AccountsAtRisk; !reflect.DeepEqual(got, want) {
		t.Fatalf("after fix: got %+v, want %+v", got, want)
	}
}

func TestAccountsAtRiskUseCurrentFindingsBeyondHistoryWindow(t *testing.T) {
	for _, backend := range []struct {
		name string
		new  func(*testing.T, string) *Server
	}{{"json", newTestServer}, {"bbolt", newTestServerWithBbolt}} {
		t.Run(backend.name, func(t *testing.T) {
			s := backend.new(t, "")
			now := time.Now()
			active := alert.Finding{Check: "webshell", Severity: alert.Critical, TenantID: "alice", Message: "Still active", Timestamp: now.Add(-48 * time.Hour)}
			historical := alert.Finding{Check: "webshell", Severity: alert.High, TenantID: "bob", Message: "Already dismissed", Timestamp: now}
			s.store.AppendHistory([]alert.Finding{active, historical})
			s.store.SetLatestFindings([]alert.Finding{
				active,
				{Check: "world_writable_php", Severity: alert.Warning, TenantID: "carol", Message: "Warning only", Timestamp: now},
				{Check: "webshell", Severity: alert.Critical, Message: "No account attribution", Timestamp: now},
			})
			got := getStatsRisk(t, s)
			want := []statsRiskAccount{{"alice", "CRITICAL", 1}}
			if !reflect.DeepEqual(got.AccountsAtRisk, want) {
				t.Errorf("accounts = %+v, want %+v", got.AccountsAtRisk, want)
			}
			wantCounts := map[string]int{"critical": 0, "high": 1, "warning": 0, "total": 1}
			if !reflect.DeepEqual(got.Last24h, wantCounts) {
				t.Errorf("24h counts = %v, want %v", got.Last24h, wantCounts)
			}
		})
	}
}

func TestAccountsAtRiskRefreshWithoutHistoryChanges(t *testing.T) {
	withMemoAges(t, time.Hour, time.Hour)
	s := newTestServerWithBbolt(t, "")
	now := time.Now()
	critical := alert.Finding{Check: "webshell", Severity: alert.Critical, TenantID: "alice", Message: "Critical", FilePath: "/home/alice/critical.php", Timestamp: now}
	high := alert.Finding{Check: "webshell", Severity: alert.High, TenantID: "alice", Message: "High", FilePath: "/home/alice/high.php", Timestamp: now}
	s.store.AppendHistory([]alert.Finding{critical, high})
	s.store.SetLatestFindings([]alert.Finding{critical, high})
	mark := s.store.HistoryMark()
	assertRisk := func(want []statsRiskAccount) {
		t.Helper()
		got := getStatsRisk(t, s)
		if !reflect.DeepEqual(got.AccountsAtRisk, want) {
			t.Errorf("accounts = %+v, want %+v", got.AccountsAtRisk, want)
		}
		wantCounts := map[string]int{"critical": 1, "high": 1, "warning": 0, "total": 2}
		if !reflect.DeepEqual(got.Last24h, wantCounts) {
			t.Errorf("24h counts = %v, want %v", got.Last24h, wantCounts)
		}
		if s.store.HistoryMark() != mark || s.statsMemo.computes != 1 {
			t.Fatal("history must remain unchanged and its summary cached")
		}
	}
	assertRisk([]statsRiskAccount{{"alice", "CRITICAL", 2}})

	if err := s.store.SaveSuppressions([]state.SuppressionRule{{ID: "sup-1", Check: "webshell", PathPattern: critical.FilePath, CreatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	assertRisk([]statsRiskAccount{{"alice", "HIGH", 1}})
	if err := s.store.SaveSuppressions(nil); err != nil {
		t.Fatal(err)
	}
	assertRisk([]statsRiskAccount{{"alice", "CRITICAL", 2}})

	if !s.store.DemoteLatestFinding(critical, alert.Warning) {
		t.Fatal("critical finding was not demoted")
	}
	assertRisk([]statsRiskAccount{{"alice", "HIGH", 2}})
	if !s.store.DemoteLatestFinding(high, alert.Warning) {
		t.Fatal("high finding was not demoted")
	}
	assertRisk([]statsRiskAccount{})
	if !s.store.RestoreLatestFindingSeverity(storedFinding(t, s, critical.Key())) {
		t.Fatal("critical finding was not restored")
	}
	assertRisk([]statsRiskAccount{{"alice", "CRITICAL", 2}})
	s.store.DismissLatestFinding(critical.Key())
	assertRisk([]statsRiskAccount{})
}

func TestAccountsAtRiskOrderAndLimit(t *testing.T) {
	s := newTestServer(t, "")
	now := time.Now()
	var findings []alert.Finding
	// More findings cannot outrank a critical account. Equal critical rows
	// must keep their name order across polls, including at the cutoff.
	for i := 0; i < 4; i++ {
		findings = append(findings, alert.Finding{Check: "webshell", Severity: alert.High, TenantID: "manyhigh", Message: fmt.Sprintf("High %d", i), Timestamp: now})
	}
	for i := 50; i >= 0; i-- {
		name := fmt.Sprintf("acct%02d", i)
		findings = append(findings, alert.Finding{Check: "webshell", Severity: alert.Critical, TenantID: name, Message: name, Timestamp: now})
	}
	findings = append(findings, alert.Finding{Check: "world_writable_php", Severity: alert.Warning, TenantID: "acct50", Message: "Extra warning", Timestamp: now})
	s.store.SetLatestFindings(findings)
	want := []statsRiskAccount{{"acct50", "CRITICAL", 2}}
	for i := 0; i < 49; i++ {
		want = append(want, statsRiskAccount{fmt.Sprintf("acct%02d", i), "CRITICAL", 1})
	}
	for i := 0; i < 3; i++ {
		if got := getStatsRisk(t, s).AccountsAtRisk; !reflect.DeepEqual(got, want) {
			t.Fatalf("poll %d: accounts = %+v, want %+v", i, got, want)
		}
	}
}
