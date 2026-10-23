package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

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

	type risk struct {
		Account  string `json:"account"`
		Severity string `json:"severity"`
		Findings int    `json:"findings"`
	}
	atRisk := func() []risk {
		t.Helper()
		w := httptest.NewRecorder()
		s.apiStats(w, httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil))
		var body struct {
			AccountsAtRisk []risk `json:"accounts_at_risk"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		return body.AccountsAtRisk
	}

	want := []risk{{"alice", "CRITICAL", 1}, {"bob", "HIGH", 2}}
	if got := atRisk(); !reflect.DeepEqual(got, want) {
		t.Fatalf("before fix: got %+v, want %+v", got, want)
	}

	s.store.DismissLatestFinding(fixed.Key())
	want = []risk{{"bob", "HIGH", 2}}
	if got := atRisk(); !reflect.DeepEqual(got, want) {
		t.Fatalf("after fix: got %+v, want %+v", got, want)
	}
}
