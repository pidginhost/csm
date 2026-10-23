package webui

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

const webuiFindingContext = "ModSecurity is disabled for account alice (all domains) (set in /etc/apache2/conf.d/userdata/ssl/2_4/alice/modsec.conf): requests there are not filtered and leave no modsec audit record."

// The findings APIs the dashboard and integrations read carry a finding's
// context beside its details, under the key the finding always had.
func TestFindingsAPIsCarryContext(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Severity:  alert.Critical,
		Check:     "webshell",
		Message:   "Known webshell found: /home/alice/public_html/x.php",
		Details:   "Size: 10",
		Context:   webuiFindingContext,
		FilePath:  "/home/alice/public_html/x.php",
		Timestamp: time.Now(),
	}
	s.store.SetLatestFindings([]alert.Finding{f})

	w := httptest.NewRecorder()
	s.apiFindingsEnriched(w, httptest.NewRequest("GET", "/", nil))
	var enriched []enrichedFinding
	decodeItems(t, w.Body.Bytes(), &enriched)
	if len(enriched) != 1 || enriched[0].Context != webuiFindingContext || enriched[0].Details != "Size: 10" || enriched[0].Key != f.Key() {
		t.Fatalf("enriched findings = %+v, want details, context and the unchanged key", enriched)
	}

	w = httptest.NewRecorder()
	s.apiFindings(w, httptest.NewRequest("GET", "/", nil))
	var current []struct {
		Details string `json:"details"`
		Context string `json:"context"`
	}
	decodeItems(t, w.Body.Bytes(), &current)
	if len(current) != 1 || current[0].Context != webuiFindingContext || current[0].Details != "Size: 10" {
		t.Fatalf("findings API items = %+v, want details and context", current)
	}
}

// History rows embed the stored finding, so its context reaches the history
// page as is.
func TestHistoryRowsCarryContext(t *testing.T) {
	raw, err := json.Marshal(withAccountIP([]alert.Finding{{Check: "webshell", Context: webuiFindingContext}}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"context":"ModSecurity is disabled for account alice`) {
		t.Fatalf("history row lacks context: %s", raw)
	}
}
