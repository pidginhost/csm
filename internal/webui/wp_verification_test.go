package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestWPVerificationSummaryAccountAttribution(t *testing.T) {
	for _, check := range []string{"wp_core_unverified", "wp_plugin_inventory_unverified"} {
		for _, account := range []string{"", "alice"} {
			t.Run(check+"/"+account, func(t *testing.T) {
				s := newTestServer(t, "tok")
				f := alert.Finding{
					Check: check, Severity: alert.Warning, TenantID: account,
					Message: "WordPress verification repeatedly failed for many installations",
					// The bounded sample may contain only one account even when
					// other accounts are affected. It is not attribution evidence.
					Details:  "Reason: wp-cli timed out\n- \"/home/alice/site\"\n... and more\n",
					DedupKey: "reason:wp-cli timed out", Timestamp: time.Now(),
				}
				s.store.SetLatestFindings([]alert.Finding{f})
				w := httptest.NewRecorder()
				s.apiFindingsEnriched(w, httptest.NewRequest(http.MethodGet, "/api/findings/enriched", nil))
				var data struct {
					Findings []enrichedFinding `json:"items"`
				}
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d", w.Code)
				}
				if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
					t.Fatal(err)
				}
				if len(data.Findings) != 1 {
					t.Fatalf("summary missing from findings table: %+v", data.Findings)
				}
				got := data.Findings[0]
				if got.Account != account {
					t.Errorf("summary account = %q, want %q", got.Account, account)
				}
				if got.Key != f.Key() || got.FilePath != "" || got.HasFix || got.HasVerify {
					t.Errorf("summary row has incorrect identity or actions: %+v", got)
				}
			})
		}
	}
}
