package webui

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestHistoryResponsesRedactStoredCredentials(t *testing.T) {
	s := newTestServerWithBbolt(t, "")
	s.store.AppendHistory([]alert.Finding{{
		Check: "cpanel_login_realtime", Timestamp: time.Now().UTC(),
		Message: "password=message-fixture", Details: "[cpaneld] NEW shop:session-fixture",
		TenantID: "shop", SourceIP: "198.51.100.23",
	}})
	for _, query := range []string{"/", "/?search=shop", "/?checks=cpanel_login_realtime"} {
		w := httptest.NewRecorder()
		s.apiHistory(w, httptest.NewRequest(http.MethodGet, query, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("history status = %d", w.Code)
		}
		var response struct {
			Findings []historyFinding `json:"items"`
			Total    int              `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != 1 || len(response.Findings) != 1 {
			t.Fatalf("history response for %s = %+v", query, response)
		}
		f := response.Findings[0]
		if f.Message != "password=[REDACTED]" || f.Details != "[cpaneld] NEW shop:[REDACTED]" ||
			f.Account != "shop" || f.IP != "198.51.100.23" {
			t.Errorf("history response for %s = %+v", query, f)
		}
	}
	w := httptest.NewRecorder()
	s.apiHistoryCSV(w, httptest.NewRequest(http.MethodGet, "/", nil))
	rows, err := csv.NewReader(w.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(rows[1]) != 5 {
		t.Fatalf("history CSV rows = %v", rows)
	}
	if rows[1][3] != "password=[REDACTED]" || rows[1][4] != "[cpaneld] NEW shop:[REDACTED]" {
		t.Errorf("history CSV row = %v", rows[1])
	}
}
