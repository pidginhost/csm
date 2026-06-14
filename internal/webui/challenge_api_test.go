package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The challenge-stats endpoint must always return the four fields the web UI
// renders, with the right JSON shapes, even with no daemon provider wired.
func TestApiChallengeStatsReturnsShape(t *testing.T) {
	s := &Server{cfg: &config.Config{}}

	rec := httptest.NewRecorder()
	s.apiChallengeStats(rec, httptest.NewRequest(http.MethodGet, "/api/v1/challenge/stats", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}

	var resp struct {
		Pending       int            `json:"pending"`
		Escalated     int            `json:"escalated"`
		RoutedByCheck map[string]int `json:"routed_by_check"`
		Recent        []struct {
			IP    string `json:"ip"`
			Check string `json:"check"`
		} `json:"recent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.RoutedByCheck == nil {
		t.Error("routed_by_check must be a JSON object, not null")
	}
}
