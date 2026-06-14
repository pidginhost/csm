package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
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
	if resp.Recent == nil {
		t.Error("recent must be a JSON array, not null")
	}
}

func TestApiChallengeStatsUsesProviderAutomationOnly(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.SetHealthProvider(challengeStatsOnlyProvider{automation: health.AutomationStatus{
		ChallengePending:   7,
		ChallengeEscalated: 3,
	}})

	rec := httptest.NewRecorder()
	s.apiChallengeStats(rec, httptest.NewRequest(http.MethodGet, "/api/v1/challenge/stats", nil))

	var resp struct {
		Pending   int `json:"pending"`
		Escalated int `json:"escalated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.Pending != 7 || resp.Escalated != 3 {
		t.Fatalf("pending/escalated = %d/%d, want 7/3", resp.Pending, resp.Escalated)
	}
}

type challengeStatsOnlyProvider struct {
	// The embedded nil Provider makes any non-AutomationStatus method call
	// panic, which keeps this endpoint from accidentally rebuilding status.
	health.Provider
	automation health.AutomationStatus
}

func (p challengeStatsOnlyProvider) AutomationStatus() health.AutomationStatus {
	return p.automation
}
