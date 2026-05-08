package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
)

func TestIncidentAPIListReturnsJSONArray(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	_, _, _ = c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})

	srv := newTestServerWithIncidentCorrelator(t, c)

	req := httptest.NewRequest("GET", "/api/v1/incidents", nil)
	w := httptest.NewRecorder()
	srv.apiIncidentList(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	var list []incident.Incident
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 incident, got %d", len(list))
	}
}

func TestIncidentAPIShowReturnsByID(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	id, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})

	srv := newTestServerWithIncidentCorrelator(t, c)
	req := httptest.NewRequest("GET", "/api/v1/incidents/"+id, nil)
	w := httptest.NewRecorder()
	srv.apiIncidentShow(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	var inc incident.Incident
	if err := json.NewDecoder(w.Body).Decode(&inc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if inc.ID != id {
		t.Errorf("id: got %q want %q", inc.ID, id)
	}
}

func TestIncidentAPIShowMissReturns404(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	srv := newTestServerWithIncidentCorrelator(t, c)
	req := httptest.NewRequest("GET", "/api/v1/incidents/inc_nope", nil)
	w := httptest.NewRecorder()
	srv.apiIncidentShow(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status: %d", w.Code)
	}
}

func TestIncidentAPIStatusTransitions(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	id, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})

	srv := newTestServerWithIncidentCorrelator(t, c)
	body := `{"status":"resolved","details":"operator-marked"}`
	req := httptest.NewRequest("POST", "/api/v1/incidents/"+id+"/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.apiIncidentStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
	got, _ := c.Get(id)
	if got.Status != incident.StatusResolved {
		t.Errorf("Status: %v", got.Status)
	}
}

func newTestServerWithIncidentCorrelator(t *testing.T, c *incident.Correlator) *Server {
	t.Helper()
	return &Server{incidentCorrelator: c}
}
