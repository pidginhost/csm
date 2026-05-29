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

// An oversized status body is rejected instead of being buffered wholesale
// into memory. The handler caps the body like every other mutating endpoint.
func TestIncidentAPIStatusRejectsOversizeBody(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	id, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})

	srv := newTestServerWithIncidentCorrelator(t, c)
	huge := `{"status":"resolved","details":"` + strings.Repeat("A", 64*1024) + `"}`
	req := httptest.NewRequest("POST", "/api/v1/incidents/"+id+"/status", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.apiIncidentStatus(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("oversize body must be rejected, got 200")
	}
	if got, _ := c.Get(id); got.Status == incident.StatusResolved {
		t.Error("status must not change when the body is rejected")
	}
}

// TestIncidentAPIListPaginatedReturnsEnvelope: when the request carries
// any pagination parameter (limit, offset, status), the response shape
// switches to an envelope with items + total + offset + limit + status.
// Bare-array shape is preserved when no pagination params are present
// so existing API consumers (phpanel, SIEM tooling) see no diff.
func TestIncidentAPIListPaginatedReturnsEnvelope(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	for i := 0; i < 5; i++ {
		_, _, _ = c.OnFinding(alert.Finding{
			Check:     "x",
			Severity:  alert.High,
			TenantID:  "acct" + string(rune('a'+i)),
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
		})
	}
	srv := newTestServerWithIncidentCorrelator(t, c)

	req := httptest.NewRequest("GET", "/api/v1/incidents?limit=2&offset=1", nil)
	w := httptest.NewRecorder()
	srv.apiIncidentList(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
	var env struct {
		Items  []incident.Incident `json:"items"`
		Total  int                 `json:"total"`
		Offset int                 `json:"offset"`
		Limit  int                 `json:"limit"`
		Status string              `json:"status"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Total != 5 {
		t.Errorf("total = %d, want 5", env.Total)
	}
	if len(env.Items) != 2 {
		t.Errorf("items len = %d, want 2", len(env.Items))
	}
	if env.Offset != 1 || env.Limit != 2 {
		t.Errorf("envelope: offset=%d limit=%d, want 1/2", env.Offset, env.Limit)
	}
}

func TestIncidentAPIListStatusFilterReturnsEnvelope(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	id1, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})
	_, _, _ = c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "bob", Timestamp: time.Now()})
	if err := c.SetStatus(id1, incident.StatusResolved, ""); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	srv := newTestServerWithIncidentCorrelator(t, c)
	req := httptest.NewRequest("GET", "/api/v1/incidents?status=open", nil)
	w := httptest.NewRecorder()
	srv.apiIncidentList(w, req)

	var env struct {
		Items  []incident.Incident `json:"items"`
		Total  int                 `json:"total"`
		Status string              `json:"status"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Total != 1 {
		t.Errorf("total = %d, want 1 (open)", env.Total)
	}
	if env.Status != "open" {
		t.Errorf("envelope status = %q, want open", env.Status)
	}
	if len(env.Items) != 1 || env.Items[0].Status != incident.StatusOpen {
		t.Errorf("items = %+v", env.Items)
	}
}

// Limit > server ceiling must be capped, not rejected; the client gets
// what it asked for up to the safe max so a misbehaving consumer cannot
// drag the daemon into an OOM via a giant page request.
func TestIncidentAPIListLimitCappedToServerCeiling(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	srv := newTestServerWithIncidentCorrelator(t, c)
	req := httptest.NewRequest("GET", "/api/v1/incidents?limit=999999", nil)
	w := httptest.NewRecorder()
	srv.apiIncidentList(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	var env struct {
		Limit int `json:"limit"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Limit > maxIncidentPageSize {
		t.Errorf("limit %d exceeds ceiling %d", env.Limit, maxIncidentPageSize)
	}
}

// Invalid status values must surface as 400 Bad Request rather than
// silently degrading to "all" - otherwise a typo like ?status=opn
// would render every record and confuse the operator.
func TestIncidentAPIListInvalidStatusReturns400(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	srv := newTestServerWithIncidentCorrelator(t, c)
	req := httptest.NewRequest("GET", "/api/v1/incidents?status=opn", nil)
	w := httptest.NewRecorder()
	srv.apiIncidentList(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// "active" is a UI-only convenience that maps to (open, contained); the
// server understands it explicitly so a single round-trip page covers
// the default web-UI filter shape.
func TestIncidentAPIListActiveStatusReturnsOpenAndContained(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	id1, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})
	id2, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "bob", Timestamp: time.Now()})
	_, _, _ = c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "eve", Timestamp: time.Now()})
	if err := c.SetStatus(id1, incident.StatusContained, ""); err != nil {
		t.Fatalf("SetStatus contained: %v", err)
	}
	if err := c.SetStatus(id2, incident.StatusResolved, ""); err != nil {
		t.Fatalf("SetStatus resolved: %v", err)
	}

	srv := newTestServerWithIncidentCorrelator(t, c)
	req := httptest.NewRequest("GET", "/api/v1/incidents?status=active", nil)
	w := httptest.NewRecorder()
	srv.apiIncidentList(w, req)

	var env struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Total != 2 {
		t.Errorf("active total = %d, want 2 (open + contained)", env.Total)
	}
}

func newTestServerWithIncidentCorrelator(t *testing.T, c *incident.Correlator) *Server {
	t.Helper()
	return &Server{incidentCorrelator: c}
}
