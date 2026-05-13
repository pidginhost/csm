package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
)

func seedSprayIncidents(t *testing.T, c *incident.Correlator, ip string, count int) {
	t.Helper()
	now := time.Now()
	for i := 0; i < count; i++ {
		_, _, err := c.OnFinding(alert.Finding{
			Check:     "email_auth_failure_realtime",
			Severity:  alert.High,
			Mailbox:   "victim" + strconv.Itoa(i) + "-" + strings.ReplaceAll(ip, ".", "-") + "@example.com",
			SourceIP:  ip,
			Timestamp: now.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}
}

func TestAPIIncidentGroupsRejectsNonGet(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	srv := newTestServerWithIncidentCorrelator(t, c)
	w := httptest.NewRecorder()
	srv.apiIncidentGroups(w, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/groups", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestAPIIncidentGroupsBucketsByIP(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	seedSprayIncidents(t, c, "192.0.2.1", 4)
	seedSprayIncidents(t, c, "192.0.2.2", 1)

	srv := newTestServerWithIncidentCorrelator(t, c)
	w := httptest.NewRecorder()
	srv.apiIncidentGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/groups", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp incident.GroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp.Groups) != 2 {
		t.Fatalf("groups = %d, want 2 attacker-IP groups: %+v", len(resp.Groups), resp.Groups)
	}
	if resp.Groups[0].SourceKind != "ip" || resp.Groups[0].Source != "192.0.2.1" || resp.Groups[0].IncidentCount != 4 {
		t.Fatalf("first group = %+v, want 192.0.2.1 with 4 incidents", resp.Groups[0])
	}
	if resp.Groups[1].SourceKind != "ip" || resp.Groups[1].Source != "192.0.2.2" || resp.Groups[1].IncidentCount != 1 {
		t.Fatalf("second group = %+v, want 192.0.2.2 with 1 incident", resp.Groups[1])
	}
}

func TestAPIIncidentGroupsRejectsUnknownStatus(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	srv := newTestServerWithIncidentCorrelator(t, c)
	w := httptest.NewRecorder()
	srv.apiIncidentGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/groups?status=garbage", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown status", w.Code)
	}
}

func TestAPIIncidentGroupsReadScopeAccess(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	seedSprayIncidents(t, c, "192.0.2.1", 2)

	srv := &Server{
		incidentCorrelator: c,
		cfg:                &config.Config{},
	}
	srv.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "admin", Token: "admin-tok", Scope: "admin"},
		{Name: "read", Token: "read-tok", Scope: "read"},
	}
	handler := srv.requireRead(http.HandlerFunc(srv.apiIncidentGroups))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/groups", nil)
	req.Header.Set("Authorization", "Bearer read-tok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("read-scope status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestAPIIncidentGroupsHonorsOffset(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	// Three IPs with distinct counts (.1=3, .2=2, .3=1) for deterministic order.
	seedSprayIncidents(t, c, "192.0.2.1", 3)
	seedSprayIncidents(t, c, "192.0.2.2", 2)
	seedSprayIncidents(t, c, "192.0.2.3", 1)

	srv := newTestServerWithIncidentCorrelator(t, c)
	w := httptest.NewRecorder()
	srv.apiIncidentGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/groups?offset=1&limit=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp incident.GroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if resp.TotalGroups != 3 {
		t.Fatalf("TotalGroups = %d, want 3 (pre-pagination)", resp.TotalGroups)
	}
	if len(resp.Groups) != 1 || resp.Groups[0].Source != "192.0.2.2" {
		t.Fatalf("offset=1 limit=1 returned %+v, want single group .2", resp.Groups)
	}
}

func TestAPIIncidentGroupsActiveFilterDefault(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	now := time.Now()
	// One open, one resolved.
	openID, _, _ := c.OnFinding(alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, TenantID: "alice", SourceIP: "192.0.2.1", Timestamp: now})
	doneID, _, _ := c.OnFinding(alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, TenantID: "bob", SourceIP: "192.0.2.2", Timestamp: now})
	_ = c.SetStatus(doneID, incident.StatusResolved, "manual")
	if openID == "" || doneID == "" {
		t.Fatal("seed incidents missing")
	}

	srv := newTestServerWithIncidentCorrelator(t, c)
	w := httptest.NewRecorder()
	srv.apiIncidentGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/groups", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp incident.GroupsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	for _, g := range resp.Groups {
		if g.ResolvedCount > 0 {
			t.Errorf("default surface should hide resolved incidents, got group with %d resolved", g.ResolvedCount)
		}
	}
}
