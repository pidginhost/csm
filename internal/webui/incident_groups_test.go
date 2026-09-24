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

// incidentGroupsPage is the groups route's answer: the groups under items
// plus the paging keys.
type incidentGroupsPage struct {
	Groups           []incident.Group `json:"items"`
	Total            int              `json:"total"`
	Offset           int              `json:"offset"`
	Limit            int              `json:"limit"`
	ScannedIncidents int              `json:"scanned_incidents"`
	Truncated        bool             `json:"truncated"`
}

func seedSprayIncidents(t *testing.T, c *incident.Correlator, ip string, count int) {
	t.Helper()
	now := time.Now()
	for i := 0; i < count; i++ {
		// Post-auth abuse keys on the mailbox, so distinct mailboxes from one
		// source produce distinct incidents the groups API then buckets by the
		// shared timeline IP. (Failed-login findings would collapse onto the
		// attacker IP as one mailbox_bruteforce incident.)
		_, _, err := c.OnFinding(alert.Finding{
			Check:     "email_compromised_account",
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
	var resp incidentGroupsPage
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

// The status is accepted in any case; it must also filter in any case, not
// pass validation and then match nothing.
func TestAPIIncidentGroupsStatusIsCaseInsensitive(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	seedSprayIncidents(t, c, "192.0.2.1", 2)
	srv := newTestServerWithIncidentCorrelator(t, c)
	for _, status := range []string{"open", "Open", "%20OPEN%20"} {
		w := httptest.NewRecorder()
		srv.apiIncidentGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/groups?status="+status, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status=%s: code %d, body %s", status, w.Code, w.Body.String())
		}
		var resp incidentGroupsPage
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Groups) != 1 || resp.Groups[0].IncidentCount != 2 {
			t.Errorf("status=%s: groups = %+v, want the open group", status, resp.Groups)
		}
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
	var resp incidentGroupsPage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if resp.Total != 3 {
		t.Fatalf("total = %d, want 3 (pre-pagination)", resp.Total)
	}
	if len(resp.Groups) != 1 || resp.Groups[0].Source != "192.0.2.2" {
		t.Fatalf("offset=1 limit=1 returned %+v, want single group .2", resp.Groups)
	}
}

func TestIncidentPagesReportRemainingMatches(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{})
	seedSprayIncidents(t, c, "192.0.2.1", 1)
	seedSprayIncidents(t, c, "192.0.2.2", 1)
	srv := newTestServerWithIncidentCorrelator(t, c)
	for _, route := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/api/v1/incidents", srv.apiIncidentList},
		{"/api/v1/incidents/groups", srv.apiIncidentGroups},
	} {
		for offset := 0; offset < 3; offset++ {
			t.Run(route.path+strconv.Itoa(offset), func(t *testing.T) {
				w := httptest.NewRecorder()
				route.handler(w, httptest.NewRequest(http.MethodGet, route.path+"?limit=1&offset="+strconv.Itoa(offset), nil))
				body := decodeCapped(t, route.path, w)
				if *body.Truncated != (offset == 0) || body.Total == nil || *body.Total != 2 {
					t.Fatalf("incorrect page metadata: %s", w.Body.String())
				}
			})
		}
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
	var resp incidentGroupsPage
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	for _, g := range resp.Groups {
		if g.ResolvedCount > 0 {
			t.Errorf("default surface should hide resolved incidents, got group with %d resolved", g.ResolvedCount)
		}
	}
}
