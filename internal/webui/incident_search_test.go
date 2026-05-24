package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
)

// TestAPIIncidentSearchSurfacesIncidentTimelineEvent proves the IP-search
// path reads incident timelines, not just finding history. The finding
// history is intentionally left empty so a passing test confirms the
// incident-side fold-in.
func TestAPIIncidentSearchSurfacesIncidentTimelineEvent(t *testing.T) {
	srv := newTestServer(t, "tok")
	c := incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 1})
	srv.incidentCorrelator = c

	ip := "203.0.113.42"
	now := time.Now().Add(-2 * time.Hour)
	f := alert.Finding{
		Check:     "modsec_csm_block_escalation",
		Message:   "ModSecurity rule 900116 from " + ip,
		Severity:  alert.Critical,
		SourceIP:  ip,
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incident?ip="+ip+"&hours=24", nil)
	w := httptest.NewRecorder()
	srv.apiIncident(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp struct {
		Events []timelineEvent `json:"events"`
		Total  int             `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total == 0 {
		t.Fatalf("Total = 0, want >=1 from incident timeline (response: %s)", w.Body.String())
	}
	foundIncidentSource := false
	for _, e := range resp.Events {
		if len(e.Source) >= len("incident:") && e.Source[:len("incident:")] == "incident:" {
			foundIncidentSource = true
		}
	}
	if !foundIncidentSource {
		t.Errorf("no event tagged with incident: source; events = %+v", resp.Events)
	}
}

// TestAPIIncidentSearchAccountMatchesIncidentIdentity proves the account
// search path matches inc.Account / Mailbox / Domain even when the
// finding history slice is empty.
func TestAPIIncidentSearchAccountMatchesIncidentIdentity(t *testing.T) {
	srv := newTestServer(t, "tok")
	c := incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 1})
	srv.incidentCorrelator = c

	mailbox := "victim@example.com"
	ip := "203.0.113.43"
	f := alert.Finding{
		Check:     "email_auth_failure_realtime",
		Message:   "Email authentication failure for " + mailbox + " from " + ip,
		Severity:  alert.High,
		Mailbox:   mailbox,
		SourceIP:  ip,
		Timestamp: time.Now().Add(-30 * time.Minute),
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incident?account="+mailbox+"&hours=24", nil)
	w := httptest.NewRecorder()
	srv.apiIncident(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Events []timelineEvent `json:"events"`
		Total  int             `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total == 0 {
		t.Fatalf("account search returned 0 events for incident with matching mailbox: %s", w.Body.String())
	}
}

// TestAPIIncidentSearchHonorsCutoff proves the hours window prunes older
// incident-timeline events even though incident objects themselves
// outlast the finding-history rotation.
func TestAPIIncidentSearchHonorsCutoff(t *testing.T) {
	srv := newTestServer(t, "tok")
	c := incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 1})
	srv.incidentCorrelator = c

	ip := "203.0.113.44"
	old := time.Now().Add(-48 * time.Hour)
	f := alert.Finding{
		Check:     "modsec_csm_block_escalation",
		Message:   "stale event from " + ip,
		Severity:  alert.High,
		SourceIP:  ip,
		Timestamp: old,
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incident?ip="+ip+"&hours=1", nil)
	w := httptest.NewRecorder()
	srv.apiIncident(w, req)
	var resp struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 0 {
		t.Fatalf("hours=1 returned %d events for a 48h-old event; want 0", resp.Total)
	}
}

func TestAPIIncidentSearchReportsSnapshotCap(t *testing.T) {
	srv := newTestServer(t, "tok")
	c := incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 1})
	base := time.Now().Add(-time.Hour)
	incidents := make([]incident.Incident, 0, incidentSnapshotScanCap+1)
	queryIP := ""
	for i := 0; i < incidentSnapshotScanCap+1; i++ {
		suffix := strconv.Itoa(i)
		account := "acct-cap-" + suffix
		ip := "192.0.2." + suffix
		at := base.Add(time.Duration(i) * time.Second)
		if i == incidentSnapshotScanCap {
			queryIP = ip
		}
		incidents = append(incidents, incident.Incident{
			ID:             "inc-cap-" + suffix,
			Kind:           incident.KindMailboxTakeover,
			Status:         incident.StatusOpen,
			Severity:       alert.High,
			Account:        account,
			CorrelationKey: &incident.Key{Account: account},
			CreatedAt:      at,
			UpdatedAt:      at,
			Timeline: []incident.IncidentEvent{{
				Time:     at,
				Check:    "email_auth_failure_realtime",
				Message:  "failure from " + ip,
				RemoteIP: ip,
			}},
		})
	}
	c.Restore(incidents)
	srv.incidentCorrelator = c

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incident?ip="+queryIP+"&hours=24", nil)
	w := httptest.NewRecorder()
	srv.apiIncident(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-CSM-Truncated"); got != "1" {
		t.Fatalf("X-CSM-Truncated = %q, want 1 when incident snapshot scan cap is hit", got)
	}
	var resp struct {
		Events    []timelineEvent `json:"events"`
		Total     int             `json:"total"`
		Truncated bool            `json:"truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Truncated {
		t.Fatal("truncated = false, want true when incident snapshot scan cap is hit")
	}
	if resp.Total == 0 || len(resp.Events) == 0 {
		t.Fatalf("query IP from capped page returned no events: %s", w.Body.String())
	}
}
