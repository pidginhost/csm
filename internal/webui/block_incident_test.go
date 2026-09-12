package webui

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/incident"
)

// Blocking from the incident view has to land on the incident, or an operator
// reading the timeline later cannot tell whether anyone acted. It also has to
// settle the automatic escalation ladder so the two paths do not fight.
func TestBlockIPRecordsTheActionOnTheNamedIncident(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	s.blocker = &stubBlocker{}

	c := incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 1})
	id, _, err := c.OnFinding(alert.Finding{
		Severity:  alert.Critical,
		Check:     "mail_bruteforce",
		Message:   "brute force from 203.0.113.99",
		SourceIP:  "203.0.113.99",
		Timestamp: time.Now(),
	})
	if err != nil || id == "" {
		t.Fatalf("OnFinding: id=%q err=%v", id, err)
	}
	s.SetIncidentCorrelator(c)

	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.99","reason":"spray","duration":"24h","incident_id":"` + id + `"}`
	req := httptest.NewRequest("POST", "/api/v1/block-ip", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)

	if w.Code != 200 {
		t.Fatalf("block returned %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "blocked" {
		t.Fatalf("response = %v, want a blocked status", resp)
	}

	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("incident vanished")
	}
	var found bool
	for _, a := range inc.Actions {
		if a.Action == "operator_block" {
			found = true
		}
	}
	if !found {
		t.Fatalf("incident actions %+v carry no operator_block", inc.Actions)
	}
	if inc.AutoBlock.Count == 0 {
		t.Error("operator block did not settle the automatic escalation ladder")
	}
}

// An unknown or absent incident id must never fail the block itself: the
// firewall action is the point, the incident note is bookkeeping.
func TestBlockIPSucceedsWithoutAnIncidentID(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	s.blocker = &stubBlocker{}
	s.SetIncidentCorrelator(incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 1}))

	for _, body := range []string{
		`{"ip":"203.0.113.99","reason":"r","duration":"24h"}`,
		`{"ip":"203.0.113.99","reason":"r","duration":"24h","incident_id":"inc_missing"}`,
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/block-ip", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.apiBlockIP(w, req)
		if w.Code != 200 {
			t.Errorf("block with body %s returned %d: %s", body, w.Code, w.Body.String())
		}
	}
}
