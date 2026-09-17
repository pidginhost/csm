package webui

import (
	"encoding/json"
	"errors"
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
		`{"ip":"203.0.113.99","duration":"0","incident_id":123}`,
		`{"ip":"203.0.113.99","duration":"0","incident_id":{}}`,
		`{"ip":"203.0.113.99","duration":"0","incident_id":[]}`,
		`{"ip":"203.0.113.99","duration":"0","incident_id":false}`,
		`{"ip":"203.0.113.99","duration":"0","incident_id":null}`,
	} {
		blocker := &stubBlocker{}
		s.blocker = blocker
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/block-ip", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.apiBlockIP(w, req)
		if w.Code != 200 {
			t.Errorf("block with body %s returned %d: %s", body, w.Code, w.Body.String())
		}
		if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.99" {
			t.Errorf("block with body %s made firewall calls %v", body, blocker.blocked)
		}
	}
}

type incidentOperatorBlocker struct {
	stubBlocker
	ttl time.Duration
	err error
}

func (b *incidentOperatorBlocker) BlockIPForce(ip, reason string, ttl time.Duration) error {
	b.ttl = ttl
	b.blocked = append(b.blocked, ip)
	return b.err
}

func TestIncidentBlockBookkeepingMatchesFirewallOutcome(t *testing.T) {
	for _, tc := range []struct {
		name, ip string
		fail     bool
	}{
		{"permanent", "203.0.113.99", false},
		{"unrelated", "203.0.113.100", false},
		{"failed", "203.0.113.99", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerWithFirewall(t, "tok")
			b := &incidentOperatorBlocker{}
			if tc.fail {
				b.err = errors.New("firewall unavailable")
			}
			s.blocker = b
			c := incident.NewCorrelator(incident.CorrelatorConfig{})
			c.Restore([]incident.Incident{{ID: "inc_test", Status: incident.StatusOpen, CorrelationKey: &incident.Key{RemoteIP: "203.0.113.99"}}})
			s.SetIncidentCorrelator(c)
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/v1/block-ip", strings.NewReader(`{"ip":"`+tc.ip+`","duration":"0","incident_id":"inc_test"}`))
			s.apiBlockIP(w, r)
			wantCode := 200
			if tc.fail {
				wantCode = 500
			}
			if w.Code != wantCode {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			if len(b.blocked) != 1 || b.blocked[0] != tc.ip || b.ttl != 0 {
				t.Fatalf("force block = %+v", b)
			}
			inc, _ := c.Get("inc_test")
			if tc.name == "permanent" {
				if inc.AutoBlock.Count != 1 || !inc.AutoBlock.ExpiresAt.IsZero() || len(inc.Actions) != 1 {
					t.Fatalf("permanent operator state = %+v", inc)
				}
			} else if inc.AutoBlock.Count != 0 || len(inc.Actions) != 0 {
				t.Fatalf("incident falsely marked blocked: %+v", inc)
			}
		})
	}
}
