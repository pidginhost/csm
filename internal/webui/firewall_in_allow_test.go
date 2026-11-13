package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestFirewallPortExceptionCountMatchesAllowedList(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	state := firewall.FirewallState{
		PortAllowed: []firewall.PortAllowEntry{{IP: "203.0.113.4", Port: 8080, Proto: "tcp"}},
	}
	stateDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		rules []firewall.InAllowRule
		want  int
	}{
		{"state only", nil, 1},
		{"state and config", []firewall.InAllowRule{
			{Port: 3306, Sources: []string{"203.0.113.10", "198.51.100.0/28"}},
			{Port: 5432, Sources: []string{"2001:db8::11"}},
		}, 4},
		{"config removed", nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.cfg.Firewall.TCPInAllow = tc.rules
			status := httptest.NewRecorder()
			s.apiFirewallStatus(status, httptest.NewRequest(http.MethodGet, "/", nil))
			if status.Code != http.StatusOK {
				t.Fatalf("status HTTP code = %d", status.Code)
			}
			var summary struct {
				Count int `json:"port_allow_count"`
			}
			if err := json.Unmarshal(status.Body.Bytes(), &summary); err != nil {
				t.Fatal(err)
			}
			if summary.Count != tc.want {
				t.Errorf("port exception count = %d, want %d", summary.Count, tc.want)
			}

			allowed := httptest.NewRecorder()
			s.apiFirewallAllowed(allowed, httptest.NewRequest(http.MethodGet, "/", nil))
			if allowed.Code != http.StatusOK {
				t.Fatalf("allowed HTTP code = %d", allowed.Code)
			}
			var entries struct {
				Ports []firewallPortAllowView `json:"port_allowed"`
			}
			if err := json.Unmarshal(allowed.Body.Bytes(), &entries); err != nil {
				t.Fatal(err)
			}
			if len(entries.Ports) != tc.want {
				t.Errorf("listed port exceptions = %d, want %d", len(entries.Ports), tc.want)
			}
		})
	}
}
