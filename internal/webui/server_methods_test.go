package webui

import (
	"encoding/json"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestSetEmailQuarantine(t *testing.T) {
	s := newTestServer(t, "tok")
	s.SetEmailQuarantine(nil) // should not panic
}

func TestSetEmailAVWatcherMode(t *testing.T) {
	s := newTestServer(t, "tok")
	s.SetEmailAVWatcherMode("milter")
	if s.emailAVWatcherMode != "milter" {
		t.Errorf("got %q", s.emailAVWatcherMode)
	}
}

// TestSetVersion is in coverage_test.go.

func TestCsmConfigJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	s.version = "2.2.2"

	raw := s.csmConfigJSON()
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatalf("csmConfigJSON not valid JSON: %v\nraw: %q", err, raw)
	}
	if data["version"] != "2.2.2" {
		t.Errorf("version = %v", data["version"])
	}
	if data["firewall"] != true {
		t.Errorf("firewall = %v", data["firewall"])
	}
}

func TestBroadcastNoPanic(t *testing.T) {
	s := newTestServer(t, "tok")
	// Broadcast with no listeners should not panic.
	s.Broadcast(nil)
}
