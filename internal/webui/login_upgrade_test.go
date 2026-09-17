package webui

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestLoginUpgradeEmailSettings(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: host.example\nalerts:\n  email:\n    disabled_checks: [ssh_login_realtime, ftp_login_realtime]\n")
	w := httptest.NewRecorder()
	s.apiSettingsGet(w, settingsAuthedReq("GET", "/api/v1/settings/alerts", "tok", ""))
	if w.Code != 200 {
		t.Fatalf("GET status=%d: %s", w.Code, w.Body.String())
	}
	var response struct {
		Values struct {
			Email struct {
				DisabledChecks []string `json:"disabled_checks"`
			} `json:"email"`
		} `json:"values"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh_login_unknown_ip", "ftp_login"}
	if !slices.Equal(response.Values.Email.DisabledChecks, want) {
		t.Errorf("GET exclusions = %v, want %v", response.Values.Email.DisabledChecks, want)
	}
	section, _ := LookupSettingsSection("alerts")
	clone := &config.Config{}
	_, errs := buildChangeSet(section, clone, map[string]json.RawMessage{
		"email.disabled_checks": json.RawMessage(`["ssh_login_realtime","ftp_login_realtime"]`),
	})
	if len(errs) != 0 || !slices.Equal(clone.Alerts.Email.DisabledChecks, want) {
		t.Fatalf("save old exclusions: errors=%v, values=%v", errs, clone.Alerts.Email.DisabledChecks)
	}
}
