package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

var cpanelOnlySettingsFields = map[string][]string{
	"suppressions":  {"upcp_window_start", "upcp_window_end", "known_api_tokens", "suppress_cpanel_login_alerts"},
	"auto_response": {"block_cpanel_logins"},
}

func TestFilterSettingsSectionDropsGatedFields(t *testing.T) {
	for id, gated := range cpanelOnlySettingsFields {
		full, _ := LookupSettingsSection(id)
		on, ok := filterSettingsSection(full, map[string]bool{"cpanel": true})
		if !ok || len(on.Fields) != len(full.Fields) {
			t.Fatalf("%s on cPanel: ok=%v fields=%d, want all %d", id, ok, len(on.Fields), len(full.Fields))
		}
		off, ok := filterSettingsSection(full, map[string]bool{})
		if !ok {
			t.Fatalf("%s dropped off cPanel", id)
		}
		if len(off.Fields) != len(full.Fields)-len(gated) {
			t.Errorf("%s off cPanel: %d fields, want %d", id, len(off.Fields), len(full.Fields)-len(gated))
		}
		for _, path := range gated {
			if lookupSchemaField(off, path) != nil {
				t.Errorf("%s.%s shown off cPanel", id, path)
			}
		}
		// The rest keep their order.
		var want []string
		for _, f := range full.Fields {
			if lookupSchemaField(off, f.YAMLPath) != nil {
				want = append(want, f.YAMLPath)
			}
		}
		for i, f := range off.Fields {
			if f.YAMLPath != want[i] {
				t.Fatalf("%s: field %d is %s, want %s", id, i, f.YAMLPath, want[i])
			}
		}
		// Filtering must not edit the shared schema.
		again, _ := LookupSettingsSection(id)
		if len(again.Fields) != len(full.Fields) {
			t.Fatalf("%s: filtering changed the schema", id)
		}
	}
}

func TestFilterSettingsSectionDropsGatedSection(t *testing.T) {
	av, _ := LookupSettingsSection("email_av")
	if _, ok := filterSettingsSection(av, map[string]bool{}); ok {
		t.Error("email_av kept with emailAV off")
	}
	if _, ok := filterSettingsSection(av, map[string]bool{"emailAV": true}); !ok {
		t.Error("email_av dropped with emailAV on")
	}
}

const featureSettingsYAML = `hostname: t.example.com
suppressions:
  suppress_cpanel_login_alerts: true
  suppress_webmail_alerts: false
auto_response:
  enabled: true
  block_ips: false
  block_cpanel_logins: true
`

func TestSettingsSectionsAPIHidesGatedContent(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", featureSettingsYAML)
	setTestPlatform(s, platform.PanelNone, platform.MTAPostfix)

	w := httptest.NewRecorder()
	s.apiSettingsSections(w, settingsAuthedReq("GET", "/api/v1/settings", "tok", ""))
	if strings.Contains(w.Body.String(), `"id":"email_av"`) || strings.Contains(w.Body.String(), "block_cpanel_logins") {
		t.Error("section list shows cPanel-only settings off cPanel")
	}
	if !strings.Contains(w.Body.String(), `"id":"auto_response"`) {
		t.Error("section list lost auto_response")
	}

	w = httptest.NewRecorder()
	s.apiSettingsGet(w, settingsAuthedReq("GET", "/api/v1/settings/email_av", "tok", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("GET email_av = %d, want 404", w.Code)
	}

	w = httptest.NewRecorder()
	s.apiSettingsGet(w, settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", ""))
	var resp struct {
		Values map[string]json.RawMessage `json:"values"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.Values["block_cpanel_logins"]; ok {
		t.Error("GET auto_response returns the hidden block_cpanel_logins value")
	}
	if _, ok := resp.Values["block_ips"]; !ok {
		t.Error("GET auto_response lost block_ips")
	}

	setTestPlatform(s, platform.PanelCPanel, platform.MTAExim)
	w = httptest.NewRecorder()
	s.apiSettingsSections(w, settingsAuthedReq("GET", "/api/v1/settings", "tok", ""))
	if !strings.Contains(w.Body.String(), `"id":"email_av"`) || !strings.Contains(w.Body.String(), "block_cpanel_logins") {
		t.Error("section list hides cPanel settings on cPanel")
	}
}

func TestSettingsSaveKeepsHiddenCpanelValues(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", featureSettingsYAML)
	setTestPlatform(s, platform.PanelNone, platform.MTAPostfix)

	if w := postSettingsChange(t, s, "auto_response", `{"block_ips":true}`); w.Code != http.StatusOK {
		t.Fatalf("save auto_response = %d: %s", w.Code, w.Body.String())
	}
	if w := postSettingsChange(t, s, "suppressions", `{"suppress_webmail_alerts":true}`); w.Code != http.StatusOK {
		t.Fatalf("save suppressions = %d: %s", w.Code, w.Body.String())
	}
	disk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"block_cpanel_logins: true", "suppress_cpanel_login_alerts: true", "block_ips: true", "suppress_webmail_alerts: true"} {
		if !strings.Contains(string(disk), want) {
			t.Errorf("config lost or missed %q:\n%s", want, disk)
		}
	}
}

func TestSettingsSaveRejectsHiddenField(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", featureSettingsYAML)
	setTestPlatform(s, platform.PanelNone, platform.MTAPostfix)

	w := postSettingsChange(t, s, "auto_response", `{"block_cpanel_logins":false}`)
	if got := settingsFieldErrors(t, w)["block_cpanel_logins"]; got != "unknown field" {
		t.Errorf("status %d, field error %q; want unknown field", w.Code, got)
	}
	disk, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(disk), "block_cpanel_logins: true") {
		t.Error("hidden field was changed on disk")
	}
}
