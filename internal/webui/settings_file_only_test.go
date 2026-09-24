package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// hostBindingSuffixes name the leaf keys that point the root daemon at a
// command, an executable, a filesystem path, a socket or an environment
// variable. A Web UI session must never be able to change them: a command
// runs as root, a path is written or read as root, and an env-var name can
// redirect a stored credential to an address of the caller's choosing.
var hostBindingSuffixes = []string{"_command", "_bin", "_file", "_socket", "_env", "_path"}

func isHostBindingField(yamlPath string) bool {
	leaf := yamlPath
	if i := strings.LastIndexByte(yamlPath, '.'); i >= 0 {
		leaf = yamlPath[i+1:]
	}
	if leaf == "file" {
		return true
	}
	for _, suffix := range hostBindingSuffixes {
		if strings.HasSuffix(leaf, suffix) {
			return true
		}
	}
	return false
}

func TestHostBindingSettingsFieldsAreFileOnly(t *testing.T) {
	for _, section := range AllSettingsSections() {
		for _, field := range section.Fields {
			full := section.YAMLPath + "." + field.YAMLPath
			if isHostBindingField(field.YAMLPath) && !field.FileOnly {
				t.Errorf("%s names a command, path, socket or env var but is editable from the web UI", full)
			}
		}
	}
}

// The suffix rule above could miss a field whose name does not follow the
// convention, so the known set is pinned explicitly as well.
func TestKnownHostBindingSettingsFieldsAreFileOnly(t *testing.T) {
	want := map[string][]string{
		"modsec":        {"rules_file", "overrides_file", "reload_command"},
		"performance":   {"wp_cron_fix.php_bin"},
		"email_av":      {"clamd_socket"},
		"mail_logs":     {"file"},
		"firewall":      {"country_db_path"},
		"alerts":        {"webhook.hmac_secret_env"},
		"auto_response": {"verdict_callback.hmac_secret_env"},
		"reputation":    {"rspamd.token_env", "upstream.token_env", "central.pubkey_env"},
	}
	for sectionID, fields := range want {
		section, ok := LookupSettingsSection(sectionID)
		if !ok {
			t.Fatalf("section %q missing", sectionID)
		}
		for _, path := range fields {
			f := lookupSchemaField(section, path)
			if f == nil {
				t.Errorf("%s.%s missing from schema", sectionID, path)
				continue
			}
			if !f.FileOnly {
				t.Errorf("%s.%s must be file-only", sectionID, path)
			}
		}
	}
}

func postSettingsChange(t *testing.T, s *Server, section, changes string) *httptest.ResponseRecorder {
	t.Helper()
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, settingsAuthedReq("GET", "/api/v1/settings/"+section, "tok", ""))
	if getW.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", section, getW.Code, getW.Body.String())
	}
	req := settingsAuthedReq("POST", "/api/v1/settings/"+section, "tok", `{"changes":`+changes+`}`)
	req.Header.Set("If-Match", getW.Header().Get("ETag"))
	setSessionCSRF(s, req)
	w := httptest.NewRecorder()
	s.apiSettingsPost(w, req)
	return w
}

func settingsFieldErrors(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var resp struct {
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode errors: %v (body %s)", err, w.Body.String())
	}
	out := map[string]string{}
	for _, e := range resp.Errors {
		out[e.Field] = e.Message
	}
	return out
}

const fileOnlyTestConfig = `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@example.com"]
    from: csm@example.com
    smtp: smtp.example.com:587
modsec:
  rules_file: /etc/apache2/conf.d/modsec2.user.conf
  overrides_file: /etc/apache2/conf.d/csm-overrides.conf
  reload_command: /usr/sbin/apachectl graceful
`

func TestSettingsPOSTRejectsFileOnlyFieldsAndLeavesConfigUntouched(t *testing.T) {
	cases := []struct {
		section, changes, field string
	}{
		{"modsec", `{"reload_command":"touch /tmp/csm-owned"}`, "reload_command"},
		{"modsec", `{"overrides_file":"/etc/passwd"}`, "overrides_file"},
		{"modsec", `{"rules_file":"/etc/shadow"}`, "rules_file"},
		{"performance", `{"wp_cron_fix.php_bin":"/tmp/php"}`, "wp_cron_fix.php_bin"},
		{"reputation", `{"upstream.token_env":"CSM_OTHER_SECRET"}`, "upstream.token_env"},
		{"email_av", `{"clamd_socket":"/run/docker.sock"}`, "clamd_socket"},
	}
	for _, tc := range cases {
		t.Run(tc.section+"/"+tc.field, func(t *testing.T) {
			s, cfgPath := newSettingsTestServer(t, "tok", fileOnlyTestConfig)
			before, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			w := postSettingsChange(t, s, tc.section, tc.changes)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("code = %d, want 422, body = %s", w.Code, w.Body.String())
			}
			msg, ok := settingsFieldErrors(t, w)[tc.field]
			if !ok {
				t.Fatalf("no error for %s: %s", tc.field, w.Body.String())
			}
			if !strings.Contains(msg, "csm.yaml") {
				t.Errorf("error %q should tell the operator to edit csm.yaml", msg)
			}
			after, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("config file changed although the save was refused")
			}
		})
	}
}

func TestSettingsGETMarksFileOnlyFields(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", fileOnlyTestConfig)
	w := httptest.NewRecorder()
	s.apiSettingsGet(w, settingsAuthedReq("GET", "/api/v1/settings/modsec", "tok", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Section struct {
			Fields []struct {
				YAMLPath string `json:"yaml_path"`
				FileOnly bool   `json:"file_only"`
			} `json:"fields"`
		} `json:"section"`
		Values map[string]interface{} `json:"values"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, f := range resp.Section.Fields {
		if !f.FileOnly {
			t.Errorf("modsec.%s not marked file_only in GET schema", f.YAMLPath)
		}
	}
	if resp.Values["reload_command"] != "/usr/sbin/apachectl graceful" {
		t.Errorf("file-only value must stay visible, got %v", resp.Values["reload_command"])
	}
}

const credentialURLTestConfig = `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@example.com"]
    from: csm@example.com
    smtp: smtp.example.com:587
reputation:
  upstream:
    enabled: true
    url: https://intel.example.com
    token: stored-upstream-token-0123456789
  rspamd:
    enabled: true
    url: https://rspamd.example.com
    token_env: CSM_RSPAMD_TOKEN
`

func TestSettingsPOSTCredentialURLChangeRequiresNewToken(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", credentialURLTestConfig)
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	w := postSettingsChange(t, s, "reputation", `{"upstream.url":"https://collector.example.net"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("URL change without token: code = %d, want 422, body = %s", w.Code, w.Body.String())
	}
	if _, ok := settingsFieldErrors(t, w)["upstream.url"]; !ok {
		t.Fatalf("expected an upstream.url error, got %s", w.Body.String())
	}

	w = postSettingsChange(t, s, "reputation", `{"upstream.url":"https://collector.example.net","upstream.token":"***REDACTED***"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("URL change with redacted placeholder: code = %d, want 422", w.Code)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("config changed although the URL change was refused")
	}

	w = postSettingsChange(t, s, "reputation", `{"upstream.url":"https://collector.example.net","upstream.token":"fresh-token-for-new-address-01"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("URL change with new token: code = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestSettingsPOSTCredentialURLChangeRefusedWhenTokenComesFromEnv(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", credentialURLTestConfig)
	w := postSettingsChange(t, s, "reputation", `{"rspamd.url":"https://collector.example.net","rspamd.token":"typed-in-password-0123"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code = %d, want 422, body = %s", w.Code, w.Body.String())
	}
	msg := settingsFieldErrors(t, w)["rspamd.url"]
	if !strings.Contains(msg, "csm.yaml") {
		t.Fatalf("rspamd.url error = %q, want a pointer to csm.yaml", msg)
	}
}

func TestFirewallTentativeApplyRejectsFileOnlyField(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	installRollbackManager(t, s.cfg.StatePath, cfgPath)
	s.restartDaemon = func() ([]byte, error) { return nil, nil }
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, settingsAuthedReq("GET", "/api/v1/settings/firewall", "tok", ""))
	req := settingsAuthedReq("POST", "/api/v1/settings/firewall/tentative-apply", "tok",
		`{"changes":{"country_db_path":"/etc/shadow"},"timeout_min":2}`)
	req.Header.Set("If-Match", getW.Header().Get("ETag"))
	setSessionCSRF(s, req)
	w := httptest.NewRecorder()
	s.apiFirewallTentativeApply(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code = %d, want 422, body = %s", w.Code, w.Body.String())
	}
	if _, ok := settingsFieldErrors(t, w)["country_db_path"]; !ok {
		t.Fatalf("expected country_db_path error, got %s", w.Body.String())
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("config changed although tentative apply was refused")
	}
}

func TestSettingsPageRendersFileOnlyFieldsReadOnly(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/settings.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	for _, want := range []string{
		// The field is shown read-only and says where it is changed.
		"if (field.file_only) {",
		"inp.readOnly = true;",
		`"Set in csm.yaml. The web UI cannot change this setting."`,
		// A read-only field can never become part of a save.
		"if (field.file_only) return;",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("settings.js missing %q", want)
		}
	}
}

func TestSettingsPOSTCredentialURLUnchangedDoesNotNeedToken(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", credentialURLTestConfig)
	w := postSettingsChange(t, s, "reputation", `{"upstream.url":"https://intel.example.com","upstream.timeout_sec":9}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200, body = %s", w.Code, w.Body.String())
	}
}

func TestSettingsPOSTCredentialRebindHonorsDropInToken(t *testing.T) {
	for _, service := range []string{"upstream", "rspamd"} {
		t.Run(service, func(t *testing.T) {
			// Generate fixture credentials; neither belongs in diagnostic output.
			stored, entered := newSuppressionID(), newSuppressionID()
			body := fileOnlyTestConfig + "reputation:\n  " + service + ":\n    url: https://intel.example.com\n"
			s, cfgPath, _ := newSettingsTestServerWithConfDir(t, "tok", body, map[string]string{
				"credential.yaml": "reputation:\n  " + service + ":\n    token: " + stored + "\n",
			})
			before, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			changes, err := json.Marshal(map[string]string{service + ".url": "https://collector.example.net", service + ".token": entered})
			if err != nil {
				t.Fatal(err)
			}
			w := postSettingsChange(t, s, "reputation", string(changes))
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("credential overridden by drop-in: got %d, want 422", w.Code)
			}
			if settingsFieldErrors(t, w)[service+".url"] == "" {
				t.Fatal("missing address validation error")
			}
			after, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("rejected credential rebind changed disk")
			}
		})
	}
}
