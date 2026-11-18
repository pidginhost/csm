package webui

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var phpOnlySettingsFields = map[string][]string{
	"thresholds":    {"xmlrpc_threshold"},
	"auto_response": {"enforce_permissions", "fix_wp_cron"},
	"performance": {
		"php_process_warn_per_user", "php_process_critical_total_multiplier",
		"wp_memory_limit_max_mb", "wp_transient_warn_mb", "wp_transient_critical_mb",
		"wp_cron_fix.interval_minutes", "wp_cron_fix.php_bin",
	},
}

func TestPHPSettingsHiddenWithoutPHP(t *testing.T) {
	for id, gated := range phpOnlySettingsFields {
		full, _ := LookupSettingsSection(id)
		off, ok := filterSettingsSection(full, map[string]bool{})
		if !ok {
			t.Fatalf("%s dropped without PHP", id)
		}
		for _, path := range gated {
			if lookupSchemaField(full, path) == nil {
				t.Fatalf("%s.%s is not in the schema", id, path)
			}
			if lookupSchemaField(off, path) != nil {
				t.Errorf("%s.%s shown without PHP", id, path)
			}
		}
		on, _ := filterSettingsSection(full, map[string]bool{"php": true, "cpanel": true})
		for _, path := range gated {
			if lookupSchemaField(on, path) == nil {
				t.Errorf("%s.%s hidden with PHP", id, path)
			}
		}
	}

	shield, _ := LookupSettingsSection("php_shield")
	if _, ok := filterSettingsSection(shield, map[string]bool{}); ok {
		t.Error("php_shield shown without PHP")
	}
	if _, ok := filterSettingsSection(shield, map[string]bool{"php": true, "phpShield": true}); !ok {
		t.Error("php_shield hidden with PHP")
	}
}

const phpSettingsYAML = `hostname: t.example.com
auto_response:
  enabled: true
  block_ips: false
  enforce_permissions: true
performance:
  wp_cron_fix:
    interval_minutes: 18
    php_bin: /usr/bin/php8.3
php_shield:
  enabled: true
`

func TestSettingsAPIWithoutPHP(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", phpSettingsYAML)
	setTestPHP(s, false)

	w := httptest.NewRecorder()
	s.apiSettingsSections(w, settingsAuthedReq("GET", "/api/v1/settings", "tok", ""))
	body := w.Body.String()
	for _, hidden := range []string{`"id":"php_shield"`, "enforce_permissions", "php_process_warn_per_user", "wp_cron_fix"} {
		if strings.Contains(body, hidden) {
			t.Errorf("section list shows %s without PHP", hidden)
		}
	}
	if !strings.Contains(body, `"id":"performance"`) {
		t.Error("section list lost performance")
	}

	w = httptest.NewRecorder()
	s.apiSettingsGet(w, settingsAuthedReq("GET", "/api/v1/settings/php_shield", "tok", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("GET php_shield = %d, want 404", w.Code)
	}

	w = httptest.NewRecorder()
	s.apiSettingsGet(w, settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", ""))
	var resp struct {
		Values map[string]json.RawMessage `json:"values"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.Values["enforce_permissions"]; ok {
		t.Error("GET auto_response returns the hidden enforce_permissions value")
	}

	// A save neither accepts the hidden field nor drops its value on disk.
	w = postSettingsChange(t, s, "auto_response", `{"enforce_permissions":false}`)
	if got := settingsFieldErrors(t, w)["enforce_permissions"]; got != "unknown field" {
		t.Errorf("status %d, field error %q; want unknown field", w.Code, got)
	}
	if w = postSettingsChange(t, s, "auto_response", `{"block_ips":true}`); w.Code != http.StatusOK {
		t.Fatalf("save auto_response = %d: %s", w.Code, w.Body.String())
	}
	disk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"enforce_permissions: true", "block_ips: true"} {
		if !strings.Contains(string(disk), want) {
			t.Errorf("config lost or missed %q:\n%s", want, disk)
		}
	}

	setTestPHP(s, true)
	w = httptest.NewRecorder()
	s.apiSettingsSections(w, settingsAuthedReq("GET", "/api/v1/settings", "tok", ""))
	if !strings.Contains(w.Body.String(), `"id":"php_shield"`) {
		t.Error("section list hides php_shield with PHP installed")
	}
}

func TestPerformancePagePHPCardsFollowFeature(t *testing.T) {
	s := newTestServer(t, "tok")
	has := func(out, id string) bool { return strings.Contains(out, `id="`+id+`"`) }

	setTestPHP(s, true)
	out := renderRealPage(t, s, "performance")
	if !has(out, "stat-php") || !has(out, "php-consumers") {
		t.Error("PHP cards missing with PHP installed")
	}

	setTestPHP(s, false)
	out = renderRealPage(t, s, "performance")
	if has(out, "stat-php") || has(out, "php-consumers") || strings.Contains(out, "Top PHP Consumers") {
		t.Error("PHP cards rendered without PHP")
	}
	if !has(out, "perf-findings") || !strings.Contains(out, `class="col-12"`) {
		t.Error("performance findings do not take the full row without PHP")
	}
}

func TestSettingsWithoutPHPKeepsNestedValuesPrivate(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", phpSettingsYAML)
	setTestPHP(s, false)
	w := httptest.NewRecorder()
	s.apiSettingsGet(w, settingsAuthedReq("GET", "/api/v1/settings/performance", "tok", ""))
	var resp struct{ Values map[string]json.RawMessage }
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("GET performance: status %d, err %v", w.Code, err)
	}
	if _, ok := resp.Values["wp_cron_fix"]; ok {
		t.Error("GET performance returned hidden WP-Cron settings")
	}
	w = postSettingsChange(t, s, "performance", `{"error_log_warn_size_mb":25}`)
	if w.Code != http.StatusOK {
		t.Fatalf("save performance: %d %s", w.Code, w.Body.String())
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"interval_minutes: 18", "php_bin: /usr/bin/php8.3", "error_log_warn_size_mb: 25"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("saved config missing %q", want)
		}
	}
}

func TestPerformanceCardsUseOnePHPResult(t *testing.T) {
	s := newTestServer(t, "tok")
	funcs := s.templateFuncs()
	reads := 0
	funcs["feature"] = func(name string) bool {
		if name != "php" {
			return s.feature(name)
		}
		reads++
		return reads == 1
	}
	page, err := template.New("performance.html").Funcs(funcs).ParseFiles("../../ui/templates/performance.html")
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := page.ExecuteTemplate(&out, "content", nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`id="stat-php"`, `id="php-consumers"`, `class="col-lg-7"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("inconsistent PHP layout: missing %s", want)
		}
	}
}
