package webui

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSettingsSectionsAreStable(t *testing.T) {
	got := SettingsSectionIDs()
	want := []string{
		"alerts", "thresholds", "suppressions", "auto_response",
		"reputation", "email_protection", "challenge", "php_shield",
		"signatures", "email_av", "modsec", "performance", "cloudflare",
		"geoip", "infra_ips", "disabled_checks", "sentry", "firewall",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("section IDs drifted:\n  got  = %v\n  want = %v", got, want)
	}
}

func TestEverySectionHasYAMLPath(t *testing.T) {
	for _, id := range SettingsSectionIDs() {
		s, ok := LookupSettingsSection(id)
		if !ok {
			t.Errorf("section %q not found", id)
			continue
		}
		if s.YAMLPath == "" {
			t.Errorf("section %q has empty YAMLPath", id)
		}
		if len(s.Fields) == 0 {
			t.Errorf("section %q has no fields", id)
		}
	}
}

func TestSettingsRestartHintsMatchHotReloadManifest(t *testing.T) {
	policies := map[string]config.ReloadPolicy{}
	for _, policy := range config.HotReloadManifest() {
		policies[policy.Field] = policy
	}

	for _, section := range AllSettingsSections() {
		policy, ok := policies[section.YAMLPath]
		if !ok {
			continue
		}
		if section.ReloadTag != policy.Tag {
			t.Errorf("%s reload_tag = %q, want %q", section.ID, section.ReloadTag, policy.Tag)
		}
		if section.Restart != policy.RestartRequired {
			t.Errorf("%s restart_hint = %v, want %v", section.ID, section.Restart, policy.RestartRequired)
		}
	}
}

func TestSchemaCoversAllInScopeConfigFields(t *testing.T) {
	inScope := map[string]string{
		"alerts": "alerts", "thresholds": "thresholds",
		"suppressions": "suppressions", "auto_response": "auto_response",
		"reputation": "reputation", "email_protection": "email_protection",
		"challenge": "challenge", "php_shield": "php_shield",
		"signatures": "signatures", "email_av": "email_av",
		"modsec": "modsec", "performance": "performance",
		"cloudflare": "cloudflare", "geoip": "geoip",
		"infra_ips": "infra_ips", "disabled_checks": "disabled_checks",
		"sentry": "sentry", "firewall": "firewall",
	}

	cfgType := reflect.TypeOf(config.Config{})
	for i := 0; i < cfgType.NumField(); i++ {
		field := cfgType.Field(i)
		tag := field.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		yamlName := tag
		if idx := strings.IndexByte(tag, ','); idx >= 0 {
			yamlName = tag[:idx]
		}
		sectionID, isInScope := inScope[yamlName]
		if !isInScope {
			continue
		}
		if _, ok := LookupSettingsSection(sectionID); !ok {
			t.Errorf("in-scope yaml field %q has no schema section %q", yamlName, sectionID)
		}
	}
}

func findSchemaField(section SettingsSection, yamlName string) *SettingsField {
	for i := range section.Fields {
		if section.Fields[i].YAMLPath == yamlName ||
			strings.HasSuffix(section.Fields[i].YAMLPath, "."+yamlName) {
			return &section.Fields[i]
		}
	}
	return nil
}

func TestSecretFieldsAreMarkedSecret(t *testing.T) {
	known := []struct{ section, field string }{
		{"alerts", "webhook.hmac_secret"},
		{"reputation", "abuseipdb_key"},
		{"geoip", "license_key"},
		{"sentry", "dsn"},
	}
	for _, k := range known {
		s, _ := LookupSettingsSection(k.section)
		f := findSchemaField(s, k.field)
		if f == nil {
			t.Errorf("field %s.%s missing", k.section, k.field)
			continue
		}
		if !f.Secret {
			t.Errorf("field %s.%s not marked secret", k.section, k.field)
		}
	}
}

func TestAlertsWebhookTypeIncludesPhpanel(t *testing.T) {
	s, _ := LookupSettingsSection("alerts")
	f := findSchemaField(s, "webhook.type")
	if f == nil {
		t.Fatal("webhook.type field missing")
	}
	for _, opt := range f.Options {
		if opt == "phpanel" {
			return
		}
	}
	t.Fatalf("webhook.type options = %v, want phpanel", f.Options)
}

func TestEnumArrayFieldsCarryOptionsSource(t *testing.T) {
	cases := []struct {
		section, field, source string
	}{
		{"alerts", "email.disabled_checks", "check_names"},
		{"disabled_checks", "", "disabled_check_names"},
		{"geoip", "editions", "geoip_editions"},
	}
	for _, c := range cases {
		s, _ := LookupSettingsSection(c.section)
		f := findSchemaField(s, c.field)
		if f == nil {
			t.Errorf("field %s.%s missing", c.section, c.field)
			continue
		}
		if f.Type != "[]enum" {
			t.Errorf("field %s.%s type = %q, want []enum", c.section, c.field, f.Type)
		}
		if f.OptionsSource != c.source {
			t.Errorf("field %s.%s options_source = %q, want %q", c.section, c.field, f.OptionsSource, c.source)
		}
	}
}

func TestResolveFieldOptionsFillsCheckNames(t *testing.T) {
	s, _ := LookupSettingsSection("alerts")
	resolveFieldOptions(&s)
	f := findSchemaField(s, "email.disabled_checks")
	if f == nil {
		t.Fatal("email.disabled_checks missing")
	}
	if len(f.Options) == 0 {
		t.Fatal("Options not populated")
	}
	if len(f.OptionGroups) == 0 {
		t.Fatal("OptionGroups not populated")
	}
	// The registry has test_alert as Internal — it must not leak into options.
	for _, o := range f.Options {
		if o == "test_alert" {
			t.Errorf("internal check %q leaked into public options", o)
		}
	}
	// Spot-check a known public entry.
	found := false
	for _, o := range f.Options {
		if o == "webshell" {
			found = true
			break
		}
	}
	if !found {
		t.Error(`"webshell" missing from resolved disabled_checks options`)
	}
}

func TestResolveFieldOptionsFillsDisabledCheckNames(t *testing.T) {
	s, _ := LookupSettingsSection("disabled_checks")
	resolveFieldOptions(&s)
	f := findSchemaField(s, "")
	if f == nil {
		t.Fatal("disabled_checks field missing")
	}
	if len(f.Options) == 0 {
		t.Fatal("Options not populated")
	}
	if len(f.OptionGroups) == 0 {
		t.Fatal("OptionGroups not populated")
	}
	for _, want := range []string{"waf_rules", "suspicious_crontab", "new_php_in_sensitive_dir_clean"} {
		if !hasOption(f.Options, want) {
			t.Fatalf("%q missing from top-level disabled_checks options: %v", want, f.Options)
		}
	}
	for _, blocked := range []string{"crontabs", "modsec_block_realtime", "test_alert"} {
		if hasOption(f.Options, blocked) {
			t.Fatalf("%q should not be exposed in top-level disabled_checks options: %v", blocked, f.Options)
		}
	}
}

func TestResolveFieldOptionsFillsGeoIPEditions(t *testing.T) {
	s, _ := LookupSettingsSection("geoip")
	resolveFieldOptions(&s)
	f := findSchemaField(s, "editions")
	if f == nil {
		t.Fatal("editions missing")
	}
	if len(f.OptionGroups) != 2 {
		t.Fatalf("want 2 option groups (free, paid), got %d", len(f.OptionGroups))
	}
	// First group should contain GeoLite2-City (free).
	foundCity := false
	for _, v := range f.OptionGroups[0].Values {
		if v == "GeoLite2-City" {
			foundCity = true
			break
		}
	}
	if !foundCity {
		t.Error("GeoLite2-City not in free group")
	}
}

func hasOption(options []string, want string) bool {
	for _, opt := range options {
		if opt == want {
			return true
		}
	}
	return false
}

func TestNullablePointerFieldsFlagged(t *testing.T) {
	cases := []struct{ section, field string }{
		{"performance", "enabled"},
		{"geoip", "auto_update"},
	}
	for _, c := range cases {
		s, _ := LookupSettingsSection(c.section)
		f := findSchemaField(s, c.field)
		if f == nil {
			t.Errorf("field %s.%s missing", c.section, c.field)
			continue
		}
		if !f.Nullable {
			t.Errorf("field %s.%s should be Nullable=true", c.section, c.field)
		}
	}
}
