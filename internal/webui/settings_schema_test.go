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
		"geoip", "infra_ips", "sentry",
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

func TestSchemaCoversAllInScopeConfigFields(t *testing.T) {
	inScope := map[string]string{
		"alerts": "alerts", "thresholds": "thresholds",
		"suppressions": "suppressions", "auto_response": "auto_response",
		"reputation": "reputation", "email_protection": "email_protection",
		"challenge": "challenge", "php_shield": "php_shield",
		"signatures": "signatures", "email_av": "email_av",
		"modsec": "modsec", "performance": "performance",
		"cloudflare": "cloudflare", "geoip": "geoip",
		"infra_ips": "infra_ips", "sentry": "sentry",
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
