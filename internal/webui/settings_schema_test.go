package webui

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSettingsSectionsAreStable(t *testing.T) {
	got := SettingsSectionIDs()
	want := []string{
		"alerts", "thresholds", "mail_logs", "suppressions", "auto_response",
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
		"mail_logs":    "mail_logs",
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

func TestFirewallRateLimitSchemaDocumentsMeterAddressFamilies(t *testing.T) {
	section, ok := LookupSettingsSection("firewall")
	if !ok {
		t.Fatal("firewall settings section missing")
	}
	// SYN/conn-rate/UDP meters are dual-stack (IPv6 keyed per /64); the
	// concurrent connection limit stays IPv4-only (no v6 connlimit).
	tests := []struct {
		field     string
		label     string
		helpToken string
		group     string
	}{
		{"conn_rate_limit", "Conn rate limit (per IP/min)", "IPv6 metered per /64", FieldGroupRateLimits},
		{"conn_limit", "Concurrent connections per IPv4", "IPv4 only", FieldGroupRateLimits},
		{"syn_flood_protection", "SYN flood protection", "IPv6 metered per /64", FieldGroupFloodProtection},
		{"udp_flood", "UDP flood protection", "IPv6 metered per /64", FieldGroupFloodProtection},
		{"udp_flood_rate", "UDP packets/sec", "IPv6 metered per /64", FieldGroupFloodProtection},
		{"udp_flood_burst", "UDP burst allowance", "IPv6 metered per /64", FieldGroupFloodProtection},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			f := findSchemaField(section, tt.field)
			if f == nil {
				t.Fatalf("%s field missing", tt.field)
			}
			if f.Label != tt.label {
				t.Fatalf("%s label = %q, want %q", tt.field, f.Label, tt.label)
			}
			if !strings.Contains(f.Help, tt.helpToken) {
				t.Fatalf("%s help = %q, want %q", tt.field, f.Help, tt.helpToken)
			}
			if f.FieldGroup != tt.group {
				t.Fatalf("%s group = %q, want %q", tt.field, f.FieldGroup, tt.group)
			}
		})
	}
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

func TestReputationReportingSchemaFieldsResolveToConfig(t *testing.T) {
	section, ok := LookupSettingsSection("reputation")
	if !ok {
		t.Fatal("reputation settings section missing")
	}
	tests := []struct {
		path string
		typ  string
		raw  json.RawMessage
	}{
		{"report.enabled", "bool", json.RawMessage(`true`)},
		{"report.classes", "[]string", json.RawMessage(`["bruteforce","php_relay"]`)},
		{"report.spool_max", "int", json.RawMessage(`500`)},
		{"central.enabled", "bool", json.RawMessage(`true`)},
		{"central.set_url", "string", json.RawMessage(`"https://abuse.example/set"`)},
		{"central.pubkey_env", "string", json.RawMessage(`"CSM_CENTRAL_PUBKEY"`)},
		{"central.action", "string", json.RawMessage(`"challenge"`)},
		{"central.block_threshold", "int", json.RawMessage(`80`)},
		{"central.refresh_interval", "string", json.RawMessage(`"6h"`)},
	}

	for _, tt := range tests {
		field := lookupSchemaField(section, tt.path)
		if field == nil {
			t.Fatalf("reputation schema field %q missing", tt.path)
		}
		if field.Type != tt.typ {
			t.Fatalf("reputation schema field %q type = %q, want %q", tt.path, field.Type, tt.typ)
		}
		var cfg config.Config
		fullPath := strings.Split(section.YAMLPath+"."+tt.path, ".")
		if err := applyToClone(&cfg, fullPath, tt.raw); err != nil {
			t.Fatalf("reputation schema field %q does not resolve to config: %v", tt.path, err)
		}
	}
}

func TestAutoResponseSchemaIncludesVerdictResponseSignatureToggle(t *testing.T) {
	s, _ := LookupSettingsSection("auto_response")
	f := findSchemaField(s, "verdict_callback.require_response_signature")
	if f == nil {
		t.Fatal("verdict response signature toggle missing")
	}
	if f.Type != "bool" {
		t.Fatalf("response signature toggle type = %q, want bool", f.Type)
	}
}

func TestAutoResponseSchemaIncludesVerdictUnsignedOptIn(t *testing.T) {
	s, _ := LookupSettingsSection("auto_response")
	f := findSchemaField(s, "verdict_callback.allow_unsigned")
	if f == nil {
		t.Fatal("verdict unsigned opt-in field missing")
	}
	if f.Type != "bool" {
		t.Fatalf("verdict unsigned opt-in type = %q, want bool", f.Type)
	}
}

func TestAutoResponseSchemaIncludesMaxBlocksPerHour(t *testing.T) {
	s, _ := LookupSettingsSection("auto_response")
	f := findSchemaField(s, "max_blocks_per_hour")
	if f == nil {
		t.Fatal("max_blocks_per_hour field missing")
	}
	if f.Type != "int" {
		t.Fatalf("max_blocks_per_hour type = %q, want int", f.Type)
	}
	if f.Min == nil || *f.Min != 0 {
		t.Fatalf("max_blocks_per_hour min = %v, want 0", f.Min)
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

func TestAlertsSchemaIncludesBlockDigest(t *testing.T) {
	s, _ := LookupSettingsSection("alerts")
	for _, name := range []string{
		"block_digest.enabled",
		"block_digest.countries",
		"block_digest.interval",
		"block_digest.live",
		"block_digest.send_on",
		"block_digest.channel",
		"block_digest.min_block",
	} {
		if findSchemaField(s, name) == nil {
			t.Fatalf("%s field missing", name)
		}
	}

	sendOn := findSchemaField(s, "block_digest.send_on")
	for _, want := range []string{"any", "customer"} {
		if !hasOption(sendOn.Options, want) {
			t.Fatalf("block_digest.send_on options = %v, missing %q", sendOn.Options, want)
		}
	}
	channel := findSchemaField(s, "block_digest.channel")
	for _, want := range []string{"", "email", "webhook"} {
		if !hasOption(channel.Options, want) {
			t.Fatalf("block_digest.channel options = %v, missing %q", channel.Options, want)
		}
	}
	minBlock := findSchemaField(s, "block_digest.min_block")
	if minBlock.Min == nil || *minBlock.Min != 0 {
		t.Fatalf("block_digest.min_block min = %v, want 0", minBlock.Min)
	}
}

func TestMailLogsSchemaUsesEnumSource(t *testing.T) {
	s, _ := LookupSettingsSection("mail_logs")
	if !s.Restart {
		t.Fatal("mail_logs should be marked restart-required")
	}
	source := findSchemaField(s, "source")
	if source == nil {
		t.Fatal("mail_logs.source field missing")
	}
	if source.Type != "enum" {
		t.Fatalf("mail_logs.source type = %q, want enum", source.Type)
	}
	for _, want := range []string{"auto", "file", "journal"} {
		if !hasOption(source.Options, want) {
			t.Fatalf("mail_logs.source options = %v, missing %q", source.Options, want)
		}
	}
	units := findSchemaField(s, "units")
	if units == nil {
		t.Fatal("mail_logs.units field missing")
	}
	if units.Type != "[]string" {
		t.Fatalf("mail_logs.units type = %q, want []string", units.Type)
	}
}

func TestThresholdsSchemaIncludesAccountScanMaxFiles(t *testing.T) {
	s, _ := LookupSettingsSection("thresholds")
	f := findSchemaField(s, "account_scan_max_files")
	if f == nil {
		t.Fatal("account_scan_max_files field missing")
	}
	if f.Type != "int" {
		t.Fatalf("account_scan_max_files type = %q, want int", f.Type)
	}
	if f.Min == nil || *f.Min != 1 {
		t.Fatalf("account_scan_max_files min = %v, want 1", f.Min)
	}
	if f.Max == nil || *f.Max != 100000 {
		t.Fatalf("account_scan_max_files max = %v, want 100000", f.Max)
	}
	if f.FieldGroup != FieldGroupLimits {
		t.Fatalf("account_scan_max_files group = %q, want %q", f.FieldGroup, FieldGroupLimits)
	}
}

func TestThresholdsSchemaIncludesCrontabBase64BlobMaxBytes(t *testing.T) {
	s, _ := LookupSettingsSection("thresholds")
	f := findSchemaField(s, "crontab_base64_blob_max_bytes")
	if f == nil {
		t.Fatal("crontab_base64_blob_max_bytes field missing")
	}
	if f.Type != "int" {
		t.Fatalf("crontab_base64_blob_max_bytes type = %q, want int", f.Type)
	}
	if f.Min == nil || *f.Min != 1024 {
		t.Fatalf("crontab_base64_blob_max_bytes min = %v, want 1024", f.Min)
	}
	if f.Max == nil || *f.Max != 1048576 {
		t.Fatalf("crontab_base64_blob_max_bytes max = %v, want 1048576", f.Max)
	}
	if f.FieldGroup != FieldGroupLimits {
		t.Fatalf("crontab_base64_blob_max_bytes group = %q, want %q", f.FieldGroup, FieldGroupLimits)
	}
	if !strings.Contains(f.Help, "multiple of 4") {
		t.Fatalf("crontab_base64_blob_max_bytes help = %q, want multiple-of-4 guidance", f.Help)
	}
}

func TestThresholdsSchemaIncludesMailBruteAccountKey(t *testing.T) {
	s, _ := LookupSettingsSection("thresholds")
	f := findSchemaField(s, "mail_brute_account_key")
	if f == nil {
		t.Fatal("mail_brute_account_key field missing")
	}
	if f.Type != "string" {
		t.Fatalf("mail_brute_account_key type = %q, want string", f.Type)
	}
	if f.FieldGroup != FieldGroupMailBruteForce {
		t.Fatalf("mail_brute_account_key group = %q, want %q", f.FieldGroup, FieldGroupMailBruteForce)
	}
	if f.Placeholder != "builtin:dovecot-user" {
		t.Fatalf("mail_brute_account_key placeholder = %q", f.Placeholder)
	}
}

func TestThresholdsSchemaIncludesHTTPDistributedMinIPs(t *testing.T) {
	s, _ := LookupSettingsSection("thresholds")
	f := findSchemaField(s, "http_distributed_min_ips")
	if f == nil {
		t.Fatal("http_distributed_min_ips field missing")
	}
	if f.Type != "int" {
		t.Fatalf("http_distributed_min_ips type = %q, want int", f.Type)
	}
	if f.Min == nil || *f.Min != 0 {
		t.Fatalf("http_distributed_min_ips min = %v, want 0", f.Min)
	}
	if f.FieldGroup != FieldGroupWebBruteForce {
		t.Fatalf("http_distributed_min_ips group = %q, want %q", f.FieldGroup, FieldGroupWebBruteForce)
	}
	if !strings.Contains(f.Help, "0 disables") {
		t.Fatalf("http_distributed_min_ips help = %q, want disable guidance", f.Help)
	}
}

func TestThresholdsSchemaIncludesXMLRPCThreshold(t *testing.T) {
	s, _ := LookupSettingsSection("thresholds")
	f := findSchemaField(s, "xmlrpc_threshold")
	if f == nil {
		t.Fatal("xmlrpc_threshold field missing")
	}
	if f.Type != "int" {
		t.Fatalf("xmlrpc_threshold type = %q, want int", f.Type)
	}
	if f.Min == nil || *f.Min != 0 {
		t.Fatalf("xmlrpc_threshold min = %v, want 0", f.Min)
	}
	if f.FieldGroup != FieldGroupWebBruteForce {
		t.Fatalf("xmlrpc_threshold group = %q, want %q", f.FieldGroup, FieldGroupWebBruteForce)
	}
	if !strings.Contains(f.Help, "0 disables") {
		t.Fatalf("xmlrpc_threshold help = %q, want disable guidance", f.Help)
	}
}

func TestThresholdsSchemaIncludesHTTPScannerProfileFields(t *testing.T) {
	s, _ := LookupSettingsSection("thresholds")
	cases := []struct {
		name      string
		typ       string
		min, max  int64
		hasMax    bool
		wantGroup string
	}{
		{"http_scanner_min_requests", "int", 0, 0, false, FieldGroupWebBruteForce},
		{"http_scanner_error_pct", "int", 1, 100, true, FieldGroupWebBruteForce},
		{"http_scanner_min_distinct_paths", "int", 1, int64(config.HTTPScannerMaxDistinctPaths), true, FieldGroupWebBruteForce},
		{"http_scanner_status_codes", "[]int", 100, 599, true, FieldGroupWebBruteForce},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := findSchemaField(s, tc.name)
			if f == nil {
				t.Fatalf("%s field missing", tc.name)
			}
			if f.Type != tc.typ {
				t.Fatalf("%s type = %q, want %q", tc.name, f.Type, tc.typ)
			}
			if f.Min == nil || *f.Min != tc.min {
				t.Fatalf("%s min = %v, want %d", tc.name, f.Min, tc.min)
			}
			if tc.hasMax {
				if f.Max == nil || *f.Max != tc.max {
					t.Fatalf("%s max = %v, want %d", tc.name, f.Max, tc.max)
				}
			} else if f.Max != nil {
				t.Fatalf("%s max = %v, want nil", tc.name, f.Max)
			}
			if f.FieldGroup != tc.wantGroup {
				t.Fatalf("%s group = %q, want %q", tc.name, f.FieldGroup, tc.wantGroup)
			}
		})
	}
}

func TestAutoResponseSchemaIncludesHTTPScannerAction(t *testing.T) {
	s, ok := LookupSettingsSection("auto_response")
	if !ok {
		t.Fatal("auto_response section missing")
	}
	f := findSchemaField(s, "http_scanner_action")
	if f == nil {
		t.Fatal("http_scanner_action field missing")
	}
	if f.Type != "enum" {
		t.Fatalf("type = %q, want enum", f.Type)
	}
	if len(f.Options) != 2 || f.Options[0] != "challenge" || f.Options[1] != "block" {
		t.Fatalf("options = %v, want [challenge block]", f.Options)
	}
}

func TestThresholdsSchemaIncludesCredStuffingDistinctAccounts(t *testing.T) {
	s, _ := LookupSettingsSection("thresholds")
	f := findSchemaField(s, "cred_stuffing_distinct_accounts")
	if f == nil {
		t.Fatal("cred_stuffing_distinct_accounts field missing")
	}
	if f.Type != "int" {
		t.Fatalf("cred_stuffing_distinct_accounts type = %q, want int", f.Type)
	}
	if f.Min == nil || *f.Min != 2 {
		t.Fatalf("cred_stuffing_distinct_accounts min = %v, want 2", f.Min)
	}
	if f.Max == nil || *f.Max != 200 {
		t.Fatalf("cred_stuffing_distinct_accounts max = %v, want 200", f.Max)
	}
	if f.FieldGroup != FieldGroupAccountSpray {
		t.Fatalf("cred_stuffing_distinct_accounts group = %q, want %q", f.FieldGroup, FieldGroupAccountSpray)
	}
	if !strings.Contains(f.Help, "Default 5") {
		t.Fatalf("cred_stuffing_distinct_accounts help = %q, want default guidance", f.Help)
	}
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
	for _, want := range []string{"waf_rules", "suspicious_crontab", "new_php_in_sensitive_dir_clean", "http_scanner_profile"} {
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
