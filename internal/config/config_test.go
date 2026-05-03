package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "csm-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("hostname: test\n")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Hostname != "test" {
		t.Errorf("hostname = %q, want 'test'", cfg.Hostname)
	}
	if cfg.Thresholds.MailQueueWarn != 500 {
		t.Errorf("mail_queue_warn = %d, want 500", cfg.Thresholds.MailQueueWarn)
	}
	if cfg.Thresholds.DeepScanIntervalMin != 60 {
		t.Errorf("deep_scan_interval = %d, want 60", cfg.Thresholds.DeepScanIntervalMin)
	}
	if cfg.Alerts.MaxPerHour != 30 {
		t.Errorf("max_per_hour = %d, want 30", cfg.Alerts.MaxPerHour)
	}
	if cfg.StatePath != "/var/lib/csm/state" {
		t.Errorf("state_path = %q, want '/var/lib/csm/state'", cfg.StatePath)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		wantError int
	}{
		{
			name: "empty hostname",
			cfg: func() Config {
				c := Config{Hostname: ""}
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 2, // hostname + no alert method
		},
		{
			name: "placeholder hostname",
			cfg: func() Config {
				c := Config{Hostname: "SET_HOSTNAME_HERE"}
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 2,
		},
		{
			name: "email enabled no recipients",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Email.Enabled = true
				c.Alerts.Email.SMTP = "localhost:25"
				c.Alerts.Email.From = "csm@test.com"
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 1,
		},
		{
			name: "webhook enabled no URL",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Webhook.Enabled = true
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 1,
		},
		{
			name: "valid config",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Email.Enabled = true
				c.Alerts.Email.To = []string{"admin@test.com"}
				c.Alerts.Email.SMTP = "localhost:25"
				c.Alerts.Email.From = "csm@test.com"
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := Validate(&tt.cfg)
			errors := 0
			for _, r := range results {
				if r.Level == "error" {
					errors++
				}
			}
			if errors != tt.wantError {
				t.Errorf("Validate() returned %d errors, want %d: %v", errors, tt.wantError, results)
			}
		})
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "csm-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	_, _ = tmpFile.WriteString("invalid: [yaml: {{{\n")
	tmpFile.Close()

	_, err = Load(tmpFile.Name())
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load("/nonexistent/path/csm.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestConfig_SMTPBruteForceDefaultsApplied(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: \"\"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]int{
		"SMTPBruteForceThreshold":    5,
		"SMTPBruteForceWindowMin":    10,
		"SMTPBruteForceSuppressMin":  60,
		"SMTPBruteForceSubnetThresh": 8,
		"SMTPAccountSprayThreshold":  12,
		"SMTPBruteForceMaxTracked":   20000,
	}
	got := map[string]int{
		"SMTPBruteForceThreshold":    cfg.Thresholds.SMTPBruteForceThreshold,
		"SMTPBruteForceWindowMin":    cfg.Thresholds.SMTPBruteForceWindowMin,
		"SMTPBruteForceSuppressMin":  cfg.Thresholds.SMTPBruteForceSuppressMin,
		"SMTPBruteForceSubnetThresh": cfg.Thresholds.SMTPBruteForceSubnetThresh,
		"SMTPAccountSprayThreshold":  cfg.Thresholds.SMTPAccountSprayThreshold,
		"SMTPBruteForceMaxTracked":   cfg.Thresholds.SMTPBruteForceMaxTracked,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
}

func TestLoadBytesAppliesSameDefaultsAsLoad(t *testing.T) {
	yamlBody := []byte("hostname: example.com\n")

	tmp := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(tmp, yamlBody, 0o600); err != nil {
		t.Fatal(err)
	}
	fromDisk, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}

	fromBytes, err := LoadBytes(yamlBody)
	if err != nil {
		t.Fatal(err)
	}

	fromDisk.ConfigFile = ""
	fromBytes.ConfigFile = ""

	if !reflect.DeepEqual(fromDisk, fromBytes) {
		t.Fatalf("LoadBytes drifted from Load:\n  disk  = %#v\n  bytes = %#v", fromDisk, fromBytes)
	}
	if fromBytes.StatePath != "/var/lib/csm/state" {
		t.Errorf("default StatePath not applied: %q", fromBytes.StatePath)
	}
}

func TestConfig_MailBruteForceDefaultsApplied(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: \"\"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]int{
		"MailBruteForceThreshold":    5,
		"MailBruteForceWindowMin":    10,
		"MailBruteForceSuppressMin":  60,
		"MailBruteForceSubnetThresh": 8,
		"MailAccountSprayThreshold":  12,
		"MailBruteForceMaxTracked":   20000,
	}
	got := map[string]int{
		"MailBruteForceThreshold":    cfg.Thresholds.MailBruteForceThreshold,
		"MailBruteForceWindowMin":    cfg.Thresholds.MailBruteForceWindowMin,
		"MailBruteForceSuppressMin":  cfg.Thresholds.MailBruteForceSuppressMin,
		"MailBruteForceSubnetThresh": cfg.Thresholds.MailBruteForceSubnetThresh,
		"MailAccountSprayThreshold":  cfg.Thresholds.MailAccountSprayThreshold,
		"MailBruteForceMaxTracked":   cfg.Thresholds.MailBruteForceMaxTracked,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
}

func TestLoadWithConfDir_Override(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))
	must(t, os.WriteFile(main, []byte("hostname: main-host\nstate_path: /opt/csm/state\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(confd, "10-phpanel.yaml"),
		[]byte("hostname: phpanel-host\n"), 0o600))

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "phpanel-host" {
		t.Fatalf("expected conf.d override, got %q", cfg.Hostname)
	}
	if cfg.StatePath != "/opt/csm/state" {
		t.Fatalf("expected main state_path retained, got %q", cfg.StatePath)
	}
}

func TestLoadWithConfDir_NoDirIsLoadEquivalent(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	must(t, os.WriteFile(main, []byte("hostname: solo\n"), 0o600))

	cfg, err := LoadWithDir(main, filepath.Join(dir, "absent"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "solo" {
		t.Fatalf("expected solo, got %q", cfg.Hostname)
	}
}

func TestWebUITokens_BackwardCompatLegacyAuthToken(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
webui:
  enabled: true
  auth_token: "legacy-secret"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WebUI.Tokens) != 1 {
		t.Fatalf("expected legacy auth_token to migrate into tokens slice, got %d entries", len(cfg.WebUI.Tokens))
	}
	if cfg.WebUI.Tokens[0].Scope != "admin" {
		t.Fatalf("expected admin scope, got %q", cfg.WebUI.Tokens[0].Scope)
	}
	if cfg.WebUI.Tokens[0].Token != "legacy-secret" {
		t.Fatalf("expected legacy token preserved, got %q", cfg.WebUI.Tokens[0].Token)
	}
	// Legacy field must still be set so callers reading it directly during the migration window see no diff.
	if cfg.WebUI.AuthToken != "legacy-secret" {
		t.Fatalf("expected legacy AuthToken preserved, got %q", cfg.WebUI.AuthToken)
	}
}

func TestWebUITokens_MixedAdminAndRead(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
webui:
  enabled: true
  tokens:
    - name: admin
      token: "admin-secret"
      scope: admin
    - name: phpanel
      token: "panel-secret"
      scope: read
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WebUI.Tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(cfg.WebUI.Tokens))
	}
	if cfg.WebUI.Tokens[1].Scope != "read" {
		t.Fatalf("expected read scope on phpanel token, got %q", cfg.WebUI.Tokens[1].Scope)
	}
}

func TestWebUITokens_RejectsUnknownScope(t *testing.T) {
	_, err := LoadBytes([]byte(`
webui:
  enabled: true
  tokens:
    - name: bad
      token: "x"
      scope: superuser
`))
	if err == nil {
		t.Fatal("expected error for unknown scope")
	}
}

func TestWebUITokens_RejectsEmptyToken(t *testing.T) {
	_, err := LoadBytes([]byte(`
webui:
  enabled: true
  tokens:
    - name: empty
      token: ""
      scope: read
`))
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestWebUITokens_RejectsEmptyName(t *testing.T) {
	_, err := LoadBytes([]byte(`
webui:
  enabled: true
  tokens:
    - name: ""
      token: "x"
      scope: read
`))
	if err == nil {
		t.Fatal("expected error for empty token name")
	}
}

func TestWebUITokens_RejectsDuplicateToken(t *testing.T) {
	_, err := LoadBytes([]byte(`
webui:
  enabled: true
  tokens:
    - name: admin
      token: "same"
      scope: admin
    - name: phpanel
      token: "same"
      scope: read
`))
	if err == nil {
		t.Fatal("expected error for duplicate token")
	}
}

func TestMailLogs_DefaultsToAuto(t *testing.T) {
	cfg, err := LoadBytes([]byte(``))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MailLogs.Source != "auto" {
		t.Fatalf("expected default source=auto, got %q", cfg.MailLogs.Source)
	}
}

func TestMailLogs_AcceptsExplicitJournal(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
mail_logs:
  source: journal
  units:
    - postfix
    - dovecot
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MailLogs.Source != "journal" {
		t.Fatalf("expected journal, got %q", cfg.MailLogs.Source)
	}
	if len(cfg.MailLogs.Units) != 2 {
		t.Fatalf("expected 2 units, got %v", cfg.MailLogs.Units)
	}
}

func TestMailLogs_RejectsUnknownSource(t *testing.T) {
	_, err := LoadBytes([]byte(`mail_logs: { source: kafka }`))
	if err == nil {
		t.Fatal("expected error for unknown source")
	}
}

func TestMailLogs_RejectsEmptyJournalUnit(t *testing.T) {
	_, err := LoadBytes([]byte(`
mail_logs:
  source: journal
  units:
    - postfix
    - ""
`))
	if err == nil {
		t.Fatal("expected error for empty journal unit")
	}
}

func TestMailBrute_DefaultsToBuiltinDovecotUser(t *testing.T) {
	cfg, err := LoadBytes([]byte(``))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Thresholds.MailBruteAccountKey != "builtin:dovecot-user" {
		t.Fatalf("expected builtin:dovecot-user, got %q", cfg.Thresholds.MailBruteAccountKey)
	}
}

func TestMailBrute_AcceptsCustomRegex(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
thresholds:
  mail_brute_account_key: 'regex:user=([^,\s]+)'
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Thresholds.MailBruteAccountKey == "" {
		t.Fatal("expected regex value preserved")
	}
}

func TestMailBrute_RejectsInvalidRegex(t *testing.T) {
	_, err := LoadBytes([]byte(`
thresholds:
  mail_brute_account_key: 'regex:[unclosed'
`))
	if err == nil {
		t.Fatal("expected error for unclosed regex")
	}
}

func TestMailBrute_RejectsRegexWithoutCapture(t *testing.T) {
	_, err := LoadBytes([]byte(`
thresholds:
  mail_brute_account_key: 'regex:user=[^,\s]+'
`))
	if err == nil {
		t.Fatal("expected error for regex without capture group")
	}
}

func TestMailBrute_RejectsUnknownPrefix(t *testing.T) {
	_, err := LoadBytes([]byte(`
thresholds:
  mail_brute_account_key: 'something-weird'
`))
	if err == nil {
		t.Fatal("expected error for unknown prefix")
	}
}

func TestAutoResponse_DryRunDefaultsTrueForSafety(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
auto_response:
  enabled: true
  block_ips: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoResponseDryRunEnabled() {
		t.Fatal("expected dry_run default=true (safety) when not specified")
	}
}

func TestAutoResponse_ExplicitFalseAllowsLiveBlock(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
auto_response:
  enabled: true
  block_ips: true
  dry_run: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoResponseDryRunEnabled() {
		t.Fatal("explicit false must allow live blocking")
	}
}

func TestAutoResponse_ExplicitTrueIsDryRun(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
auto_response:
  enabled: true
  block_ips: true
  dry_run: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoResponseDryRunEnabled() {
		t.Fatal("explicit true must dry-run")
	}
}

func TestUpstreamTI_DisabledByDefault(t *testing.T) {
	cfg, err := LoadBytes([]byte(``))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Reputation.Upstream.Enabled {
		t.Fatal("expected upstream disabled by default")
	}
}

func TestUpstreamTI_AcceptsURLAndToken(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
reputation:
  upstream:
    enabled: true
    url: https://panel.example.com/api/csm/ti
    token_env: CSM_UPSTREAM_TOKEN
    cache_ttl_min: 30
    timeout_sec: 4
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Reputation.Upstream.URL != "https://panel.example.com/api/csm/ti" {
		t.Fatalf("URL not preserved")
	}
	if cfg.Reputation.Upstream.CacheTTLMin != 30 {
		t.Fatalf("cache TTL not preserved")
	}
	if cfg.Reputation.Upstream.TimeoutSec != 4 {
		t.Fatalf("timeout not preserved")
	}
}

func TestUpstreamTI_RejectsEnabledWithoutURL(t *testing.T) {
	_, err := LoadBytes([]byte(`
reputation:
  upstream:
    enabled: true
`))
	if err == nil {
		t.Fatal("expected error: upstream enabled but URL missing")
	}
}

func TestUpstreamTI_RejectsEnabledWithInvalidURL(t *testing.T) {
	_, err := LoadBytes([]byte(`
reputation:
  upstream:
    enabled: true
    url: panel.example.com/api/csm/ti
`))
	if err == nil {
		t.Fatal("expected error: upstream URL must include scheme and host")
	}
}

func TestUpstreamTI_RejectsInvalidCacheTTL(t *testing.T) {
	_, err := LoadBytes([]byte(`
reputation:
  upstream:
    enabled: true
    url: https://panel.example.com/api/csm/ti
    cache_ttl_min: -1
`))
	if err == nil {
		t.Fatal("expected error for negative cache_ttl_min")
	}
}

func TestUpstreamTI_RejectsInvalidTimeout(t *testing.T) {
	_, err := LoadBytes([]byte(`
reputation:
  upstream:
    enabled: true
    url: https://panel.example.com/api/csm/ti
    timeout_sec: -1
`))
	if err == nil {
		t.Fatal("expected error for negative timeout_sec")
	}
}

func TestUpstreamTI_DefaultsApply(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
reputation:
  upstream:
    enabled: true
    url: http://example.com/ti
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Reputation.Upstream.CacheTTLMin != 15 {
		t.Fatalf("expected default cache_ttl_min=15, got %d", cfg.Reputation.Upstream.CacheTTLMin)
	}
	if cfg.Reputation.Upstream.TimeoutSec != 5 {
		t.Fatalf("expected default timeout_sec=5, got %d", cfg.Reputation.Upstream.TimeoutSec)
	}
}

func TestVerdictCallback_DisabledByDefault(t *testing.T) {
	cfg, err := LoadBytes([]byte(``))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoResponse.VerdictCallback.Enabled {
		t.Fatal("expected verdict_callback disabled by default")
	}
}

func TestVerdictCallback_AcceptsURLAndSecret(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
    url: https://panel.example.com/api/csm/verdict
    hmac_secret_env: CSM_VERDICT_HMAC
    timeout_sec: 2
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoResponse.VerdictCallback.URL == "" {
		t.Fatal("URL not preserved")
	}
	if cfg.AutoResponse.VerdictCallback.TimeoutSec != 2 {
		t.Fatalf("timeout not preserved")
	}
}

func TestVerdictCallback_RejectsEnabledWithoutURL(t *testing.T) {
	_, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
`))
	if err == nil {
		t.Fatal("expected error: enabled but URL missing")
	}
}

func TestVerdictCallback_RejectsInvalidURL(t *testing.T) {
	_, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
    url: panel.example.com/api/csm/verdict
`))
	if err == nil {
		t.Fatal("expected error: URL must include scheme")
	}
}

func TestVerdictCallback_RejectsInvalidTimeout(t *testing.T) {
	_, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
    url: https://panel.example.com/v
    timeout_sec: -1
`))
	if err == nil {
		t.Fatal("expected error for negative timeout_sec")
	}
}
