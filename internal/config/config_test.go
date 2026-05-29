package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"gopkg.in/yaml.v3"
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
	if cfg.Thresholds.DomlogMaxFiles != 500 {
		t.Errorf("domlog_max_files = %d, want 500", cfg.Thresholds.DomlogMaxFiles)
	}
	if cfg.Thresholds.AccountScanMaxFiles != 10000 {
		t.Errorf("account_scan_max_files = %d, want 10000", cfg.Thresholds.AccountScanMaxFiles)
	}
	if cfg.Thresholds.CrontabBase64BlobMaxBytes != 16384 {
		t.Errorf("crontab_base64_blob_max_bytes = %d, want 16384", cfg.Thresholds.CrontabBase64BlobMaxBytes)
	}
	if cfg.Thresholds.DomlogTailLines != 500 {
		t.Errorf("domlog_tail_lines = %d, want 500", cfg.Thresholds.DomlogTailLines)
	}
	if cfg.Thresholds.DomlogMaxAgeMin != 30 {
		t.Errorf("domlog_max_age_min = %d, want 30", cfg.Thresholds.DomlogMaxAgeMin)
	}
	if cfg.Thresholds.MailLogTailLines != 500 {
		t.Errorf("mail_log_tail_lines = %d, want 500", cfg.Thresholds.MailLogTailLines)
	}
	if cfg.Thresholds.SyslogMessagesTailLines != 200 {
		t.Errorf("syslog_messages_tail_lines = %d, want 200", cfg.Thresholds.SyslogMessagesTailLines)
	}
	if cfg.Thresholds.HTTPFloodWindowMin != 5 {
		t.Errorf("http_flood_window_min = %d, want 5", cfg.Thresholds.HTTPFloodWindowMin)
	}
	if cfg.Thresholds.HTTPFloodThreshold != 0 {
		t.Errorf("http_flood_threshold = %d, want 0 (disabled by default)", cfg.Thresholds.HTTPFloodThreshold)
	}
	if cfg.Thresholds.HTTPUASpoofThreshold != 30 {
		t.Errorf("http_ua_spoof_threshold = %d, want 30", cfg.Thresholds.HTTPUASpoofThreshold)
	}
	if cfg.Thresholds.HTTPDistributedMinIPs != 0 {
		t.Errorf("http_distributed_min_ips = %d, want 0 (disabled when unset)", cfg.Thresholds.HTTPDistributedMinIPs)
	}
	if cfg.Alerts.MaxPerHour != 30 {
		t.Errorf("max_per_hour = %d, want 30", cfg.Alerts.MaxPerHour)
	}
	if cfg.StatePath != "/var/lib/csm/state" {
		t.Errorf("state_path = %q, want '/var/lib/csm/state'", cfg.StatePath)
	}
	// Challenge listener defaults to loopback so a fresh install never
	// exposes the PoW listener to the public internet without an
	// operator's deliberate opt-in via listen_addr: 0.0.0.0.
	if cfg.Challenge.ListenAddr != "127.0.0.1" {
		t.Errorf("challenge.listen_addr = %q, want '127.0.0.1'", cfg.Challenge.ListenAddr)
	}
	if cfg.Challenge.ListenPort != 8439 {
		t.Errorf("challenge.listen_port = %d, want 8439", cfg.Challenge.ListenPort)
	}
}

func TestChallengeListenAddrHonorsOperatorOverride(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "csm-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("challenge:\n  listen_addr: 0.0.0.0\n")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Challenge.ListenAddr != "0.0.0.0" {
		t.Errorf("operator override lost; got %q want 0.0.0.0", cfg.Challenge.ListenAddr)
	}
}

func TestDomlogMaxAgeMinHonorsOperatorOverride(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "csm-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("thresholds:\n  domlog_max_age_min: 90\n")
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := tmpFile.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Thresholds.DomlogMaxAgeMin != 90 {
		t.Errorf("domlog_max_age_min override = %d, want 90", cfg.Thresholds.DomlogMaxAgeMin)
	}
}

func TestIncidentAutoCloseDefaultThresholdsUseIncidentKinds(t *testing.T) {
	got := defaultIncidentAutoCloseThresholds()
	want := map[string]time.Duration{
		"mailbox_takeover":       24 * time.Hour,
		"credential_spray":       24 * time.Hour,
		"web_account_compromise": 7 * 24 * time.Hour,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaultIncidentAutoCloseThresholds = %#v, want %#v", got, want)
	}
	if _, ok := got["pam_failure"]; ok {
		t.Fatal("default thresholds must not include check name pam_failure")
	}
	if _, ok := got["wp_login_bruteforce"]; ok {
		t.Fatal("default thresholds must not include check name wp_login_bruteforce")
	}
	if _, ok := got["host_takeover"]; ok {
		t.Fatal("default thresholds must not auto-close host_takeover")
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

func TestConfig_SMTPProbeDefaultsAppliedWhenOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: \"\"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Thresholds.SMTPProbeThreshold != 100 {
		t.Errorf("SMTPProbeThreshold = %d, want 100", cfg.Thresholds.SMTPProbeThreshold)
	}
	if cfg.Thresholds.SMTPProbeWindowMin != 5 {
		t.Errorf("SMTPProbeWindowMin = %d, want 5", cfg.Thresholds.SMTPProbeWindowMin)
	}
	if cfg.Thresholds.SMTPProbeSuppressMin != 60 {
		t.Errorf("SMTPProbeSuppressMin = %d, want 60", cfg.Thresholds.SMTPProbeSuppressMin)
	}
	if cfg.Thresholds.SMTPProbeMaxTracked != 20000 {
		t.Errorf("SMTPProbeMaxTracked = %d, want 20000", cfg.Thresholds.SMTPProbeMaxTracked)
	}
}

func TestConfig_SMTPProbeThresholdExplicitZeroDisables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	body := []byte("thresholds:\n  smtp_probe_threshold: 0\n")
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Thresholds.SMTPProbeThreshold != 0 {
		t.Errorf("SMTPProbeThreshold = %d, want 0", cfg.Thresholds.SMTPProbeThreshold)
	}
	if cfg.Thresholds.SMTPProbeWindowMin != 5 {
		t.Errorf("SMTPProbeWindowMin = %d, want 5", cfg.Thresholds.SMTPProbeWindowMin)
	}
}

func TestConfig_SMTPProbeThresholdDropInZeroDisables(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confd, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(main, []byte("hostname: \"\"\n"), 0644); err != nil {
		t.Fatalf("write main: %v", err)
	}
	if err := os.WriteFile(filepath.Join(confd, "10-disable-smtp-probe.yaml"),
		[]byte("thresholds:\n  smtp_probe_threshold: 0\n"), 0644); err != nil {
		t.Fatalf("write drop-in: %v", err)
	}

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatalf("LoadWithDir: %v", err)
	}
	if cfg.Thresholds.SMTPProbeThreshold != 0 {
		t.Errorf("SMTPProbeThreshold = %d, want 0", cfg.Thresholds.SMTPProbeThreshold)
	}
}

func TestPackagedDefaultFirewallMatchesRuntimeDefaults(t *testing.T) {
	data, err := os.ReadFile("../../build/packaging/csm.yaml.default")
	if err != nil {
		t.Skipf("packaged default config not readable from this layout: %v", err)
	}
	cfg, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	want := firewall.DefaultConfig()

	if cfg.Firewall.ConnLimit != want.ConnLimit {
		t.Errorf("packaged conn_limit = %d, want runtime default %d", cfg.Firewall.ConnLimit, want.ConnLimit)
	}
	if len(cfg.Firewall.PortFlood) != len(want.PortFlood) {
		t.Fatalf("packaged port_flood len = %d, want %d", len(cfg.Firewall.PortFlood), len(want.PortFlood))
	}
	for i := range want.PortFlood {
		if cfg.Firewall.PortFlood[i] != want.PortFlood[i] {
			t.Errorf("packaged port_flood[%d] = %+v, want %+v", i, cfg.Firewall.PortFlood[i], want.PortFlood[i])
		}
	}
}

func TestPackagedDefaultFeatureSamplesPreserveEffectiveDefaults(t *testing.T) {
	data, err := os.ReadFile("../../build/packaging/csm.yaml.default")
	if err != nil {
		t.Skipf("packaged default config not readable from this layout: %v", err)
	}
	cfg, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}

	if cfg.MailLogs.Source != "auto" {
		t.Errorf("mail_logs.source = %q, want auto", cfg.MailLogs.Source)
	}
	if cfg.MailLogs.File != "" {
		t.Errorf("mail_logs.file = %q, want empty", cfg.MailLogs.File)
	}
	if want := []string{"postfix", "dovecot"}; !reflect.DeepEqual(cfg.MailLogs.Units, want) {
		t.Errorf("mail_logs.units = %v, want %v", cfg.MailLogs.Units, want)
	}

	direct := cfg.Detection.DirectSMTPEgress
	if direct.Enabled {
		t.Fatal("detection.direct_smtp_egress.enabled must stay false in the packaged default")
	}
	if direct.Backend != "auto" {
		t.Errorf("detection.direct_smtp_egress.backend = %q, want auto", direct.Backend)
	}
	if direct.DryRun == nil || !*direct.DryRun {
		t.Fatalf("detection.direct_smtp_egress.dry_run = %v, want explicit true", direct.DryRun)
	}
	if !cfg.DirectSMTPEgressDryRunEnabled() {
		t.Fatal("direct SMTP egress sample must remain effectively dry-run")
	}
	if want := []int{25, 465, 587}; !reflect.DeepEqual(direct.Ports, want) {
		t.Errorf("detection.direct_smtp_egress.ports = %v, want %v", direct.Ports, want)
	}

	if cfg.BPFEnforcement.Enabled {
		t.Fatal("bpf_enforcement.enabled must stay false in the packaged default")
	}
	if cfg.BPFEnforcement.DirectSMTPEgress {
		t.Fatal("bpf_enforcement.direct_smtp_egress must stay false in the packaged default")
	}
	if cfg.BPFEnforcement.VerdictCallback {
		t.Fatal("bpf_enforcement.verdict_callback must stay false in the packaged default")
	}
	if cfg.BPFEnforcement.DryRun == nil || !*cfg.BPFEnforcement.DryRun {
		t.Fatalf("bpf_enforcement.dry_run = %v, want explicit true", cfg.BPFEnforcement.DryRun)
	}
	if !cfg.BPFEnforcementDryRunEnabled() {
		t.Fatal("BPF enforcement sample must remain effectively dry-run")
	}
}

func TestProductionReferenceConfigExposesTunableThresholds(t *testing.T) {
	data, err := os.ReadFile("../../configs/csm.yaml.production.example")
	if err != nil {
		t.Skipf("production reference config not readable from this layout: %v", err)
	}

	cfg, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Thresholds.HTTPFloodWindowMin != 5 {
		t.Errorf("http_flood_window_min = %d, want 5", cfg.Thresholds.HTTPFloodWindowMin)
	}
	if cfg.Thresholds.HTTPFloodThreshold != 0 {
		t.Errorf("http_flood_threshold = %d, want 0", cfg.Thresholds.HTTPFloodThreshold)
	}
	if cfg.Thresholds.HTTPUASpoofThreshold != 30 {
		t.Errorf("http_ua_spoof_threshold = %d, want 30", cfg.Thresholds.HTTPUASpoofThreshold)
	}
	if cfg.Thresholds.HTTPDistributedMinIPs != 10 {
		t.Errorf("http_distributed_min_ips = %d, want 10", cfg.Thresholds.HTTPDistributedMinIPs)
	}
	if cfg.Reputation.BotVerifyEnabled == nil || !*cfg.Reputation.BotVerifyEnabled {
		t.Fatal("reputation.bot_verify_enabled must be explicitly true in production reference config")
	}
	if cfg.AutoResponse.MaxBlocksPerHour != DefaultMaxBlocksPerHour {
		t.Errorf("auto_response.max_blocks_per_hour = %d, want %d", cfg.AutoResponse.MaxBlocksPerHour, DefaultMaxBlocksPerHour)
	}

	var raw struct {
		Thresholds   map[string]yaml.Node `yaml:"thresholds"`
		Reputation   map[string]yaml.Node `yaml:"reputation"`
		AutoResponse map[string]yaml.Node `yaml:"auto_response"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	for _, key := range []string{
		"http_flood_threshold",
		"http_flood_window_min",
		"http_ua_spoof_threshold",
		"http_distributed_min_ips",
		"http_ua_scripting_enabled",
		"http_ua_headless_enabled",
		"http_ua_empty_enabled",
		"crontab_base64_blob_max_bytes",
	} {
		if _, ok := raw.Thresholds[key]; !ok {
			t.Errorf("production reference config missing thresholds.%s", key)
		}
	}
	if _, ok := raw.Reputation["bot_verify_enabled"]; !ok {
		t.Error("production reference config missing reputation.bot_verify_enabled")
	}
	if _, ok := raw.AutoResponse["max_blocks_per_hour"]; !ok {
		t.Error("production reference config missing auto_response.max_blocks_per_hour")
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
	if fromBytes.AutoResponse.MaxBlocksPerHour != DefaultMaxBlocksPerHour {
		t.Errorf("default AutoResponse.MaxBlocksPerHour = %d, want %d", fromBytes.AutoResponse.MaxBlocksPerHour, DefaultMaxBlocksPerHour)
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
    url: http://127.0.0.1:8080/ti
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

func TestUpstreamTI_RejectsNonLoopbackHTTP(t *testing.T) {
	_, err := LoadBytes([]byte(`
reputation:
  upstream:
    enabled: true
    url: http://panel.example.com/api/csm/ti
`))
	if err == nil {
		t.Fatal("expected error: non-loopback http upstream URL must be refused")
	}
}

func TestUpstreamTI_AcceptsLoopbackHTTP(t *testing.T) {
	for _, addr := range []string{
		"http://127.0.0.1:8080/ti",
		"http://localhost:8080/ti",
		"http://LOCALHOST:8080/ti",
		"http://[::1]:8080/ti",
	} {
		t.Run(addr, func(t *testing.T) {
			if _, err := LoadBytes([]byte(`
reputation:
  upstream:
    enabled: true
    url: ` + addr + `
`)); err != nil {
				t.Fatalf("loopback http should be accepted, got %v", err)
			}
		})
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
	t.Setenv("CSM_VERDICT_HMAC", "test-secret")
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

func TestVerdictCallback_AcceptsResponseSignatureOptOut(t *testing.T) {
	t.Setenv("CSM_VERDICT_HMAC", "test-secret")
	cfg, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
    url: https://panel.example.com/api/csm/verdict
    hmac_secret_env: CSM_VERDICT_HMAC
    require_response_signature: false
`))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.AutoResponse.VerdictCallback.RequireResponseSignature
	if got == nil || *got {
		t.Fatalf("RequireResponseSignature = %v, want explicit false", got)
	}
}

func TestVerdictCallback_RejectsEnabledWithoutSecret(t *testing.T) {
	t.Setenv("CSM_VERDICT_HMAC", "")
	_, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
    url: https://panel.example.com/api/csm/verdict
    hmac_secret_env: CSM_VERDICT_HMAC
`))
	if err == nil {
		t.Fatal("verdict callback with empty env secret must be rejected")
	}
}

func TestVerdictCallback_AllowsExplicitUnsignedOptIn(t *testing.T) {
	t.Setenv("CSM_VERDICT_HMAC", "")
	_, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
    url: https://panel.example.com/api/csm/verdict
    hmac_secret_env: CSM_VERDICT_HMAC
    allow_unsigned: true
`))
	if err != nil {
		t.Fatalf("explicit allow_unsigned should permit empty secret, got %v", err)
	}
}

func TestVerdictCallback_RejectsEnabledWithoutAnySecretConfig(t *testing.T) {
	_, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
    url: https://panel.example.com/api/csm/verdict
`))
	if err == nil {
		t.Fatal("verdict callback without hmac_secret or hmac_secret_env must be rejected")
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

func TestVerdictCallback_RejectsURLWithoutHost(t *testing.T) {
	_, err := LoadBytes([]byte(`
auto_response:
  verdict_callback:
    enabled: true
    url: https:///api/csm/verdict
`))
	if err == nil {
		t.Fatal("expected error: URL must include host")
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

func TestConfig_DirectSMTPEgressRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	yaml := []byte(`hostname: ""
detection:
  direct_smtp_egress:
    enabled: true
    backend: bpf
    dry_run: false
    ports: [25, 465, 587, 2525]
`)
	if err := os.WriteFile(path, yaml, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Detection.DirectSMTPEgress.Enabled {
		t.Errorf("Enabled: want true")
	}
	if cfg.Detection.DirectSMTPEgress.Backend != "bpf" {
		t.Errorf("Backend: %q", cfg.Detection.DirectSMTPEgress.Backend)
	}
	if cfg.Detection.DirectSMTPEgress.DryRun == nil || *cfg.Detection.DirectSMTPEgress.DryRun {
		t.Errorf("DryRun: want explicit false, got %v", cfg.Detection.DirectSMTPEgress.DryRun)
	}
	if len(cfg.Detection.DirectSMTPEgress.Ports) != 4 || cfg.Detection.DirectSMTPEgress.Ports[3] != 2525 {
		t.Errorf("Ports: %+v", cfg.Detection.DirectSMTPEgress.Ports)
	}
}

func TestConfig_DirectSMTPEgressDefaultPortsAreStandard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	yaml := []byte(`hostname: ""
detection:
  direct_smtp_egress:
    enabled: true
`)
	if err := os.WriteFile(path, yaml, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []int{25, 465, 587}
	got := cfg.Detection.DirectSMTPEgress.Ports
	if len(got) != len(want) {
		t.Fatalf("default ports len: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("Ports[%d]: want %d, got %d", i, p, got[i])
		}
	}
	if cfg.Detection.DirectSMTPEgress.Backend != "auto" {
		t.Errorf("default Backend: want auto, got %q", cfg.Detection.DirectSMTPEgress.Backend)
	}
}

func TestConfig_DirectSMTPEgressDryRunDefaultsTrue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	yaml := []byte(`hostname: ""
detection:
  direct_smtp_egress:
    enabled: true
`)
	if err := os.WriteFile(path, yaml, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DirectSMTPEgressDryRunEnabled() {
		t.Errorf("DryRun should default to true when omitted (safety default)")
	}
}

func TestConfig_DirectSMTPEgressRejectsInvalidPort(t *testing.T) {
	_, err := LoadBytes([]byte(`
detection:
  direct_smtp_egress:
    enabled: true
    ports: [25, 65561]
`))
	if err == nil {
		t.Fatal("expected invalid direct_smtp_egress port to fail config load")
	}
}

func TestConfig_DirectSMTPEgressRejectsInvalidBackend(t *testing.T) {
	_, err := LoadBytes([]byte(`
detection:
  direct_smtp_egress:
    enabled: true
    backend: sideways
`))
	if err == nil {
		t.Fatal("expected invalid direct_smtp_egress backend to fail config load")
	}
}

func TestConfig_BPFEnforcementRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	yaml := []byte(`hostname: ""
detection:
  direct_smtp_egress:
    enabled: true
bpf_enforcement:
  enabled: true
  dry_run: false
  direct_smtp_egress: true
  verdict_callback: false
`)
	if err := os.WriteFile(path, yaml, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.BPFEnforcement.Enabled {
		t.Errorf("Enabled: want true")
	}
	if cfg.BPFEnforcement.DryRun == nil || *cfg.BPFEnforcement.DryRun {
		t.Errorf("DryRun: want explicit false; got %v", cfg.BPFEnforcement.DryRun)
	}
	if !cfg.BPFEnforcement.DirectSMTPEgress {
		t.Errorf("DirectSMTPEgress: want true")
	}
	if cfg.BPFEnforcement.VerdictCallback {
		t.Errorf("VerdictCallback: want false")
	}
}

func TestConfig_BPFEnforcementDryRunDefaultsTrue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	yaml := []byte(`hostname: ""
detection:
  direct_smtp_egress:
    enabled: true
bpf_enforcement:
  enabled: true
  direct_smtp_egress: true
`)
	if err := os.WriteFile(path, yaml, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.BPFEnforcementDryRunEnabled() {
		t.Errorf("DryRun should default true (safety) when omitted")
	}
}

func TestConfig_BPFEnforcementDryRunExplicitTrueUnmarshalsPointer(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
bpf_enforcement:
  dry_run: true
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.BPFEnforcement.DryRun == nil {
		t.Fatal("bpf_enforcement.dry_run=true must unmarshal to a non-nil pointer")
	}
	if !*cfg.BPFEnforcement.DryRun {
		t.Fatal("bpf_enforcement.dry_run=true must preserve true")
	}
}

func TestConfig_BPFEnforcementDryRunAnyLayerWins(t *testing.T) {
	cfg := &Config{}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	cfg.Detection.DirectSMTPEgress.Enabled = true
	falseValue := false
	cfg.AutoResponse.DryRun = &falseValue
	cfg.Detection.DirectSMTPEgress.DryRun = &falseValue
	cfg.BPFEnforcement.DryRun = &falseValue
	if cfg.BPFEnforcementDryRunEnabled() {
		t.Fatal("all three dry_run layers explicit false should allow live enforcement")
	}

	trueValue := true
	cfg.Detection.DirectSMTPEgress.DryRun = &trueValue
	if !cfg.BPFEnforcementDryRunEnabled() {
		t.Fatal("detector dry_run=true must force BPF dry-run")
	}
	cfg.Detection.DirectSMTPEgress.DryRun = &falseValue
	cfg.AutoResponse.DryRun = &trueValue
	if !cfg.BPFEnforcementDryRunEnabled() {
		t.Fatal("global auto_response dry_run=true must force BPF dry-run")
	}
}

func TestConfig_BPFEnforcementDefaultsAllOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: \"\"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BPFEnforcement.Enabled {
		t.Errorf("default Enabled must be false")
	}
	if cfg.BPFEnforcement.DirectSMTPEgress {
		t.Errorf("default DirectSMTPEgress must be false")
	}
}

func TestBotVerifyEnabled_DefaultTrue(t *testing.T) {
	cfg := &Config{}
	if !cfg.BotVerifyEnabled() {
		t.Error("default must be true")
	}
}

func TestBotVerifyEnabled_ExplicitFalse(t *testing.T) {
	f := false
	cfg := &Config{}
	cfg.Reputation.BotVerifyEnabled = &f
	if cfg.BotVerifyEnabled() {
		t.Error("explicit false must be honored")
	}
}
