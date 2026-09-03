package config

import (
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// egressWarnings returns the outbound lockout warnings only, so a test can
// assert an exact count without the inbound web UI or sshd checks leaking in.
func egressWarnings(cfg *Config) []ValidationResult {
	var out []ValidationResult
	for _, r := range Validate(cfg) {
		if r.Level != "warn" {
			continue
		}
		if r.Field == "firewall.tcp_out" || r.Field == "firewall.tcp6_out" {
			out = append(out, r)
		}
	}
	return out
}

// egressTestConfig enables the firewall with an egress policy that allows
// only HTTPS, so anything else the daemon dials has to be warned about.
func egressTestConfig(tcpOut []int) *Config {
	cfg := lockoutTestConfig(&firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{22, 443, 9443},
		TCPOut:        tcpOut,
		ConnRateLimit: 200,
	})
	return cfg
}

func assertWarnMentions(t *testing.T, results []ValidationResult, field string, parts ...string) {
	t.Helper()
	for _, r := range results {
		if r.Field != field {
			continue
		}
		ok := true
		for _, p := range parts {
			if !strings.Contains(r.Message, p) {
				ok = false
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("no %s warning mentioning %v in %v", field, parts, results)
}

// A phpanel agent host went silent to its control plane because the shipped
// tcp_out did not include the panel port: every delivery failed with
// "connection refused" while the host looked healthy locally.
func TestValidateEgressWebhookPort(t *testing.T) {
	t.Run("explicit port missing from tcp_out warns", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api/csm/findings"
		assertWarnMentions(t, egressWarnings(cfg), "firewall.tcp_out", "alerts.webhook.url", "8443", "panel.example.com")
	})

	t.Run("https defaults to 443", func(t *testing.T) {
		cfg := egressTestConfig([]int{80})
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://panel.example.com/api"
		assertWarnMentions(t, egressWarnings(cfg), "firewall.tcp_out", "alerts.webhook.url", "443")
	})

	t.Run("http defaults to 80", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "http://panel.example.com/api"
		assertWarnMentions(t, egressWarnings(cfg), "firewall.tcp_out", "alerts.webhook.url", "80")
	})

	t.Run("port present is silent", func(t *testing.T) {
		cfg := egressTestConfig([]int{443, 8443})
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api"
		if got := egressWarnings(cfg); len(got) != 0 {
			t.Errorf("allowed port must not warn, got %v", got)
		}
	})

	t.Run("disabled webhook is silent", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Alerts.Webhook.Enabled = false
		cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api"
		if got := egressWarnings(cfg); len(got) != 0 {
			t.Errorf("a disabled feature dials nothing, got %v", got)
		}
	})

	t.Run("disabled firewall is silent", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Firewall.Enabled = false
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api"
		if got := egressWarnings(cfg); len(got) != 0 {
			t.Errorf("a disabled firewall drops nothing, got %v", got)
		}
	})

	t.Run("unparseable URL is left to the URL validator", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "://not a url"
		if got := egressWarnings(cfg); len(got) != 0 {
			t.Errorf("no port can be derived, so no egress warning, got %v", got)
		}
	})
}

// The output chain accepts loopback before any port rule, so a local
// destination can never be refused by tcp_out.
func TestValidateEgressSkipsLoopback(t *testing.T) {
	for _, u := range []string{
		"https://127.0.0.1:8443/api",
		"http://localhost:8080/api",
		"http://[::1]:9/api",
		"http://127.5.5.5:11334",
	} {
		t.Run(u, func(t *testing.T) {
			cfg := egressTestConfig([]int{443})
			cfg.Alerts.Webhook.Enabled = true
			cfg.Alerts.Webhook.URL = u
			if got := egressWarnings(cfg); len(got) != 0 {
				t.Errorf("loopback destination must not warn, got %v", got)
			}
		})
	}
}

// An empty tcp_out and udp_out means the output chain is accept-all, so no
// egress warning applies no matter what is dialed.
func TestValidateEgressSilentWithoutOutboundPolicy(t *testing.T) {
	cfg := egressTestConfig(nil)
	cfg.Firewall.UDPOut = nil
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api"
	if got := egressWarnings(cfg); len(got) != 0 {
		t.Errorf("no outbound policy means nothing is refused, got %v", got)
	}
}

func TestValidateEgressIPv6(t *testing.T) {
	t.Run("explicit tcp6_out missing the port warns", func(t *testing.T) {
		cfg := egressTestConfig([]int{443, 8443})
		cfg.Firewall.IPv6 = true
		cfg.Firewall.TCP6Out = []int{443}
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api"
		got := egressWarnings(cfg)
		assertWarnMentions(t, got, "firewall.tcp6_out", "8443", "alerts.webhook.url")
		if len(got) != 1 {
			t.Errorf("tcp_out allows the port, so only the IPv6 warning is due, got %v", got)
		}
	})

	t.Run("inherited tcp6_out reports through tcp_out only", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Firewall.IPv6 = true
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api"
		got := egressWarnings(cfg)
		assertWarnMentions(t, got, "firewall.tcp_out", "8443")
		if len(got) != 1 {
			t.Errorf("an inherited tcp6_out is the same policy, one warning expected, got %v", got)
		}
	})

	t.Run("IPv6 not managed skips tcp6_out", func(t *testing.T) {
		cfg := egressTestConfig([]int{443, 8443})
		cfg.Firewall.IPv6 = false
		cfg.Firewall.TCP6Out = []int{443}
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api"
		if got := egressWarnings(cfg); len(got) != 0 {
			t.Errorf("unmanaged IPv6 egress is accepted wholesale, got %v", got)
		}
	})

	t.Run("literal IPv4 destination never warns on tcp6_out", func(t *testing.T) {
		cfg := egressTestConfig([]int{443, 8443})
		cfg.Firewall.IPv6 = true
		cfg.Firewall.TCP6Out = []int{443}
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://198.51.100.10:8443/api"
		if got := egressWarnings(cfg); len(got) != 0 {
			t.Errorf("an IPv4 literal is never dialed over IPv6, got %v", got)
		}
	})

	t.Run("literal IPv6 destination warns on tcp6_out even when inherited", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Firewall.IPv6 = true
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://[2001:db8::10]:8443/api"
		got := egressWarnings(cfg)
		assertWarnMentions(t, got, "firewall.tcp6_out", "8443")
		if len(got) != 1 {
			t.Errorf("an IPv6 literal is never dialed over IPv4, one warning expected, got %v", got)
		}
	})

	t.Run("IPv4 bypass when only IPv6 egress is restricted", func(t *testing.T) {
		cfg := egressTestConfig(nil)
		cfg.Firewall.UDPOut = nil
		cfg.Firewall.IPv6 = true
		cfg.Firewall.TCP6Out = []int{443}
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api"
		got := egressWarnings(cfg)
		assertWarnMentions(t, got, "firewall.tcp6_out", "8443")
		if len(got) != 1 {
			t.Errorf("IPv4 egress is accepted wholesale in this shape, got %v", got)
		}
	})
}

// smtp_block installs a per-UID accept for the mail ports ahead of the port
// rules, and the daemon runs as root, so its own alert mail still leaves even
// when tcp_out omits the port.
func TestValidateEgressSMTPBlockAllowsRootMail(t *testing.T) {
	cfg := egressTestConfig([]int{443})
	cfg.Alerts.Email.SMTP = "mail.example.com:587"
	cfg.Firewall.SMTPBlock = true
	cfg.Firewall.SMTPPorts = []int{25, 465, 587}
	if got := egressWarnings(cfg); len(got) != 0 {
		t.Errorf("root reaches smtp_block ports regardless of tcp_out, got %v", got)
	}

	cfg.Firewall.SMTPBlock = false
	assertWarnMentions(t, egressWarnings(cfg), "firewall.tcp_out", "alerts.email.smtp", "587")
}

// Every outbound endpoint the daemon reads from its own config is covered,
// so a host whose findings, verdicts or intel silently stop flowing is
// caught before the firewall applies.
func TestValidateEgressCoversConfiguredEndpoints(t *testing.T) {
	const host = "svc.example.com"
	cases := []struct {
		label string
		port  int
		apply func(cfg *Config)
	}{
		{"alerts.heartbeat.url", 8081, func(cfg *Config) {
			cfg.Alerts.Heartbeat.Enabled = true
			cfg.Alerts.Heartbeat.URL = "https://svc.example.com:8081/ping"
		}},
		{"alerts.audit_log.syslog.address", 6514, func(cfg *Config) {
			cfg.Alerts.AuditLog.Syslog.Enabled = true
			cfg.Alerts.AuditLog.Syslog.Network = "tls"
			cfg.Alerts.AuditLog.Syslog.Address = "svc.example.com:6514"
		}},
		{"auto_response.verdict_callback.url", 8082, func(cfg *Config) {
			cfg.AutoResponse.VerdictCallback.Enabled = true
			cfg.AutoResponse.VerdictCallback.URL = "https://svc.example.com:8082/verdict"
		}},
		{"reputation.upstream.url", 8083, func(cfg *Config) {
			cfg.Reputation.Upstream.Enabled = true
			cfg.Reputation.Upstream.URL = "https://svc.example.com:8083/api/csm/ti"
		}},
		{"reputation.rspamd.url", 11334, func(cfg *Config) {
			cfg.Reputation.Rspamd.Enabled = true
			cfg.Reputation.Rspamd.URL = "http://svc.example.com:11334"
		}},
		{"reputation.report.targets[0].url", 8084, func(cfg *Config) {
			cfg.Reputation.Report.Enabled = true
			cfg.Reputation.Report.Targets = append(cfg.Reputation.Report.Targets, struct {
				Name      string `yaml:"name"`
				URL       string `yaml:"url"`
				Transport string `yaml:"transport"`
				NodeID    string `yaml:"node_id"`
				KeyID     string `yaml:"key_id"`
				KeyEnv    string `yaml:"key_env"`
				TokenEnv  string `yaml:"token_env"`
			}{Name: "central", URL: "https://svc.example.com:8084/reports"})
		}},
		{"reputation.central.set_url", 8085, func(cfg *Config) {
			cfg.Reputation.Central.Enabled = true
			cfg.Reputation.Central.SetURL = "https://svc.example.com:8085/set"
		}},
		{"signatures.update_url", 8086, func(cfg *Config) {
			cfg.Signatures.UpdateURL = "https://svc.example.com:8086/rules.yml"
		}},
		{"signatures.yara_forge.download_url", 8087, func(cfg *Config) {
			cfg.Signatures.YaraForge.Enabled = true
			cfg.Signatures.YaraForge.DownloadURL = "https://svc.example.com:8087/{tier}/{version}.zip"
		}},
		{"sentry.dsn", 8088, func(cfg *Config) {
			cfg.Sentry.Enabled = true
			cfg.Sentry.DSN = "https://public@svc.example.com:8088/42"
		}},
		{"updates.github_api_url", 8089, func(cfg *Config) {
			cfg.Updates.GitHubAPIURL = "https://svc.example.com:8089/releases/latest"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			cfg := egressTestConfig([]int{443})
			tc.apply(cfg)
			assertWarnMentions(t, egressWarnings(cfg), "firewall.tcp_out", tc.label, strconv.Itoa(tc.port), host)
		})
	}
}

// Syslog over UDP is not a TCP dial and must not produce a tcp_out warning.
func TestValidateEgressIgnoresUDPSyslog(t *testing.T) {
	cfg := egressTestConfig([]int{443})
	cfg.Alerts.AuditLog.Syslog.Enabled = true
	cfg.Alerts.AuditLog.Syslog.Network = "udp"
	cfg.Alerts.AuditLog.Syslog.Address = "svc.example.com:514"
	if got := egressWarnings(cfg); len(got) != 0 {
		t.Errorf("udp syslog is not governed by tcp_out, got %v", got)
	}
}

// Threat feeds, AbuseIPDB, MaxMind, YARA Forge, bot ranges and the release
// check all live on vendor HTTPS endpoints that are not configurable, so
// dropping 443 from tcp_out silences all of them at once.
func TestValidateEgressBuiltInHTTPS(t *testing.T) {
	cfg := egressTestConfig([]int{80})
	got := egressWarnings(cfg)
	assertWarnMentions(t, got, "firewall.tcp_out", "443", "built-in")
	if len(got) != 1 {
		t.Errorf("one warning for the built-in endpoints, got %v", got)
	}

	cfg = egressTestConfig([]int{443})
	if got := egressWarnings(cfg); len(got) != 0 {
		t.Errorf("443 allowed must be silent, got %v", got)
	}
}

// A conf.d fragment can declare the ports its owning service needs outbound.
// The list is checked, never merged, so a later fragment or the operator's
// policy dropping the port is reported instead of discovered from a silent
// node.
func TestValidateFirewallRequiredTCPOut(t *testing.T) {
	t.Run("declared port missing from tcp_out warns", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Firewall.RequiredTCPOut = []int{9100}
		assertWarnMentions(t, egressWarnings(cfg), "firewall.tcp_out", "required_tcp_out", "9100")
	})

	t.Run("declared port present is silent", func(t *testing.T) {
		cfg := egressTestConfig([]int{443, 9100})
		cfg.Firewall.RequiredTCPOut = []int{9100}
		if got := egressWarnings(cfg); len(got) != 0 {
			t.Errorf("allowed required port must not warn, got %v", got)
		}
	})

	t.Run("explicit tcp6_out missing the port warns", func(t *testing.T) {
		cfg := egressTestConfig([]int{443, 9100})
		cfg.Firewall.IPv6 = true
		cfg.Firewall.TCP6Out = []int{443}
		cfg.Firewall.RequiredTCPOut = []int{9100}
		assertWarnMentions(t, egressWarnings(cfg), "firewall.tcp6_out", "required_tcp_out", "9100")
	})

	t.Run("declared port is never merged into the policy", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Firewall.RequiredTCPOut = []int{9100}
		if containsPort(cfg.Firewall.TCPOut, 9100) {
			t.Error("required_tcp_out must stay a check, not an allow rule")
		}
	})

	t.Run("out of range value is an error", func(t *testing.T) {
		cfg := egressTestConfig([]int{443})
		cfg.Firewall.RequiredTCPOut = []int{70000}
		if _, ok := findResult(Validate(cfg), "error", "firewall.required_tcp_out"); !ok {
			t.Errorf("port 70000 cannot select a service; results=%v", Validate(cfg))
		}
	})
}
