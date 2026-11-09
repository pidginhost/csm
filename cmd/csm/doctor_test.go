package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/webui"
)

func validDoctorConfig() *config.Config {
	cfg := &config.Config{Hostname: "host.example.com"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"admin@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.MaxPerHour = 10
	cfg.InfraIPs = []string{"198.51.100.10"}
	return cfg
}

func TestDoctor_FormatHumanIncludesSuggestions(t *testing.T) {
	d := DoctorReport{
		Checks: []DoctorCheck{
			{Name: "config valid", Status: "fail", Message: "missing infra_ips", Fix: "add infra_ips: [...] under csm.yaml"},
			{Name: "watchers attached", Status: "ok"},
		},
	}
	out := d.Human()
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "Fix:") {
		t.Fatalf("expected FAIL and Fix: in human output, got %s", out)
	}
}

func TestDoctor_CollapseFails(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "warn"},
		{Name: "c", Status: "fail"},
	}
	if got := collapseDoctor(checks); got != "fail" {
		t.Fatalf("expected fail, got %s", got)
	}
}

func TestDoctor_CollapseWarn(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "warn"},
	}
	if got := collapseDoctor(checks); got != "warn" {
		t.Fatalf("expected warn, got %s", got)
	}
}

func TestDoctor_CollapseOK(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "ok"},
	}
	if got := collapseDoctor(checks); got != "ok" {
		t.Fatalf("expected ok, got %s", got)
	}
}

func TestBuildDoctorReport_ConfigErrorIsJSONFriendly(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return nil, errors.New("bad yaml") },
		func() ([]byte, error) {
			t.Fatal("status should not be read when config is invalid")
			return nil, nil
		},
		integrityOK,
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if len(report.Checks) != 1 || report.Checks[0].Name != "config valid" || report.Checks[0].Status != "fail" {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
	if _, err := json.Marshal(report); err != nil {
		t.Fatalf("report must remain JSON-encodable: %v", err)
	}
}

func TestBuildDoctorReport_InvalidStatusJSONFails(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return []byte("{"), nil },
		integrityOK,
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if !strings.Contains(report.Human(), "health snapshot available") {
		t.Fatalf("expected health snapshot failure, got %s", report.Human())
	}
}

func TestBuildDoctorReport_MissingSnapshotFails(t *testing.T) {
	payload, err := json.Marshal(control.StatusResult{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return payload, nil },
		integrityOK,
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
}

func TestBuildDoctorReport_EmptyWatcherRegistryFails(t *testing.T) {
	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return payload, nil },
		integrityOK,
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if !strings.Contains(report.Human(), "watchers registered") {
		t.Fatalf("expected watcher registry failure, got %s", report.Human())
	}
}

func TestBuildDoctorReportIncludesConfigWarnings(t *testing.T) {
	// Pin the SSH probe at a path with no config so this test sees only the
	// web UI warning it is about, on any host.
	defer config.SetSSHDConfigPath(filepath.Join(t.TempDir(), "absent"))()

	cfg := validDoctorConfig()
	cfg.WebUI.Enabled = true
	cfg.WebUI.Listen = "0.0.0.0:9443"
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "operator", Token: "secret", Scope: "admin"}}
	cfg.Firewall = &firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{22, 443},
		ConnRateLimit: 200,
	}
	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}

	report := buildDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func() ([]byte, error) { return payload, nil },
		integrityOK,
	)
	if report.OverallStatus != "warn" {
		t.Fatalf("OverallStatus = %q, want warn\n%s", report.OverallStatus, report.Human())
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "config: firewall.tcp_in" && check.Status == "warn" && strings.Contains(check.Message, "9443") {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor omitted firewall lockout warning: %+v", report.Checks)
	}
}

// doctor is the tool operators run before enabling the firewall, so the SSH
// reachability probe has to reach the report, not just `csm validate --deep`.
func TestBuildDoctorReportIncludesSSHLockoutWarning(t *testing.T) {
	sshdPath := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(sshdPath, []byte("Port 22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer config.SetSSHDConfigPath(sshdPath)()

	cfg := validDoctorConfig()
	cfg.Firewall = &firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{80, 443},
		ConnRateLimit: 200,
	}
	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}

	report := buildDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func() ([]byte, error) { return payload, nil },
		integrityOK,
	)
	for _, check := range report.Checks {
		if check.Name == "config: firewall.tcp_in" && check.Status == "warn" && strings.Contains(check.Message, "sshd") {
			return
		}
	}
	t.Fatalf("doctor omitted the SSH lockout warning: %+v", report.Checks)
}

func TestBuildDoctorReportStopsOnConfigValidationError(t *testing.T) {
	cfg := validDoctorConfig()
	cfg.Hostname = ""
	report := buildDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func() ([]byte, error) {
			t.Fatal("daemon status must not be read after config validation fails")
			return nil, nil
		},
		integrityOK,
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "config: hostname" && check.Status == "fail" {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor omitted validation error: %+v", report.Checks)
	}
}

func TestBuildChallengeDoctorReport_DisabledWarnsWithoutLiveChecks(t *testing.T) {
	called := false
	report := buildChallengeDoctorReport(
		func() (*config.Config, error) { return &config.Config{}, nil },
		func(*config.Config) []DoctorCheck {
			called = true
			return nil
		},
		func(*config.Config) DoctorCheck {
			called = true
			return DoctorCheck{}
		},
	)
	if called {
		t.Fatal("disabled challenge should not probe webserver or gate")
	}
	if report.OverallStatus != "warn" {
		t.Fatalf("OverallStatus = %q, want warn", report.OverallStatus)
	}
}

func TestBuildChallengeDoctorReport_OK(t *testing.T) {
	cert := writeDoctorTempFile(t, "cert.pem")
	key := writeDoctorTempFile(t, "key.pem")
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PublicURL = "https://server.example.com:8439/challenge"
	cfg.Challenge.TLSCert = cert
	cfg.Challenge.TLSKey = key
	cfg.Challenge.PortGate.Enabled = true

	report := buildChallengeDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func(*config.Config) []DoctorCheck {
			return []DoctorCheck{
				{Name: "challenge webserver snippet", Status: "ok"},
				{Name: "challenge webserver configtest", Status: "ok"},
			}
		},
		func(*config.Config) DoctorCheck {
			return DoctorCheck{Name: "challenge gate endpoint", Status: "ok"}
		},
	)
	if report.OverallStatus != "ok" {
		t.Fatalf("OverallStatus = %q, want ok\n%s", report.OverallStatus, report.Human())
	}
}

func TestBuildChallengeDoctorReport_PublicURLFailureIsFatal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PortGate.Enabled = true

	report := buildChallengeDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func(*config.Config) []DoctorCheck { return nil },
		func(*config.Config) DoctorCheck { return DoctorCheck{Name: "challenge gate endpoint", Status: "ok"} },
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if !strings.Contains(report.Human(), "challenge public URL") {
		t.Fatalf("expected public URL failure, got %s", report.Human())
	}
}

func challengeDoctorReportFor(cfg *config.Config) DoctorReport {
	return buildChallengeDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func(*config.Config) []DoctorCheck {
			return []DoctorCheck{{Name: "challenge webserver snippet", Status: "ok"}}
		},
		func(*config.Config) DoctorCheck { return DoctorCheck{Name: "challenge gate endpoint", Status: "ok"} },
	)
}

func requireAllChallengeChecksOK(t *testing.T, report DoctorReport) {
	t.Helper()
	for _, c := range report.Checks {
		if c.Status != "ok" {
			t.Fatalf("%s = %s, want ok\n%s", c.Name, c.Status, report.Human())
		}
	}
}

func TestBuildChallengeDoctorReport_LoopbackListenerBehindLocalProxyFails(t *testing.T) {
	// Local accounts connect from loopback too, so a proxy on this host must
	// use the socket; trusting the loopback listener's address is refused.
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "127.0.0.1"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PublicURL = "https://challenge.example.com/challenge"
	cfg.Challenge.TrustedProxies = []string{"127.0.0.1"}

	pinDoctorHost(t)
	report := challengeDoctorReportFor(cfg)
	if report.OverallStatus != "fail" {
		t.Fatalf("overall = %s, want fail\n%s", report.OverallStatus, report.Human())
	}
	if c := findCheck(t, report, "challenge trusted proxies"); c.Status != "fail" {
		t.Fatalf("trusted proxies check = %+v, want fail", c)
	}
	for _, c := range report.Checks {
		if c.Name == "challenge public URL" {
			if c.Status != "fail" || !strings.Contains(c.Message, config.ChallengeSocketExample) {
				t.Fatalf("public URL check = %s %q, want fail pointing at the socket", c.Status, c.Message)
			}
			return
		}
	}
	t.Fatal("no challenge public URL check")
}

func TestBuildChallengeDoctorReport_RemoteProxyServesTLS(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PublicURL = "https://challenge.example.com/challenge"
	cfg.Challenge.TrustedProxies = []string{"192.0.2.10"}

	requireAllChallengeChecksOK(t, challengeDoctorReportFor(cfg))
}

func TestChallengeProxyChecksNeedAValidProxy(t *testing.T) {
	for _, tc := range []struct {
		name, scheme      string
		trusted           []string
		wantTLS, wantGate string
	}{
		{"HTTPS behind proxy", "https", []string{"192.0.2.10"}, "ok", "ok"},
		{"plain HTTP public URL behind proxy", "http", []string{"192.0.2.10"}, "warn", "ok"},
		{"blank proxies", "https", []string{"", "  "}, "fail", "warn"},
		{"invalid proxy", "https", []string{"not-an-ip"}, "fail", "warn"},
		{"invalid CIDR", "https", []string{"192.0.2.0/99"}, "fail", "warn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Challenge.ListenAddr = "0.0.0.0"
			cfg.Challenge.ListenPort = 8439
			cfg.Challenge.PublicURL = tc.scheme + "://challenge.example.com:8439/challenge"
			cfg.Challenge.TrustedProxies = tc.trusted
			if check := challengeTLSCheck(cfg); check.Status != tc.wantTLS {
				t.Errorf("TLS = %+v, want %s", check, tc.wantTLS)
			}
			if check := challengePortGateCheck(cfg); check.Status != tc.wantGate {
				t.Errorf("port gate = %+v, want %s", check, tc.wantGate)
			}
		})
	}
}

func TestChallengeTLSFailsWhenPublicURLTargetsPlainListener(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.20"), net.ParseIP("2001:db8::20")}, nil
	}))
	for _, tc := range []struct{ listen, public string }{
		{"192.0.2.20", "https://192.0.2.20:8439/challenge"},
		{"0.0.0.0", "https://192.0.2.20:8439/challenge"},
		{"2001:db8::20", "https://[2001:db8::20]:8439/challenge"},
		{"::", "https://[2001:db8::20]:8439/challenge"},
		{"::ffff:192.0.2.20", "https://192.0.2.20:8439/challenge"},
	} {
		t.Run(tc.listen, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Challenge.ListenAddr = tc.listen
			cfg.Challenge.ListenPort = 8439
			cfg.Challenge.PublicURL = tc.public
			cfg.Challenge.TrustedProxies = []string{"192.0.2.10"}
			if check := challengeTLSCheck(cfg); check.Status != "fail" {
				t.Fatalf("TLS = %+v; HTTPS targets the plain HTTP listener", check)
			}
			if check := challengePortGateCheck(cfg); check.Status != "warn" {
				t.Fatalf("port gate = %+v; browsers reach the listener directly", check)
			}
		})
	}
}

func TestChallengePortGateTreatsPlainHTTPURLOnPort80AsDirect(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.20")}, nil
	}))
	cfg := &config.Config{}
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 80
	cfg.Challenge.PublicURL = "http://192.0.2.20/challenge"
	cfg.Challenge.TrustedProxies = []string{"192.0.2.10"}
	if check := challengePortGateCheck(cfg); check.Status != "warn" {
		t.Fatalf("port gate = %+v; browsers reach the listener directly", check)
	}
}

func TestChallengeTLSDoesNotMistakeProxyForListener(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.20"), net.ParseIP("2001:db8::20")}, nil
	}))
	for _, tc := range []struct{ listen, public string }{
		{"192.0.2.20", "https://192.0.2.20/challenge"},
		{"0.0.0.0", "https://192.0.2.30:8439/challenge"},
		{"0.0.0.0", "https://[2001:db8::20]:8439/challenge"},
	} {
		t.Run(tc.public, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Challenge.ListenAddr = tc.listen
			cfg.Challenge.ListenPort = 8439
			cfg.Challenge.PublicURL = tc.public
			cfg.Challenge.TrustedProxies = []string{"192.0.2.10"}
			if check := challengeTLSCheck(cfg); check.Status != "ok" {
				t.Fatalf("TLS = %+v; the proxy serves HTTPS", check)
			}
		})
	}
}

func TestBuildChallengeDoctorReport_DirectListenerStillNeedsTLSAndGate(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PublicURL = "https://challenge.example.com/challenge"

	got := map[string]string{}
	for _, c := range challengeDoctorReportFor(cfg).Checks {
		got[c.Name] = c.Status
	}
	if got["challenge TLS"] != "fail" || got["challenge port gate"] != "warn" {
		t.Fatalf("TLS = %q, port gate = %q; want fail and warn", got["challenge TLS"], got["challenge port gate"])
	}
}

func TestChallengeGateProbeReachesLiveListener(t *testing.T) {
	// The trusted-proxy case moved to the socket: the server now refuses to
	// trust loopback (TestChallengeGateProbeReachesSocketListener).
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "127.0.0.1"
	srv := challenge.New(cfg, nil)
	ln, err := srv.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Shutdown)
	cfg.Challenge.ListenPort = ln.Addr().(*net.TCPAddr).Port

	if got := defaultChallengeGateProbe(cfg); got.Status != "ok" {
		t.Fatalf("probe = %+v, want ok", got)
	}
}

func TestChallengeGateProbeURLUsesConfiguredTLS(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.ListenAddr = "::"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.TLSCert = "/tmp/cert.pem"
	cfg.Challenge.TLSKey = "/tmp/key.pem"

	got, socket, err := challengeGateProbeTarget(cfg)
	if err != nil || socket != "" {
		t.Fatal(err, socket)
	}
	if got != "https://[::1]:8439/challenge/gate" {
		t.Fatalf("probe URL = %q, want https://[::1]:8439/challenge/gate", got)
	}
}

func TestChallengeGateProbeURLIgnoresWebUITLSOnLoopback(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.ListenAddr = "127.0.0.1"
	cfg.Challenge.ListenPort = 8439
	cfg.WebUI.TLSCert = "/tmp/webui-cert.pem"
	cfg.WebUI.TLSKey = "/tmp/webui-key.pem"

	got, socket, err := challengeGateProbeTarget(cfg)
	if err != nil || socket != "" {
		t.Fatal(err, socket)
	}
	if got != "http://127.0.0.1:8439/challenge/gate" {
		t.Fatalf("probe URL = %q, want http://127.0.0.1:8439/challenge/gate", got)
	}
}

func writeDoctorTempFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// pinDoctorHost gives the host-local trust check a fixed host address.
func pinDoctorHost(t *testing.T) {
	t.Helper()
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.250")}, nil
	}))
}

// socketDoctorCfg points the challenge at a socket in a short private
// directory, owned by the test's own group, so placement checks pass.
func socketDoctorCfg(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = os.RemoveAll(dir)
	})
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("own group not resolvable: %v", err)
	}
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "unix:" + filepath.Join(dir, "c.sock")
	cfg.Challenge.ListenGroup = g.Name
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PublicURL = "https://challenge.example.com/challenge"
	return cfg, dir
}

func findCheck(t *testing.T, report DoctorReport, name string) DoctorCheck {
	t.Helper()
	for _, c := range report.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check\n%s", name, report.Human())
	return DoctorCheck{}
}

func TestBuildChallengeDoctorReport_SocketListenerAllOK(t *testing.T) {
	pinDoctorHost(t)
	cfg, _ := socketDoctorCfg(t)
	cfg.WebUI.TLSCert = "/nonexistent/webui.crt"
	cfg.WebUI.TLSKey = "/nonexistent/webui.key"
	report := challengeDoctorReportFor(cfg)
	requireAllChallengeChecksOK(t, report)
	findCheck(t, report, "challenge socket")
	findCheck(t, report, "challenge trusted proxies")
}

func TestBuildChallengeDoctorReport_HostLocalTrustFails(t *testing.T) {
	pinDoctorHost(t)
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PublicURL = "https://challenge.example.com/challenge"
	cfg.Challenge.TrustedProxies = []string{"198.51.100.2", "127.0.0.1"}
	c := findCheck(t, challengeDoctorReportFor(cfg), "challenge trusted proxies")
	if c.Status != "fail" || !strings.Contains(c.Message, "127.0.0.1") || !strings.Contains(c.Fix, config.ChallengeSocketExample) {
		t.Fatalf("trusted proxies check = %+v, want fail naming the entry with the socket fix", c)
	}
}

func TestChallengePortGateWarnsOnSocketListener(t *testing.T) {
	cfg, _ := socketDoctorCfg(t)
	if c := challengePortGateCheck(cfg); c.Status != "ok" || !strings.Contains(c.Message, "no TCP port") {
		t.Fatalf("socket without gate = %+v, want ok", c)
	}
	cfg.Challenge.PortGate.Enabled = true
	if c := challengePortGateCheck(cfg); c.Status != "warn" {
		t.Fatalf("socket with gate = %+v, want warn", c)
	}
}

func TestChallengeSocketCheckFailsOnUnknownGroup(t *testing.T) {
	pinDoctorHost(t)
	cfg, _ := socketDoctorCfg(t)
	cfg.Challenge.ListenGroup = "csm-no-such-group"
	c := findCheck(t, challengeDoctorReportFor(cfg), "challenge socket")
	if c.Status != "fail" || !strings.Contains(c.Message, "csm-no-such-group") || c.Fix == "" {
		t.Fatalf("socket check = %+v, want fail naming the group", c)
	}
}

func TestChallengeSocketCheckFailsOnWritableParent(t *testing.T) {
	pinDoctorHost(t)
	cfg, dir := socketDoctorCfg(t)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	c := findCheck(t, challengeDoctorReportFor(cfg), "challenge socket")
	if c.Status != "fail" || !strings.Contains(c.Message, dir) {
		t.Fatalf("socket check = %+v, want fail naming %s", c, dir)
	}
}

func TestChallengeGateProbeReachesSocketListener(t *testing.T) {
	pinDoctorHost(t)
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			cfg, dir := socketDoctorCfg(t)
			// A socket has no TCP port, including when it serves TLS.
			cfg.Challenge.ListenPort = 0
			if scheme == "https" {
				cfg.Challenge.TLSCert = filepath.Join(dir, "cert.pem")
				cfg.Challenge.TLSKey = filepath.Join(dir, "key.pem")
				if err := webui.EnsureTLSCert(cfg.Challenge.TLSCert, cfg.Challenge.TLSKey); err != nil {
					t.Fatal(err)
				}
			}
			srv := challenge.New(cfg, nil)
			ln, err := srv.Listen()
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = srv.Serve(ln) }()
			t.Cleanup(srv.Shutdown)
			got := defaultChallengeGateProbe(cfg)
			if got.Status != "ok" || got.Message != cfg.Challenge.ListenAddr {
				t.Fatalf("probe = %+v, want ok naming %s", got, cfg.Challenge.ListenAddr)
			}
		})
	}
}
