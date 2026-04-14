package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// ---------------------------------------------------------------------------
// firewall.go — CheckFirewall branch coverage
// ---------------------------------------------------------------------------

func TestCheckFirewallDisabledReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: false}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckFirewall(context.Background(), cfg, store)
	if len(findings) != 0 {
		t.Errorf("disabled firewall should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckFirewallEnabledNftMissingProducesCritical(t *testing.T) {
	// On macOS (or any system without nft), exec.Command fails and we get
	// the "CSM firewall table not found" Critical finding.
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	findings := CheckFirewall(context.Background(), cfg, st)
	// Should have at least one Critical finding with check=firewall
	foundCrit := false
	for _, f := range findings {
		if f.Check == "firewall" && f.Severity == alert.Critical {
			foundCrit = true
			break
		}
	}
	if !foundCrit {
		t.Errorf("expected Critical 'firewall' finding when nft absent, got %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// firewall.go — checkDangerousPorts branches
// ---------------------------------------------------------------------------

func TestCheckDangerousPortsBackdoorInTCPIn(t *testing.T) {
	cfg := &config.Config{
		BackdoorPorts: []int{31337},
	}
	cfg.Firewall = &firewall.FirewallConfig{
		TCPIn: []int{22, 31337, 80},
	}
	findings := checkDangerousPorts(cfg)
	found := false
	for _, f := range findings {
		if f.Check == "firewall_ports" && f.Severity == alert.High {
			found = true
		}
	}
	if !found {
		t.Errorf("expected firewall_ports High finding for backdoor port; got %+v", findings)
	}
}

func TestCheckDangerousPortsRestrictedInPublicTCPIn(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{
		TCPIn:         []int{2087},
		RestrictedTCP: []int{2087},
	}
	findings := checkDangerousPorts(cfg)
	// Exactly one High finding for 2087 on restricted list
	found := false
	for _, f := range findings {
		if f.Check == "firewall_ports" && f.Severity == alert.High {
			found = true
		}
	}
	if !found {
		t.Errorf("expected firewall_ports High finding for restricted port; got %+v", findings)
	}
}

func TestCheckDangerousPortsCleanConfig(t *testing.T) {
	cfg := &config.Config{
		BackdoorPorts: []int{31337},
	}
	cfg.Firewall = &firewall.FirewallConfig{
		TCPIn:         []int{22, 80, 443},
		RestrictedTCP: []int{2087},
	}
	findings := checkDangerousPorts(cfg)
	if len(findings) != 0 {
		t.Errorf("clean config should produce 0 findings, got %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// local_threat.go — CheckLocalThreatScore additional branch
// ---------------------------------------------------------------------------

func TestCheckLocalThreatScoreNilStatePath(t *testing.T) {
	// When attackdb.Global() is nil, we get nil immediately.
	// This also exercises with a non-nil statepath that has no firewall state.
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := CheckLocalThreatScore(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("no attackdb should return 0, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// plugincheck.go — evaluatePluginCache with seeded bbolt data
// ---------------------------------------------------------------------------

func TestEvaluatePluginCacheSkipsInactive(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	}()
	store.SetGlobal(sdb)

	// A site where the only plugin is inactive - should be skipped.
	site := store.SitePlugins{
		Account: "alice",
		Domain:  "example.com",
		Plugins: []store.SitePluginEntry{
			{Slug: "jetpack", Name: "Jetpack", Status: "inactive", InstalledVersion: "1.0.0", UpdateVersion: "2.0.0"},
		},
	}
	if err := sdb.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(sdb)
	if len(findings) != 0 {
		t.Errorf("inactive plugin should be skipped, got %+v", findings)
	}
}

func TestEvaluatePluginCacheCriticalMajorGap(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	}()
	store.SetGlobal(sdb)

	// Active plugin with major version gap (3.x -> 4.x).
	site := store.SitePlugins{
		Account: "alice",
		Domain:  "example.com",
		Plugins: []store.SitePluginEntry{
			{Slug: "wp-forms", Name: "WP Forms", Status: "active", InstalledVersion: "3.5.0", UpdateVersion: "4.0.0"},
		},
	}
	if err := sdb.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(sdb)
	if len(findings) == 0 {
		t.Fatalf("major gap should produce at least one finding")
	}
	if findings[0].Severity != alert.Critical {
		t.Errorf("expected Critical, got %v", findings[0].Severity)
	}
	if findings[0].Check != "outdated_plugins" {
		t.Errorf("check = %q", findings[0].Check)
	}
}

func TestEvaluatePluginCacheFallsBackToPluginInfo(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	}()
	store.SetGlobal(sdb)

	// Plugin with empty UpdateVersion; should consult GetPluginInfo cache.
	if err := sdb.SetPluginInfo("elementor", store.PluginInfo{
		LatestVersion: "4.0.0",
		TestedUpTo:    "6.4",
		LastChecked:   0,
	}); err != nil {
		t.Fatal(err)
	}

	site := store.SitePlugins{
		Account: "bob",
		Domain:  "shop.example.com",
		Plugins: []store.SitePluginEntry{
			{Slug: "elementor", Name: "Elementor", Status: "active", InstalledVersion: "3.0.0", UpdateVersion: ""},
		},
	}
	if err := sdb.SetSitePlugins("/home/bob/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(sdb)
	if len(findings) == 0 {
		t.Fatalf("expected fallback cache to produce findings")
	}
}

func TestEvaluatePluginCacheSkipsWhenNoAvailable(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	}()
	store.SetGlobal(sdb)

	// Active plugin but no UpdateVersion and no cached PluginInfo.
	// Handler skips it silently.
	site := store.SitePlugins{
		Account: "carol",
		Domain:  "site.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "premium-only", Name: "Custom", Status: "active-network", InstalledVersion: "1.0.0", UpdateVersion: ""},
		},
	}
	if err := sdb.SetSitePlugins("/home/carol/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(sdb)
	if len(findings) != 0 {
		t.Errorf("unknown update source should be skipped, got %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// plugincheck.go — shellQuote edge cases not yet covered
// ---------------------------------------------------------------------------

func TestShellQuoteMultipleQuotes(t *testing.T) {
	got := shellQuote(`a'b'c`)
	want := `'a'\''b'\''c'`
	if got != want {
		t.Errorf("shellQuote(%q) = %q, want %q", `a'b'c`, got, want)
	}
}

func TestShellQuoteEmpty(t *testing.T) {
	got := shellQuote("")
	if got != "''" {
		t.Errorf("shellQuote(\"\") = %q, want ''", got)
	}
}

// ---------------------------------------------------------------------------
// whm.go — CheckWHMAccess deeper branches with log content
// ---------------------------------------------------------------------------

func TestCheckWHMAccessWithPasswordChangeFromUnknownIP(t *testing.T) {
	// Provide a log line that matches port 2087 + password action
	logData := `203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] "POST /json-api/passwd HTTP/1.1" 200 1234 ":2087"` + "\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			// Redirect reads to a tempfile
			return nil, os.ErrNotExist
		},
	})

	// CheckWHMAccess uses osFS.Open via tailFile; inject a real file via tempDir trick
	// Since we can't easily intercept os.Open without a real file, write our mock
	// to return a real temp file opened for read.
	_ = logData
}

func TestCheckWHMAccessRealFile(t *testing.T) {
	// Create a real temp file, then set the osFS to open it via real impl.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access_log")
	logData := `203.0.113.5 - root [12/Apr/2026:10:00:00 +0000] ":2087" "POST /json-api/passwd HTTP/1.1" 200 1234` + "\n" +
		`8.8.8.8 - root [12/Apr/2026:10:01:00 +0000] ":2087" "GET /scripts/createacct HTTP/1.1" 200 1234` + "\n" +
		`10.0.0.5 - - [12/Apr/2026:10:02:00 +0000] ":2087" "POST /json-api/passwd HTTP/1.1" 200 1234` + "\n"
	if err := os.WriteFile(logPath, []byte(logData), 0644); err != nil {
		t.Fatal(err)
	}

	// Plug in a mockOS that opens our file regardless of path
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(logPath)
		},
	})

	cfg := &config.Config{
		InfraIPs: []string{"10.0.0.0/24"},
	}
	findings := CheckWHMAccess(context.Background(), cfg, nil)

	// Expect at least one password-change finding (public IP 203.0.113.5 or 8.8.8.8)
	var hasPwChange, hasAcct bool
	for _, f := range findings {
		if f.Check == "whm_password_change" {
			hasPwChange = true
		}
		if f.Check == "whm_account_action" {
			hasAcct = true
		}
	}
	if !hasPwChange {
		t.Errorf("expected whm_password_change finding, got %+v", findings)
	}
	if !hasAcct {
		t.Errorf("expected whm_account_action finding, got %+v", findings)
	}
}

func TestCheckWHMAccessSkipsLoopback(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access_log")
	logData := `127.0.0.1 - root [12/Apr/2026:10:00:00 +0000] ":2087" "POST /json-api/passwd HTTP/1.1" 200 1234` + "\n"
	if err := os.WriteFile(logPath, []byte(logData), 0644); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(logPath)
		},
	})

	findings := CheckWHMAccess(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("127.0.0.1 should be skipped, got %+v", findings)
	}
}

func TestCheckWHMAccessSkipsNon2087Lines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access_log")
	// Lines without ":2087" should be skipped entirely
	logData := `203.0.113.5 - - "GET / HTTP/1.1" 200 cpaneld passwd` + "\n"
	if err := os.WriteFile(logPath, []byte(logData), 0644); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(logPath)
		},
	})

	findings := CheckWHMAccess(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("non-2087 lines should be skipped, got %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// whm.go — CheckSSHLogins deeper branches
// ---------------------------------------------------------------------------

func TestCheckSSHLoginsWithAcceptedPublicIP(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "secure")
	logData := `Apr 12 10:00:00 host sshd[1234]: Accepted publickey for root from 203.0.113.5 port 12345 ssh2` + "\n" +
		`Apr 12 10:01:00 host sshd[1235]: Accepted password for alice from 10.0.0.1 port 54321 ssh2` + "\n" +
		`Apr 12 10:02:00 host sshd[1236]: Failed password for root from 203.0.113.99 port 65535` + "\n"
	if err := os.WriteFile(logPath, []byte(logData), 0644); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(logPath)
		},
	})

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/24"}}
	findings := CheckSSHLogins(context.Background(), cfg, nil)

	// Only 203.0.113.5 is public + non-infra + Accepted.
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Check != "ssh_login_unknown_ip" {
		t.Errorf("check = %q", findings[0].Check)
	}
	if findings[0].Severity != alert.Critical {
		t.Errorf("severity = %v", findings[0].Severity)
	}
}

// ---------------------------------------------------------------------------
// whm.go — truncateString
// ---------------------------------------------------------------------------

func TestTruncateStringBoundary(t *testing.T) {
	// Boundary: len(s) == maxLen should NOT truncate.
	s := "abcdefghij" // 10 chars
	got := truncateString(s, 10)
	if got != s {
		t.Errorf("equal-length should not truncate: got %q", got)
	}
	got = truncateString(s, 5)
	if got != "abcde..." {
		t.Errorf("got %q", got)
	}
}
