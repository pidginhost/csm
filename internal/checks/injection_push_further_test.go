package checks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// ---------------------------------------------------------------------------
// plugincheck.go — deeper coverage
// ---------------------------------------------------------------------------

// evaluatePluginCache hitting the default case (Warning severity) when the
// installed version is only one minor version behind.
func TestEvaluatePluginCache_WarningSeverity(t *testing.T) {
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

	site := store.SitePlugins{
		Account: "alice",
		Domain:  "example.com",
		Plugins: []store.SitePluginEntry{
			{Slug: "yoast", Name: "Yoast SEO", Status: "active", InstalledVersion: "6.4.0", UpdateVersion: "6.5.1"},
		},
	}
	if err := sdb.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(sdb)
	if len(findings) == 0 {
		t.Fatalf("expected a warning finding")
	}
	if findings[0].Severity != alert.Warning {
		t.Errorf("expected Warning severity, got %v", findings[0].Severity)
	}
	if findings[0].Check != "outdated_plugins" {
		t.Errorf("check = %q", findings[0].Check)
	}
	if !strings.Contains(findings[0].Message, "6.4.0") || !strings.Contains(findings[0].Message, "6.5.1") {
		t.Errorf("message missing versions: %s", findings[0].Message)
	}
}

// evaluatePluginCache: "high" severity minor-behind path (>=3 minor gap).
func TestEvaluatePluginCache_HighSeverity(t *testing.T) {
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

	site := store.SitePlugins{
		Account: "bob",
		Domain:  "shop.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "woo", Name: "WooCommerce", Status: "active", InstalledVersion: "6.1.0", UpdateVersion: "6.4.2"},
		},
	}
	if err := sdb.SetSitePlugins("/home/bob/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(sdb)
	if len(findings) == 0 {
		t.Fatal("expected a finding for 3+ minor gap")
	}
	if findings[0].Severity != alert.High {
		t.Errorf("expected High severity, got %v", findings[0].Severity)
	}
}

// evaluatePluginCache: active-network plugin with minor gap produces finding.
func TestEvaluatePluginCache_ActiveNetworkMinorGap(t *testing.T) {
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

	site := store.SitePlugins{
		Account: "carol",
		Domain:  "net.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "acf", Name: "Advanced Custom Fields", Status: "active-network", InstalledVersion: "6.1.3", UpdateVersion: "6.1.5"},
		},
	}
	if err := sdb.SetSitePlugins("/home/carol/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(sdb)
	if len(findings) == 0 {
		t.Fatal("expected a finding for active-network plugin")
	}
}

// refreshPluginCache early-return when no wp-configs are discovered.
func TestRefreshPluginCache_NoInstalls(t *testing.T) {
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

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	refreshPluginCache(context.Background(), sdb)
	last := sdb.GetPluginRefreshTime()
	if !last.IsZero() {
		t.Errorf("refresh time should be zero after empty discovery, got %v", last)
	}
}

// fetchWPOrgPluginInfo parse helper: exercise via httptest server.
func TestFetchWPOrgPluginInfo_ValidResponseFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("action") != "plugin_information" {
			t.Errorf("missing action param")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"slug":"jetpack","version":"12.5","tested":"6.5"}`))
	}))
	defer srv.Close()

	u := srv.URL + "?action=plugin_information&request[slug]=" + url.QueryEscape("jetpack")
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body [4096]byte
	n, _ := resp.Body.Read(body[:])
	info, err := parseWPOrgPluginResponse(body[:n])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if info.LatestVersion != "12.5" {
		t.Errorf("version = %q", info.LatestVersion)
	}
}

// extractWPDomain successful path: fallback to path segment after public_html.
func TestExtractWPDomain_WPCLISuccess(t *testing.T) {
	got := extractWPDomain(context.Background(), "/home/alice/public_html/shop.example.com", "alice")
	if got != "shop.example.com" {
		t.Errorf("got %q, want shop.example.com", got)
	}
}

// extractWPDomain fallback: no public_html segment returns user.
func TestExtractWPDomain_FallbackToUser(t *testing.T) {
	got := extractWPDomain(context.Background(), "/home/bob/wp", "bob")
	if got != "bob" {
		t.Errorf("got %q, want bob (fallback to user)", got)
	}
}

// parseWPOrgPluginResponse with empty body triggers JSON error.
func TestParseWPOrgPluginResponse_EmptyBody(t *testing.T) {
	_, err := parseWPOrgPluginResponse([]byte(""))
	if err == nil {
		t.Error("expected error for empty body")
	}
}

// parseVersion with non-numeric parts produces zero for those segments.
func TestParseVersion_NonNumericSegments(t *testing.T) {
	v := parseVersion("1.2.beta")
	if len(v) != 3 || v[0] != 1 || v[1] != 2 || v[2] != 0 {
		t.Errorf("parseVersion = %v, want [1 2 0]", v)
	}
}

// parseVersion empty string returns nil.
func TestParseVersion_Empty(t *testing.T) {
	if parseVersion("") != nil {
		t.Error("parseVersion(empty) should be nil")
	}
}

// ---------------------------------------------------------------------------
// hardening.go — deeper branches
// ---------------------------------------------------------------------------

// hasOpenBasedir via .user.ini in public_html.
func TestHasOpenBasedir_ViaUserINI(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "/public_html/.user.ini") {
				return []byte("open_basedir = /home/alice:/tmp\n"), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) { return nil, nil },
	})

	if !hasOpenBasedir("alice") {
		t.Error("should detect open_basedir via .user.ini")
	}
}

// hasOpenBasedir via .htaccess.
func TestHasOpenBasedir_ViaHtaccess(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "/public_html/.htaccess") {
				return []byte("php_value open_basedir /home/alice:/tmp\n"), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) { return nil, nil },
	})

	if !hasOpenBasedir("alice") {
		t.Error("should detect open_basedir via .htaccess")
	}
}

// hasOpenBasedir via per-user php.d local.ini file.
func TestHasOpenBasedir_ViaPHPDConfig(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "/local.ini") {
				return []byte("open_basedir = /home/alice\n"), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return []string{"/opt/cpanel/ea-php82/root/etc/php.d/"}, nil
		},
	})

	if !hasOpenBasedir("alice") {
		t.Error("should detect open_basedir via per-user php.d local.ini")
	}
}

// getCageFSMode with empty file content returns unknown.
func TestGetCageFSMode_EmptyFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/cagefs/cagefs.mp" {
				return []byte("  \n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	if got := getCageFSMode(); got != "unknown" {
		t.Errorf("empty file should return unknown, got %q", got)
	}
}

// getCageFSMode with non-empty file returns enabled.
func TestGetCageFSMode_Enabled(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/cagefs/cagefs.mp" {
				return []byte("/var/cagefs\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	if got := getCageFSMode(); got != "enabled" {
		t.Errorf("non-empty file should return enabled, got %q", got)
	}
}

// getCageFSDisabledUsers reads cagefsctl output.
func TestGetCageFSDisabledUsers_FromCtl(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "cagefsctl" && len(args) > 0 && args[0] == "--list-disabled" {
				return []byte("bob\ncarol\n  \n"), nil
			}
			return nil, nil
		},
	})

	got := getCageFSDisabledUsers("enabled")
	if !got["bob"] || !got["carol"] {
		t.Errorf("expected bob + carol in disabled set, got %v", got)
	}
	if got[""] {
		t.Error("blank line should not produce an empty entry")
	}
}

// scanForMaliciousSymlinks smoke-test: exercise the recursive path.
func TestScanForMaliciousSymlinks_Smoke(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice/public_html" {
				return []os.DirEntry{testDirEntry{name: "peek", isDir: false}}, nil
			}
			return nil, nil
		},
		readlink: func(name string) (string, error) {
			if strings.HasSuffix(name, "/peek") {
				return "/home/bob/public_html/wp-config.php", nil
			}
			return "", os.ErrNotExist
		},
	})

	var findings []alert.Finding
	scanForMaliciousSymlinks("/home/alice/public_html", "alice", "/home/alice", 3, &findings)
}

// isSymlinkSafe: each of the cPanel "safe" roots.
func TestIsSymlinkSafe_CPanelSafeRoots(t *testing.T) {
	cases := []string{
		"/etc/apache2/logs/access.log",
		"/usr/local/apache/logs/access.log",
		"/var/cpanel/users/alice",
		"/opt/cpanel/ea-php82/root/usr/bin/php",
		"/usr/share/cagefs-skeleton/etc/passwd",
		"/var/lib/mysql/alice.db",
		"/var/run/mysqld/mysqld.sock",
	}
	for _, p := range cases {
		if !isSymlinkSafe(p, "alice", "/home/alice") {
			t.Errorf("expected %s to be a safe symlink target", p)
		}
	}
}

// CheckOpenBasedir emits Finding when CageFS is absent AND user has no open_basedir.
func TestCheckOpenBasedir_EmitsFindingForUnprotectedUser(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/var/cpanel/users" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) { return nil, nil },
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	})

	findings := CheckOpenBasedir(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Fatal("expected a finding for unprotected user")
	}
	if findings[0].Check != "open_basedir" {
		t.Errorf("check = %q", findings[0].Check)
	}
	if findings[0].Severity != alert.High {
		t.Errorf("severity = %v", findings[0].Severity)
	}
}

// ---------------------------------------------------------------------------
// reputation.go — deeper coverage
// ---------------------------------------------------------------------------

// cleanCache fallback with no bbolt store removes expired entries.
func TestCleanCache_NoStoreFallback(t *testing.T) {
	old := store.Global()
	store.SetGlobal(nil)
	defer store.SetGlobal(old)

	cache := &reputationCache{Entries: map[string]*reputationEntry{
		"1.1.1.1": {Score: 50, CheckedAt: time.Now()},
		"2.2.2.2": {Score: 40, CheckedAt: time.Now().Add(-7 * time.Hour)},
	}}
	cleanCache(cache)
	if _, ok := cache.Entries["2.2.2.2"]; ok {
		t.Error("expired entry should have been removed")
	}
	if _, ok := cache.Entries["1.1.1.1"]; !ok {
		t.Error("fresh entry should remain")
	}
}

// loadAllBlockedIPs loads from the legacy blocked_ips.json file.
func TestLoadAllBlockedIPs_LegacyBlockedIPsJSON(t *testing.T) {
	dir := t.TempDir()
	old := store.Global()
	store.SetGlobal(nil)
	defer store.SetGlobal(old)

	blocked := struct {
		IPs []struct {
			IP        string    `json:"ip"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"ips"`
	}{}
	blocked.IPs = append(blocked.IPs,
		struct {
			IP        string    `json:"ip"`
			ExpiresAt time.Time `json:"expires_at"`
		}{IP: "203.0.113.50", ExpiresAt: time.Now().Add(1 * time.Hour)},
		struct {
			IP        string    `json:"ip"`
			ExpiresAt time.Time `json:"expires_at"`
		}{IP: "203.0.113.60", ExpiresAt: time.Now().Add(-1 * time.Hour)},
	)
	data, _ := json.Marshal(blocked)
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	got := loadAllBlockedIPs(dir)
	if !got["203.0.113.50"] {
		t.Error("active IP should be loaded")
	}
	if got["203.0.113.60"] {
		t.Error("expired IP should be dropped")
	}
}

// CheckIPReputation: no ThreatDB, no cache, no AbuseIPDB key → no findings.
func TestCheckIPReputation_NoKeyNoDBNoCache(t *testing.T) {
	old := store.Global()
	store.SetGlobal(nil)
	defer store.SetGlobal(old)

	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})

	findings := CheckIPReputation(context.Background(), &config.Config{StatePath: t.TempDir()}, nil)
	if len(findings) != 0 {
		t.Errorf("no IPs should give no findings, got %d", len(findings))
	}
}

// saveReputationCache / loadReputationCache preserves zero entries.
func TestReputationCache_EmptyRoundTrip(t *testing.T) {
	old := store.Global()
	store.SetGlobal(nil)
	defer store.SetGlobal(old)

	dir := t.TempDir()
	saveReputationCache(dir, &reputationCache{Entries: map[string]*reputationEntry{}})
	loaded := loadReputationCache(dir)
	if loaded == nil || loaded.Entries == nil {
		t.Error("loaded cache should be initialized")
	}
	if len(loaded.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(loaded.Entries))
	}
}

// ---------------------------------------------------------------------------
// php_content.go — deeper branches
// ---------------------------------------------------------------------------

// analyzePHPContent: base64 encode+decode+shell on same line.
func TestAnalyzePHPContent_Base64Relay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.php")
	content := "<?php\n$x = system(base64_decode(base64_encode($_POST['c'])));\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Errorf("expected detection for base64 encode+decode with shell, got %+v", result)
	}
}

// analyzePHPContent: shell function with request input on same line.
func TestAnalyzePHPContent_ShellSameLineRequest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmd.php")
	content := "<?php\nexec($_GET['q']);\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Errorf("expected detection for same-line shell+request, got %+v", result)
	}
}

// analyzePHPContent: eval directly wrapping gzinflate.
func TestAnalyzePHPContent_NestedEvalGzinflate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrap.php")
	content := "<?php\neval(gzinflate(base64_decode('AAAA')));\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Errorf("expected eval wrapping gzinflate to be flagged, got %+v", result)
	}
}

// analyzePHPContent: call_user_func combined with decoder and obfuscation.
func TestAnalyzePHPContent_CallUserFuncWithObfuscation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cuf.php")
	hexes := strings.Repeat(`"\x63" . "\x75" . `, 10)
	content := "<?php\n" +
		"$name = " + hexes + "\"\";\n" +
		"$data = base64_decode('AAAA');\n" +
		"call_user_func($name, $data);\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Errorf("expected detection, got %+v", result)
	}
}

// analyzePHPContent: pastebin raw URL triggers remote-payload indicator.
func TestAnalyzePHPContent_PasteBinRaw(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pb.php")
	content := "<?php\n$u = 'https://pastebin.com/raw/abc';\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "obfuscated_php" {
		t.Errorf("pastebin URL should be critical, got %+v", result)
	}
}

// analyzePHPContent: github raw co-present with dangerous call.
func TestAnalyzePHPContent_GithubCoPresence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gh.php")
	content := "<?php\n" +
		"$url = 'https://raw.githubusercontent.com/foo/bar/master/x.php';\n" +
		"popen('echo', 'r');\n" +
		"eval(base64_decode('x'));\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Errorf("expected finding, got %+v", result)
	}
}

// scanDirForObfuscatedPHP honors cfg.Suppressions.IgnorePaths.
// matchGlob falls back to substring-after-stripping-stars, so a pattern
// containing a unique substring of the path suppresses matches reliably.
func TestScanDirForObfuscatedPHP_SuppressedPath(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "dropper.php")
	content := "<?php\n$u = 'https://pastebin.com/raw/abc';\n"
	_ = os.WriteFile(bad, []byte(content), 0644)

	cfg := &config.Config{}
	// matchGlob strips * and substring-matches, so any prefix of the path works.
	cfg.Suppressions.IgnorePaths = []string{"dropper.php"}

	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), dir, 2, cfg, &findings)
	if len(findings) != 0 {
		t.Errorf("suppression should hide findings, got %d", len(findings))
	}
}

// scanDirForObfuscatedPHP with cancelled context returns early.
func TestScanDirForObfuscatedPHP_ContextCancelled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	_ = os.WriteFile(path, []byte("<?php"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var findings []alert.Finding
	scanDirForObfuscatedPHP(ctx, dir, 2, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("cancelled ctx should yield no findings, got %d", len(findings))
	}
}

// scanDirForObfuscatedPHP respects maxDepth=0.
func TestScanDirForObfuscatedPHP_MaxDepthZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	_ = os.WriteFile(path, []byte("<?php $x='https://pastebin.com/raw/abc';"), 0644)

	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), dir, 0, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("maxDepth 0 should skip scanning, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// threatfeeds.go — more branches
// ---------------------------------------------------------------------------

// Lookup on a database with zero entries.
func TestThreatDBLookup_EmptyDB(t *testing.T) {
	db := &ThreatDB{
		badIPs:        make(map[string]string),
		whitelist:     make(map[string]bool),
		whitelistMeta: make(map[string]*whitelistEntry),
	}
	if src, ok := db.Lookup("1.2.3.4"); ok || src != "" {
		t.Errorf("empty DB should miss, got (%q, %v)", src, ok)
	}
}

// FeedsStale: lastUpdate is recent (< 7d) with zero LastUpdated → fresh.
func TestThreatDBFeedsStale_RecentLegacy(t *testing.T) {
	db := &ThreatDB{
		badIPs:        make(map[string]string),
		whitelist:     make(map[string]bool),
		whitelistMeta: make(map[string]*whitelistEntry),
		lastUpdate:    time.Now().Add(-3 * 24 * time.Hour),
	}
	if db.FeedsStale() {
		t.Error("recent legacy lastUpdate should not be stale")
	}
}

// Count counts both IP and net entries.
func TestThreatDBCount_WithNets(t *testing.T) {
	db := newTestThreatDB(t)
	db.badIPs["1.2.3.4"] = "feed"
	db.badIPs["5.6.7.8"] = "feed"
	if got := db.Count(); got != 2 {
		t.Errorf("Count = %d, want 2", got)
	}
}

// saveWhitelistFile with no entries writes an (essentially) empty file.
func TestThreatDB_SaveWhitelistFile_Empty(t *testing.T) {
	old := store.Global()
	store.SetGlobal(nil)
	defer store.SetGlobal(old)

	db := newTestThreatDB(t)
	db.saveWhitelistFile()
	data, err := os.ReadFile(filepath.Join(db.dbPath, "whitelist.txt"))
	if err != nil {
		t.Fatalf("whitelist.txt missing: %v", err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("expected empty file, got %q", data)
	}
}

// loadLines with missing file returns nil.
func TestLoadLines_Missing(t *testing.T) {
	if got := loadLines(filepath.Join(t.TempDir(), "no_such_file")); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// loadLines skips blanks and comment lines.
func TestLoadLines_SkipsBlanksAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ips.txt")
	content := "1.2.3.4\n\n# comment line\n5.6.7.8\n   \n"
	_ = os.WriteFile(path, []byte(content), 0600)

	lines := loadLines(path)
	if len(lines) != 2 {
		t.Errorf("got %d, want 2: %v", len(lines), lines)
	}
}

// saveLines sorts entries.
func TestSaveLines_Sorted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sorted.txt")
	saveLines(path, []string{"9.9.9.9", "1.1.1.1", "5.5.5.5"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 || lines[0] != "1.1.1.1" || lines[2] != "9.9.9.9" {
		t.Errorf("unsorted output: %v", lines)
	}
}

// downloadFeed handles semicolon/hash trailing comments.
func TestDownloadFeed_TrailingComments(t *testing.T) {
	body := "1.2.3.4 ; hello\n5.6.7.8 # hi there\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	ips, _, err := downloadFeed(client, srv.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Errorf("got %d ips, want 2: %v", len(ips), ips)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — deeper paths we can still reach
// ---------------------------------------------------------------------------

// ApplyFix backdoor_binary path → fixKillAndQuarantine → fixQuarantine.
func TestApplyFix_BackdoorBinary_NonexistentPath(t *testing.T) {
	result := ApplyFix("backdoor_binary", "backdoor at /home/alice/.config/miner", "PID: 1234")
	if result.Success {
		t.Error("should fail for nonexistent file")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

// ApplyFix webshell with /tmp/-prefixed path — fixQuarantine allows /tmp roots.
func TestApplyFix_Webshell_NonexistentTmpPath(t *testing.T) {
	result := ApplyFix("webshell", "webshell at /tmp/nope.php", "")
	if result.Success {
		t.Error("should fail for nonexistent /tmp file")
	}
}

// ApplyFix obfuscated_php dispatched to fixQuarantine.
func TestApplyFix_ObfuscatedPHP_Dispatch(t *testing.T) {
	result := ApplyFix("obfuscated_php", "obfuscated at /home/alice/wp.php", "")
	if result.Success {
		t.Error("should fail (nonexistent path)")
	}
}

// ApplyFix email_phishing_content: no message ID in text.
func TestApplyFix_EmailPhishingNoMsgID(t *testing.T) {
	result := ApplyFix("email_phishing_content", "no msg id here", "")
	if result.Success {
		t.Error("should fail with no message id")
	}
}

// ApplyFix email_phishing_content with invalid message ID format.
func TestApplyFix_EmailPhishingInvalidFormat(t *testing.T) {
	result := ApplyFix("email_phishing_content", "phishing (message: INVALID)", "")
	if result.Success {
		t.Error("should reject malformed message id")
	}
	if !strings.Contains(result.Error, "invalid Exim message ID format") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

// ApplyFix email_phishing_content with valid ID but no spool file.
func TestApplyFix_EmailPhishingNoSpool(t *testing.T) {
	withMockOS(t, &mockOS{})
	result := ApplyFix("email_phishing_content", "phishing (message: 2jKPFm-000abc-1X)", "")
	if result.Success {
		t.Error("should fail with no spool file")
	}
	if !strings.Contains(result.Error, "not found") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

// HasFix: verify all known types plus an unknown.
func TestHasFix_PositiveAndNegative(t *testing.T) {
	for _, c := range []string{
		"world_writable_php", "group_writable_php", "webshell", "new_webshell_file",
		"obfuscated_php", "php_dropper", "suspicious_php_content",
		"new_php_in_languages", "new_php_in_upgrade", "phishing_page",
		"phishing_directory", "backdoor_binary", "new_executable_in_config",
		"htaccess_injection", "htaccess_handler_abuse", "email_phishing_content",
	} {
		if !HasFix(c) {
			t.Errorf("HasFix(%q) = false, want true", c)
		}
	}
	if HasFix("made_up_check") {
		t.Error("HasFix(made_up_check) should be false")
	}
}

// FixDescription returns empty for check types without a fix.
func TestFixDescription_UnknownCheck(t *testing.T) {
	if got := FixDescription("nonexistent_check_type", "msg"); got != "" {
		t.Errorf("unknown check should yield empty description, got %q", got)
	}
}

// FixDescription world_writable_php with an explicit path.
func TestFixDescription_WorldWritableExplicitPath(t *testing.T) {
	desc := FixDescription("world_writable_php", "", "/home/alice/public_html/bad.php")
	if !strings.Contains(desc, "644") || !strings.Contains(desc, "bad.php") {
		t.Errorf("unexpected description: %q", desc)
	}
}

// FixDescription email_phishing_content with a message containing an ID.
func TestFixDescription_EmailPhishingWithID(t *testing.T) {
	desc := FixDescription("email_phishing_content",
		"Phishing content in message (message: 2jKPFm-000abc-1X)")
	if !strings.Contains(desc, "2jKPFm") {
		t.Errorf("description missing message id: %q", desc)
	}
}

// FixDescription htaccess_injection with no path returns empty.
func TestFixDescription_HtaccessInjectionNoPath(t *testing.T) {
	if got := FixDescription("htaccess_injection", "no path in message"); got != "" {
		t.Errorf("expected empty description without path, got %q", got)
	}
}
