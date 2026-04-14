package checks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// ---------------------------------------------------------------------------
// helpers — swap package-level *http.Client with a server-redirecting one.
// ---------------------------------------------------------------------------

// rewriteTransport rewrites every outgoing request to the given test server's
// host/scheme. The original path/query are preserved so the handler still sees
// what the production code constructed.
type rewriteTransport struct{ targetURL *url.URL }

func (rt *rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme = rt.targetURL.Scheme
	r2.URL.Host = rt.targetURL.Host
	r2.Host = rt.targetURL.Host
	return http.DefaultTransport.RoundTrip(r2)
}

// resetWeakPasswords zeros the weak password cache + sync.Once so the next
// loadWeakPasswords() call re-runs the loader. We do not "save+restore" the
// previous Once because sync.Once is non-copyable; instead we simply clear
// state on cleanup, leaving the next caller to re-populate from the real FS.
func resetWeakPasswords(t *testing.T) {
	t.Helper()
	weakPasswordOnce = sync.Once{}
	weakPasswords = nil
	t.Cleanup(func() {
		weakPasswordOnce = sync.Once{}
		weakPasswords = nil
	})
}

// withRewriteHTTPClient swaps the supplied package-level *http.Client pointer
// with one that redirects all requests to the test server, restored on cleanup.
func withRewriteHTTPClient(t *testing.T, holder **http.Client, srv *httptest.Server) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	old := *holder
	*holder = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &rewriteTransport{targetURL: u},
	}
	t.Cleanup(func() { *holder = old })
}

// ---------------------------------------------------------------------------
// plugincheck.go — fetchWPOrgPluginInfo via httptest server
// ---------------------------------------------------------------------------

func TestFetchWPOrgPluginInfo_SuccessViaTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "plugin_information") {
			t.Errorf("expected action=plugin_information in query: %s", r.URL.RawQuery)
		}
		if !strings.Contains(r.URL.RawQuery, "akismet") {
			t.Errorf("expected slug=akismet in query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"slug":"akismet","version":"5.3","tested":"6.4"}`))
	}))
	defer srv.Close()

	withRewriteHTTPClient(t, &wpOrgHTTPClient, srv)

	info, err := fetchWPOrgPluginInfo(context.Background(), "akismet")
	if err != nil {
		t.Fatalf("fetchWPOrgPluginInfo: %v", err)
	}
	if info.LatestVersion != "5.3" {
		t.Errorf("LatestVersion = %q, want 5.3", info.LatestVersion)
	}
	if info.TestedUpTo != "6.4" {
		t.Errorf("TestedUpTo = %q, want 6.4", info.TestedUpTo)
	}
	if info.LastChecked == 0 {
		t.Error("LastChecked should be populated with current unix timestamp")
	}
}

func TestFetchWPOrgPluginInfo_NotFoundError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"Plugin not found."}`))
	}))
	defer srv.Close()

	withRewriteHTTPClient(t, &wpOrgHTTPClient, srv)

	_, err := fetchWPOrgPluginInfo(context.Background(), "definitely-not-real")
	if err == nil {
		t.Fatal("expected error for plugin-not-found body")
	}
	if !strings.Contains(err.Error(), "Plugin not found") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestFetchWPOrgPluginInfo_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	withRewriteHTTPClient(t, &wpOrgHTTPClient, srv)

	_, err := fetchWPOrgPluginInfo(context.Background(), "anything")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestFetchWPOrgPluginInfo_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `not valid json`)
	}))
	defer srv.Close()

	withRewriteHTTPClient(t, &wpOrgHTTPClient, srv)

	_, err := fetchWPOrgPluginInfo(context.Background(), "x")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestFetchWPOrgPluginInfo_TransportFailure(t *testing.T) {
	// Empty server then close it, so the client's request fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // immediately closed → connection refused

	withRewriteHTTPClient(t, &wpOrgHTTPClient, srv)

	_, err := fetchWPOrgPluginInfo(context.Background(), "x")
	if err == nil {
		t.Fatal("expected transport failure error")
	}
	if !strings.Contains(err.Error(), "HTTP request failed") {
		t.Errorf("wrong error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// plugincheck.go — CheckOutdatedPlugins entry-point branches
// ---------------------------------------------------------------------------

func TestCheckOutdatedPlugins_NilStoreReturnsNil(t *testing.T) {
	// Make sure store.Global() returns nil for this test.
	old := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(old) })

	got := CheckOutdatedPlugins(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("nil store should return nil, got %v", got)
	}
}

func TestCheckOutdatedPlugins_FreshCacheSkipsRefresh(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	})
	store.SetGlobal(sdb)

	// Mark cache as fresh (just refreshed) so refreshPluginCache is skipped.
	if err := sdb.SetPluginRefreshTime(time.Now()); err != nil {
		t.Fatal(err)
	}

	// Seed an active outdated plugin so evaluatePluginCache emits a finding.
	site := store.SitePlugins{
		Account: "alice",
		Domain:  "alice.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "yoast", Name: "Yoast SEO", Status: "active",
				InstalledVersion: "20.0.0", UpdateVersion: "21.5.0"},
		},
	}
	if err := sdb.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Thresholds.PluginCheckIntervalMin = 1440 // 24h

	findings := CheckOutdatedPlugins(context.Background(), cfg, nil)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from evaluatePluginCache")
	}
	if findings[0].Check != "outdated_plugins" {
		t.Errorf("unexpected check: %q", findings[0].Check)
	}
}

// ---------------------------------------------------------------------------
// plugincheck.go — refreshPluginCache: ctx-cancelled before any work
// ---------------------------------------------------------------------------

func TestRefreshPluginCache_ContextCancelledNoOp(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	})
	store.SetGlobal(sdb)

	// Force findAllWPInstalls to return at least one path so jobs channel is
	// populated, but cancel the context before the workers can run wp-cli.
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "public_html/wp-config") {
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Should return without panic; no findings written, no refresh time bumped.
	refreshPluginCache(ctx, sdb)

	got := sdb.GetPluginRefreshTime()
	if !got.IsZero() {
		t.Errorf("refresh time should remain zero on cancelled ctx, got %v", got)
	}
}

func TestRefreshPluginCache_NoWPInstallsEarlyReturn(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	})
	store.SetGlobal(sdb)

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) { return nil, nil },
	})

	refreshPluginCache(context.Background(), sdb)

	if !sdb.GetPluginRefreshTime().IsZero() {
		t.Error("no installs path should not bump refresh time")
	}
}

// ---------------------------------------------------------------------------
// plugincheck.go — findAllWPInstalls skip patterns
// ---------------------------------------------------------------------------

func TestFindAllWPInstalls_SkipsCacheBackupTrash(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			// Return the same paths for every glob to also exercise dedup.
			return []string{
				"/home/alice/public_html/wp-config.php",
				"/home/alice/public_html/cache/wp-config.php",
				"/home/alice/public_html/backup/wp-config.php",
				"/home/alice/public_html/.trash/wp-config.php",
				"/home/alice/PUBLIC_HTML/Staging/wp-config.php", // Mixed case
			}, nil
		},
	})

	results := findAllWPInstalls()

	for _, r := range results {
		low := strings.ToLower(r)
		for _, frag := range []string{"/cache/", "/backup", "/staging", "/.trash/"} {
			if strings.Contains(low, frag) {
				t.Errorf("expected %q to be filtered (matches %q)", r, frag)
			}
		}
	}

	// After all 3 patterns return the same input, dedup should leave just 1.
	if len(results) != 1 {
		t.Errorf("dedup failed: got %d results, want 1; %v", len(results), results)
	}
	if results[0] != "/home/alice/public_html/wp-config.php" {
		t.Errorf("unexpected survivor: %q", results[0])
	}
}

// ---------------------------------------------------------------------------
// plugincheck.go — extractWPDomain: strips http/https prefix
// ---------------------------------------------------------------------------

func TestExtractWPDomain_FallbackPublicHTMLSegment(t *testing.T) {
	// wp-cli will fail (no `su`/`wp` available in tests) → exercises the
	// fallback path that pulls "shop.example.com" out after public_html.
	got := extractWPDomain(context.Background(),
		"/home/alice/public_html/shop.example.com", "alice")
	if got != "shop.example.com" {
		t.Errorf("got %q, want shop.example.com", got)
	}
}

func TestExtractWPDomain_FallbackToUserName(t *testing.T) {
	got := extractWPDomain(context.Background(),
		"/home/alice/public_html", "alice")
	if got != "alice" {
		t.Errorf("got %q, want alice (user fallback)", got)
	}
}

// ---------------------------------------------------------------------------
// plugincheck.go — shellQuote single-quote escape
// ---------------------------------------------------------------------------

func TestShellQuote_PlainString(t *testing.T) {
	if got := shellQuote("hello"); got != "'hello'" {
		t.Errorf("shellQuote(hello) = %q, want 'hello'", got)
	}
}

func TestShellQuote_EmbeddedSingleQuote(t *testing.T) {
	got := shellQuote("a'b")
	want := `'a'\''b'`
	if got != want {
		t.Errorf("shellQuote = %q, want %q", got, want)
	}
}

func TestShellQuote_Empty(t *testing.T) {
	if got := shellQuote(""); got != "''" {
		t.Errorf("shellQuote(empty) = %q, want ''", got)
	}
}

// ---------------------------------------------------------------------------
// plugincheck.go — parseVersion edge cases
// ---------------------------------------------------------------------------

func TestParseVersion_EmptyString(t *testing.T) {
	if got := parseVersion(""); got != nil {
		t.Errorf("parseVersion(\"\") = %v, want nil", got)
	}
}

func TestParseVersion_NonNumericTreatedAsZero(t *testing.T) {
	got := parseVersion("1.beta.3")
	if len(got) != 3 || got[0] != 1 || got[1] != 0 || got[2] != 3 {
		t.Errorf("parseVersion(1.beta.3) = %v, want [1 0 3]", got)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — loadWeakPasswords via mock filesystem
// ---------------------------------------------------------------------------

func TestLoadWeakPasswords_FromMockOS(t *testing.T) {
	resetWeakPasswords(t)

	// Write a tmp wordlist and have the mock OS open it.
	tmp := t.TempDir()
	wlPath := filepath.Join(tmp, "weak.txt")
	content := "# header comment, skipped\n" +
		"password\n" + // 8 chars, kept
		"abc\n" + // 3 chars, skipped
		"qwerty\n" + // 6 chars, kept
		"\n" +
		"# trailing comment\n" +
		"letmein\n" // 7 chars, kept
	if err := os.WriteFile(wlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/opt/csm/configs/weak_passwords.txt" {
				return os.Open(wlPath)
			}
			return nil, os.ErrNotExist
		},
	})

	got := loadWeakPasswords()
	if len(got) != 3 {
		t.Fatalf("want 3 words, got %d: %v", len(got), got)
	}
	want := map[string]bool{"password": true, "qwerty": true, "letmein": true}
	for _, w := range got {
		if !want[w] {
			t.Errorf("unexpected word %q in list", w)
		}
	}
}

func TestLoadWeakPasswords_MissingFileNoEntries(t *testing.T) {
	resetWeakPasswords(t)

	withMockOS(t, &mockOS{}) // open returns ErrNotExist by default

	got := loadWeakPasswords()
	if len(got) != 0 {
		t.Errorf("missing file should produce empty list, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — checkWordlist with empty list returns empty
// ---------------------------------------------------------------------------

func TestCheckWordlist_NoMatchesWhenEmpty(t *testing.T) {
	resetWeakPasswords(t)

	withMockOS(t, &mockOS{}) // missing wordlist → loadWeakPasswords returns nil

	if got := checkWordlist("{SHA512-CRYPT}$6$abc$xyz"); got != "" {
		t.Errorf("empty wordlist should yield empty match, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — checkHIBP via httptest with rewrite transport
// ---------------------------------------------------------------------------

func TestCheckHIBP_FoundCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HIBP path is /range/{prefix}; we don't enforce it here but echo a body
		// containing the SHA-1 suffix the production code computes for "password".
		// SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
		// prefix = "5BAA6", suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
		_, _ = io.WriteString(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n"+
			"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:7\r\n")
	}))
	defer srv.Close()

	withRewriteHTTPClient(t, &hibpClient, srv)

	if n := checkHIBP("password"); n != 42 {
		t.Errorf("checkHIBP(password) = %d, want 42", n)
	}
}

func TestCheckHIBP_NotFoundReturnsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n")
	}))
	defer srv.Close()

	withRewriteHTTPClient(t, &hibpClient, srv)

	if n := checkHIBP("password"); n != 0 {
		t.Errorf("not-found suffix should return 0, got %d", n)
	}
}

func TestCheckHIBP_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	withRewriteHTTPClient(t, &hibpClient, srv)

	if n := checkHIBP("password"); n != 0 {
		t.Errorf("non-200 should return 0, got %d", n)
	}
}

func TestCheckHIBP_TransportFailureReturnsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // immediately closed

	withRewriteHTTPClient(t, &hibpClient, srv)

	if n := checkHIBP("password"); n != 0 {
		t.Errorf("transport failure should return 0, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — parseHIBPCount additional edge cases
// ---------------------------------------------------------------------------

func TestParseHIBPCount_WhitespaceAroundFields(t *testing.T) {
	body := "  ABC123 :  5  \r\n"
	if got := parseHIBPCount(body, "abc123"); got != 5 {
		t.Errorf("parseHIBPCount with whitespace = %d, want 5", got)
	}
}

func TestParseHIBPCount_FirstMatchWins(t *testing.T) {
	body := "ABC:1\r\nABC:2\r\n"
	if got := parseHIBPCount(body, "ABC"); got != 1 {
		t.Errorf("first match should win = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — CheckEmailPasswords throttle/empty paths
// ---------------------------------------------------------------------------

func TestCheckEmailPasswords_NilStoreReturnsNil(t *testing.T) {
	old := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(old) })

	got := CheckEmailPasswords(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("nil store should return nil, got %v", got)
	}
}

func TestCheckEmailPasswords_ThrottledByRecentRefresh(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	})
	store.SetGlobal(sdb)

	// Refresh just happened → throttle skips the audit.
	if err := sdb.SetEmailPWLastRefresh(time.Now()); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 1440 // 24h

	old := ForceAll
	ForceAll = false
	t.Cleanup(func() { ForceAll = old })

	got := CheckEmailPasswords(context.Background(), cfg, nil)
	if got != nil {
		t.Errorf("throttled call should return nil, got %v", got)
	}
}

func TestCheckEmailPasswords_NoShadowFilesEarlyReturn(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	})
	store.SetGlobal(sdb)

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) { return nil, nil },
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 1

	old := ForceAll
	ForceAll = true // bypass throttle
	t.Cleanup(func() { ForceAll = old })

	got := CheckEmailPasswords(context.Background(), cfg, nil)
	if got != nil {
		t.Errorf("no shadow files should return nil, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — discoverShadowFiles malformed paths get skipped
// ---------------------------------------------------------------------------

func TestDiscoverShadowFiles_SkipsTooShortPaths(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{
				"too/short",                          // <5 parts → skipped
				"/home/alice/etc/example.com/shadow", // valid
			}, nil
		},
	})
	got := discoverShadowFiles()
	if len(got) != 1 {
		t.Fatalf("got %d, want 1; %+v", len(got), got)
	}
	if got[0].account != "alice" || got[0].domain != "example.com" {
		t.Errorf("wrong parse: %+v", got[0])
	}
}

// ---------------------------------------------------------------------------
// remediate.go — ApplyFix dispatch additional branches
// ---------------------------------------------------------------------------

func TestApplyFix_NewWebshellFile_NonexistentPath(t *testing.T) {
	r := ApplyFix("new_webshell_file", "", "", "/tmp/never-exists-here.php")
	if r.Success {
		t.Error("nonexistent path must not succeed")
	}
}

func TestApplyFix_PhishingDirectory_DispatchesToQuarantine(t *testing.T) {
	// /home/... outside an existing tree → resolveExistingFixPath fails.
	r := ApplyFix("phishing_directory", "", "", "/home/alice/public_html/phish")
	if r.Success {
		t.Error("nonexistent dir under /home should fail")
	}
}

func TestApplyFix_NewExecutableInConfig_DispatchesToKillAndQuarantine(t *testing.T) {
	r := ApplyFix("new_executable_in_config", "", "", "/home/alice/.config/miner")
	if r.Success {
		t.Error("nonexistent path should fail")
	}
	// We expect an error string from resolveExistingFixPath
	if r.Error == "" {
		t.Error("expected an error message")
	}
}

func TestApplyFix_HtaccessHandlerAbuse_RoutesToFixHtaccess(t *testing.T) {
	r := ApplyFix("htaccess_handler_abuse", "", "", "/home/alice/public_html/.htaccess")
	if r.Success {
		t.Error("nonexistent .htaccess path should fail")
	}
}

func TestApplyFix_SuspiciousPHPContent_RoutesToQuarantine(t *testing.T) {
	r := ApplyFix("suspicious_php_content", "", "", "/tmp/missing.php")
	if r.Success {
		t.Error("missing tmp file should fail")
	}
}

// ---------------------------------------------------------------------------
// remediate.go — fixPermissions branches without writing protected paths
// ---------------------------------------------------------------------------

func TestFixPermissions_EmptyPath(t *testing.T) {
	r := fixPermissions("")
	if r.Success {
		t.Error("empty path must not succeed")
	}
	if !strings.Contains(r.Error, "could not extract file path") {
		t.Errorf("wrong error: %s", r.Error)
	}
}

func TestFixPermissions_OutsideHomeRejected(t *testing.T) {
	r := fixPermissions("/etc/passwd")
	if r.Success {
		t.Error("must not chmod /etc/passwd")
	}
	if !strings.Contains(r.Error, "outside the allowed") {
		t.Errorf("wrong error: %s", r.Error)
	}
}

func TestFixPermissions_NonexistentUnderHome(t *testing.T) {
	r := fixPermissions("/home/never_exists_account/never_exists.php")
	if r.Success {
		t.Error("nonexistent file must not succeed")
	}
}

// ---------------------------------------------------------------------------
// remediate.go — fixHtaccess with non-.htaccess basename
// ---------------------------------------------------------------------------

func TestFixHtaccess_NonHtaccessBasename(t *testing.T) {
	r := fixHtaccess("/home/alice/public_html/index.php", "anything")
	if r.Success {
		t.Error("non-.htaccess base must be rejected")
	}
	if !strings.Contains(r.Error, "only applies to .htaccess files") {
		t.Errorf("wrong error: %s", r.Error)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — sanitizeFixPath edge cases
// ---------------------------------------------------------------------------

func TestSanitizeFixPath_EmptyInput(t *testing.T) {
	// "" cleans to ".", which then fails the absolute-path check.
	_, err := sanitizeFixPath("", []string{"/home"})
	if err == nil {
		t.Error("empty path should error")
	}
}

func TestSanitizeFixPath_WhitespaceOnly(t *testing.T) {
	_, err := sanitizeFixPath("   ", []string{"/home"})
	if err == nil {
		t.Error("whitespace-only path should error")
	}
}

func TestSanitizeFixPath_RelativeRejected(t *testing.T) {
	_, err := sanitizeFixPath("relative/path.php", []string{"/home"})
	if err == nil {
		t.Error("relative path should error")
	}
	if !strings.Contains(err.Error(), "must be absolute") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestSanitizeFixPath_AcceptsAllowedRoot(t *testing.T) {
	got, err := sanitizeFixPath("/home/alice/public_html/x.php", []string{"/home"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/home/alice/public_html/x.php" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — isPathWithinOrEqual covers exact-match and prefix-match
// ---------------------------------------------------------------------------

func TestIsPathWithinOrEqual_ExactMatch(t *testing.T) {
	if !isPathWithinOrEqual("/home", "/home") {
		t.Error("exact match should be true")
	}
}

func TestIsPathWithinOrEqual_NestedSubpath(t *testing.T) {
	if !isPathWithinOrEqual("/home/alice/file.php", "/home") {
		t.Error("/home/alice/file.php should be within /home")
	}
}

func TestIsPathWithinOrEqual_LooksLikeButNot(t *testing.T) {
	// "/homer" must NOT count as within "/home" — the separator check
	// prevents this footgun.
	if isPathWithinOrEqual("/homer/file.php", "/home") {
		t.Error("/homer should NOT match /home")
	}
}

// ---------------------------------------------------------------------------
// local_threat.go — wraps the nil-attackdb fallthrough one more time
// alongside the firewall-state read so we exercise the loadAllBlockedIPs
// branch that runs even when attackdb is nil.
// ---------------------------------------------------------------------------

func TestCheckLocalThreatScore_WithEmptyStateDirReturnsNil(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	got := CheckLocalThreatScore(context.Background(), cfg, nil)
	if got != nil {
		t.Errorf("nil attackdb path should return nil findings, got %v", got)
	}
}

func TestCheckLocalThreatScore_WithSeededFirewallStateStillReturnsNil(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0755); err != nil {
		t.Fatal(err)
	}
	// A minimal firewall state.json with a future-dated block.
	stateBytes := []byte(`{"blocked":[{"ip":"1.2.3.4","expires_at":"2099-01-01T00:00:00Z"}]}`)
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), stateBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// Make sure store.Global() is nil so loadAllBlockedIPs reads the flat file.
	old := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(old) })

	cfg := &config.Config{StatePath: dir}
	got := CheckLocalThreatScore(context.Background(), cfg, nil)
	// attackdb.Global() is nil → returns nil before consulting blocked map.
	if got != nil {
		t.Errorf("expected nil (no attackdb), got %v", got)
	}
}
