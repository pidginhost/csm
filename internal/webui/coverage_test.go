package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// --- parseDuration -----------------------------------------------------

func TestParseDurationEmpty(t *testing.T) {
	if got := parseDuration(""); got != 0 {
		t.Errorf("empty = %v, want 0", got)
	}
}

func TestParseDurationZero(t *testing.T) {
	if got := parseDuration("0"); got != 0 {
		t.Errorf("'0' = %v, want 0", got)
	}
}

func TestParseDurationDays(t *testing.T) {
	if got := parseDuration("7d"); got != 7*24*time.Hour {
		t.Errorf("7d = %v, want 168h", got)
	}
	if got := parseDuration("30d"); got != 30*24*time.Hour {
		t.Errorf("30d = %v, want 720h", got)
	}
}

func TestParseDurationHours(t *testing.T) {
	if got := parseDuration("24h"); got != 24*time.Hour {
		t.Errorf("24h = %v", got)
	}
}

func TestParseDurationInvalidDaysFallsBack(t *testing.T) {
	if got := parseDuration("abcd"); got != 0 {
		t.Errorf("abcd = %v, want 0", got)
	}
}

func TestParseDurationInvalidBareGoesToGoParser(t *testing.T) {
	// "not a duration" → time.ParseDuration fails → returns 0.
	if got := parseDuration("not a duration"); got != 0 {
		t.Errorf("garbage = %v, want 0", got)
	}
}

// --- isPathUnder / isPathWithin / pathWithinAny -----------------------

func TestIsPathUnderStrict(t *testing.T) {
	if !isPathUnder("/home/alice/file", "/home/alice") {
		t.Error("file under base should return true")
	}
}

func TestIsPathUnderNotPrefix(t *testing.T) {
	// /home/aliceX is NOT under /home/alice (prefix trick).
	if isPathUnder("/home/aliceX/file", "/home/alice") {
		t.Error("prefix trick should be rejected")
	}
}

func TestIsPathUnderBaseItself(t *testing.T) {
	// The base itself is not "under" itself.
	if isPathUnder("/home/alice", "/home/alice") {
		t.Error("base path is not strictly 'under' itself")
	}
}

func TestIsPathWithinEqualIsTrue(t *testing.T) {
	if !isPathWithin("/home/alice", "/home/alice") {
		t.Error("equal paths should be within")
	}
}

func TestIsPathWithinChildIsTrue(t *testing.T) {
	if !isPathWithin("/home/alice/x", "/home/alice") {
		t.Error("child should be within")
	}
}

func TestIsPathWithinUnrelatedIsFalse(t *testing.T) {
	if isPathWithin("/etc/passwd", "/home") {
		t.Error("unrelated path should not be within")
	}
}

func TestPathWithinAnyMatches(t *testing.T) {
	bases := []string{"/var/log", "/home"}
	if !pathWithinAny("/home/alice", bases) {
		t.Error("should match /home base")
	}
	if !pathWithinAny("/var/log/csm", bases) {
		t.Error("should match /var/log base")
	}
	if pathWithinAny("/etc/shadow", bases) {
		t.Error("unrelated path should not match any")
	}
}

// --- homeAccountRoot ---------------------------------------------------

func TestHomeAccountRootValid(t *testing.T) {
	if got := homeAccountRoot("/home/alice/public_html/x"); got != "/home/alice" {
		t.Errorf("got %q, want /home/alice", got)
	}
}

func TestHomeAccountRootNonHome(t *testing.T) {
	if got := homeAccountRoot("/var/www/site"); got != "" {
		t.Errorf("non-/home = %q, want empty", got)
	}
}

func TestHomeAccountRootTooShallow(t *testing.T) {
	// /home or /home/alice alone has fewer than 4 parts.
	if got := homeAccountRoot("/home/alice"); got != "" {
		t.Errorf("got %q, want empty (too shallow)", got)
	}
}

// --- nearestExistingAncestor ------------------------------------------

func TestNearestExistingAncestorHit(t *testing.T) {
	dir := t.TempDir()
	// dir exists; a nested non-existent path walks up to dir.
	got, err := nearestExistingAncestor(filepath.Join(dir, "nope", "never"))
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Clean(dir) {
		t.Errorf("got %q, want %q", got, dir)
	}
}

func TestNearestExistingAncestorExactPath(t *testing.T) {
	dir := t.TempDir()
	got, err := nearestExistingAncestor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Clean(dir) {
		t.Errorf("got %q, want %q", got, dir)
	}
}

// --- quarantineEntryID + resolveQuarantineEntry -----------------------

func TestQuarantineEntryIDPlain(t *testing.T) {
	// For a non-pre_clean path, we just get the basename without .meta.
	p := filepath.Join(quarantineDir, "abc123.meta")
	if got := quarantineEntryID(p); got != "abc123" {
		t.Errorf("got %q, want abc123", got)
	}
}

func TestResolveQuarantineEntryEmpty(t *testing.T) {
	if _, err := resolveQuarantineEntry(""); err == nil {
		t.Fatal("empty ID should error")
	}
}

func TestResolveQuarantineEntryDotDot(t *testing.T) {
	if _, err := resolveQuarantineEntry(".."); err == nil {
		t.Fatal(".. should error")
	}
}

func TestResolveQuarantineEntryPlain(t *testing.T) {
	ref, err := resolveQuarantineEntry("abc123")
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != "abc123" {
		t.Errorf("ID = %q", ref.ID)
	}
	if ref.MetaPath != ref.ItemPath+".meta" {
		t.Errorf("MetaPath = %q, want %s.meta", ref.MetaPath, ref.ItemPath)
	}
}

func TestResolveQuarantineEntryPreClean(t *testing.T) {
	ref, err := resolveQuarantineEntry("pre_clean:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ref.ItemPath, "pre_clean") {
		t.Errorf("pre_clean path missing: %q", ref.ItemPath)
	}
}

// --- listMetaFiles / readQuarantineMeta -------------------------------

func TestListMetaFilesEmpty(t *testing.T) {
	if got := listMetaFiles(filepath.Join(t.TempDir(), "never")); got != nil {
		t.Errorf("missing dir = %v, want nil", got)
	}
}

func TestListMetaFilesFiltersMetaOnly(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.meta", "b.meta", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	got := listMetaFiles(dir)
	if len(got) != 2 {
		t.Errorf("got %d, want 2 .meta files", len(got))
	}
	for _, p := range got {
		if !strings.HasSuffix(p, ".meta") {
			t.Errorf("non-meta file in result: %q", p)
		}
	}
}

func TestReadQuarantineMetaSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.meta")
	meta := quarantineMeta{
		OriginalPath: "/home/a/shell.php",
		Owner:        1000,
		Group:        1000,
		Mode:         "0644",
		Size:         42,
		QuarantineAt: time.Now(),
		Reason:       "malware",
	}
	data, _ := json.Marshal(meta)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := readQuarantineMeta(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.OriginalPath != meta.OriginalPath {
		t.Errorf("OriginalPath = %q", got.OriginalPath)
	}
	if got.Size != 42 {
		t.Errorf("Size = %d", got.Size)
	}
}

func TestReadQuarantineMetaMissing(t *testing.T) {
	if _, err := readQuarantineMeta(filepath.Join(t.TempDir(), "missing.meta")); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestReadQuarantineMetaCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.meta")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readQuarantineMeta(path); err == nil {
		t.Fatal("corrupt file should error")
	}
}

// --- validateQuarantineRestorePath ------------------------------------

func TestValidateQuarantineRestorePathEmpty(t *testing.T) {
	if _, err := validateQuarantineRestorePath(""); err == nil {
		t.Fatal("empty path should error")
	}
}

func TestValidateQuarantineRestorePathRelative(t *testing.T) {
	if _, err := validateQuarantineRestorePath("relative/path"); err == nil {
		t.Fatal("relative path should error")
	}
}

func TestValidateQuarantineRestorePathOutsideRoots(t *testing.T) {
	if _, err := validateQuarantineRestorePath("/etc/shadow"); err == nil {
		t.Fatal("path outside roots should error")
	}
}

func TestValidateQuarantineRestorePathValidTmp(t *testing.T) {
	// /tmp exists on macOS and Linux.
	got, err := validateQuarantineRestorePath("/tmp/csm-test-restore")
	if err != nil {
		t.Fatalf("valid /tmp path errored: %v", err)
	}
	if got == "" {
		t.Error("valid path returned empty result")
	}
}

// --- severityClass / severityLabel / severityRank / timeAgo / formatTime

func TestSeverityClassAllLevels(t *testing.T) {
	cases := map[alert.Severity]string{
		alert.Critical:     "critical",
		alert.High:         "high",
		alert.Warning:      "warning",
		alert.Severity(99): "info",
	}
	for sev, want := range cases {
		if got := severityClass(sev); got != want {
			t.Errorf("severityClass(%d) = %q, want %q", sev, got, want)
		}
	}
}

func TestSeverityLabelAllLevels(t *testing.T) {
	cases := map[alert.Severity]string{
		alert.Critical:     "CRITICAL",
		alert.High:         "HIGH",
		alert.Warning:      "WARNING",
		alert.Severity(99): "INFO",
	}
	for sev, want := range cases {
		if got := severityLabel(sev); got != want {
			t.Errorf("severityLabel(%d) = %q", sev, got)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	cases := map[string]int{
		"CRITICAL": 3,
		"HIGH":     2,
		"WARNING":  1,
		"INFO":     0,
		"unknown":  0,
	}
	for label, want := range cases {
		if got := severityRank(label); got != want {
			t.Errorf("severityRank(%q) = %d, want %d", label, got, want)
		}
	}
}

func TestTimeAgoJustNow(t *testing.T) {
	if got := timeAgo(time.Now().Add(-30 * time.Second)); got != "just now" {
		t.Errorf("got %q, want 'just now'", got)
	}
}

func TestTimeAgoMinutes(t *testing.T) {
	got := timeAgo(time.Now().Add(-30 * time.Minute))
	if !strings.HasSuffix(got, "m ago") {
		t.Errorf("got %q, want Xm ago", got)
	}
}

func TestTimeAgoHours(t *testing.T) {
	got := timeAgo(time.Now().Add(-5 * time.Hour))
	if !strings.HasSuffix(got, "h ago") {
		t.Errorf("got %q, want Xh ago", got)
	}
}

func TestTimeAgoDays(t *testing.T) {
	got := timeAgo(time.Now().Add(-3 * 24 * time.Hour))
	if !strings.HasSuffix(got, "d ago") {
		t.Errorf("got %q, want Xd ago", got)
	}
}

func TestFormatTime(t *testing.T) {
	ts := time.Date(2026, 4, 11, 10, 30, 45, 0, time.UTC)
	if got := formatTime(ts); got != "2026-04-11 10:30:45" {
		t.Errorf("got %q", got)
	}
}

// --- extractClientIP --------------------------------------------------

func TestExtractClientIPRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	if got := extractClientIP(req); got != "203.0.113.5" {
		t.Errorf("got %q, want 203.0.113.5", got)
	}
}

func TestExtractClientIPIgnoresXForwardedFor(t *testing.T) {
	// extractClientIP intentionally trusts only RemoteAddr — XFF is
	// trivially spoofable and this value ends up in the audit log.
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 198.51.100.1")
	if got := extractClientIP(req); got != "127.0.0.1" {
		t.Errorf("got %q, want 127.0.0.1 (XFF must be ignored)", got)
	}
}

func TestExtractClientIPIPv6(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"
	if got := extractClientIP(req); got != "2001:db8::1" {
		t.Errorf("got %q, want 2001:db8::1", got)
	}
}

func TestExtractClientIPNoPortInRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5" // unusual, no port
	if got := extractClientIP(req); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

// --- Server auth / CSRF -----------------------------------------------

func newTestServer(t *testing.T, token string) *Server {
	t.Helper()
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.WebUI.AuthToken = token
	cfg.WebUI.UIDir = filepath.Join(t.TempDir(), "ui-missing")
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	s, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s
}

func TestIsAuthenticatedEmptyTokenRejectsAll(t *testing.T) {
	s := newTestServer(t, "") // empty token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer anything")
	if s.isAuthenticated(req) {
		t.Error("empty token should reject all auth")
	}
}

func TestIsAuthenticatedBearerValid(t *testing.T) {
	s := newTestServer(t, "supersecret-token")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer supersecret-token")
	if !s.isAuthenticated(req) {
		t.Error("valid Bearer should authenticate")
	}
}

func TestIsAuthenticatedBearerInvalid(t *testing.T) {
	s := newTestServer(t, "supersecret-token")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	if s.isAuthenticated(req) {
		t.Error("wrong Bearer should not authenticate")
	}
}

func TestIsAuthenticatedCookieValid(t *testing.T) {
	s := newTestServer(t, "cookie-token")
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: "cookie-token"})
	if !s.isAuthenticated(req) {
		t.Error("valid cookie should authenticate")
	}
}

func TestIsAuthenticatedNoCredentials(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("GET", "/", nil)
	if s.isAuthenticated(req) {
		t.Error("no credentials should reject")
	}
}

func TestRequireAuthRedirectsBrowser(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	s.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler should not run for unauthed request")
	})).ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("code = %d, want 302", w.Code)
	}
	if w.Header().Get("Location") != "/login" {
		t.Errorf("Location = %q", w.Header().Get("Location"))
	}
}

func TestRequireAuth401sAPIRequests(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("GET", "/api/things", nil)
	w := httptest.NewRecorder()
	s.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler should not run")
	})).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestRequireAuthPassesAuthenticated(t *testing.T) {
	s := newTestServer(t, "real-token")
	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Header.Set("Authorization", "Bearer real-token")
	w := httptest.NewRecorder()
	called := false
	s.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	})).ServeHTTP(w, req)
	if !called {
		t.Error("authenticated handler was not called")
	}
}

func TestCSRFTokenStable(t *testing.T) {
	s := newTestServer(t, "t")
	t1 := s.csrfToken()
	t2 := s.csrfToken()
	if t1 != t2 {
		t.Error("csrfToken should be stable within a process")
	}
	if len(t1) != 32 {
		t.Errorf("length = %d, want 32", len(t1))
	}
}

func TestValidateCSRFGETAlwaysOK(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("GET", "/api/x", nil)
	if !s.validateCSRF(req) {
		t.Error("GET should always pass CSRF")
	}
}

func TestValidateCSRFBearerBypass(t *testing.T) {
	s := newTestServer(t, "the-token")
	req := httptest.NewRequest("POST", "/api/x", nil)
	req.Header.Set("Authorization", "Bearer the-token")
	if !s.validateCSRF(req) {
		t.Error("Bearer auth should bypass CSRF")
	}
}

func TestValidateCSRFHeaderTokenMatch(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("POST", "/api/x", nil)
	req.Header.Set("X-CSRF-Token", s.csrfToken())
	if !s.validateCSRF(req) {
		t.Error("matching header token should pass CSRF")
	}
}

func TestValidateCSRFHeaderTokenMismatch(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("POST", "/api/x", nil)
	req.Header.Set("X-CSRF-Token", "wrong")
	if s.validateCSRF(req) {
		t.Error("wrong header token should fail CSRF")
	}
}

func TestValidateCSRFNoTokenFails(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("POST", "/api/x", nil)
	if s.validateCSRF(req) {
		t.Error("no token on POST should fail CSRF")
	}
}

func TestRequireCSRFBlocksInvalid(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("POST", "/api/x", strings.NewReader("x=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.requireCSRF(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler should not run")
	})).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", w.Code)
	}
}

func TestIsBearerAuthValid(t *testing.T) {
	s := newTestServer(t, "abc")
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer abc")
	if !s.isBearerAuth(req) {
		t.Error("valid bearer should return true")
	}
}

func TestIsBearerAuthMissing(t *testing.T) {
	s := newTestServer(t, "abc")
	req := httptest.NewRequest("POST", "/", nil)
	if s.isBearerAuth(req) {
		t.Error("no header should return false")
	}
}

// --- handleLogout -----------------------------------------------------

func TestHandleLogoutClearsCookie(t *testing.T) {
	s := newTestServer(t, "t")
	req := httptest.NewRequest("POST", "/logout", nil)
	w := httptest.NewRecorder()
	s.handleLogout(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("code = %d, want 302", w.Code)
	}
	// csm_auth cookie should be cleared (MaxAge < 0).
	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "csm_auth" && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("csm_auth cookie not cleared")
	}
}

// --- acquireScan / releaseScan ---------------------------------------

func TestAcquireScanOneAtATime(t *testing.T) {
	s := newTestServer(t, "t")
	if !s.acquireScan() {
		t.Fatal("first acquire should succeed")
	}
	if s.acquireScan() {
		t.Error("second acquire should fail while first is held")
	}
	s.releaseScan()
	if !s.acquireScan() {
		t.Error("acquire after release should succeed")
	}
	s.releaseScan()
}

// --- Setter helpers ---------------------------------------------------

func TestSetSigCount(t *testing.T) {
	s := newTestServer(t, "t")
	s.SetSigCount(123)
	if s.sigCount != 123 {
		t.Errorf("sigCount = %d, want 123", s.sigCount)
	}
}

func TestSetHealthInfo(t *testing.T) {
	s := newTestServer(t, "t")
	s.SetHealthInfo(true, 7)
	if !s.fanotifyActive {
		t.Error("fanotifyActive should be true")
	}
	if s.logWatcherCount != 7 {
		t.Errorf("logWatcherCount = %d, want 7", s.logWatcherCount)
	}
}

func TestSetVersion(t *testing.T) {
	s := newTestServer(t, "t")
	s.SetVersion("2.3.0")
	if s.version != "2.3.0" {
		t.Errorf("version = %q", s.version)
	}
}

func TestHasUI(t *testing.T) {
	s := newTestServer(t, "t")
	// Test server constructs with a non-existent UI dir, so HasUI() is false.
	if s.HasUI() {
		t.Error("HasUI should be false with non-existent UI dir")
	}
}

// --- validateAccountName (untested branches) --------------------------

func TestValidateAccountNameFirstCharDigit(t *testing.T) {
	if err := validateAccountName("9abc"); err == nil {
		t.Error("digit-leading name should error")
	}
}

// --- decodeJSONBodyLimited --------------------------------------------

func TestDecodeJSONBodyLimitedValid(t *testing.T) {
	body := strings.NewReader(`{"name":"test","count":5}`)
	req := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()

	var dst struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	if err := decodeJSONBodyLimited(w, req, 0, &dst); err != nil {
		t.Fatal(err)
	}
	if dst.Name != "test" || dst.Count != 5 {
		t.Errorf("got %+v", dst)
	}
}

func TestDecodeJSONBodyLimitedUnknownField(t *testing.T) {
	body := strings.NewReader(`{"unknown":"field"}`)
	req := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()
	var dst struct {
		Name string `json:"name"`
	}
	if err := decodeJSONBodyLimited(w, req, 0, &dst); err == nil {
		t.Error("unknown field should error")
	}
}

func TestDecodeJSONBodyLimitedMultipleValues(t *testing.T) {
	body := strings.NewReader(`{"name":"a"}{"name":"b"}`)
	req := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()
	var dst struct {
		Name string `json:"name"`
	}
	err := decodeJSONBodyLimited(w, req, 0, &dst)
	if err == nil || !strings.Contains(err.Error(), "single JSON value") {
		t.Errorf("err = %v, want 'single JSON value' error", err)
	}
}

func TestDecodeJSONBodyLimitedMalformed(t *testing.T) {
	body := strings.NewReader(`not json`)
	req := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()
	var dst map[string]any
	if err := decodeJSONBodyLimited(w, req, 64, &dst); err == nil {
		t.Error("malformed JSON should error")
	}
}

// --- API handlers ------------------------------------------------------
//
// Small set of handler tests for endpoints that only touch the Server's
// cfg + store. Each exercises the handler via httptest.NewRecorder
// without needing the full router + CSRF + auth middleware.

func TestAPIStatusJSON(t *testing.T) {
	s := newTestServer(t, "token")
	s.SetSigCount(42)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.apiStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["rules_loaded"] != float64(42) {
		t.Errorf("rules_loaded = %v, want 42", got["rules_loaded"])
	}
	if _, ok := got["uptime"]; !ok {
		t.Error("uptime missing from status")
	}
	if _, ok := got["started_at"]; !ok {
		t.Error("started_at missing from status")
	}
}

func TestAPIHealthJSON(t *testing.T) {
	s := newTestServer(t, "token")
	s.SetHealthInfo(true, 9)
	s.SetSigCount(100)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	s.apiHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["fanotify"] != true {
		t.Errorf("fanotify = %v", got["fanotify"])
	}
	if got["log_watchers"] != float64(9) {
		t.Errorf("log_watchers = %v, want 9", got["log_watchers"])
	}
	if got["rules_loaded"] != float64(100) {
		t.Errorf("rules_loaded = %v, want 100", got["rules_loaded"])
	}
}

func TestAPIFindingsEmpty(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	w := httptest.NewRecorder()
	s.apiFindings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := strings.TrimSpace(w.Body.String())
	// Empty findings serializes as `null` (because result is a nil slice).
	// Also accept "[]" if the implementation ever switches to
	// pre-allocating an empty slice.
	if body != "null" && body != "[]" {
		t.Errorf("body = %q, want null or []", body)
	}
}

func TestAPIFindingsWithStoreEntries(t *testing.T) {
	s := newTestServer(t, "token")
	s.store.SetLatestFindings([]alert.Finding{
		{Check: "malware", Message: "shell found", Severity: alert.Critical, Timestamp: time.Now()},
		{Check: "auto_block", Message: "AUTO-BLOCK: 1.2.3.4", Severity: alert.High, Timestamp: time.Now()}, // filtered
		{Check: "waf_status", Message: "WAF not active", Severity: alert.High, Timestamp: time.Now()},
	})

	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	w := httptest.NewRecorder()
	s.apiFindings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var result []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	// auto_block should be filtered out; expect 2 results.
	if len(result) != 2 {
		t.Errorf("got %d findings, want 2 (auto_block filtered)", len(result))
	}
	for _, f := range result {
		if f["check"] == "auto_block" {
			t.Error("auto_block should have been filtered")
		}
	}
}

// --- queryInt ----------------------------------------------------------

func TestQueryIntDefault(t *testing.T) {
	req := httptest.NewRequest("GET", "/x", nil)
	if got := queryInt(req, "limit", 50); got != 50 {
		t.Errorf("got %d, want 50", got)
	}
}

func TestQueryIntValid(t *testing.T) {
	req := httptest.NewRequest("GET", "/x?limit=20", nil)
	if got := queryInt(req, "limit", 50); got != 20 {
		t.Errorf("got %d, want 20", got)
	}
}

func TestQueryIntInvalidFallsBack(t *testing.T) {
	req := httptest.NewRequest("GET", "/x?limit=abc", nil)
	if got := queryInt(req, "limit", 50); got != 50 {
		t.Errorf("got %d, want 50 (fallback)", got)
	}
}

func TestQueryIntNegativeFallsBack(t *testing.T) {
	req := httptest.NewRequest("GET", "/x?limit=-10", nil)
	if got := queryInt(req, "limit", 50); got != 50 {
		t.Errorf("got %d, want 50 (negative rejected)", got)
	}
}

// --- csvEscape ---------------------------------------------------------

func TestCsvEscapeNoQuoting(t *testing.T) {
	if got := csvEscape("plain text"); got != "plain text" {
		t.Errorf("got %q, want plain text", got)
	}
}

func TestCsvEscapeComma(t *testing.T) {
	if got := csvEscape("a,b,c"); got != `"a,b,c"` {
		t.Errorf("got %q", got)
	}
}

func TestCsvEscapeQuoteIsDoubled(t *testing.T) {
	if got := csvEscape(`say "hi"`); got != `"say ""hi"""` {
		t.Errorf("got %q", got)
	}
}

func TestCsvEscapeNewline(t *testing.T) {
	if got := csvEscape("line1\nline2"); got != "\"line1\nline2\"" {
		t.Errorf("got %q", got)
	}
}

// --- writeJSON / writeJSONError ---------------------------------------

func TestWriteJSONSetsContentType(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, map[string]string{"key": "value"})
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(w.Body.String(), `"key"`) {
		t.Errorf("body missing key: %s", w.Body.String())
	}
}

func TestWriteJSONErrorStatusAndBody(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, "forbidden", http.StatusForbidden)
	if w.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", w.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["error"] != "forbidden" {
		t.Errorf("error field = %q", got["error"])
	}
}

// --- apiHistoryCSV -----------------------------------------------------

func TestAPIHistoryCSVEmpty(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("GET", "/api/v1/history.csv", nil)
	w := httptest.NewRecorder()
	s.apiHistoryCSV(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("code = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("Content-Type = %q", ct)
	}
	// Always has the header row.
	if !strings.HasPrefix(w.Body.String(), "Timestamp,Severity,Check,Message,Details") {
		t.Errorf("missing CSV header: %s", w.Body.String())
	}
}

// --- apiDismissFinding -------------------------------------------------

func TestAPIDismissFindingMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("GET", "/api/v1/dismiss", nil)
	w := httptest.NewRecorder()
	s.apiDismissFinding(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d, want 405", w.Code)
	}
}

func TestAPIDismissFindingEmptyKey(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("POST", "/api/v1/dismiss", strings.NewReader(`{"key":""}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiDismissFinding(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", w.Code)
	}
}

func TestAPIDismissFindingSuccess(t *testing.T) {
	s := newTestServer(t, "token")
	// Seed a finding in the store so DismissFinding has something to mark.
	s.store.Update([]alert.Finding{{Check: "c", Message: "m"}})

	req := httptest.NewRequest("POST", "/api/v1/dismiss",
		strings.NewReader(`{"key":"c:m"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiDismissFinding(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", w.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["status"] != "dismissed" {
		t.Errorf("status = %q", got["status"])
	}
}

// --- apiBlockIP / apiUnblockIP (with stub blocker) --------------------

type stubBlocker struct {
	blocked   []string
	unblocked []string
}

func (b *stubBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	b.blocked = append(b.blocked, ip)
	return nil
}

func (b *stubBlocker) UnblockIP(ip string) error {
	b.unblocked = append(b.unblocked, ip)
	return nil
}

func TestAPIBlockIPMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("GET", "/api/v1/block-ip", nil)
	w := httptest.NewRecorder()
	s.apiBlockIP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d", w.Code)
	}
}

func TestAPIBlockIPMissingIP(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("POST", "/api/v1/block-ip",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", w.Code)
	}
}

func TestAPIBlockIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("POST", "/api/v1/block-ip",
		strings.NewReader(`{"ip":"not-an-ip"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", w.Code)
	}
}

func TestAPIBlockIPPrivateIPRejected(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("POST", "/api/v1/block-ip",
		strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP should be rejected, code = %d", w.Code)
	}
}

func TestAPIBlockIPNoBlockerReturns503(t *testing.T) {
	s := newTestServer(t, "token")
	// s.blocker is nil by default
	req := httptest.NewRequest("POST", "/api/v1/block-ip",
		strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiBlockIP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", w.Code)
	}
}

func TestAPIBlockIPSuccess(t *testing.T) {
	s := newTestServer(t, "token")
	blocker := &stubBlocker{}
	s.SetIPBlocker(blocker)

	req := httptest.NewRequest("POST", "/api/v1/block-ip",
		strings.NewReader(`{"ip":"203.0.113.5","reason":"bruteforce"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiBlockIP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", w.Code)
	}
	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.5" {
		t.Errorf("blocker.blocked = %v", blocker.blocked)
	}
}

func TestAPIUnblockIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "token")
	s.SetIPBlocker(&stubBlocker{})
	req := httptest.NewRequest("POST", "/api/v1/unblock-ip",
		strings.NewReader(`{"ip":"not-valid"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", w.Code)
	}
}

func TestAPIUnblockIPNoBlocker(t *testing.T) {
	s := newTestServer(t, "token")
	req := httptest.NewRequest("POST", "/api/v1/unblock-ip",
		strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", w.Code)
	}
}

// --- formatRemaining (firewall_api.go) --------------------------------

func TestFormatRemainingPermanent(t *testing.T) {
	if got := formatRemaining(time.Time{}); got != "permanent" {
		t.Errorf("got %q, want permanent", got)
	}
}

func TestFormatRemainingExpired(t *testing.T) {
	if got := formatRemaining(time.Now().Add(-1 * time.Hour)); got != "0h0m" {
		t.Errorf("got %q, want 0h0m (clamped)", got)
	}
}

func TestFormatRemainingFuture(t *testing.T) {
	got := formatRemaining(time.Now().Add(2*time.Hour + 30*time.Minute))
	// Should be "2h30m" or "2h29m" depending on sub-second drift.
	if got != "2h30m" && got != "2h29m" {
		t.Errorf("got %q, want ~2h30m", got)
	}
}

// --- apiFirewallStatus -------------------------------------------------

func TestAPIFirewallStatusJSON(t *testing.T) {
	s := newTestServer(t, "token")
	s.cfg.Firewall = &firewall.FirewallConfig{
		Enabled:  true,
		TCPIn:    []int{22, 80, 443},
		InfraIPs: []string{"10.0.0.1"},
	}

	req := httptest.NewRequest("GET", "/api/v1/firewall/status", nil)
	w := httptest.NewRecorder()
	s.apiFirewallStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != true {
		t.Errorf("enabled = %v, want true", got["enabled"])
	}
	if got["blocked_count"] != float64(0) {
		t.Errorf("blocked_count = %v, want 0", got["blocked_count"])
	}
	tcp, ok := got["tcp_in"].([]any)
	if !ok || len(tcp) != 3 {
		t.Errorf("tcp_in = %v, want 3 entries", got["tcp_in"])
	}
}

func TestAPIFirewallStatusInfraFallback(t *testing.T) {
	s := newTestServer(t, "token")
	s.cfg.Firewall = &firewall.FirewallConfig{}
	// firewall.infra_ips empty, top-level infra_ips set.
	s.cfg.InfraIPs = []string{"10.0.0.5"}

	req := httptest.NewRequest("GET", "/api/v1/firewall/status", nil)
	w := httptest.NewRecorder()
	s.apiFirewallStatus(w, req)

	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	infra, _ := got["infra_ips"].([]any)
	if len(infra) != 1 || infra[0] != "10.0.0.5" {
		t.Errorf("infra_ips fallback = %v", got["infra_ips"])
	}
}

// --- apiFirewallAllowed ------------------------------------------------

func TestAPIFirewallAllowedReadsState(t *testing.T) {
	s := newTestServer(t, "token")
	// Seed a firewall state.json in {StatePath}/firewall/
	fwDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(fwDir, 0755); err != nil {
		t.Fatal(err)
	}
	state := `{
		"allowed": [
			{"ip":"203.0.113.10","reason":"trusted","expires_at":"0001-01-01T00:00:00Z"},
			{"ip":"198.51.100.1","reason":"temp","expires_at":"2099-01-01T00:00:00Z"}
		]
	}`
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), []byte(state), 0600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/v1/firewall/allowed", nil)
	w := httptest.NewRecorder()
	s.apiFirewallAllowed(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.10") {
		t.Errorf("body missing 203.0.113.10: %s", body)
	}
	if !strings.Contains(body, "198.51.100.1") {
		t.Errorf("body missing 198.51.100.1: %s", body)
	}
}
