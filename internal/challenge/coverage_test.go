package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// --- IPList ------------------------------------------------------------

func TestNewIPListDefaultsToEmpty(t *testing.T) {
	l := NewIPList(t.TempDir())
	if l.Contains("1.2.3.4") {
		t.Error("fresh list should not contain any IP")
	}
}

func TestIPListAddContainsRemove(t *testing.T) {
	l := NewIPList(t.TempDir())
	l.Add("1.2.3.4", "brute force", time.Hour)
	if !l.Contains("1.2.3.4") {
		t.Error("Add should make Contains return true")
	}

	// Verify the file on disk.
	data, err := os.ReadFile(l.path)
	if err != nil {
		t.Fatalf("list file not written: %v", err)
	}
	if !strings.Contains(string(data), "1.2.3.4 challenge") {
		t.Errorf("list file missing IP line:\n%s", data)
	}

	l.Remove("1.2.3.4")
	if l.Contains("1.2.3.4") {
		t.Error("Remove should make Contains return false")
	}

	// File should be rewritten without the IP.
	data, _ = os.ReadFile(l.path)
	if strings.Contains(string(data), "1.2.3.4 challenge") {
		t.Errorf("list file still contains removed IP:\n%s", data)
	}
}

func TestIPListExpiredEntriesReturnsAndRemoves(t *testing.T) {
	l := NewIPList(t.TempDir())
	l.Add("1.1.1.1", "test", 1*time.Hour)
	l.Add("2.2.2.2", "test", -1*time.Hour) // already expired
	l.Add("3.3.3.3", "test", -5*time.Minute)

	expired := l.ExpiredEntries()
	expiredIPs := make(map[string]bool)
	for _, e := range expired {
		expiredIPs[e.IP] = true
	}
	if !expiredIPs["2.2.2.2"] || !expiredIPs["3.3.3.3"] {
		t.Errorf("expired = %v, want [2.2.2.2 3.3.3.3]", expired)
	}
	if expiredIPs["1.1.1.1"] {
		t.Error("fresh entry should not be expired")
	}
	if l.Contains("2.2.2.2") {
		t.Error("expired entries should be removed from the list")
	}
	if !l.Contains("1.1.1.1") {
		t.Error("fresh entries should remain")
	}
}

func TestIPListExpiredEntriesEmptyListReturnsNil(t *testing.T) {
	l := NewIPList(t.TempDir())
	if got := l.ExpiredEntries(); got != nil {
		t.Errorf("got %v, want nil for empty list", got)
	}
}

func TestIPListCleanExpired(t *testing.T) {
	l := NewIPList(t.TempDir())
	l.Add("1.1.1.1", "test", -1*time.Hour)
	l.CleanExpired()
	if l.Contains("1.1.1.1") {
		t.Error("CleanExpired should remove expired entries")
	}
}

// --- sanitizeRedirectDest ---------------------------------------------

func TestSanitizeRedirectDestEmptyDefaultsToRoot(t *testing.T) {
	if got := sanitizeRedirectDest("", "example.com"); got != "/" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeRedirectDestRelativePathAllowed(t *testing.T) {
	if got := sanitizeRedirectDest("/dashboard", "example.com"); got != "/dashboard" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeRedirectDestRelativePathWithQuery(t *testing.T) {
	if got := sanitizeRedirectDest("/search?q=test", "example.com"); got != "/search?q=test" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeRedirectDestSameHostAbsolute(t *testing.T) {
	got := sanitizeRedirectDest("https://example.com/page", "example.com")
	if got != "https://example.com/page" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeRedirectDestCrossOriginRejected(t *testing.T) {
	if got := sanitizeRedirectDest("https://evil.com/phish", "example.com"); got != "/" {
		t.Errorf("cross-origin = %q, want /", got)
	}
}

func TestSanitizeRedirectDestProtocolRelativeRejected(t *testing.T) {
	// //evil.com is interpreted as absolute scheme-relative.
	if got := sanitizeRedirectDest("//evil.com/path", "example.com"); got != "/" {
		t.Errorf("protocol-relative = %q, want /", got)
	}
}

func TestSanitizeRedirectDestJavaScriptURIRejected(t *testing.T) {
	if got := sanitizeRedirectDest("javascript:alert(1)", "example.com"); got != "/" {
		t.Errorf("javascript URI = %q, want /", got)
	}
}

func TestSanitizeRedirectDestDataURIRejected(t *testing.T) {
	if got := sanitizeRedirectDest("data:text/html,<script>alert(1)</script>", "example.com"); got != "/" {
		t.Errorf("data URI = %q, want /", got)
	}
}

func TestSanitizeRedirectDestFileURIRejected(t *testing.T) {
	if got := sanitizeRedirectDest("file:///etc/passwd", "example.com"); got != "/" {
		t.Errorf("file URI = %q, want /", got)
	}
}

func TestSanitizeRedirectDestBackslashRejected(t *testing.T) {
	// Some browsers normalize \ to / so /\evil.com could become //evil.com.
	if got := sanitizeRedirectDest(`/\evil.com`, "example.com"); got != "/" {
		t.Errorf("backslash path = %q, want /", got)
	}
}

func TestSanitizeRedirectDestRelativeWithoutLeadingSlashRejected(t *testing.T) {
	if got := sanitizeRedirectDest("dashboard", "example.com"); got != "/" {
		t.Errorf("got %q, want /", got)
	}
}

func TestSanitizeRedirectDestRequestHostWithPort(t *testing.T) {
	// requestHost may include a port (RemoteAddr style). The host match
	// should still work via net.SplitHostPort.
	got := sanitizeRedirectDest("https://example.com/page", "example.com:8443")
	if got != "https://example.com/page" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeRedirectDestNonHTTPSchemeRejected(t *testing.T) {
	if got := sanitizeRedirectDest("ftp://example.com/file", "example.com"); got != "/" {
		t.Errorf("ftp scheme = %q, want /", got)
	}
}

func TestSanitizeRedirectDestMalformedURL(t *testing.T) {
	// %ZZ is an invalid escape sequence so url.Parse errors.
	if got := sanitizeRedirectDest("%ZZ", "example.com"); got != "/" {
		t.Errorf("malformed URL = %q, want /", got)
	}
}

// --- verifyPoW --------------------------------------------------------

func TestVerifyPoWZeroDifficultyAcceptsAny(t *testing.T) {
	if !verifyPoW("nonce", "sol", 0) {
		t.Error("difficulty 0 should accept any solution")
	}
}

func TestVerifyPoWDifficulty1(t *testing.T) {
	// Brute force a valid solution locally.
	nonce := "fixednonce"
	var solution string
	for i := 0; i < 1_000_000; i++ {
		s := fmt.Sprintf("%x", i)
		h := sha256.Sum256([]byte(nonce + s))
		if hex.EncodeToString(h[:])[0] == '0' {
			solution = s
			break
		}
	}
	if solution == "" {
		t.Fatal("could not find a difficulty-1 solution within 1M attempts")
	}
	if !verifyPoW(nonce, solution, 1) {
		t.Error("solution should verify at difficulty 1")
	}
}

func TestVerifyPoWRejectsBadSolution(t *testing.T) {
	if verifyPoW("nonce", "wrong", 1) {
		t.Error("obviously-wrong solution should be rejected")
	}
}

func TestVerifyPoWDifficultyGreaterThanHashLength(t *testing.T) {
	// A difficulty so high no hex string can satisfy it.
	if verifyPoW("nonce", "solution", 100) {
		t.Error("impossibly high difficulty should reject")
	}
}

// --- generateNonce ----------------------------------------------------

func TestGenerateNonceUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n := generateNonce()
		if len(n) != 32 { // 16 bytes hex-encoded
			t.Errorf("length = %d, want 32", len(n))
		}
		if seen[n] {
			t.Error("nonce collision (100 samples)")
		}
		seen[n] = true
	}
}

// --- Server constructor + handlers ------------------------------------

type stubUnblocker struct {
	mu      sync.Mutex
	called  int
	lastIP  string
	lastRsn string
}

func (u *stubUnblocker) TempAllowIP(ip, reason string, _ time.Duration) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.called++
	u.lastIP = ip
	u.lastRsn = reason
	return nil
}

func newTestServer(t *testing.T, cfg *config.Config) (*Server, *stubUnblocker, *IPList) {
	t.Helper()
	u := &stubUnblocker{}
	l := NewIPList(t.TempDir())
	s := New(cfg, u, l)
	return s, u, l
}

func baseCfg() *config.Config {
	c := &config.Config{}
	c.Challenge.Secret = "test-secret-32bytes-for-hmac-use"
	c.Challenge.Difficulty = 0 // accept any PoW solution in tests
	c.Challenge.ListenPort = 0
	return c
}

func TestNewRandomSecretWhenEmpty(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.Secret = "" // force random generation
	s := New(cfg, nil, nil)
	if len(s.secret) != 32 {
		t.Errorf("random secret length = %d, want 32", len(s.secret))
	}
}

func TestNewWiresTrustedProxies(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"10.0.0.1", "  10.0.0.2  "}
	s := New(cfg, nil, nil)
	if !s.trustedProxies["10.0.0.1"] {
		t.Error("10.0.0.1 should be trusted")
	}
	if !s.trustedProxies["10.0.0.2"] {
		t.Error("10.0.0.2 should be trusted after whitespace trim")
	}
}

func TestHandleChallengeRendersPageWithIP(t *testing.T) {
	s, _, _ := newTestServer(t, baseCfg())

	req := httptest.NewRequest("GET", "/challenge", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	w := httptest.NewRecorder()

	s.handleChallenge(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.5") {
		t.Error("page should contain the requesting IP")
	}
}

func TestHandleVerifyRejectsGET(t *testing.T) {
	s, _, _ := newTestServer(t, baseCfg())
	req := httptest.NewRequest("GET", "/challenge/verify", nil)
	req.RemoteAddr = "1.2.3.4:1"
	w := httptest.NewRecorder()
	s.handleVerify(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET verify = %d, want 405", w.Code)
	}
}

func TestHandleVerifyRejectsBadToken(t *testing.T) {
	s, _, _ := newTestServer(t, baseCfg())
	form := url.Values{
		"nonce":    {"xxx"},
		"token":    {"wrong"},
		"solution": {"anything"},
	}
	req := httptest.NewRequest("POST", "/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:1"
	w := httptest.NewRecorder()
	s.handleVerify(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("bad token = %d, want 403", w.Code)
	}
}

func TestHandleVerifyRejectsBadSolution(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.Difficulty = 4 // force a real PoW check
	s, _, _ := newTestServer(t, cfg)

	nonce := "fixed-nonce"
	ip := "1.2.3.4"
	token := s.makeToken(ip, nonce)

	form := url.Values{
		"nonce":    {nonce},
		"token":    {token},
		"solution": {"000"}, // will NOT hash to 4 leading zeros
	}
	req := httptest.NewRequest("POST", "/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":1"
	w := httptest.NewRecorder()
	s.handleVerify(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("bad PoW = %d, want 403", w.Code)
	}
}

func TestHandleVerifySuccessPath(t *testing.T) {
	// Difficulty 0 so any solution validates — lets us focus on the
	// unblocker + replay + cookie + redirect logic.
	s, unblocker, list := newTestServer(t, baseCfg())
	ip := "1.2.3.4"
	list.Add(ip, "test", time.Hour)

	nonce := "fresh-nonce-1"
	token := s.makeToken(ip, nonce)
	form := url.Values{
		"nonce":    {nonce},
		"token":    {token},
		"solution": {"0"},
		"dest":     {"/home"},
	}
	req := httptest.NewRequest("POST", "/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "example.com"
	req.RemoteAddr = ip + ":10000"
	w := httptest.NewRecorder()
	s.handleVerify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("success path = %d, want 200", w.Code)
	}
	if unblocker.called != 1 {
		t.Errorf("unblocker.called = %d, want 1", unblocker.called)
	}
	if unblocker.lastIP != ip {
		t.Errorf("unblocker.lastIP = %q", unblocker.lastIP)
	}
	if list.Contains(ip) {
		t.Error("IP should be removed from challenge list after verify")
	}
	// csm_verified cookie should be set.
	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "csm_verified" {
			found = true
			if !c.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
		}
	}
	if !found {
		t.Error("csm_verified cookie not set")
	}
	body := w.Body.String()
	if !strings.Contains(body, "/home") {
		t.Error("redirect body should include sanitized dest")
	}
}

func TestHandleVerifyCookieHasSecurityAttributes(t *testing.T) {
	// The verification cookie grants the client a bypass of the PoW gate
	// for ~4 hours, so it must carry all the hardening attributes: HttpOnly
	// (no JS access), SameSite (no cross-site attachment), and Secure (no
	// leakage over plaintext links). CSM is designed to run behind HTTPS;
	// plaintext deployments are not supported.
	s, _, _ := newTestServer(t, baseCfg())
	ip := "1.2.3.4"
	nonce := "fresh-nonce-secure"
	token := s.makeToken(ip, nonce)

	form := url.Values{
		"nonce":    {nonce},
		"token":    {token},
		"solution": {"0"},
	}
	req := httptest.NewRequest("POST", "/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "example.com"
	req.RemoteAddr = ip + ":1"
	w := httptest.NewRecorder()
	s.handleVerify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("setup: verify returned %d, want 200", w.Code)
	}

	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "csm_verified" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("csm_verified cookie not set")
	}
	if !cookie.Secure {
		t.Error("cookie must have Secure attribute")
	}
	if !cookie.HttpOnly {
		t.Error("cookie must have HttpOnly attribute")
	}
	if cookie.SameSite != http.SameSiteLaxMode && cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Lax or Strict", cookie.SameSite)
	}
}

func TestHandleVerifyReplayIsRejected(t *testing.T) {
	s, _, _ := newTestServer(t, baseCfg())
	ip := "1.2.3.4"
	nonce := "replay-nonce"
	token := s.makeToken(ip, nonce)

	form := url.Values{
		"nonce":    {nonce},
		"token":    {token},
		"solution": {"0"},
	}
	mkReq := func() *http.Request {
		r := httptest.NewRequest("POST", "/challenge/verify", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Host = "example.com"
		r.RemoteAddr = ip + ":1"
		return r
	}

	w1 := httptest.NewRecorder()
	s.handleVerify(w1, mkReq())
	if w1.Code != 200 {
		t.Fatalf("first call = %d, want 200", w1.Code)
	}

	w2 := httptest.NewRecorder()
	s.handleVerify(w2, mkReq())
	if w2.Code != http.StatusForbidden {
		t.Errorf("replay = %d, want 403", w2.Code)
	}
}

func TestHandleVerifyUnblockerNilIsTolerated(t *testing.T) {
	cfg := baseCfg()
	s := New(cfg, nil, nil) // no unblocker, no list

	ip := "1.2.3.4"
	nonce := "nonce-nil-unblocker"
	token := s.makeToken(ip, nonce)

	form := url.Values{
		"nonce":    {nonce},
		"token":    {token},
		"solution": {"0"},
	}
	req := httptest.NewRequest("POST", "/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "example.com"
	req.RemoteAddr = ip + ":1"
	w := httptest.NewRecorder()
	s.handleVerify(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("nil unblocker should not fail the request: got %d", w.Code)
	}
}

// --- extractIP trusted-proxy handling ---------------------------------

func TestExtractIPNoTrustedProxyUsesRemoteAddr(t *testing.T) {
	s := New(baseCfg(), nil, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1") // should be ignored
	if got := s.extractIP(req); got != "203.0.113.10" {
		t.Errorf("got %q, want 203.0.113.10", got)
	}
}

func TestExtractIPTrustedProxyUsesRightmostXFF(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"10.0.0.1"}
	s := New(cfg, nil, nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	// Client-controlled left, proxy-appended right.
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 203.0.113.10")
	if got := s.extractIP(req); got != "203.0.113.10" {
		t.Errorf("got %q, want 203.0.113.10 (rightmost XFF)", got)
	}
}

func TestExtractIPTrustedProxyNoXFFFallsBackToRemote(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"10.0.0.1"}
	s := New(cfg, nil, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	if got := s.extractIP(req); got != "10.0.0.1" {
		t.Errorf("got %q, want 10.0.0.1", got)
	}
}

func TestExtractIPTrustedProxyBogusXFFFallsBackToRemote(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"10.0.0.1"}
	s := New(cfg, nil, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "not-an-ip, garbage")
	if got := s.extractIP(req); got != "10.0.0.1" {
		t.Errorf("got %q, want 10.0.0.1 (fallback)", got)
	}
}

func TestExtractIPUntrustedPeerIgnoresXFF(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"10.0.0.1"}
	s := New(cfg, nil, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "5.5.5.5:1" // NOT the trusted proxy
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	if got := s.extractIP(req); got != "5.5.5.5" {
		t.Errorf("got %q, want 5.5.5.5 (XFF must be ignored for untrusted peer)", got)
	}
}

// --- CleanExpired on Server.verified map -----------------------------

func TestServerCleanExpired(t *testing.T) {
	s := New(baseCfg(), nil, nil)
	s.verifiedMu.Lock()
	s.verified["old"] = time.Now().Add(-5 * time.Hour)
	s.verified["recent"] = time.Now()
	s.verifiedMu.Unlock()

	s.CleanExpired()

	s.verifiedMu.Lock()
	_, oldStill := s.verified["old"]
	_, recentStill := s.verified["recent"]
	s.verifiedMu.Unlock()

	if oldStill {
		t.Error("old entry should be cleaned")
	}
	if !recentStill {
		t.Error("recent entry should remain")
	}
}

// --- makeToken / makeVerifyCookie -------------------------------------

func TestMakeTokenDeterministicAndIPBound(t *testing.T) {
	s := New(baseCfg(), nil, nil)
	t1 := s.makeToken("1.2.3.4", "n1")
	t2 := s.makeToken("1.2.3.4", "n1")
	if t1 != t2 {
		t.Error("same (ip,nonce) should produce the same token")
	}
	t3 := s.makeToken("5.5.5.5", "n1") // different IP
	if t1 == t3 {
		t.Error("different IP should produce a different token")
	}
}

func TestMakeVerifyCookieHas32Chars(t *testing.T) {
	s := New(baseCfg(), nil, nil)
	c := s.makeVerifyCookie("1.2.3.4")
	if len(c) != 32 {
		t.Errorf("cookie length = %d, want 32", len(c))
	}
}

// --- Shutdown doesn't panic when srv hasn't been Start'ed ------------

func TestServerShutdownIdempotent(t *testing.T) {
	s := New(baseCfg(), nil, nil)
	s.Shutdown()
	// Second call — http.Server.Close is idempotent.
	s.Shutdown()
}
