package challenge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// newServerForTest returns a server and its challenge list. A verification
// flow that completes takes the IP off the list, which is what the tests
// below assert; nothing else is observable from a pass.
func newServerForTest(t *testing.T) (*Server, *IPList) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Challenge.Secret = "test-secret-for-hmac"
	cfg.Challenge.ListenPort = 0
	cfg.Challenge.Difficulty = 1
	list := NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	s := New(cfg, list)
	return s, list
}

// configureCaptcha enables the CAPTCHA fallback by pointing it at a
// fake provider endpoint. Returns the server URL so tests can assert
// the call shape if they want.
func configureCaptcha(t *testing.T, s *Server, success bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": success})
	}))
	t.Cleanup(srv.Close)
	prev := providerEndpoint["turnstile"]
	providerEndpoint["turnstile"] = srv.URL
	t.Cleanup(func() { providerEndpoint["turnstile"] = prev })

	s.cfg.Challenge.CaptchaFallback.Provider = "turnstile"
	s.cfg.Challenge.CaptchaFallback.SiteKey = "test-site-key"
	s.cfg.Challenge.CaptchaFallback.SecretKey = "test-secret"
	s.cfg.Challenge.CaptchaFallback.Timeout = 2 * time.Second
	p, err := NewCaptchaProvider("turnstile", "test-secret", 2*time.Second)
	if err != nil {
		t.Fatalf("NewCaptchaProvider: %v", err)
	}
	s.captcha = p
	return srv.URL
}

func TestHandleChallengeBypassesViaAdminCookie(t *testing.T) {
	s, list := newServerForTest(t)
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	s.cfg.Challenge.VerifiedSession.CookieName = "csm_admin_session"
	list.Add("1.2.3.4", "test", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "1.2.3.4:55000"
	req.AddCookie(&http.Cookie{Name: "csm_admin_session", Value: signer.Issue("1.2.3.4")})
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if list.Contains("1.2.3.4") {
		t.Fatal("admin-cookie bypass did not clear the pending challenge")
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "Verified") {
		t.Errorf("body did not include verified page: %q", body)
	}
}

func TestHandleChallengeNoBypassWhenCookieIPMismatch(t *testing.T) {
	s, list := newServerForTest(t)
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	s.cfg.Challenge.VerifiedSession.CookieName = "csm_admin_session"
	list.Add("9.9.9.9", "test", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "9.9.9.9:55000" // different IP
	req.AddCookie(&http.Cookie{Name: "csm_admin_session", Value: signer.Issue("1.2.3.4")})
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)

	if !list.Contains("9.9.9.9") {
		t.Error("cookie for another IP must not clear this IP's pending challenge")
	}
	body, _ := io.ReadAll(rr.Body)
	// Should be the regular challenge page, not the verified page.
	if !strings.Contains(string(body), "Checking your connection") {
		t.Errorf("body should be PoW page when bypass fails: %q", body[:min(200, len(body))])
	}
}

func TestHandleChallengeBypassesViaVerifiedCrawler(t *testing.T) {
	s, list := newServerForTest(t)
	r := &fakeResolver{
		addr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com."}},
		host: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}},
	}
	s.crawlers = NewCrawlerVerifier([]string{"googlebot"}, time.Minute, r)
	list.Add("66.249.66.1", "test", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "66.249.66.1:55000"
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if list.Contains("66.249.66.1") {
		t.Fatal("verified-crawler bypass did not clear the pending challenge")
	}
}

func TestHandleChallengeNoBypassForSpoofedCrawler(t *testing.T) {
	s, list := newServerForTest(t)
	// PTR matches the suffix but the forward resolves to a different IP.
	r := &fakeResolver{
		addr: map[string][]string{"6.6.6.6": {"fake.googlebot.com."}},
		host: map[string][]string{"fake.googlebot.com": {"66.249.66.1"}},
	}
	s.crawlers = NewCrawlerVerifier([]string{"googlebot"}, time.Minute, r)
	list.Add("6.6.6.6", "test", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "6.6.6.6:55000"
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)

	if !list.Contains("6.6.6.6") {
		t.Error("spoofed crawler must keep its pending challenge")
	}
}

func TestHandleChallengeServesCaptchaNoscriptWhenConfigured(t *testing.T) {
	s, list := newServerForTest(t)
	configureCaptcha(t, s, true)
	list.Add("1.2.3.4", "test", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "1.2.3.4:55000"
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "<noscript>") {
		t.Error("body missing noscript block")
	}
	if !strings.Contains(body, "cf-turnstile") {
		t.Error("body missing turnstile widget marker")
	}
	if !strings.Contains(body, "test-site-key") {
		t.Error("body missing configured site key")
	}
	if !strings.Contains(body, `action="/challenge/captcha-verify"`) {
		t.Error("body missing captcha-verify form action")
	}
}

func TestHandleChallengeOmitsCaptchaWhenNoProvider(t *testing.T) {
	s, list := newServerForTest(t)
	list.Add("1.2.3.4", "test", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "1.2.3.4:55000"
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, "cf-turnstile") || strings.Contains(body, "h-captcha") {
		t.Errorf("captcha widget present without provider: %q", body)
	}
}

func TestHandleCaptchaVerifySuccess(t *testing.T) {
	s, list := newServerForTest(t)
	configureCaptcha(t, s, true)

	ip := "1.2.3.4"
	list.Add(ip, "test", time.Hour)
	nonce := generateNonce()
	token := s.makeToken(ip, nonce)

	form := url.Values{}
	form.Set("nonce", nonce)
	form.Set("token", token)
	form.Set("captcha-token", "visitor-token")
	form.Set("dest", "/dashboard")

	req := httptest.NewRequest(http.MethodPost, "/challenge/captcha-verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":55000"
	rr := httptest.NewRecorder()
	s.handleCaptchaVerify(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if list.Contains(ip) {
		t.Error("accepted CAPTCHA did not clear the pending challenge")
	}
}

func TestHandleCaptchaVerifyProviderRejectsToken(t *testing.T) {
	s, list := newServerForTest(t)
	configureCaptcha(t, s, false) // provider returns success: false

	ip := "1.2.3.4"
	list.Add(ip, "test", time.Hour)
	nonce := generateNonce()
	token := s.makeToken(ip, nonce)

	form := url.Values{}
	form.Set("nonce", nonce)
	form.Set("token", token)
	form.Set("captcha-token", "bad-token")

	req := httptest.NewRequest(http.MethodPost, "/challenge/captcha-verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":55000"
	rr := httptest.NewRecorder()
	s.handleCaptchaVerify(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
	if !list.Contains(ip) {
		t.Error("rejected CAPTCHA must keep the pending challenge")
	}
}

func TestHandleCaptchaVerifyProviderRejectDoesNotConsumeNonce(t *testing.T) {
	s, list := newServerForTest(t)
	var success atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": success.Load()})
	}))
	t.Cleanup(srv.Close)
	prev := providerEndpoint["turnstile"]
	providerEndpoint["turnstile"] = srv.URL
	t.Cleanup(func() { providerEndpoint["turnstile"] = prev })

	s.cfg.Challenge.CaptchaFallback.Provider = "turnstile"
	s.cfg.Challenge.CaptchaFallback.SiteKey = "test-site-key"
	s.cfg.Challenge.CaptchaFallback.SecretKey = "test-secret"
	s.cfg.Challenge.CaptchaFallback.Timeout = 2 * time.Second
	p, err := NewCaptchaProvider("turnstile", "test-secret", 2*time.Second)
	if err != nil {
		t.Fatalf("NewCaptchaProvider: %v", err)
	}
	s.captcha = p

	ip := "1.2.3.4"
	list.Add(ip, "test", time.Hour)
	nonce := generateNonce()
	token := s.makeToken(ip, nonce)
	post := func(captchaToken string) *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set("nonce", nonce)
		form.Set("token", token)
		form.Set("captcha-token", captchaToken)
		req := httptest.NewRequest(http.MethodPost, "/challenge/captcha-verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip + ":55000"
		rr := httptest.NewRecorder()
		s.handleCaptchaVerify(rr, req)
		return rr
	}

	if rr := post("bad-token"); rr.Code != http.StatusForbidden {
		t.Fatalf("failed CAPTCHA status = %d, want 403", rr.Code)
	}
	if !list.Contains(ip) {
		t.Fatal("failed CAPTCHA must keep the pending challenge")
	}

	success.Store(true)
	if rr := post("visitor-token"); rr.Code != http.StatusOK {
		t.Fatalf("retry after failed CAPTCHA status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if list.Contains(ip) {
		t.Fatal("retry that passed did not clear the pending challenge")
	}
}

func TestHandleCaptchaVerifyNotFoundWhenDisabled(t *testing.T) {
	s, _ := newServerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/challenge/captcha-verify", strings.NewReader("foo=bar"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:55000"
	rr := httptest.NewRecorder()
	s.handleCaptchaVerify(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when CAPTCHA disabled", rr.Code)
	}
}

func TestHandleCaptchaVerifyReplayRejected(t *testing.T) {
	s, list := newServerForTest(t)
	configureCaptcha(t, s, true)

	ip := "1.2.3.4"
	list.Add(ip, "test", time.Hour)
	nonce := generateNonce()
	token := s.makeToken(ip, nonce)
	form := url.Values{}
	form.Set("nonce", nonce)
	form.Set("token", token)
	form.Set("captcha-token", "ok")

	first := httptest.NewRequest(http.MethodPost, "/challenge/captcha-verify", strings.NewReader(form.Encode()))
	first.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	first.RemoteAddr = ip + ":55000"
	rr1 := httptest.NewRecorder()
	s.handleCaptchaVerify(rr1, first)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first status = %d", rr1.Code)
	}

	// Listed again by a later signal, the visitor replays the spent nonce.
	list.Add(ip, "test", time.Hour)
	second := httptest.NewRequest(http.MethodPost, "/challenge/captcha-verify", strings.NewReader(form.Encode()))
	second.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	second.RemoteAddr = ip + ":55000"
	rr2 := httptest.NewRecorder()
	s.handleCaptchaVerify(rr2, second)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("second status = %d, want 403 (replay)", rr2.Code)
	}
}

func TestHandleAdminTokenIssuesCookieOnSuccess(t *testing.T) {
	s, _ := newServerForTest(t)
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	s.cfg.Challenge.VerifiedSession.AdminSecret = "the-secret"
	s.cfg.Challenge.VerifiedSession.CookieName = "csm_admin_session"

	form := url.Values{}
	form.Set("secret", "the-secret")
	req := httptest.NewRequest(http.MethodPost, "/challenge/admin-token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:55000"
	rr := httptest.NewRecorder()
	s.handleAdminToken(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rr.Code)
	}
	resp := rr.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no Set-Cookie header")
	}
	var got *http.Cookie
	for _, c := range cookies {
		if c.Name == "csm_admin_session" {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatalf("admin cookie not set; got %v", cookies)
	}
	if !got.Secure || !got.HttpOnly {
		t.Errorf("cookie not Secure/HttpOnly: %+v", got)
	}
	if err := signer.Verify(got.Value, "1.2.3.4"); err != nil {
		t.Errorf("issued cookie failed signer Verify: %v", err)
	}
}

func TestHandleAdminTokenForbidsWrongSecret(t *testing.T) {
	s, _ := newServerForTest(t)
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	s.cfg.Challenge.VerifiedSession.AdminSecret = "the-secret"

	form := url.Values{}
	form.Set("secret", "wrong")
	req := httptest.NewRequest(http.MethodPost, "/challenge/admin-token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:55000"
	rr := httptest.NewRecorder()
	s.handleAdminToken(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestHandleAdminTokenNotFoundWhenDisabled(t *testing.T) {
	s, _ := newServerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/challenge/admin-token", strings.NewReader("secret=anything"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:55000"
	rr := httptest.NewRecorder()
	s.handleAdminToken(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when sessions disabled", rr.Code)
	}
}

func TestHandleAdminTokenRateLimitsBruteForce(t *testing.T) {
	s, _ := newServerForTest(t)
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	s.cfg.Challenge.VerifiedSession.AdminSecret = "the-secret"

	postWith := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/challenge/admin-token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "1.2.3.4:55000"
		rr := httptest.NewRecorder()
		s.handleAdminToken(rr, req)
		return rr
	}

	// Burn through the failure budget with wrong secrets.
	for i := 0; i < adminMaxFailuresInWindow; i++ {
		rr := postWith("secret=wrong")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("attempt %d status = %d, want 403", i, rr.Code)
		}
	}
	// Next attempt -- even with the correct secret -- must be 429.
	if rr := postWith("secret=the-secret"); rr.Code != http.StatusTooManyRequests {
		t.Errorf("post-budget status = %d, want 429", rr.Code)
	}
}

func TestHandleAdminTokenSuccessClearsRateLimit(t *testing.T) {
	s, _ := newServerForTest(t)
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	s.cfg.Challenge.VerifiedSession.AdminSecret = "the-secret"

	postWith := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/challenge/admin-token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "1.2.3.4:55000"
		rr := httptest.NewRecorder()
		s.handleAdminToken(rr, req)
		return rr
	}

	// A few wrong tries (under the budget), then a correct one.
	for i := 0; i < adminMaxFailuresInWindow-1; i++ {
		_ = postWith("secret=wrong")
	}
	if rr := postWith("secret=the-secret"); rr.Code != http.StatusNoContent {
		t.Fatalf("under-budget correct attempt status = %d, want 204", rr.Code)
	}
	// Failure log should now be cleared, so we can burn the full budget again.
	for i := 0; i < adminMaxFailuresInWindow; i++ {
		rr := postWith("secret=wrong")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("post-success attempt %d status = %d, want 403", i, rr.Code)
		}
	}
}

func TestServerCleanExpiredPrunesAdminFailures(t *testing.T) {
	s, _ := newServerForTest(t)
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	s.cfg.Challenge.VerifiedSession.AdminSecret = "the-secret"

	// Inject an aged-out failure directly so we don't need to wait
	// the full adminFailureWindow in the test.
	s.adminFailures["1.2.3.4"] = []time.Time{time.Now().Add(-2 * adminFailureWindow)}
	s.adminFailures["5.5.5.5"] = []time.Time{time.Now()} // recent, must survive

	s.CleanExpired()

	if _, ok := s.adminFailures["1.2.3.4"]; ok {
		t.Error("aged-out failure entry not pruned")
	}
	if _, ok := s.adminFailures["5.5.5.5"]; !ok {
		t.Error("recent failure entry incorrectly pruned")
	}
}

func TestServerCleanExpiredEvictsCrawlerCache(t *testing.T) {
	s, _ := newServerForTest(t)
	r := &fakeResolver{
		addr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com."}},
		host: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}},
	}
	s.crawlers = NewCrawlerVerifier([]string{"googlebot"}, time.Minute, r)

	// Populate the cache, then wind back the entry's expiry.
	if !s.crawlers.Verified(context.Background(), "66.249.66.1") {
		t.Fatal("Verified = false")
	}
	s.crawlers.mu.Lock()
	e := s.crawlers.cache["66.249.66.1"]
	e.expires = time.Now().Add(-time.Hour)
	s.crawlers.cache["66.249.66.1"] = e
	s.crawlers.mu.Unlock()

	s.CleanExpired()

	s.crawlers.mu.Lock()
	_, ok := s.crawlers.cache["66.249.66.1"]
	s.crawlers.mu.Unlock()
	if ok {
		t.Error("expired crawler cache entry not evicted by CleanExpired")
	}
}

func TestHandleAdminTokenForbidsEmptyAdminSecret(t *testing.T) {
	s, _ := newServerForTest(t)
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	// AdminSecret intentionally left empty -- a misconfigured deployment
	// must not accept any caller.

	form := url.Values{}
	form.Set("secret", "")
	req := httptest.NewRequest(http.MethodPost, "/challenge/admin-token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:55000"
	rr := httptest.NewRecorder()
	s.handleAdminToken(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 with empty admin_secret", rr.Code)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// silence unused-import alarm when context isn't used by every assert.
var _ = context.Background
