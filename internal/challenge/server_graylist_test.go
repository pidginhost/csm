package challenge

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// httptest.NewRequest sets RemoteAddr to 192.0.2.1:1234; that is the client
// every request in this file arrives from.
const graylistTestIP = "192.0.2.1"

func solveTestPoW(t *testing.T, nonce string, difficulty int) string {
	t.Helper()
	for i := 0; i < 1_000_000; i++ {
		if sol := strconv.Itoa(i); verifyPoW(nonce, sol, difficulty) {
			return sol
		}
	}
	t.Fatal("could not solve the test PoW within 1M attempts")
	return ""
}

func verifyForm(s *Server, ip string) url.Values {
	nonce := generateNonce()
	return url.Values{
		"nonce":    {nonce},
		"token":    {s.makeToken(ip, nonce)},
		"solution": {"0"},
	}
}

// Only a visitor the webserver actually sent here has anything to verify.
// Serving the puzzle to anyone else lets an arbitrary client convert one cheap
// hash search into a verified session it was never asked for.
func TestChallengePageOnlyForListedIP(t *testing.T) {
	s, list := newTestServer(t, baseCfg())

	rec := httptest.NewRecorder()
	s.handleChallenge(rec, httptest.NewRequest(http.MethodGet, "/challenge", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unlisted IP: status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "nonce") {
		t.Fatal("unlisted IP was served the PoW page")
	}

	list.Add(graylistTestIP, "test", time.Hour)
	rec = httptest.NewRecorder()
	s.handleChallenge(rec, httptest.NewRequest(http.MethodGet, "/challenge", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("listed IP: status = %d, want 200", rec.Code)
	}
}

func TestVerifyOnlyForListedIP(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.Difficulty = 1
	s, list := newTestServer(t, cfg)

	form := verifyForm(s, graylistTestIP)
	form.Set("solution", solveTestPoW(t, form.Get("nonce"), 1))
	req := httptest.NewRequest(http.MethodPost, "/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.handleVerify(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unlisted IP with a valid solution: status = %d, want 404", rec.Code)
	}

	list.Add(graylistTestIP, "test", time.Hour)
	form = verifyForm(s, graylistTestIP)
	form.Set("solution", solveTestPoW(t, form.Get("nonce"), 1))
	req = httptest.NewRequest(http.MethodPost, "/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	s.handleVerify(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("listed IP with a valid solution: status = %d, want 200", rec.Code)
	}
	if list.Contains(graylistTestIP) {
		t.Fatal("passing the challenge must remove the IP from the challenge list")
	}
}

func TestCaptchaVerifyOnlyForListedIP(t *testing.T) {
	s, list := newTestServer(t, baseCfg())
	configureCaptcha(t, s, true)

	form := verifyForm(s, graylistTestIP)
	form.Set("captcha-token", "provider-says-yes")
	req := httptest.NewRequest(http.MethodPost, "/challenge/captcha-verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.handleCaptchaVerify(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unlisted IP with an accepted CAPTCHA: status = %d, want 404", rec.Code)
	}

	list.Add(graylistTestIP, "test", time.Hour)
	form = verifyForm(s, graylistTestIP)
	form.Set("captcha-token", "provider-says-yes")
	req = httptest.NewRequest(http.MethodPost, "/challenge/captcha-verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	s.handleCaptchaVerify(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("listed IP with an accepted CAPTCHA: status = %d, want 200", rec.Code)
	}
	if list.Contains(graylistTestIP) {
		t.Fatal("passing the CAPTCHA must remove the IP from the challenge list")
	}
}
