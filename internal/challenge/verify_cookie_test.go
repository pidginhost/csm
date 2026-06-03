package challenge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mintVerifyCookie drives a successful verification (via the admin-cookie
// bypass) and returns the csm_verified cookie the server issued for ip.
func mintVerifyCookie(t *testing.T, s *Server, ip string) *http.Cookie {
	t.Helper()
	signer, err := NewAdminSessionSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.sessionSigner = signer
	s.cfg.Challenge.VerifiedSession.Enabled = true
	s.cfg.Challenge.VerifiedSession.CookieName = "csm_admin_session"

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = ip + ":55000"
	req.AddCookie(&http.Cookie{Name: "csm_admin_session", Value: signer.Issue(ip)})
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)

	for _, c := range rr.Result().Cookies() {
		if c.Name == "csm_verified" && c.Value != "" {
			return c
		}
	}
	t.Fatal("no csm_verified cookie issued by markVerified")
	return nil
}

// A visitor who already passed the challenge presents the csm_verified cookie
// on the next request and must bypass the PoW gate, not solve it again.
func TestHandleChallengeBypassesViaVerifyCookie(t *testing.T) {
	s, unblocker := newServerForTest(t)
	ip := "1.2.3.4"
	verifyCookie := mintVerifyCookie(t, s, ip)

	// Strip the admin session so only the verify cookie can drive the bypass.
	s.sessionSigner = nil

	callsBefore := unblocker.calls
	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = ip + ":55000"
	req.AddCookie(verifyCookie)
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Verified") {
		t.Fatalf("verify cookie did not bypass PoW; body=%q", body[:min(240, len(body))])
	}
	if unblocker.calls != callsBefore+1 {
		t.Fatalf("bypass did not re-allow IP; calls=%d want %d", unblocker.calls, callsBefore+1)
	}
}

// A verify cookie is bound to one IP. Presenting it from a different IP must
// fall through to the PoW page (stolen-cookie / different-network protection).
func TestHandleChallengeVerifyCookieIPMismatchNoBypass(t *testing.T) {
	s, unblocker := newServerForTest(t)
	verifyCookie := mintVerifyCookie(t, s, "1.2.3.4")
	s.sessionSigner = nil

	callsBefore := unblocker.calls
	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "9.9.9.9:55000" // different IP than the cookie was issued for
	req.AddCookie(verifyCookie)
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, req)

	if unblocker.calls != callsBefore {
		t.Errorf("verify cookie bypassed for mismatched IP (calls %d -> %d)", callsBefore, unblocker.calls)
	}
	if !strings.Contains(rr.Body.String(), "Checking your connection") {
		t.Errorf("expected PoW page on IP mismatch, got %q", rr.Body.String()[:min(240, rr.Body.Len())])
	}
}

// handleGate must report 204 (no challenge needed) when a valid verify cookie
// is presented for an IP that is otherwise on the challenge list.
func TestHandleGateBypassesViaVerifyCookie(t *testing.T) {
	s, _ := newServerForTest(t)
	ip := "1.2.3.4"
	verifyCookie := mintVerifyCookie(t, s, ip)
	s.sessionSigner = nil
	s.ipList.Add(ip, "test", time.Hour)

	// Sanity: without the cookie the IP is challenged (401).
	bare := httptest.NewRequest(http.MethodGet, "/challenge/gate", nil)
	bare.RemoteAddr = ip + ":40000"
	rrBare := httptest.NewRecorder()
	s.handleGate(rrBare, bare)
	if rrBare.Code != http.StatusUnauthorized {
		t.Fatalf("listed IP without cookie: status = %d, want 401", rrBare.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/challenge/gate", nil)
	req.RemoteAddr = ip + ":40001"
	req.AddCookie(verifyCookie)
	rr := httptest.NewRecorder()
	s.handleGate(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("verify cookie at gate: status = %d, want 204", rr.Code)
	}
}
