package verdict

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClient_PostsSignedRequest(t *testing.T) {
	secret := "panel-secret"
	var captured []byte
	var sigHeader string
	var hits int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		captured, _ = io.ReadAll(r.Body)
		sigHeader = r.Header.Get("X-CSM-Signature")
		var req Request
		_ = json.Unmarshal(captured, &req)
		body, _ := json.Marshal(Response{
			Verdict:   "block",
			TenantID:  "tenant-99",
			Nonce:     req.Nonce,
			Timestamp: time.Now().Unix(),
		})
		w.Header().Set("X-CSM-Signature", signPayload(secret, body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: secret, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4", Reason: "bf"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != "block" || resp.TenantID != "tenant-99" {
		t.Fatalf("unexpected response %+v", resp)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 request, got %d", hits)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(captured)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sigHeader != want {
		t.Fatalf("expected sig %q, got %q", want, sigHeader)
	}

	var req Request
	if err := json.Unmarshal(captured, &req); err != nil {
		t.Fatalf("decode captured request: %v", err)
	}
	if len(req.Nonce) != 32 {
		t.Fatalf("nonce length = %d, want 32 hex chars", len(req.Nonce))
	}
	if _, err := hex.DecodeString(req.Nonce); err != nil {
		t.Fatalf("nonce must be hex: %v", err)
	}
	if req.Timestamp == 0 {
		t.Fatal("request timestamp was not populated")
	}
}

func TestClient_FailsClosedWhenNonceGenerationFails(t *testing.T) {
	orig := rand.Reader
	rand.Reader = failingRandReader{}
	t.Cleanup(func() { rand.Reader = orig })

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	_, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err == nil {
		t.Fatal("expected nonce generation error")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("error should mention nonce generation, got %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("callback must not be sent with a fallback nonce")
	}
}

func TestClient_OverwritesCallerNonceAndTimestamp(t *testing.T) {
	secret := "panel-secret"
	var gotReq Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		body, _ := json.Marshal(Response{
			Verdict:   "block",
			Nonce:     gotReq.Nonce,
			Timestamp: time.Now().Unix(),
		})
		w.Header().Set("X-CSM-Signature", signPayload(secret, body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: secret, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{
		IP:        "1.2.3.4",
		Nonce:     "caller-controlled",
		Timestamp: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if gotReq.Nonce == "caller-controlled" {
		t.Fatal("caller-supplied nonce must not be reused")
	}
	if gotReq.Timestamp == 1 {
		t.Fatal("caller-supplied timestamp must not be reused")
	}
	if gotReq.Nonce == "" || gotReq.Timestamp == 0 {
		t.Fatalf("request replay fields were not populated: %+v", gotReq)
	}
}

func TestClient_TimeoutTreatedAsAdvisory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: 30 * time.Millisecond})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected timeout error so caller can fail-open")
	}
}

func TestClient_5xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected error on 5xx")
	}
}

func TestClient_RejectsUnknownVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "downgrade"})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected error on unknown verdict string")
	}
}

func TestClient_ResolvesSecretFromEnv(t *testing.T) {
	const envVar = "TEST_VERDICT_HMAC"
	t.Setenv(envVar, "from-env")

	var sigHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigHeader = r.Header.Get("X-CSM-Signature")
		raw, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(raw, &req)
		body, _ := json.Marshal(Response{Verdict: "block", Nonce: req.Nonce, Timestamp: time.Now().Unix()})
		w.Header().Set("X-CSM-Signature", signPayload("from-env", body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Static secret empty; env should win at Ask time.
	c := New(Config{URL: srv.URL, HMACSecretEnv: envVar, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if sigHeader == "" {
		t.Fatal("expected signature header from env-resolved secret")
	}
}

func TestClient_UsesSameResolvedSecretForRequestAndResponse(t *testing.T) {
	const envVar = "TEST_VERDICT_HMAC_ROTATE"
	t.Setenv(envVar, "first-secret")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := io.ReadAll(r.Body)
		if got, want := r.Header.Get("X-CSM-Signature"), signPayload("first-secret", reqBody); got != want {
			t.Fatalf("request signature = %q, want %q", got, want)
		}
		var req Request
		_ = json.Unmarshal(reqBody, &req)
		body, _ := json.Marshal(Response{Verdict: "block", Nonce: req.Nonce, Timestamp: time.Now().Unix()})
		if err := os.Setenv(envVar, "rotated-secret"); err != nil {
			t.Fatalf("rotate env: %v", err)
		}
		w.Header().Set("X-CSM-Signature", signPayload("first-secret", body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecretEnv: envVar, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err != nil {
		t.Fatalf("response verification must use request secret, got %v", err)
	}
}

func TestClient_RejectsInvalidURLScheme(t *testing.T) {
	c := New(Config{URL: "ftp://example.com/v", Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected error on non-http(s) URL")
	}
}

func TestClient_RejectsURLWithoutHost(t *testing.T) {
	c := New(Config{URL: "https:///verdict", Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected error on URL without host")
	}
}

// With no HMAC secret configured there is no signature or replay protection,
// so an "allow" verdict carries no integrity: an on-path attacker could return
// it on every call and disable auto-blocking. The client must reject it; the
// engine then stays on its default block path. (A signed allow is exercised by
// TestClient_AcceptsSignedResponse.)
func TestClient_RejectsUnsignedAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "allow", TenantID: "t-1"})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected rejection of unsigned allow verdict")
	}
}

func TestClient_AllowUnsignedOptInAcceptsAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "allow", TenantID: "t-1"})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, AllowUnsigned: true, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != "allow" || resp.TenantID != "t-1" {
		t.Fatalf("unexpected response %+v", resp)
	}
}

// An unsigned "block" verdict is safe (it does not weaken the default), so it
// is still accepted without a secret.
func TestClient_AcceptsUnsignedBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "block"})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != "block" {
		t.Fatalf("unsigned block should be accepted, got %+v", resp)
	}
}

func TestClient_Empty200MeansDefaultBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if resp != (Response{}) {
		t.Fatalf("expected empty response for default block, got %+v", resp)
	}
}

func TestClient_RejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "block", Note: strings.Repeat("x", verdictMaxResponseBytes)})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected oversized response error")
	}
}

func TestClient_RejectsTrailingJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"verdict":"block"}{"verdict":"allow"}`)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected trailing JSON error")
	}
}

func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type failingRandReader struct{}

func (failingRandReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

// TestClient_RejectsResponseMissingNonce: when response signing is
// required, the panel must echo the request nonce so a captured old
// reply cannot be replayed on a fresh request.
func TestClient_RejectsResponseMissingNonce(t *testing.T) {
	secret := "panel-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Panel signs a reply that does NOT echo the nonce.
		body, _ := json.Marshal(Response{Verdict: "allow"})
		w.Header().Set("X-CSM-Signature", signPayload(secret, body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: secret, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected replay-protection error when response omits nonce")
	}
}

func TestClient_RejectsResponseMissingTimestamp(t *testing.T) {
	secret := "panel-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		body, _ := json.Marshal(Response{Verdict: "allow", Nonce: req.Nonce})
		w.Header().Set("X-CSM-Signature", signPayload(secret, body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: secret, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected replay-protection error when response omits timestamp")
	}
}

// TestClient_RejectsResponseWithWrongNonce: a captured old reply
// (with the previous nonce) must be rejected even if its signature is
// valid against the same secret.
func TestClient_RejectsResponseWithWrongNonce(t *testing.T) {
	secret := "panel-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(Response{Verdict: "allow", Nonce: "stale-nonce", Timestamp: time.Now().Unix()})
		w.Header().Set("X-CSM-Signature", signPayload(secret, body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: secret, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected replay error when response nonce does not match request nonce")
	}
}

// TestClient_RejectsResponseTimestampSkew: a reply whose timestamp
// is too far from CSM's clock is rejected, defeating long-lived replay
// of a captured allow reply on a fresh request that happens to reuse
// a nonce.
func TestClient_RejectsResponseTimestampSkew(t *testing.T) {
	secret := "panel-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		body, _ := json.Marshal(Response{
			Verdict:   "allow",
			Nonce:     req.Nonce,
			Timestamp: time.Now().Add(-10 * time.Minute).Unix(),
		})
		w.Header().Set("X-CSM-Signature", signPayload(secret, body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: secret, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected skew error for old timestamp reply")
	}
}

// TestClient_AcceptsNonceEcho: the happy path: panel echoes nonce and
// timestamps within skew. Verdict applies.
func TestClient_AcceptsNonceEcho(t *testing.T) {
	secret := "panel-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		body, _ := json.Marshal(Response{
			Verdict:   "allow",
			Nonce:     req.Nonce,
			Timestamp: time.Now().Unix(),
		})
		w.Header().Set("X-CSM-Signature", signPayload(secret, body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: secret, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("happy path: %v", err)
	}
	if resp.Verdict != "allow" {
		t.Errorf("verdict = %q, want allow", resp.Verdict)
	}
}

// TestClient_AcceptsSignedResponse: with a secret configured and a panel
// that signs its response body, the client accepts the verdict.
func TestClient_AcceptsSignedResponse(t *testing.T) {
	secret := "panel-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(raw, &req)
		body, _ := json.Marshal(Response{Verdict: "allow", TenantID: "t-9", Nonce: req.Nonce, Timestamp: time.Now().Unix()})
		w.Header().Set("X-CSM-Signature", signPayload(secret, body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: secret, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("expected accept on signed response, got %v", err)
	}
	if resp.Verdict != "allow" || resp.TenantID != "t-9" {
		t.Fatalf("unexpected response %+v", resp)
	}
}

// TestClient_RejectsUnsignedResponseWhenSecretSet: when an HMAC secret is
// configured, an unsigned response must be rejected to prevent on-path
// downgrade from block to allow.
func TestClient_RejectsUnsignedResponseWhenSecretSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "allow", TenantID: "tenant-attacker"})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: "panel-secret", Timeout: time.Second})
	_, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err == nil {
		t.Fatal("expected rejection of unsigned response when secret is configured")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("error must mention signature for operators, got %v", err)
	}
}

// TestClient_RejectsForgedResponseSignature: wrong signature must be
// rejected (constant-time compare).
func TestClient_RejectsForgedResponseSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(Response{Verdict: "allow"})
		// Sign with the wrong secret, simulating an on-path attacker.
		w.Header().Set("X-CSM-Signature", signPayload("not-the-real-secret", body))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, HMACSecret: "panel-secret", Timeout: time.Second})
	_, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err == nil {
		t.Fatal("expected rejection of forged response signature")
	}
}

// TestClient_OptOutSkipsResponseSignatureCheck: operators can set
// RequireResponseSignature=false during phpanel rollout to keep accepting
// unsigned responses temporarily.
func TestClient_OptOutSkipsResponseSignatureCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "block"})
	}))
	defer srv.Close()

	optOut := false
	c := New(Config{URL: srv.URL, HMACSecret: "panel-secret", RequireResponseSignature: &optOut, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("expected opt-out to skip verify, got %v", err)
	}
	if resp.Verdict != "block" {
		t.Fatalf("unexpected response %+v", resp)
	}
}

// TestClient_NoSecretSkipsResponseSignatureCheck: when no HMAC secret is
// configured at all there is no key to verify against; the client cannot
// distinguish panel from an on-path attacker and proceeds (matches
// request-side semantics).
func TestClient_NoSecretSkipsResponseSignatureCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "block"})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err != nil {
		t.Fatalf("no-secret path must skip verify, got %v", err)
	}
}

// Without a secret the replay checks are skipped for a safe "block" verdict
// (it cannot weaken the default). An unsigned "allow" is a separate matter and
// is rejected outright -- see TestClient_RejectsUnsignedAllow.
func TestClient_NoSecretSkipsResponseReplayCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{
			Verdict:   "block",
			Nonce:     "stale-nonce",
			Timestamp: time.Now().Add(-10 * time.Minute).Unix(),
		})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("no-secret path must skip replay checks for a safe verdict, got %v", err)
	}
	if resp.Verdict != "block" {
		t.Fatalf("verdict = %q, want block", resp.Verdict)
	}
}

// Opt-out only disables the HMAC signature check. A panel that does
// echo nonce in its reply still has to echo the correct one, so a
// captured-then-replayed reply with a stale nonce is rejected.
func TestClient_OptOutStillRejectsWrongNonce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "allow", Nonce: "stale-nonce-from-an-old-reply"})
	}))
	defer srv.Close()

	optOut := false
	c := New(Config{URL: srv.URL, HMACSecret: "panel-secret", RequireResponseSignature: &optOut, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected rejection of mismatched nonce even with signature opt-out")
	}
}

// A panel that echoes a stale timestamp gets rejected even on the
// opt-out path. Skew bound catches replayed-or-cached responses
// regardless of whether the panel signs.
func TestClient_OptOutStillRejectsStaleTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{
			Verdict:   "allow",
			Timestamp: time.Now().Add(-10 * time.Minute).Unix(),
		})
	}))
	defer srv.Close()

	optOut := false
	c := New(Config{URL: srv.URL, HMACSecret: "panel-secret", RequireResponseSignature: &optOut, Timeout: time.Second})
	if _, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"}); err == nil {
		t.Fatal("expected rejection of stale timestamp even with signature opt-out")
	}
}

// A panel that echoes the correct nonce on the opt-out path keeps
// working; the new best-effort check must not break this case.
func TestClient_OptOutAcceptsMatchingNonce(t *testing.T) {
	var capturedReq Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedReq)
		_ = json.NewEncoder(w).Encode(Response{
			Verdict:   "allow",
			Nonce:     capturedReq.Nonce,
			Timestamp: time.Now().Unix(),
		})
	}))
	defer srv.Close()

	optOut := false
	c := New(Config{URL: srv.URL, HMACSecret: "panel-secret", RequireResponseSignature: &optOut, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("opt-out path with matching nonce must succeed, got %v", err)
	}
	if resp.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow", resp.Verdict)
	}
}
