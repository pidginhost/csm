package verdict

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
		body, _ := json.Marshal(Response{
			Verdict:  "block",
			TenantID: "tenant-99",
		})
		w.Header().Set("X-CSM-Signature", signResponse(secret, body))
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
		body, _ := json.Marshal(Response{Verdict: "block"})
		w.Header().Set("X-CSM-Signature", signResponse("from-env", body))
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

func TestClient_AllowVerdictParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Verdict: "allow", TenantID: "t-1"})
	}))
	defer srv.Close()

	c := New(Config{URL: srv.URL, Timeout: time.Second})
	resp, err := c.Ask(context.Background(), Request{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != "allow" || resp.TenantID != "t-1" {
		t.Fatalf("unexpected response %+v", resp)
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

// signResponse mirrors the X-CSM-Signature scheme over the response body.
// Tests reuse it to fake a well-signed panel reply.
func signResponse(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// TestClient_AcceptsSignedResponse: with a secret configured and a panel
// that signs its response body, the client accepts the verdict.
func TestClient_AcceptsSignedResponse(t *testing.T) {
	secret := "panel-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(Response{Verdict: "allow", TenantID: "t-9"})
		w.Header().Set("X-CSM-Signature", signResponse(secret, body))
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
// configured, an unsigned response must be rejected to prevent MITM
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
		// Sign with the WRONG secret, simulating MITM.
		w.Header().Set("X-CSM-Signature", signResponse("not-the-real-secret", body))
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
// distinguish panel from MITM and proceeds (matches request-side semantics).
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
