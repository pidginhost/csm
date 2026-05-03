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
		_ = json.NewEncoder(w).Encode(Response{
			Verdict:  "block",
			TenantID: "tenant-99",
		})
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
		_ = json.NewEncoder(w).Encode(Response{Verdict: "block"})
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
