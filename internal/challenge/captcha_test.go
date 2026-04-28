package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewCaptchaProviderEmptyNameMeansOff(t *testing.T) {
	p, err := NewCaptchaProvider("", "secret", time.Second)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if p != nil {
		t.Errorf("provider = %v, want nil for empty name", p)
	}
}

func TestNewCaptchaProviderUnknownNameRejected(t *testing.T) {
	_, err := NewCaptchaProvider("recaptcha", "s", time.Second)
	if err == nil {
		t.Fatal("err = nil, want unknown-provider error")
	}
}

func TestNewCaptchaProviderEmptySecretRejected(t *testing.T) {
	_, err := NewCaptchaProvider("turnstile", "", time.Second)
	if err == nil {
		t.Fatal("err = nil, want missing-secret error")
	}
}

// withFakeProvider points the named provider at a test server for the
// duration of the test, restoring the live URL afterwards. Lets the
// captcha tests run without hitting the real Cloudflare/hCaptcha
// endpoints.
func withFakeProvider(t *testing.T, name string, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	prev, ok := providerEndpoint[name]
	providerEndpoint[name] = srv.URL
	t.Cleanup(func() {
		if ok {
			providerEndpoint[name] = prev
		} else {
			delete(providerEndpoint, name)
		}
	})
	return srv.URL
}

func TestCaptchaProviderVerifySuccess(t *testing.T) {
	var gotForm url.Values
	withFakeProvider(t, "turnstile", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	p, err := NewCaptchaProvider("turnstile", "secret-key", time.Second)
	if err != nil {
		t.Fatalf("NewCaptchaProvider: %v", err)
	}

	ok, err := p.Verify(context.Background(), "visitor-token", "1.2.3.4")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify returned false on success")
	}
	if got := gotForm.Get("secret"); got != "secret-key" {
		t.Errorf("secret form field = %q, want secret-key", got)
	}
	if got := gotForm.Get("response"); got != "visitor-token" {
		t.Errorf("response form field = %q, want visitor-token", got)
	}
	if got := gotForm.Get("remoteip"); got != "1.2.3.4" {
		t.Errorf("remoteip form field = %q, want 1.2.3.4", got)
	}
}

func TestCaptchaProviderVerifyFailure(t *testing.T) {
	withFakeProvider(t, "hcaptcha", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": false})
	})

	p, err := NewCaptchaProvider("hcaptcha", "secret", time.Second)
	if err != nil {
		t.Fatalf("NewCaptchaProvider: %v", err)
	}
	ok, err := p.Verify(context.Background(), "bad-token", "")
	if err != nil {
		t.Errorf("Verify err = %v, want nil for accepted-but-failed", err)
	}
	if ok {
		t.Error("Verify returned true on provider failure response")
	}
}

func TestCaptchaProviderVerifyEmptyTokenRejected(t *testing.T) {
	p, err := NewCaptchaProvider("turnstile", "secret", time.Second)
	if err != nil {
		t.Fatalf("NewCaptchaProvider: %v", err)
	}
	_, err = p.Verify(context.Background(), "", "1.2.3.4")
	if err == nil {
		t.Fatal("Verify err = nil for empty token, want error")
	}
}

func TestCaptchaProviderVerifyNon200ReturnsError(t *testing.T) {
	withFakeProvider(t, "turnstile", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	p, err := NewCaptchaProvider("turnstile", "secret", time.Second)
	if err != nil {
		t.Fatalf("NewCaptchaProvider: %v", err)
	}
	_, err = p.Verify(context.Background(), "token", "")
	if err == nil {
		t.Fatal("Verify err = nil on 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want it to mention status code", err)
	}
}

func TestCaptchaProviderVerifyContextCanceled(t *testing.T) {
	withFakeProvider(t, "turnstile", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})
	p, err := NewCaptchaProvider("turnstile", "secret", time.Second)
	if err != nil {
		t.Fatalf("NewCaptchaProvider: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = p.Verify(ctx, "token", "")
	if err == nil {
		t.Fatal("Verify err = nil for cancelled context")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") {
		t.Errorf("err = %v, want context cancellation", err)
	}
}
