package verdict

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const classSecret = "class-test-secret-value"

// replyWith answers each request with resp built from it, signed with the
// test secret unless unsigned is set.
func replyWith(unsigned bool, resp func(Request) Response) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		body, _ := json.Marshal(resp(req))
		if !unsigned {
			w.Header().Set("X-CSM-Signature", signPayload(classSecret, body))
		}
		_, _ = w.Write(body)
	}
}

func raw(body string, signed bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if signed {
			w.Header().Set("X-CSM-Signature", signPayload(classSecret, []byte(body)))
		}
		_, _ = w.Write([]byte(body))
	}
}

func bound(v string) func(Request) Response {
	return func(req Request) Response {
		return Response{Verdict: v, Nonce: req.Nonce, Timestamp: time.Now().Unix()}
	}
}

// Every failed exchange carries one fixed class (spec 4.4). A caller can
// report the class without the error text, which can hold a URL or panel
// text. Configured signature opt-outs keep working, and no error carries
// the secret.
func TestClientClassifiesFailures(t *testing.T) {
	optOut := false
	cases := []struct {
		name    string
		handler http.HandlerFunc
		cfg     func(url string) Config
		want    ErrorClass
	}{
		{name: "no url", cfg: func(string) Config { return Config{} }, want: ClassConfiguration},
		{name: "bad scheme", cfg: func(string) Config { return Config{URL: "ftp://192.0.2.1/v"} }, want: ClassConfiguration},
		{name: "no host", cfg: func(string) Config { return Config{URL: "http:///v"} }, want: ClassConfiguration},
		{name: "status", handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }, want: ClassHTTPStatus},
		{name: "size", handler: raw(strings.Repeat(" ", verdictMaxResponseBytes+1), true), want: ClassBodySize},
		{name: "malformed", handler: raw(`{"verdict":`, true), want: ClassDecode},
		{name: "trailing", handler: raw(`{"verdict":"block"} {}`, true), want: ClassDecode},
		{name: "unknown verdict", handler: replyWith(false, bound("maybe")), want: ClassProtocol},
		{name: "missing signature", handler: replyWith(true, bound("block")), want: ClassSignature},
		{name: "bad signature", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-CSM-Signature", "sha256=00")
			_, _ = w.Write([]byte(`{}`))
		}, want: ClassSignature},
		{name: "unsigned allow", handler: replyWith(true, bound("allow")), cfg: func(url string) Config { return Config{URL: url} }, want: ClassSignature},
		{name: "nonce mismatch", handler: replyWith(false, func(Request) Response {
			return Response{Verdict: "allow", Nonce: "0123", Timestamp: time.Now().Unix()}
		}), want: ClassReplay},
		{name: "missing nonce", handler: replyWith(false, func(Request) Response { return Response{Verdict: "allow", Timestamp: time.Now().Unix()} }), want: ClassReplay},
		{name: "missing timestamp", handler: replyWith(false, func(req Request) Response { return Response{Verdict: "allow", Nonce: req.Nonce} }), want: ClassReplay},
		{name: "stale timestamp", handler: replyWith(false, func(req Request) Response {
			return Response{Verdict: "allow", Nonce: req.Nonce, Timestamp: time.Now().Add(-time.Hour).Unix()}
		}), want: ClassReplay},
		{name: "opt-out wrong nonce", handler: replyWith(true, func(Request) Response { return Response{Verdict: "block", Nonce: "0123"} }), cfg: func(url string) Config {
			return Config{URL: url, HMACSecret: classSecret, RequireResponseSignature: &optOut}
		}, want: ClassReplay},
		{name: "opt-out unbound allow", handler: replyWith(true, func(Request) Response { return Response{Verdict: "allow"} }), cfg: func(url string) Config {
			return Config{URL: url, HMACSecret: classSecret, RequireResponseSignature: &optOut}
		}, want: ClassReplay},
		{name: "timeout", handler: func(_ http.ResponseWriter, r *http.Request) {
			// The server sees the client leave only once the body is read.
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
		}, cfg: func(url string) Config {
			return Config{URL: url, HMACSecret: classSecret, Timeout: 20 * time.Millisecond}
		}, want: ClassTimeout},
		{name: "opt-out unsigned block", handler: replyWith(true, func(Request) Response { return Response{Verdict: "block"} }), cfg: func(url string) Config {
			return Config{URL: url, HMACSecret: classSecret, RequireResponseSignature: &optOut}
		}},
		{name: "signed allow", handler: replyWith(false, bound("allow"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := ""
			if tc.handler != nil {
				srv := httptest.NewServer(tc.handler)
				t.Cleanup(srv.Close)
				url = srv.URL
			}
			cfg := Config{URL: url, HMACSecret: classSecret, Timeout: time.Second}
			if tc.cfg != nil {
				cfg = tc.cfg(url)
			}
			_, err := New(cfg).Ask(context.Background(), Request{IP: "192.0.2.10", Reason: "CSM auto-block: ssh_brute"})
			if got := ClassOf(err); got != tc.want || (err == nil) != (tc.want == "") {
				t.Fatalf("class %q of %v, want %q", got, err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), classSecret) {
				t.Fatal("an error carries the secret")
			}
		})
	}
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(replyWith(false, bound("block")))
		srv.Close()
		_, err := New(Config{URL: srv.URL, HMACSecret: classSecret, Timeout: time.Second}).Ask(context.Background(), Request{IP: "192.0.2.10"})
		if ClassOf(err) != ClassTransport {
			t.Fatalf("class %q of %v", ClassOf(err), err)
		}
	})
	t.Run("nonce generation", func(t *testing.T) {
		orig := rand.Reader
		rand.Reader = failingRandReader{}
		t.Cleanup(func() { rand.Reader = orig })
		_, err := New(Config{URL: "http://192.0.2.1/v", Timeout: time.Second}).Ask(context.Background(), Request{IP: "192.0.2.10"})
		if ClassOf(err) != ClassNonce {
			t.Fatalf("class %q of %v", ClassOf(err), err)
		}
	})
	if ClassOf(context.Canceled) != "" {
		t.Fatal("an error Ask did not return has a class")
	}
}
