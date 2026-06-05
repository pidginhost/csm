package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func writeSigned(w http.ResponseWriter, priv ed25519.PrivateKey, payload []byte, kind string) {
	sig := ed25519.Sign(priv, payload)
	w.Header().Set("X-CSM-Signature", "ed25519="+hex.EncodeToString(sig))
	w.Header().Set("X-CSM-Kind", kind)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func TestPullerColdSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snapBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["since"]; ok {
			t.Errorf("cold pull sent since query: %q", r.URL.RawQuery)
		}
		writeSigned(w, priv, snapBytes, "snapshot")
	}))
	defer srv.Close()

	p := NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub))
	got, changed, err := p.Refresh(context.Background(), ScoredSnapshot{})
	if err != nil || !changed {
		t.Fatalf("cold pull: changed=%v err=%v", changed, err)
	}
	if got.Version != 7 || NewSet(got).Len() != 1 {
		t.Fatalf("snapshot = %+v", got)
	}
}

func TestPullerAppliesDiff(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := ScoredSnapshot{Version: 1, Entries: []ScoredEntry{
		{IP: "203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}}
	diffBytes, _ := MarshalScoredDiff(ScoredDiff{
		FromVersion: 1, ToVersion: 2,
		Added: []ScoredEntry{{IP: "203.0.113.9", Score: 55, Classes: []Class{ClassBruteforce}, LastSeen: setTS}},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query()["since"]; len(got) != 1 || got[0] != "1" {
			t.Errorf("since = %q, want exactly 1", got)
		}
		writeSigned(w, priv, diffBytes, "diff")
	}))
	defer srv.Close()

	p := NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub))
	got, changed, err := p.Refresh(context.Background(), base)
	if err != nil || !changed {
		t.Fatalf("diff pull: changed=%v err=%v", changed, err)
	}
	if got.Version != 2 || NewSet(got).Len() != 2 {
		t.Fatalf("after diff = %+v", got)
	}
}

func TestPullerNotModified(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := &trackingBody{}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotModified,
			Header:     make(http.Header),
			Body:       body,
		}, nil
	})}
	p := NewPuller(client, "https://example.invalid/decisions", hex.EncodeToString(pub))
	cur := ScoredSnapshot{Version: 5}
	got, changed, err := p.Refresh(context.Background(), cur)
	if err != nil || changed || got.Version != 5 {
		t.Fatalf("304: changed=%v err=%v ver=%d", changed, err, got.Version)
	}
	if body.read {
		t.Fatal("304 response body was read")
	}
}

func TestPullerRejectsBadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader) // wrong signer
	snapBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeSigned(w, otherPriv, snapBytes, "snapshot")
	}))
	defer srv.Close()
	p := NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub))
	if _, _, err := p.Refresh(context.Background(), ScoredSnapshot{}); err != ErrSetSignature {
		t.Fatalf("got %v, want ErrSetSignature", err)
	}
}

func TestPullerRejectsMissingOrGarbageSignatureHeader(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	snapBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	tests := []struct {
		name      string
		signature string
	}{
		{name: "missing"},
		{name: "garbage", signature: "garbage"},
		{name: "wrong scheme", signature: "hmac=00"},
		{name: "bad hex", signature: "ed25519=not-hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.signature != "" {
					w.Header().Set("X-CSM-Signature", tt.signature)
				}
				w.Header().Set("X-CSM-Kind", "snapshot")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(snapBytes)
			}))
			defer srv.Close()

			p := NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub))
			if _, _, err := p.Refresh(context.Background(), ScoredSnapshot{}); err != ErrSetSignature {
				t.Fatalf("got %v, want ErrSetSignature", err)
			}
		})
	}
}

func TestPullerDiffVersionGapErrors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Server returns a diff from version 9, but our cache is at 1: gap.
	diffBytes, _ := MarshalScoredDiff(ScoredDiff{
		FromVersion: 9, ToVersion: 10,
		Added: []ScoredEntry{{IP: "203.0.113.9", Score: 55, Classes: []Class{ClassBruteforce}, LastSeen: setTS}},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeSigned(w, priv, diffBytes, "diff")
	}))
	defer srv.Close()
	p := NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub))
	if _, _, err := p.Refresh(context.Background(), ScoredSnapshot{Version: 1}); err != ErrSetVersionGap {
		t.Fatalf("got %v, want ErrSetVersionGap (caller retries full)", err)
	}
}

func TestPullerBadStatus(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub))
	if _, _, err := p.Refresh(context.Background(), ScoredSnapshot{}); err != ErrPullStatus {
		t.Fatalf("got %v, want ErrPullStatus", err)
	}
}

func TestPullerRejectsOversizedBody(t *testing.T) {
	if _, err := readScoredSetBody(strings.NewReader("abcd"), 3); err != ErrPullBodyTooLarge {
		t.Fatalf("got %v, want ErrPullBodyTooLarge", err)
	}
}

func TestPullerRejectsMalformedSinceURL(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewPuller(srv.Client(), srv.URL+"/decisions?token=a;b", hex.EncodeToString(pub))
	if _, changed, err := p.Refresh(context.Background(), ScoredSnapshot{Version: 1}); err == nil || changed {
		t.Fatalf("changed=%v err=%v, want malformed URL error", changed, err)
	}
	if called {
		t.Fatal("server was called after malformed query")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingBody struct {
	read bool
}

func (b *trackingBody) Read([]byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

func (b *trackingBody) Close() error {
	return nil
}
