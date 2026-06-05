package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		if r.URL.Query().Get("since") != "1" {
			t.Errorf("since = %q, want 1", r.URL.Query().Get("since"))
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	p := NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub))
	cur := ScoredSnapshot{Version: 5}
	got, changed, err := p.Refresh(context.Background(), cur)
	if err != nil || changed || got.Version != 5 {
		t.Fatalf("304: changed=%v err=%v ver=%d", changed, err, got.Version)
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
