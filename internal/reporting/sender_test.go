package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	now := time.Unix(1_700_000_000, 0).UTC()
	return func() time.Time { return now }
}

// verifyingServer reconstructs the envelope from request headers and body and
// verifies the signature, mirroring the central ingest path.
func verifyingServer(t *testing.T, pub ed25519.PublicKey, secret []byte, status int) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		tsRaw := r.Header.Get("X-CSM-Timestamp")
		ts, _ := strconv.ParseInt(tsRaw, 10, 64)
		env := Envelope{
			NodeID:    r.Header.Get("X-CSM-Node"),
			KeyID:     r.Header.Get("X-CSM-Key"),
			Method:    r.Method,
			Path:      r.URL.Path,
			BodyHash:  HashBody(body),
			Timestamp: ts,
			Nonce:     r.Header.Get("X-CSM-Nonce"),
		}
		msg, err := env.canonical()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		scheme, hexSig, _ := strings.Cut(r.Header.Get("X-CSM-Signature"), "=")
		sig, _ := hex.DecodeString(hexSig)
		ok := false
		switch scheme {
		case "ed25519":
			ok = ed25519.Verify(pub, msg, sig)
		case "sha256":
			mac := hmac.New(sha256.New, secret)
			_, _ = mac.Write(msg)
			ok = hmac.Equal(sig, mac.Sum(nil))
		}
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
	})
	return httptest.NewTLSServer(h)
}

func TestSendEd25519Verifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := verifyingServer(t, pub, nil, http.StatusAccepted)
	defer srv.Close()

	s := NewSender(srv.Client(), fixedClock())
	tgt := Target{Name: "central", URL: srv.URL + "/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	if err := s.Send(context.Background(), tgt, []byte(`{"ip":"203.0.113.5"}`)); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestSendHMACVerifies(t *testing.T) {
	secret := []byte("collector-secret")
	srv := verifyingServer(t, nil, secret, http.StatusAccepted)
	defer srv.Close()

	s := NewSender(srv.Client(), fixedClock())
	tgt := Target{Name: "priv", URL: srv.URL + "/report", Transport: TransportHMAC, NodeID: "n1", KeyID: "k1", HMACSecret: secret}
	if err := s.Send(context.Background(), tgt, []byte(`{"ip":"203.0.113.5"}`)); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestSendTreatsConflictAsSuccess(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := verifyingServer(t, pub, nil, http.StatusConflict)
	defer srv.Close()
	s := NewSender(srv.Client(), fixedClock())
	tgt := Target{URL: srv.URL + "/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	if err := s.Send(context.Background(), tgt, []byte(`{}`)); err != nil {
		t.Fatalf("409 should be success: %v", err)
	}
}

func TestSendRejectsServerError(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := verifyingServer(t, pub, nil, http.StatusInternalServerError)
	defer srv.Close()
	s := NewSender(srv.Client(), fixedClock())
	tgt := Target{URL: srv.URL + "/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	if err := s.Send(context.Background(), tgt, []byte(`{}`)); err == nil {
		t.Fatal("expected rejection on 500")
	}
}

func TestSendRejectsInsecureURL(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := NewSender(nil, fixedClock())
	tgt := Target{URL: "http://collector.example.com/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	if err := s.Send(context.Background(), tgt, []byte(`{}`)); err != ErrInsecureURL {
		t.Fatalf("got %v, want ErrInsecureURL", err)
	}
}

func TestSendAllowsLoopbackHTTP(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Plain-HTTP loopback server (local collector).
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts, _ := strconv.ParseInt(r.Header.Get("X-CSM-Timestamp"), 10, 64)
		env := Envelope{NodeID: r.Header.Get("X-CSM-Node"), KeyID: r.Header.Get("X-CSM-Key"), Method: r.Method, Path: r.URL.Path, BodyHash: HashBody(body), Timestamp: ts, Nonce: r.Header.Get("X-CSM-Nonce")}
		msg, _ := env.canonical()
		_, hexSig, _ := strings.Cut(r.Header.Get("X-CSM-Signature"), "=")
		sig, _ := hex.DecodeString(hexSig)
		if !ed25519.Verify(pub, msg, sig) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	srv := httptest.NewServer(h) // http://127.0.0.1:port
	defer srv.Close()
	s := NewSender(srv.Client(), fixedClock())
	tgt := Target{URL: srv.URL + "/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	if err := s.Send(context.Background(), tgt, []byte(`{"ip":"203.0.113.5"}`)); err != nil {
		t.Fatalf("loopback http send: %v", err)
	}
}

func TestSendUnknownTransport(t *testing.T) {
	s := NewSender(nil, fixedClock())
	tgt := Target{URL: "https://x.example/report", Transport: Transport("bogus"), NodeID: "n1", KeyID: "k1"}
	if err := s.Send(context.Background(), tgt, []byte(`{}`)); err == nil {
		t.Fatal("expected error for unknown transport")
	}
}
