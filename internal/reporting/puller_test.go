package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestPullerRejectsNonLoopbackHTTP(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	p := NewPuller(client, "http://198.51.100.10/decisions", hex.EncodeToString(pub))
	if _, changed, err := p.Refresh(context.Background(), ScoredSnapshot{}); err != ErrInsecureURL || changed {
		t.Fatalf("changed=%v err=%v, want ErrInsecureURL", changed, err)
	}
	if called {
		t.Fatal("puller called transport for insecure URL")
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

var pullClock = time.Unix(1700000000, 0)

// goldenNode is the shared test identity from TestSignedGETGoldenVector.
func goldenNode() (Target, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("CSM signed GET interoperability fixture v1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return Target{
		Name: "central", Transport: TransportEd25519,
		NodeID: "n_000000000000000000000001", KeyID: "k_000000000000000000000002",
		Ed25519Key: priv, BearerToken: "must-not-be-sent",
	}, priv.Public().(ed25519.PublicKey)
}

// requireSignedPull checks r carries the node headers once each, no bearer and
// no body, and a signature over GET, its path, an empty body and pullClock. It
// returns the nonce. It runs in the server's handler goroutine, so it reports
// with t.Error, never t.Fatal.
func requireSignedPull(t *testing.T, r *http.Request, node Target, nodePub ed25519.PublicKey) string {
	t.Helper()
	if r.Header.Get("Authorization") != "" {
		t.Error("pull sent the report target's bearer token")
	}
	if body, _ := io.ReadAll(r.Body); len(body) != 0 || r.ContentLength > 0 {
		t.Errorf("pull sent a body: %q", body)
	}
	for _, h := range []string{"X-CSM-Node", "X-CSM-Key", "X-CSM-Timestamp", "X-CSM-Nonce", "X-CSM-Signature"} {
		if n := len(r.Header.Values(h)); n != 1 {
			t.Errorf("%s sent %d times", h, n)
		}
	}
	if r.Header.Get("X-CSM-Node") != node.NodeID || r.Header.Get("X-CSM-Key") != node.KeyID ||
		r.Header.Get("X-CSM-Timestamp") != strconv.FormatInt(pullClock.Unix(), 10) {
		t.Errorf("identity headers = %v", r.Header)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-CSM-Signature"), "ed25519="))
	if err != nil {
		t.Errorf("signature header: %v", err)
		return ""
	}
	nonce := r.Header.Get("X-CSM-Nonce")
	e := Envelope{NodeID: node.NodeID, KeyID: node.KeyID, Method: http.MethodGet, Path: r.URL.Path,
		BodyHash: HashBody(nil), Timestamp: pullClock.Unix(), Nonce: nonce}
	msg, _ := e.canonical()
	if !ed25519.Verify(nodePub, msg, sig) {
		t.Error("pull signature does not verify over GET, the path and an empty body")
	}
	// With the vector's nonce, the same fields give the shared golden bytes.
	e.Nonce = "0123456789abcdef0123456789abcdef"
	if golden, _ := e.canonical(); r.URL.Path == "/decisions" && hex.EncodeToString(golden) != goldenGETCanonical {
		t.Error("signed fields differ from the golden vector")
	}
	return nonce
}

func TestSignedPullSendsOnlyNodeHeaders(t *testing.T) {
	setPub, setPriv, _ := ed25519.GenerateKey(rand.Reader)
	node, nodePub := goldenNode()
	snapBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	var queries []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireSignedPull(t, r, node, nodePub)
		queries = append(queries, r.URL.Query())
		writeSigned(w, setPriv, snapBytes, "snapshot")
	}))
	defer srv.Close()

	p := NewSignedPuller(srv.Client(), srv.URL+"/decisions?since=9&token=x", hex.EncodeToString(setPub), node, func() time.Time { return pullClock })
	if _, _, err := p.Refresh(context.Background(), ScoredSnapshot{}); err != nil {
		t.Fatalf("cold pull: %v", err)
	}
	if _, _, err := p.Refresh(context.Background(), ScoredSnapshot{Version: 7}); err != nil {
		t.Fatalf("warm pull: %v", err)
	}
	if len(queries) != 2 {
		t.Fatalf("requests = %d, want 2", len(queries))
	}
	if _, ok := queries[0]["since"]; ok || queries[0].Get("token") != "x" {
		t.Fatalf("cold query = %v, want no since and the token kept", queries[0])
	}
	if got := queries[1]["since"]; len(got) != 1 || got[0] != "7" || queries[1].Get("token") != "x" {
		t.Fatalf("warm query = %v, want since=7 once and the token kept", queries[1])
	}
}

func TestUnsignedPullSendsNoNodeHeaders(t *testing.T) {
	setPub, setPriv, _ := ed25519.GenerateKey(rand.Reader)
	snapBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSM-Node") != "" || r.Header.Get("X-CSM-Signature") != "" {
			t.Error("unsigned puller sent node headers")
		}
		writeSigned(w, setPriv, snapBytes, "snapshot")
	}))
	defer srv.Close()
	if _, _, err := NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(setPub)).Refresh(context.Background(), ScoredSnapshot{}); err != nil {
		t.Fatal(err)
	}
}

func TestSignedPullFollowsNoRedirect(t *testing.T) {
	setPub, setPriv, _ := ed25519.GenerateKey(rand.Reader)
	node, _ := goldenNode()
	snapBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	landed := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		landed++
		writeSigned(w, setPriv, snapBytes, "snapshot")
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/decisions", http.StatusFound)
	}))
	defer origin.Close()
	client := origin.Client()

	signed := NewSignedPuller(client, origin.URL+"/decisions", hex.EncodeToString(setPub), node, nil)
	if _, _, err := signed.Refresh(context.Background(), ScoredSnapshot{}); !errors.Is(err, ErrPullStatus) {
		t.Fatalf("signed redirect = %v, want ErrPullStatus", err)
	}
	if landed != 0 || client.CheckRedirect != nil {
		t.Fatalf("signed pull followed a redirect (landed=%d) or changed the shared client", landed)
	}
	if _, _, err := NewPuller(client, origin.URL+"/decisions", hex.EncodeToString(setPub)).Refresh(context.Background(), ScoredSnapshot{}); err != nil || landed != 1 {
		t.Fatalf("unsigned pull lost the client's redirect policy: err=%v landed=%d", err, landed)
	}
}

func TestPullUnauthorized(t *testing.T) {
	setPub, _, _ := ed25519.GenerateKey(rand.Reader)
	node, _ := goldenNode()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	current := sampleSnapshot()
	for name, p := range map[string]*Puller{
		"signed":   NewSignedPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(setPub), node, nil),
		"unsigned": NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(setPub)),
	} {
		got, changed, err := p.Refresh(context.Background(), current)
		if !errors.Is(err, ErrPullUnauthorized) || changed || got.Version != current.Version {
			t.Fatalf("%s: got v%d changed=%v err=%v, want ErrPullUnauthorized and the current set", name, got.Version, changed, err)
		}
	}
}

func TestSignedPullerThatCannotSignSendsNothing(t *testing.T) {
	setPub, _, _ := ed25519.GenerateKey(rand.Reader)
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	node, _ := goldenNode()
	node.Ed25519Key = ed25519.PrivateKey{1, 2, 3}
	p := NewSignedPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(setPub), node, nil)
	if _, _, err := p.Refresh(context.Background(), ScoredSnapshot{}); err == nil || called {
		t.Fatalf("err=%v called=%v, want an error and no request", err, called)
	}
}

func TestPullerColdPullRejectsMalformedQuery(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	p := NewPuller(srv.Client(), srv.URL+"/decisions?token=a;b", hex.EncodeToString(pub))
	if _, changed, err := p.Refresh(context.Background(), ScoredSnapshot{}); err == nil || changed || called {
		t.Fatalf("changed=%v err=%v called=%v, want a URL error and no request", changed, err, called)
	}
}
