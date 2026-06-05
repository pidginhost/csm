package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSpoolerEnqueueAndDrainDelivers(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Verify the envelope, like the real ingest.
		env := Envelope{
			NodeID: r.Header.Get("X-CSM-Node"), KeyID: r.Header.Get("X-CSM-Key"),
			Method: r.Method, Path: r.URL.Path, BodyHash: HashBody(body),
			Nonce: r.Header.Get("X-CSM-Nonce"),
		}
		// timestamp parse omitted; verify only structure here via re-sign check
		// is covered in sender_test. Accept and record.
		_ = env
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	_ = pub

	spool, err := NewSpool(filepath.Join(t.TempDir(), "s.db"), "reports", 100)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	defer func() { _ = spool.Close() }()

	sender := NewSender(srv.Client(), fixedClock())
	tgt := Target{Name: "central", URL: srv.URL + "/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	sp := NewSpooler(spool, sender, []Target{tgt}, time.Minute)

	r := Report{IP: "203.0.113.5", Class: ClassBruteforce, Count: 1, FirstSeen: time.Unix(1_700_000_000, 0).UTC(), LastSeen: time.Unix(1_700_000_000, 0).UTC()}
	sp.Enqueue(r)
	if spool.Len() != 1 {
		t.Fatalf("spool len = %d, want 1", spool.Len())
	}

	sp.DrainOnce(context.Background())
	if spool.Len() != 0 {
		t.Fatalf("spool len = %d after drain, want 0", spool.Len())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("server received %d reports, want 1", len(bodies))
	}
	var got Report
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatalf("unmarshal received body: %v", err)
	}
	if got.IP != "203.0.113.5" || got.Class != ClassBruteforce {
		t.Fatalf("delivered report = %+v", got)
	}
}

func TestSpoolerRetainsWhenCollectorDown(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	spool, err := NewSpool(filepath.Join(t.TempDir(), "s.db"), "reports", 100)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	defer func() { _ = spool.Close() }()
	sender := NewSender(srv.Client(), fixedClock())
	tgt := Target{Name: "central", URL: srv.URL + "/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	sp := NewSpooler(spool, sender, []Target{tgt}, time.Minute)

	sp.Enqueue(Report{IP: "203.0.113.5", Class: ClassBruteforce, Count: 1, FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(1, 0)})
	sp.DrainOnce(context.Background())
	// Collector returned 500: report must be retained for retry.
	if spool.Len() != 1 {
		t.Fatalf("spool len = %d, want 1 retained after failure", spool.Len())
	}
}
