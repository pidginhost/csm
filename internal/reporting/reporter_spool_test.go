package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedSignedReport struct {
	body      []byte
	nonce     string
	timestamp int64
}

func ed25519RecordingServer(t *testing.T, pub ed25519.PublicKey, status func(call int) int) (*httptest.Server, func() []recordedSignedReport) {
	t.Helper()
	var mu sync.Mutex
	var records []recordedSignedReport
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts, err := strconv.ParseInt(r.Header.Get("X-CSM-Timestamp"), 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
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
		scheme, hexSig, ok := strings.Cut(r.Header.Get("X-CSM-Signature"), "=")
		if !ok || scheme != "ed25519" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		sig, err := hex.DecodeString(hexSig)
		if err != nil || !ed25519.Verify(pub, msg, sig) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		records = append(records, recordedSignedReport{
			body:      append([]byte(nil), body...),
			nonce:     env.Nonce,
			timestamp: env.Timestamp,
		})
		call := len(records)
		mu.Unlock()
		code := http.StatusAccepted
		if status != nil {
			code = status(call)
		}
		w.WriteHeader(code)
	}))
	return srv, func() []recordedSignedReport {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedSignedReport(nil), records...)
	}
}

func TestSpoolerEnqueueAndDrainDelivers(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, records := ed25519RecordingServer(t, pub, nil)
	defer srv.Close()

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
	gotRecords := records()
	if len(gotRecords) != 1 {
		t.Fatalf("server received %d reports, want 1", len(gotRecords))
	}
	var got Report
	if err := json.Unmarshal(gotRecords[0].body, &got); err != nil {
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

func TestSpoolerRetryBuildsFreshEnvelope(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, records := ed25519RecordingServer(t, pub, func(call int) int {
		if call == 1 {
			return http.StatusInternalServerError
		}
		return http.StatusAccepted
	})
	defer srv.Close()

	spool, err := NewSpool(filepath.Join(t.TempDir(), "s.db"), "reports", 100)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	defer func() { _ = spool.Close() }()
	now := time.Unix(1_700_000_000, 0).UTC()
	sender := NewSender(srv.Client(), func() time.Time {
		t := now
		now = now.Add(time.Second)
		return t
	})
	tgt := Target{Name: "central", URL: srv.URL + "/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	sp := NewSpooler(spool, sender, []Target{tgt}, time.Minute)

	sp.Enqueue(Report{IP: "203.0.113.5", Class: ClassBruteforce, Count: 1, FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(1, 0)})
	sp.DrainOnce(context.Background())
	if spool.Len() != 1 {
		t.Fatalf("spool len after failed drain = %d, want 1", spool.Len())
	}
	sp.DrainOnce(context.Background())
	if spool.Len() != 0 {
		t.Fatalf("spool len after retry = %d, want 0", spool.Len())
	}

	gotRecords := records()
	if len(gotRecords) != 2 {
		t.Fatalf("server received %d reports, want 2 attempts", len(gotRecords))
	}
	if string(gotRecords[0].body) != string(gotRecords[1].body) {
		t.Fatalf("retry body changed: first=%s second=%s", gotRecords[0].body, gotRecords[1].body)
	}
	if gotRecords[0].nonce == gotRecords[1].nonce {
		t.Fatal("retry reused nonce")
	}
	if gotRecords[0].timestamp == gotRecords[1].timestamp {
		t.Fatal("retry reused timestamp")
	}
}

func TestSpoolerDropsRemovedTargetAndContinues(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, records := ed25519RecordingServer(t, pub, nil)
	defer srv.Close()

	spool, err := NewSpool(filepath.Join(t.TempDir(), "s.db"), "reports", 100)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	defer func() { _ = spool.Close() }()
	if _, err := spool.Enqueue("removed", []byte(`{"ip":"198.51.100.9"}`)); err != nil {
		t.Fatalf("enqueue removed target: %v", err)
	}
	if _, err := spool.Enqueue("central", []byte(`{"ip":"203.0.113.5"}`)); err != nil {
		t.Fatalf("enqueue current target: %v", err)
	}

	sender := NewSender(srv.Client(), fixedClock())
	tgt := Target{Name: "central", URL: srv.URL + "/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "k1", Ed25519Key: priv}
	sp := NewSpooler(spool, sender, []Target{tgt}, time.Minute)
	sp.DrainOnce(context.Background())

	if spool.Len() != 0 {
		t.Fatalf("spool len = %d, want removed target dropped and current target delivered", spool.Len())
	}
	gotRecords := records()
	if len(gotRecords) != 1 {
		t.Fatalf("server received %d reports, want only current target", len(gotRecords))
	}
	if string(gotRecords[0].body) != `{"ip":"203.0.113.5"}` {
		t.Fatalf("delivered body = %s", gotRecords[0].body)
	}
}

func TestSpoolerDeduplicatesTargetNames(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	spool, err := NewSpool(filepath.Join(t.TempDir(), "s.db"), "reports", 100)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	defer func() { _ = spool.Close() }()

	targets := []Target{
		{Name: "central", URL: "https://old.example/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "old", Ed25519Key: priv},
		{Name: "central", URL: "https://new.example/report", Transport: TransportEd25519, NodeID: "n1", KeyID: "new", Ed25519Key: priv},
	}
	sp := NewSpooler(spool, NewSender(nil, fixedClock()), targets, time.Minute)
	sp.Enqueue(Report{IP: "203.0.113.5", Class: ClassBruteforce, Count: 1, FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(1, 0)})

	if spool.Len() != 1 {
		t.Fatalf("spool len = %d, want one item for duplicate target names", spool.Len())
	}
}
