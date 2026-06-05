package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/reporting"
)

func TestCentralFirebreakProtects(t *testing.T) {
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"10.10.10.0/24", "198.18.0.1"}
	d := New(cfg, nil, nil, "")
	fb := d.centralFirebreak()

	for _, ip := range []string{"127.0.0.1", "10.10.10.5", "198.18.0.1", "192.0.2.7", "203.0.113.9", "::1", "fe80::1", "not-an-ip"} {
		if !fb(ip) {
			t.Errorf("firebreak(%q) = false, want protected", ip)
		}
	}
	for _, ip := range []string{"45.76.1.1", "8.8.8.8"} {
		if fb(ip) {
			t.Errorf("firebreak(%q) = true, want actionable", ip)
		}
	}
}

func TestStartCentralConsumeDisabledClearsHook(t *testing.T) {
	prev := alert.CentralHook
	alert.SetCentralHook(func(alert.Finding) {})
	t.Cleanup(func() { alert.SetCentralHook(prev) })

	d := New(&config.Config{}, nil, nil, "")
	if loop := d.startCentralConsume(); loop != nil {
		t.Fatal("disabled consumer returned a loop")
	}
	if alert.CentralHook != nil {
		t.Fatal("disabled consumer left a stale hook")
	}
}

func TestStartCentralConsumeMisconfiguredReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.Reputation.Central.Enabled = true // but no set_url
	d := New(cfg, nil, nil, "")
	if loop := d.startCentralConsume(); loop != nil {
		t.Fatal("misconfigured consumer returned a loop")
	}
}

// centralStoreWith builds a CentralStore populated from a signed snapshot served
// by a throwaway server, returning the store and the firebreak.
func centralStoreWith(t *testing.T, entries []reporting.ScoredEntry) *reporting.CentralStore {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snap := reporting.ScoredSnapshot{Version: 1, Entries: entries}
	payload, ok := reporting.MarshalScoredSnapshot(snap)
	if !ok {
		t.Fatal("marshal snapshot")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sig := ed25519.Sign(priv, payload)
		w.Header().Set("X-CSM-Signature", "ed25519="+hex.EncodeToString(sig))
		w.Header().Set("X-CSM-Kind", "snapshot")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	store := reporting.NewCentralStore(reporting.NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub)))
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return store
}

func TestApplyCentralChallengesListedIP(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "iplist"))

	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "45.76.1.1", Score: 90, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	fb := d.centralFirebreak()
	d.applyCentral(store, reporting.ActionChallenge, 80, fb, alert.Finding{Check: "pam_bruteforce", SourceIP: "45.76.1.1"})

	if !d.ipList.Contains("45.76.1.1") {
		t.Fatal("listed IP was not challenged")
	}
}

func TestApplyCentralRespectsFirebreak(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "iplist"))

	// 203.0.113.5 is in the set but is a documentation range -> firebreak.
	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "203.0.113.5", Score: 99, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	fb := d.centralFirebreak()
	d.applyCentral(store, reporting.ActionChallenge, 80, fb, alert.Finding{Check: "pam_bruteforce", SourceIP: "203.0.113.5"})

	if d.ipList.Contains("203.0.113.5") {
		t.Fatal("firebreak-protected IP was challenged")
	}
}

func TestApplyCentralIgnoresUnlistedIP(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "iplist"))
	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "45.76.1.1", Score: 90, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	fb := d.centralFirebreak()
	d.applyCentral(store, reporting.ActionChallenge, 80, fb, alert.Finding{Check: "pam_bruteforce", SourceIP: "8.8.8.8"})
	if d.ipList.Contains("8.8.8.8") {
		t.Fatal("unlisted IP was challenged")
	}
}
