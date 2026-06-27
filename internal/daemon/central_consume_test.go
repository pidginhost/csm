package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/reporting"
)

func TestCentralFirebreakProtects(t *testing.T) {
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"10.10.10.0/24"}
	cfg.Firewall = &firewall.FirewallConfig{InfraIPs: []string{"45.76.1.0/24"}}
	d := New(cfg, nil, nil, "")
	fb := d.centralFirebreak()

	for _, ip := range []string{"127.0.0.1", "10.10.10.5", "45.76.1.7", "192.0.2.7", "198.51.100.10", "203.0.113.9", "198.18.0.1", "198.19.255.254", "2001:db8::1", "::1", "fe80::1", "not-an-ip"} {
		if !fb(ip) {
			t.Errorf("firebreak(%q) = false, want protected", ip)
		}
	}
	for _, ip := range []string{"46.76.1.1", "8.8.8.8"} {
		if fb(ip) {
			t.Errorf("firebreak(%q) = true, want actionable", ip)
		}
	}
}

func TestStartCentralConsumeWarnsOnlyForUnknownAction(t *testing.T) {
	prevHook := alert.CentralHook
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	t.Cleanup(func() {
		alert.SetCentralHook(prevHook)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("CSM_TEST_CENTRAL_PUB", hex.EncodeToString(pub))

	tests := []struct {
		action string
		warn   bool
	}{
		{action: ""},
		{action: string(reporting.ActionOff)},
		{action: string(reporting.ActionChallenge)},
		{action: string(reporting.ActionBlockIfLocalCorroborated)},
		{action: "unknown", warn: true},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			log.SetFlags(0)
			alert.SetCentralHook(nil)

			cfg := &config.Config{}
			cfg.Reputation.Central.Enabled = true
			cfg.Reputation.Central.SetURL = "https://central.example/decisions"
			cfg.Reputation.Central.PubkeyEnv = "CSM_TEST_CENTRAL_PUB"
			cfg.Reputation.Central.Action = tt.action
			d := New(cfg, nil, nil, "")
			if loop := d.startCentralConsume(); loop == nil {
				t.Fatal("enabled consumer returned nil loop")
			}

			gotWarn := strings.Contains(buf.String(), "unrecognized action")
			if gotWarn != tt.warn {
				t.Fatalf("unrecognized-action warning = %v, want %v; log=%q", gotWarn, tt.warn, buf.String())
			}
		})
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

func TestStartCentralConsumeDefaultsThresholdAndClearsHook(t *testing.T) {
	prev := alert.CentralHook
	t.Cleanup(func() { alert.SetCentralHook(prev) })

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snap := reporting.ScoredSnapshot{Version: 1, Entries: []reporting.ScoredEntry{
		{IP: "45.76.1.1", Score: centralBlockThreshold - 1, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	}}
	payload, ok := reporting.MarshalScoredSnapshot(snap)
	if !ok {
		t.Fatal("marshal snapshot")
	}
	pulled := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sig := ed25519.Sign(priv, payload)
		w.Header().Set("X-CSM-Signature", "ed25519="+hex.EncodeToString(sig))
		w.Header().Set("X-CSM-Kind", "snapshot")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		select {
		case pulled <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{}
	cfg.Reputation.Central.Enabled = true
	cfg.Reputation.Central.SetURL = srv.URL + "/decisions"
	cfg.Reputation.Central.PubkeyEnv = "CSM_TEST_CENTRAL_PUB"
	cfg.Reputation.Central.Action = string(reporting.ActionBlockIfLocalCorroborated)
	t.Setenv("CSM_TEST_CENTRAL_PUB", hex.EncodeToString(pub))

	d := New(cfg, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "iplist"))
	loop := d.startCentralConsume()
	if loop == nil {
		t.Fatal("enabled consumer returned nil loop")
	}
	if alert.CentralHook == nil {
		t.Fatal("enabled consumer did not install hook")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		loop()
	}()
	t.Cleanup(func() {
		select {
		case <-d.stopCh:
		default:
			close(d.stopCh)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("central loop did not stop")
		}
	})

	select {
	case <-pulled:
	case <-time.After(time.Second):
		t.Fatal("central consumer did not pull initial set")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		alert.CentralHook(alert.Finding{Check: "pam_bruteforce", SourceIP: "45.76.1.1"})
		if d.ipList.Contains("45.76.1.1") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !d.ipList.Contains("45.76.1.1") {
		t.Fatal("score below default block threshold should challenge, not block")
	}

	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("central loop did not stop")
	}
	if alert.CentralHook != nil {
		t.Fatal("central loop did not clear hook on stop")
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

func TestLogCentralBlockFailureSuppressesProtectedIPError(t *testing.T) {
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)

	logCentralBlockFailure("45.76.1.92", firewall.ErrIPProtected)
	if buf.Len() != 0 {
		t.Fatalf("protected-IP central refusal logged as block failure: %q", buf.String())
	}

	logCentralBlockFailure("45.76.1.92", errors.New("nft failed"))
	if !strings.Contains(buf.String(), "central-intel: block 45.76.1.92 failed: nft failed") {
		t.Fatalf("non-protected central failure was not logged: %q", buf.String())
	}
}
