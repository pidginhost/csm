package daemon

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func installDirectSMTPRDNSCacheForTest(t *testing.T, cache *checks.RDNSCache) {
	t.Helper()
	directSMTPRDNSOnce = sync.Once{}
	directSMTPRDNSCache = nil
	directSMTPRDNSOnce.Do(func() {
		directSMTPRDNSCache = cache
	})
	t.Cleanup(func() {
		directSMTPRDNSOnce = sync.Once{}
		directSMTPRDNSCache = nil
	})
}

func TestProcessConnectionEventEmitsDirectSMTPEgressFinding(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})

	ev := ConnectionEvent{
		UID:     1001,
		PID:     4242,
		Family:  2,
		DstPort: 587,
		DstIP:   net.ParseIP("203.0.113.10").To4(),
		Comm:    "ncat",
	}

	got := evaluateConnectionEvent(cfg, mta, ev, "alice")

	var sawEgress bool
	for _, f := range got {
		if f.Check == "direct_smtp_egress" {
			sawEgress = true
		}
	}
	if !sawEgress {
		t.Errorf("expected a direct_smtp_egress finding; got %+v", got)
	}
}

func TestProcessConnectionEventDoesNotDoubleEmitForSMTP(t *testing.T) {
	// EvaluateConnection skips SMTP destinations via safeRemotePorts;
	// only EvaluateDirectSMTPEgress should fire for an outbound 587.
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})

	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}

	got := evaluateConnectionEvent(cfg, mta, ev, "alice")

	checkSet := map[string]int{}
	for _, f := range got {
		checkSet[f.Check]++
	}
	if checkSet["user_outbound_connection"] != 0 {
		t.Errorf("user_outbound_connection must not double-fire on SMTP destination; got %d", checkSet["user_outbound_connection"])
	}
}

func TestProcessConnectionEventTimestampSet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}
	got := evaluateConnectionEvent(cfg, mta, ev, "alice")
	if len(got) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range got {
		if f.Timestamp.IsZero() {
			t.Errorf("Timestamp must be set on emitted finding (%s)", f.Check)
		}
		if time.Since(f.Timestamp) > time.Second {
			t.Errorf("Timestamp too old: %v", f.Timestamp)
		}
	}
}

func TestProcessConnectionEventDoesNotResolveRDNSBeforeSMTPMatch(t *testing.T) {
	var calls atomic.Int64
	installDirectSMTPRDNSCacheForTest(t, checks.NewRDNSCache(checks.RDNSCacheConfig{
		TTL: time.Minute,
		Resolve: func(ip net.IP) (string, error) {
			calls.Add(1)
			return "mail.example.com", nil
		},
	}))
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 443,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "curl",
	}

	_ = evaluateConnectionEvent(cfg, mta, ev, "alice")

	if calls.Load() != 0 {
		t.Fatalf("rDNS lookup ran before cheap direct SMTP filters; calls=%d", calls.Load())
	}
}

func TestProcessConnectionEventAddsRDNSOnlyToEmittedDirectSMTPFinding(t *testing.T) {
	var calls atomic.Int64
	installDirectSMTPRDNSCacheForTest(t, checks.NewRDNSCache(checks.RDNSCacheConfig{
		TTL: time.Minute,
		Resolve: func(ip net.IP) (string, error) {
			calls.Add(1)
			return "mail.example.com", nil
		},
	}))
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}

	got := evaluateConnectionEvent(cfg, mta, ev, "alice")

	if calls.Load() != 1 {
		t.Fatalf("rDNS calls = %d, want 1", calls.Load())
	}
	for _, f := range got {
		if f.Check == "direct_smtp_egress" {
			if !strings.Contains(f.Details, "Domain: mail.example.com") {
				t.Fatalf("direct SMTP finding missing rDNS domain: %+v", f)
			}
			return
		}
	}
	t.Fatalf("expected direct_smtp_egress finding; got %+v", got)
}

func TestProcessConnectionEventHonorsDirectSMTPBackendNone(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Backend = "none"
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}

	got := evaluateConnectionEvent(cfg, mta, ev, "alice")
	for _, f := range got {
		if f.Check == "direct_smtp_egress" {
			t.Fatalf("backend=none emitted direct_smtp_egress: %+v", got)
		}
	}
}

func TestProcessConnectionEventHonorsDirectSMTPBackendLegacy(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Backend = "legacy"
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}

	got := evaluateConnectionEvent(cfg, mta, ev, "alice")
	for _, f := range got {
		if f.Check == "direct_smtp_egress" {
			t.Fatalf("BPF evaluator emitted while direct_smtp_egress.backend=legacy: %+v", got)
		}
	}
}

func TestActiveConnectionCfgUsesHotReloadedConfig(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })

	startup := &config.Config{Hostname: "startup"}
	active := &config.Config{Hostname: "active"}
	config.SetActive(active)

	if got := activeConnectionCfg(startup); got != active {
		t.Fatalf("activeConnectionCfg returned startup config, want active hot-reload config")
	}
}
