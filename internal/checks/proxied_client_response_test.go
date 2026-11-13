package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// A client named only through a trusted proxy's forwarded header sends no
// packets to this host, and the challenge map matches the connecting
// address, so its challenge can only time out. The timeout must not become
// a block. A direct peer's challenge still escalates.
func TestChallengeRouteNeverEscalatesAChainClient(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	actions := ChallengeRouteIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "203.0.113.48", Message: "WordPress brute force from 203.0.113.48", Attribution: admission.AttributionTrustedHTTPChain},
		{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "203.0.113.49", Message: "WordPress brute force from 203.0.113.49", Attribution: admission.AttributionHTTPPeer},
	})
	if len(actions) != 2 || !mock.ips["203.0.113.48"] || !mock.ips["203.0.113.49"] {
		t.Fatalf("routed %v with %d actions, want both addresses", mock.ips, len(actions))
	}
	if !mock.nonEscalating["203.0.113.48"] {
		t.Error("a chain client's challenge timeout must not escalate to a block")
	}
	if mock.nonEscalating["203.0.113.49"] {
		t.Error("a direct peer's challenge timeout must still escalate")
	}
}

// A forwarded count names its chain even when no record of it kept an
// identity, so the challenge route still knows the client is proxied.
func TestDomlogForwardedFindingNamesItsChainWithoutARecord(t *testing.T) {
	s := newDomlogStats()
	s.markForwarded("wp_login_bruteforce", "203.0.113.48", false)
	f := alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.48"}
	s.stamp(&f, "wp_login_bruteforce")
	if f.Attribution != admission.AttributionTrustedHTTPChain {
		t.Fatalf("attribution = %v, want trusted_http_chain", f.Attribution)
	}
	if f.Observation != (alert.Observation{}) {
		t.Fatalf("observation = %+v, want none without a record", f.Observation)
	}
}

// A trusted proxy carries every visitor behind it. A finding that names it,
// as the cPanel login scans do when the proxy fronts cpsrvd, must neither
// challenge nor block it, on any automatic path. Another address in the
// same findings is still answered, so the setup can act.
func TestAutomaticResponsesNeverTargetATrustedProxy(t *testing.T) {
	const proxy, other = "198.51.100.7", "203.0.113.60"
	trusted := []string{"198.51.100.0/24"}

	t.Run("challenge", func(t *testing.T) {
		mock := &mockIPList{ips: make(map[string]bool)}
		old := challengeIPList
		SetChallengeIPList(mock)
		defer SetChallengeIPList(old)
		cfg := &config.Config{}
		cfg.Challenge.Enabled = true
		cfg.AutoResponse.BlockCpanelLogins = true
		cfg.WebServer.TrustedProxies = trusted
		ChallengeRouteIPs(cfg, []alert.Finding{
			{Check: "webmail_bruteforce", Severity: alert.High, SourceIP: proxy, Message: "Webmail brute force from " + proxy},
			{Check: "webmail_bruteforce", Severity: alert.High, SourceIP: other, Message: "Webmail brute force from " + other},
		})
		if mock.ips[proxy] || !mock.ips[other] {
			t.Fatalf("challenged %v, want only %s", mock.ips, other)
		}
	})

	t.Run("scan block", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		cfg.AutoResponse.BlockCpanelLogins = true
		cfg.WebServer.TrustedProxies = trusted
		blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
		applyBlockTestSetup(t, blocker)
		AutoBlockIPs(cfg, []alert.Finding{
			{Check: "webmail_bruteforce", Severity: alert.Critical, SourceIP: proxy, Message: "Webmail brute force from " + proxy, Timestamp: time.Now()},
			{Check: "webmail_bruteforce", Severity: alert.Critical, SourceIP: other, Message: "Webmail brute force from " + other, Timestamp: time.Now()},
		})
		if len(blocker.calls) != 1 || blocker.calls[0].ip != other {
			t.Fatalf("engine calls = %+v, want one block of %s", blocker.calls, other)
		}
		for _, p := range loadBlockState(cfg.StatePath).Pending {
			if p.IP == proxy {
				t.Fatalf("trusted proxy queued for a block: %+v", p)
			}
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		cfg.AutoResponse.BlockCpanelLogins = true
		cfg.WebServer.TrustedProxies = trusted
		cfg.AutoResponse.MaxBlocksPerHour = 1
		saveBlockState(cfg.StatePath, &blockState{BlocksThisHour: 1, HourKey: autoBlockNow().Format("2006-01-02T15")})
		blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
		applyBlockTestSetup(t, blocker)
		AutoBlockIPs(cfg, []alert.Finding{
			{Check: "webmail_bruteforce", Severity: alert.Critical, SourceIP: proxy, Message: "Webmail brute force from " + proxy, Timestamp: time.Now()},
			{Check: "webmail_bruteforce", Severity: alert.Critical, SourceIP: other, Message: "Webmail brute force from " + other, Timestamp: time.Now()},
		})
		pending := loadBlockState(cfg.StatePath).Pending
		if len(blocker.calls) != 0 || len(pending) != 1 || pending[0].IP != other {
			t.Fatalf("engine calls %+v, pending %+v; want only %s queued", blocker.calls, pending, other)
		}
	})

	t.Run("queued block", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		cfg.WebServer.TrustedProxies = trusted
		saveBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{
			{IP: proxy, Check: "wp_login_bruteforce", Reason: "queued", QueuedAt: time.Now()},
			{IP: other, Check: "wp_login_bruteforce", Reason: "queued", QueuedAt: time.Now()},
		}})
		blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
		applyBlockTestSetup(t, blocker)
		AutoBlockIPs(cfg, nil)
		if len(blocker.calls) != 1 || blocker.calls[0].ip != other {
			t.Fatalf("engine calls = %+v, want one block of %s", blocker.calls, other)
		}
		for _, p := range loadBlockState(cfg.StatePath).Pending {
			if p.IP == proxy {
				t.Fatalf("trusted proxy requeued: %+v", p)
			}
		}
	})

	t.Run("derived block", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		cfg.WebServer.TrustedProxies = trusted
		blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
		applyBlockTestSetup(t, blocker)
		for _, ip := range []string{proxy, "::ffff:" + proxy, other} {
			t.Run(ip, func(t *testing.T) {
				before := len(blocker.calls)
				_, err := ApplyBlock(cfg, ApplyBlockRequest{
					IP: ip, EngineReason: "CSM challenge-timeout: wp brute", Reason: "challenge timeout after wp brute",
					TTL: time.Hour, Source: BlockSourceChallenge, Check: "wp_login_bruteforce",
				})
				if ip != other && (!errors.Is(err, firewall.ErrIPProtected) || len(blocker.calls) != before) {
					t.Fatalf("ApplyBlock(%s) error = %v, engine calls = %+v; want ErrIPProtected and no call", ip, err, blocker.calls[before:])
				}
				if ip == other && err != nil {
					t.Fatalf("ApplyBlock(%s): %v", ip, err)
				}
			})
		}
		if len(blocker.calls) != 1 || blocker.calls[0].ip != other {
			t.Fatalf("engine calls = %+v, want one block of %s", blocker.calls, other)
		}
	})
}
