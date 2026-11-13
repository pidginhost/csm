package checks

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// Trust changes retire queued blocks even when no block can be attempted.
func TestAutoBlockRetiresTrustedProxyRetriesBeforeDeferral(t *testing.T) {
	const proxy, other = "198.51.100.7", "203.0.113.60"
	for _, mode := range []string{"rate limited", "engine unavailable", "redispatched"} {
		t.Run(mode, func(t *testing.T) {
			cfg := autoBlockQueueFixture(t, func() error {
				t.Error("deferred block reached firewall")
				return nil
			})
			cfg.WebServer.TrustedProxies = []string{"198.51.100.0/24"}
			now := time.Now()
			setAutoBlockNow(t, now)
			state := &blockState{HourKey: now.Format("2006-01-02T15")}
			var findings []alert.Finding
			for _, ip := range []string{proxy, "::ffff:" + proxy, other} {
				f := retryFinding(ip)
				state.Pending = append(state.Pending, pendingIP{
					IP: ip, Check: f.Check, Severity: f.Severity, Reason: f.Message,
					FindingID: alert.FindingID(f), QueuedAt: now,
				})
				f.AutoIPResponseEvaluated = true
				findings = append(findings, f)
			}
			switch mode {
			case "rate limited":
				cfg.AutoResponse.MaxBlocksPerHour = 1
				state.BlocksThisHour = 1
				findings = nil
			case "engine unavailable":
				SetIPBlocker(nil)
				findings = nil
			}
			if err := writeBlockState(cfg.StatePath, state); err != nil {
				t.Fatal(err)
			}
			stderr := captureStderr(t, func() { AutoBlockIPs(cfg, findings) })
			pending := loadBlockState(cfg.StatePath).Pending
			if len(pending) != 1 || pending[0].IP != other || !pending[0].QueuedAt.Equal(now) {
				t.Fatalf("pending = %+v, want only the unrelated retry with its original age", pending)
			}
			if strings.Contains(stderr, proxy) {
				t.Fatalf("protected retry logged as a failure: %s", stderr)
			}
			queued, candidates := retryQueueRows(t, now)
			if queued.Depth != 1 || queued.DroppedTotal != 0 || candidates.Depth != 0 || candidates.DroppedTotal != 0 {
				t.Fatalf("protected retries counted as lost: pending=%+v candidates=%+v", queued, candidates)
			}
		})
	}
}

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
		{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "203.0.113.48", Message: "WordPress brute force from 203.0.113.48", Attribution: admission.AttributionTrustedHTTPChain, ProxiedClient: true},
		{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "203.0.113.49", Message: "WordPress brute force from 203.0.113.49", Attribution: admission.AttributionHTTPPeer},
		// One forwarded request beside direct ones reads as a chain for
		// admission, but the address also connects here itself.
		{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "203.0.113.50", Message: "WordPress brute force from 203.0.113.50", Attribution: admission.AttributionTrustedHTTPChain},
	})
	if len(actions) != 3 || !mock.ips["203.0.113.48"] || !mock.ips["203.0.113.49"] || !mock.ips["203.0.113.50"] {
		t.Fatalf("routed %v with %d actions, want all three addresses", mock.ips, len(actions))
	}
	if !mock.nonEscalating["203.0.113.48"] {
		t.Error("a chain client's challenge timeout must not escalate to a block")
	}
	if mock.nonEscalating["203.0.113.49"] {
		t.Error("a direct peer's challenge timeout must still escalate")
	}
	if mock.nonEscalating["203.0.113.50"] {
		t.Error("a forwarded request beside direct ones must not spare the address its escalation")
	}
}

// Only a count every record of which a trusted proxy forwarded names a
// proxied client; one direct record makes the address a packet source.
func TestDomlogMixedCountIsNoProxiedClient(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"192.0.2.10"}
	var forwarded []string
	for i := 0; i < 20; i++ {
		forwarded = append(forwarded, fmt.Sprintf(`192.0.2.10 - - [09/Nov/2026:12:01:%02d +0000] "POST /wp-login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0" "203.0.113.62"`, i))
	}
	_, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, forwarded)
	if f := oneScanFinding(t, findings, "wp_login_bruteforce"); f.Attribution != admission.AttributionTrustedHTTPChain || !f.ProxiedClient {
		t.Fatalf("forwarded count read as %s, proxied %v; want a proxied chain client", f.Attribution, f.ProxiedClient)
	}
	mixed := slices.Concat(forwarded[:19], []string{domlogTestLine("203.0.113.62", 30, "POST", "/wp-login.php", 200, "Mozilla/5.0")})
	_, findings = scanDomlogFile(t, cfg, nopBotClassifier{}, mixed)
	if f := oneScanFinding(t, findings, "wp_login_bruteforce"); f.Attribution != admission.AttributionTrustedHTTPChain || f.ProxiedClient {
		t.Fatalf("mixed count read as %s, proxied %v; want a chain that is no proxied client", f.Attribution, f.ProxiedClient)
	}
}

// A forwarded count names its chain even when no record of it kept an
// identity, so the challenge route still knows the client is proxied.
func TestDomlogForwardedFindingNamesItsChainWithoutARecord(t *testing.T) {
	s := newDomlogStats()
	s.markForwarded("wp_login_bruteforce", "203.0.113.48", false)
	f := alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.48"}
	s.stamp(&f, "wp_login_bruteforce")
	if f.Attribution != admission.AttributionTrustedHTTPChain || !f.ProxiedClient {
		t.Fatalf("attribution = %v, proxied %v; want a proxied trusted_http_chain client", f.Attribution, f.ProxiedClient)
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
