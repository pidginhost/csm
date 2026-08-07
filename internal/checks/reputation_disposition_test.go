package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A Critical ip_reputation sighting was detected on a non-browser vector
// (reputationSightingSeverity grades HTTP and cPanel access High), so no
// browser exists to answer a challenge: the IP must be hard-blocked.

func TestChallengeRoute_MailVectorReputationNotRouted(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	findings := []alert.Finding{
		{
			Check:    "ip_reputation",
			Severity: alert.Critical,
			Message:  "Known malicious IP accessing server: 192.0.2.10 (source: cins-army)",
			Details:  "Detected via: SMTP auth failure\nMatched in local threat intelligence database",
			SourceIP: "192.0.2.10",
		},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 0 {
		t.Fatalf("expected no challenge actions for mail-vector reputation sighting, got %d", len(actions))
	}
	if mock.ips["192.0.2.10"] {
		t.Error("192.0.2.10 must not be on challenge list")
	}
}

func TestChallengeRoute_HTTPVectorReputationStillRouted(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	findings := []alert.Finding{
		{
			Check:    "ip_reputation",
			Severity: alert.High,
			Message:  "Known malicious IP accessing server: 192.0.2.20 (source: cins-army)",
			Details:  "Detected via: HTTP request\nMatched in local threat intelligence database",
			SourceIP: "192.0.2.20",
		},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 1 {
		t.Fatalf("expected 1 challenge action for HTTP-vector reputation sighting, got %d", len(actions))
	}
	if !mock.ips["192.0.2.20"] {
		t.Error("192.0.2.20 should be on challenge list")
	}
}

func TestAutoBlockIPs_MailVectorReputationBlocksDespiteChallengeListing(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.Challenge.Enabled = true
	setAutoResponseLive(cfg)

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(&staticChallengeIPList{ips: map[string]bool{"192.0.2.30": true}})
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "ip_reputation",
			Severity:  alert.Critical,
			Message:   "Known malicious IP accessing server: 192.0.2.30 (source: cins-army)",
			Details:   "Detected via: SMTP auth failure\nMatched in local threat intelligence database",
			SourceIP:  "192.0.2.30",
			Timestamp: time.Now(),
		},
	})

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "192.0.2.30" {
		t.Fatalf("blocked IPs = %v, want [192.0.2.30] despite challenge listing", blocker.blocked)
	}
	if len(actions) == 0 {
		t.Fatal("expected an auto_block action finding")
	}
}

func TestAutoBlockIPs_HTTPVectorReputationStillSkipsWhenChallenged(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.Challenge.Enabled = true
	setAutoResponseLive(cfg)

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(&staticChallengeIPList{ips: map[string]bool{"192.0.2.40": true}})
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "ip_reputation",
			Severity:  alert.High,
			Message:   "Known malicious IP accessing server: 192.0.2.40 (source: cins-army)",
			Details:   "Detected via: HTTP request\nMatched in local threat intelligence database",
			SourceIP:  "192.0.2.40",
			Timestamp: time.Now(),
		},
	})

	if len(blocker.blocked) != 0 {
		t.Fatalf("BlockIP called for challenge-listed HTTP-vector sighting: %v", blocker.blocked)
	}
}
