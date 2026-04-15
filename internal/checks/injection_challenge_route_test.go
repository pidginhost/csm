package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Extra ChallengeRouteIPs branch coverage on top of challenge_route_test.go.

func TestChallengeRouteIPsSkipsNonChallengeableCheck(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	// "suspicious_process" carries no attacker IP and is not on the
	// challenge allowlist → must be ignored.
	actions := ChallengeRouteIPs(cfg, []alert.Finding{
		{Check: "suspicious_process", Message: "odd process detected"},
	})
	if len(actions) != 0 {
		t.Errorf("non-challengeable check should not produce actions, got %+v", actions)
	}
	if len(mock.ips) != 0 {
		t.Errorf("no IPs expected on challenge list, got %v", mock.ips)
	}
}

func TestChallengeRouteIPsSkipsFindingWithNoIP(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	// Challengeable check but no extractable IP → skipped.
	actions := ChallengeRouteIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "brute force detected (no IP in this message)"},
	})
	if len(actions) != 0 {
		t.Errorf("finding without IP should be skipped, got %+v", actions)
	}
}

func TestChallengeRouteIPsDedupesSameIPInBatch(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	// Same attacker IP appearing in three findings — only one challenge
	// action should be produced.
	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "brute force from 203.0.113.7"},
		{Check: "xmlrpc_abuse", Message: "xmlrpc abuse from 203.0.113.7"},
		{Check: "ip_reputation", Message: "bad reputation 203.0.113.7"},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 1 {
		t.Errorf("dedup should yield 1 action, got %d: %+v", len(actions), actions)
	}
}

func TestChallengeRouteIPsSkipsInfraIP(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	cfg.Challenge.Enabled = true

	actions := ChallengeRouteIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "brute from 10.0.0.5"},
	})
	if len(actions) != 0 {
		t.Errorf("infra IP should be skipped, got %+v", actions)
	}
	if mock.ips["10.0.0.5"] {
		t.Errorf("infra IP must not be added to challenge list")
	}
}

func TestChallengeRouteIPsSkipsLocalhost(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	actions := ChallengeRouteIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "brute force from 127.0.0.1"},
	})
	if len(actions) != 0 {
		t.Errorf("localhost should be skipped, got %+v", actions)
	}
}

func TestChallengeRouteIPsSkipsAlreadyOnList(t *testing.T) {
	mock := &mockIPList{ips: map[string]bool{"203.0.113.9": true}}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	actions := ChallengeRouteIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "brute from 203.0.113.9"},
	})
	if len(actions) != 0 {
		t.Errorf("already-on-list IP should be skipped, got %+v", actions)
	}
}
