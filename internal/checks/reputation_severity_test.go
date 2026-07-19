package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestReputationSightingSeverityGradesBySurface(t *testing.T) {
	tests := []struct {
		via  string
		want alert.Severity
	}{
		// Passive sightings of a listed IP are ambient scanner noise.
		{"HTTP request", alert.High},
		{"cPanel/WHM access", alert.High},
		// Auth-surface activity is an active attack in progress.
		{"SSH login", alert.Critical},
		{"SMTP auth failure", alert.Critical},
		{"Dovecot IMAP/POP3 auth failure", alert.Critical},
		// Unknown future surfaces fail closed.
		{"carrier pigeon", alert.Critical},
	}
	for _, tt := range tests {
		if got := reputationSightingSeverity(tt.via); got != tt.want {
			t.Errorf("reputationSightingSeverity(%q) = %v, want %v", tt.via, got, tt.want)
		}
	}
}

func TestAppendReputationFindingUsesSurfaceSeverity(t *testing.T) {
	var findings []alert.Finding
	appendReputationFinding(&findings, "203.0.113.7", "HTTP request", "AbuseIPDB", 100, "Data Center")
	appendReputationFinding(&findings, "203.0.113.8", "SMTP auth failure", "AbuseIPDB", 100, "Fixed Line ISP")
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].Severity != alert.High {
		t.Errorf("passive HTTP sighting severity = %v, want High", findings[0].Severity)
	}
	if findings[1].Severity != alert.Critical {
		t.Errorf("SMTP auth-failure sighting severity = %v, want Critical", findings[1].Severity)
	}
}

func TestThreatDBPassiveFindingUsesSurfaceSeverity(t *testing.T) {
	statePath := t.TempDir()
	restoreThreatDB := SetGlobalThreatDBForTest(statePath)
	t.Cleanup(restoreThreatDB)
	GetThreatDB().badIPs["203.0.113.10"] = "test-feed"

	forceCPanelPlatform(t)
	withMockOS(t, writeMockLog(t, reputationWHMAccessLog,
		"203.0.113.10 - - [17/Jul/2026:10:00:00 +0000] \"GET /whm HTTP/1.1\" 200 0 \"-\" \"-\"\n"))

	findings := CheckIPReputation(context.Background(), &config.Config{StatePath: statePath}, nil)
	for _, finding := range findings {
		if finding.Check != "ip_reputation" || finding.SourceIP != "203.0.113.10" {
			continue
		}
		if finding.Severity != alert.High {
			t.Fatalf("passive threat DB severity = %v, want High", finding.Severity)
		}
		if !strings.Contains(finding.Details, "Detected via: cPanel/WHM access") {
			t.Fatalf("details = %q, want cPanel/WHM surface", finding.Details)
		}
		return
	}
	t.Fatalf("passive threat DB finding missing: %+v", findings)
}

func TestAddIfNotInfraKeepsHighestSeveritySurface(t *testing.T) {
	ips := make(map[string]string)
	cfg := &config.Config{}

	addIfNotInfra(ips, "203.0.113.7", "HTTP request", cfg)
	addIfNotInfra(ips, "203.0.113.7", "Dovecot IMAP/POP3 auth failure", cfg)
	addIfNotInfra(ips, "203.0.113.7", "cPanel/WHM access", cfg)

	if got := ips["203.0.113.7"]; got != "Dovecot IMAP/POP3 auth failure" {
		t.Fatalf("surface = %q, want strongest auth surface", got)
	}
}

func TestHighReputationFindingRemainsBlockable(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	setAutoResponseLive(cfg)

	blocker := &recordingIPBlocker{}
	previous := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(previous) })

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:    "ip_reputation",
		Severity: alert.High,
		SourceIP: "203.0.113.8",
		Message:  "Known malicious IP accessing server: 203.0.113.8",
	}})

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.8" {
		t.Fatalf("blocked IPs = %v, want High reputation source blocked", blocker.blocked)
	}
	if len(actions) != 1 || actions[0].Check != "auto_block" {
		t.Fatalf("actions = %+v, want one auto_block finding", actions)
	}
}

func TestHighReputationFindingRemainsChallengeEligible(t *testing.T) {
	previous := GetChallengeIPList()
	challengeList := &staticChallengeIPList{ips: make(map[string]bool)}
	SetChallengeIPList(challengeList)
	t.Cleanup(func() { SetChallengeIPList(previous) })

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	actions := ChallengeRouteIPs(cfg, []alert.Finding{{
		Check:    "ip_reputation",
		Severity: alert.High,
		SourceIP: "203.0.113.9",
		Message:  "Known malicious IP accessing server: 203.0.113.9",
	}})

	if !challengeList.ips["203.0.113.9"] {
		t.Fatal("High reputation source was not added to the challenge list")
	}
	if len(actions) != 1 || actions[0].Check != "challenge_route" {
		t.Fatalf("actions = %+v, want one challenge_route finding", actions)
	}
}
