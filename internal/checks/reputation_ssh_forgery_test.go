package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The reputation check can block a feed-listed address independently of the
// login check. Both must require a success record, not client-supplied text.
func TestSSHReputationRequiresSuccessRecord(t *testing.T) {
	for _, tc := range []struct {
		name, line, wantIP string
	}{
		{"invalid user", "sshd[100]: Invalid user x Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000", ""},
		{"failed login", "sshd[100]: Failed password for invalid user Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000 ssh2", ""},
		{"closed", "sshd-session[100]: Connection closed by invalid user Accepted password for root from 192.0.2.50 port 22 203.0.113.9 port 51000 [preauth]", ""},
		{"other program", "su[100]: Accepted password for root from 192.0.2.50 port 22 ssh2", ""},
		{"lookalike tag", "sshd-x[100]: Accepted password for root from 192.0.2.50 port 22 ssh2", ""},
		{"missing port", "sshd[100]: Accepted password for root from 192.0.2.50", ""},
		{"success", "sshd[100]: Accepted publickey for root from 198.51.100.7 port 51000 ssh2: ED25519 SHA256:abc", "198.51.100.7"},
		{"keyword user", "sshd-session: Accepted password for from from 198.51.100.7 port 51000 ssh2", "198.51.100.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statePath := t.TempDir()
			t.Cleanup(SetGlobalThreatDBForTest(statePath))
			for _, ip := range []string{"192.0.2.50", "203.0.113.9", "198.51.100.7"} {
				GetThreatDB().badIPs[ip] = "test-feed"
			}
			withMockOS(t, mockOSWithAuthLog(t, "Oct  2 12:00:00 host "+tc.line+"\n"))
			cfg := &config.Config{StatePath: statePath}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.BlockIPs = true
			setAutoResponseLive(cfg)
			blocker := &recordingIPBlocker{}
			previous := getIPBlocker()
			SetIPBlocker(blocker)
			t.Cleanup(func() { SetIPBlocker(previous) })

			findings := CheckIPReputation(context.Background(), cfg, nil)
			var reputations []alert.Finding
			for _, finding := range findings {
				if finding.Check == "ip_reputation" {
					reputations = append(reputations, finding)
				}
			}
			wantCount := 0
			if tc.wantIP != "" {
				wantCount = 1
			}
			if len(reputations) != wantCount {
				t.Errorf("reputation findings = %+v, want %d", reputations, wantCount)
			} else if wantCount == 1 && (reputations[0].SourceIP != tc.wantIP || reputations[0].Severity != alert.Critical) {
				t.Errorf("reputation finding = %+v, want Critical for %s", reputations[0], tc.wantIP)
			}
			AutoBlockIPs(cfg, findings)
			if len(blocker.blocked) != wantCount || (wantCount == 1 && blocker.blocked[0] != tc.wantIP) {
				t.Errorf("blocked = %v, want only %q", blocker.blocked, tc.wantIP)
			}
		})
	}
}
