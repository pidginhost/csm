package checks

import (
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The PAM listener's findings are thresholded brute-force evidence with a
// confirmed source IP, and the auto-response docs promise an instant block
// on threshold breach. Both PAM checks must therefore be always-blockable.
func TestAutoBlockIPs_BlocksPAMBruteForceAndCredentialStuffing(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Severity: alert.Critical,
			Check:    "pam_bruteforce",
			Message:  "PAM brute-force detected: 203.0.113.30 (5 failures in 42s)",
			SourceIP: "203.0.113.30",
		},
		{
			Severity: alert.High,
			Check:    "credential_stuffing",
			Message:  "Credential stuffing: 203.0.113.31 failed logins against 5 distinct accounts",
			SourceIP: "203.0.113.31",
		},
	})

	for _, ip := range []string{"203.0.113.30", "203.0.113.31"} {
		if !slices.Contains(blocker.blocked, ip) {
			t.Errorf("%s not blocked; blocked = %v", ip, blocker.blocked)
		}
	}
	if len(actions) != 2 {
		t.Fatalf("actions = %+v, want one auto-block per PAM finding", actions)
	}
}
