package daemon

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/reporting"
)

// auto_response.enabled and block_ips are the documented switches for
// automatic firewall blocks. Challenge timeouts and central intel are
// automatic blocks too, so either switch off must stop them.
func TestNonScanAutoBlocksHonourTheBlockSwitches(t *testing.T) {
	for _, off := range []string{"enabled", "block_ips"} {
		t.Run(off, func(t *testing.T) {
			cfg, blocker := applyWiringSetup(t)
			switch off {
			case "enabled":
				cfg.AutoResponse.Enabled = false
			case "block_ips":
				cfg.AutoResponse.BlockIPs = false
			}
			d := New(cfg, nil, nil, "")
			d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			d.ipList.Add("203.0.113.70", "wp brute", -time.Minute)

			stderr := captureAppliedBlockStderr(t, func() {
				d.escalateExpiredChallenges(parseBlockExpiry(cfg.AutoResponse.BlockExpiry))
			})
			err := d.performCentralAction(centralQueuedAction{decision: reporting.DecisionBlock, ip: "203.0.113.71"})

			if len(blocker.calls) != 0 {
				t.Fatalf("automatic blocks with %s off: %+v", off, blocker.calls)
			}
			// Switched-off blocking is the operator's choice, not a failure
			// to log every minute.
			if strings.Contains(stderr, "error blocking") || !isCentralBlockRefusal(err) {
				t.Fatalf("refusal reported as a failure: stderr %q, central err %v", stderr, err)
			}
		})
	}
}
