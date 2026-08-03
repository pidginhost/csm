package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

type cloudflareAwareBlocker struct {
	recordingIPBlocker
	covered map[string]bool
}

func (b *cloudflareAwareBlocker) CloudflareCovers(ip string) bool { return b.covered[ip] }

// A live auto-block of an IP inside a Cloudflare allow range is a silent
// no-op on 80/443 (the CF accept precedes the blocked drop). The AUTO-BLOCK
// finding must say so instead of claiming full coverage.
func TestAutoBlockWarnsWhenBlockedIPInsideCloudflareRange(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &cloudflareAwareBlocker{covered: map[string]bool{"203.0.113.40": true}}
	swapBlocker(t, blocker)

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:    "wp_login_bruteforce",
		Severity: alert.Critical,
		Message:  "brute force from 203.0.113.40",
		SourceIP: "203.0.113.40",
	}})

	var blockFinding *alert.Finding
	for i := range actions {
		if strings.HasPrefix(actions[i].Message, "AUTO-BLOCK: 203.0.113.40") {
			blockFinding = &actions[i]
		}
	}
	if blockFinding == nil {
		t.Fatalf("actions = %+v, want AUTO-BLOCK finding", actions)
	}
	wantDetails := "Reason: brute force from 203.0.113.40 (warning: " + firewall.CloudflareCoverageWarning + ")"
	if blockFinding.Details != wantDetails {
		t.Errorf("Details = %q, want %q", blockFinding.Details, wantDetails)
	}
	fields := strings.Fields(blockFinding.Message)
	if len(fields) < 2 || fields[0] != "AUTO-BLOCK:" || fields[1] != "203.0.113.40" {
		t.Errorf("Message = %q, want stable AUTO-BLOCK token and IP", blockFinding.Message)
	}
	if strings.Contains(blockFinding.Message, "Cloudflare") {
		t.Errorf("Message = %q, Cloudflare warning belongs only in Details", blockFinding.Message)
	}
}

func TestAutoBlockNoCloudflareWarningOutsideRanges(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &cloudflareAwareBlocker{covered: map[string]bool{}}
	swapBlocker(t, blocker)

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:    "wp_login_bruteforce",
		Severity: alert.Critical,
		Message:  "brute force from 203.0.113.41",
		SourceIP: "203.0.113.41",
	}})

	for i := range actions {
		if strings.HasPrefix(actions[i].Message, "AUTO-BLOCK: 203.0.113.41") {
			if strings.Contains(actions[i].Details, "Cloudflare") {
				t.Errorf("unexpected Cloudflare warning: %+v", actions[i])
			}
			return
		}
	}
	t.Fatalf("actions = %+v, want AUTO-BLOCK finding", actions)
}
