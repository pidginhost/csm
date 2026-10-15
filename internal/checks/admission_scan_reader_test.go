package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

type admissionScanBlocker struct {
	recordingIPBlocker
	statePath string
}

func (b *admissionScanBlocker) IsBlocked(ip string) bool {
	state, err := firewall.LoadState(b.statePath)
	if err != nil {
		return false
	}
	for _, entry := range state.Blocked {
		if entry.IP == ip {
			return true
		}
	}
	return false
}

func TestAutoBlockIPsCountsAnAdmissionBlockWithoutTracker(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)
	setAutoResponseLive(cfg)
	cfg.AutoResponse.MaxBlocksPerHour = 50
	writeAdmissionBlock(t, cfg.StatePath, "203.0.113.56", time.Now().Add(time.Hour))
	blocker := &admissionScanBlocker{statePath: cfg.StatePath}
	swapBlocker(t, blocker)
	findings := []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical,
		Message: "WordPress brute force from 203.0.113.56", SourceIP: "203.0.113.56", Timestamp: time.Now()}}
	if got := AutoBlockIPs(cfg, findings); len(got) != 0 || len(blocker.calls) != 0 {
		t.Fatalf("executed block was attempted again: findings=%+v, calls=%+v", got, blocker.calls)
	}
	// Positive control: removing the verified state makes the same finding
	// eligible, so the assertion above cannot pass through disabled policy.
	writeAdmissionBlock(t, cfg.StatePath, "203.0.113.57", time.Now().Add(time.Hour))
	_ = AutoBlockIPs(cfg, findings)
	if len(blocker.calls) != 1 || blocker.calls[0].ip != "203.0.113.56" {
		t.Fatalf("positive control = %+v", blocker.calls)
	}
}
