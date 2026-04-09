package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckLocalThreatScore generates findings for IPs that have accumulated
// a high local threat score but have not yet been blocked.
// Runs every 10 minutes as part of TierCritical.
func CheckLocalThreatScore(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	adb := attackdb.Global()
	if adb == nil {
		return nil
	}

	alreadyBlocked := loadAllBlockedIPs(cfg.StatePath)

	var findings []alert.Finding
	for _, rec := range adb.TopAttackers(50) {
		if alreadyBlocked[rec.IP] {
			continue
		}
		if rec.ThreatScore >= 70 {
			findings = append(findings, alert.Finding{
				Severity:  alert.Critical,
				Check:     "local_threat_score",
				Message:   fmt.Sprintf("High local threat score: %s (score %d/100, %d attacks)", rec.IP, rec.ThreatScore, rec.EventCount),
				Details:   fmt.Sprintf("Attack types: %v\nAccounts targeted: %d\nFirst seen: %s\nLast seen: %s", rec.AttackCounts, len(rec.Accounts), rec.FirstSeen.Format("2006-01-02 15:04"), rec.LastSeen.Format("2006-01-02 15:04")),
				Timestamp: time.Now(),
			})
		}
	}
	return findings
}
