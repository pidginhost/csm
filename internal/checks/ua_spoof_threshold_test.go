package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// TestUASpoofClaimedBotNegativeRequiresThreshold verifies a claimed-search-bot
// UA that fails rDNS is only hard-blocked after sustained hits (>= the
// http_ua_spoof threshold), not on a single request. A residential or mobile
// client that happens to send a bot-like User-Agent once is no longer
// auto-blocked, while a real spoof-crawler making many requests still is.
func TestUASpoofClaimedBotNegativeRequiresThreshold(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPUASpoofThreshold = 30

	mk := func(hits int) *domlogStats {
		s := newDomlogStats()
		s.uaCat["203.0.113.9"] = map[uaKind]int{uaKindClaimedBotNegative: hits}
		return s
	}
	hasSpoof := func(fs []alert.Finding) bool {
		for _, f := range fs {
			if f.Check == "http_ua_spoof" {
				return true
			}
		}
		return false
	}

	if hasSpoof(mk(1).emit(cfg)) {
		t.Error("single claimed-bot-negative hit must not hard-block (false-positive)")
	}
	if hasSpoof(mk(29).emit(cfg)) {
		t.Error("29 hits < threshold 30 must not block")
	}
	if !hasSpoof(mk(30).emit(cfg)) {
		t.Error("30 hits >= threshold must block")
	}
}
