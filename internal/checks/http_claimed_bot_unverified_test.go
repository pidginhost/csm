package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func botUALine(ip, ua string) string {
	return fmt.Sprintf(`%s - - [20/May/2026:18:00:00 +0300] "GET /robots.txt HTTP/1.1" 200 100 "-" "%s"`, ip, ua)
}

// A claimed-bot UA whose verification is still pending (cache miss) must not be
// hard-blocked: its flood is routed to the reversible http_claimed_bot_unverified
// check, not http_request_flood. A real bot verifies next cycle and is skipped;
// a spoofer that claims the same UA still cannot pass the PoW challenge this
// check routes to.
func TestClaimedBot_PendingFloodRoutesToUnverified(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50

	stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
	rec, ok := parseAccessLogRecord(botUALine("203.0.113.99", "Googlebot/2.1 fake"))
	if !ok {
		t.Fatal("parse failed")
	}
	for i := 0; i < 75; i++ {
		stats.scan(rec, cfg, pendingVerifyClassifier{})
	}
	got := stats.emit(cfg)
	var flood, unverified, uaSpoof bool
	for _, f := range got {
		switch f.Check {
		case "http_request_flood":
			flood = true
		case "http_claimed_bot_unverified":
			unverified = true
		case "http_ua_spoof":
			uaSpoof = true
		}
	}
	if flood {
		t.Error("pending claimed bot must NOT emit http_request_flood (hard block)")
	}
	if !unverified {
		t.Error("pending claimed bot flood must emit http_claimed_bot_unverified")
	}
	if uaSpoof {
		t.Error("pending claimed bot must NOT emit http_ua_spoof (fail-open)")
	}
}

// Same protection on the scanner-profile path: a pending claimed bot whose 404
// crawl trips the scanner gates is routed to http_claimed_bot_unverified, not
// hard-blocked via http_scanner_profile.
func TestClaimedBot_PendingScannerRoutesToUnverified(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPScannerMinRequests = 10
	cfg.Thresholds.HTTPScannerErrorPct = 80
	cfg.Thresholds.HTTPScannerMinDistinctPaths = 5

	stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf(`203.0.113.98 - - [20/May/2026:18:00:00 +0300] "GET /probe-%d HTTP/1.1" 404 100 "-" "ClaudeBot/1.0 fake"`, i)
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			t.Fatal("parse failed")
		}
		stats.scan(rec, cfg, pendingVerifyClassifier{})
	}
	got := stats.emit(cfg)
	var scanner, unverified bool
	for _, f := range got {
		switch f.Check {
		case "http_scanner_profile":
			scanner = true
		case "http_claimed_bot_unverified":
			unverified = true
		}
	}
	if scanner {
		t.Error("pending claimed bot must NOT emit http_scanner_profile (hard block)")
	}
	if !unverified {
		t.Error("pending claimed bot scanner crawl must emit http_claimed_bot_unverified")
	}
}

// An attacker must not downgrade a hard block to a soft challenge by mixing in
// a single claimed-bot request. Only when the claimed-bot UA is the in-window
// majority is the IP treated as a pending bot; otherwise the flood is hard
// blocked as usual.
func TestClaimedBot_MixedTrafficStillFloods(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50

	stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
	botRec, _ := parseAccessLogRecord(botUALine("203.0.113.97", "Googlebot/2.1 fake"))
	browserUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	browserRec, ok := parseAccessLogRecord(botUALine("203.0.113.97", browserUA))
	if !ok {
		t.Fatal("parse failed")
	}
	for i := 0; i < 5; i++ {
		stats.scan(botRec, cfg, pendingVerifyClassifier{})
	}
	for i := 0; i < 70; i++ {
		stats.scan(browserRec, cfg, pendingVerifyClassifier{})
	}
	got := stats.emit(cfg)
	counts := map[string]int{}
	for _, f := range got {
		counts[f.Check]++
	}
	if counts["http_request_flood"] == 0 {
		t.Error("mostly-browser flood with one claimed-bot request must still hard-block (http_request_flood)")
	}
	if counts["http_claimed_bot_unverified"] != 0 {
		t.Error("a minority claimed-bot UA must not downgrade the flood to http_claimed_bot_unverified")
	}
}

// Once verification resolves positive, the bot is skipped entirely: no abuse
// finding of any kind, even under flood-level volume.
func TestClaimedBot_VerifiedNotCounted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50

	stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
	rec, ok := parseAccessLogRecord(botUALine("203.0.113.96", "Googlebot/2.1"))
	if !ok {
		t.Fatal("parse failed")
	}
	for i := 0; i < 75; i++ {
		stats.scan(rec, cfg, verifiedBotClassifier{})
	}
	got := stats.emit(cfg)
	if len(got) != 0 {
		t.Errorf("a verified bot must produce no findings, got %+v", got)
	}
}

// verifiedBotClassifier reports the claimed bot as verified.
type verifiedBotClassifier struct{}

func (verifiedBotClassifier) IsVerifiedBot(string, string) bool { return true }
