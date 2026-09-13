package checks

import (
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/threatintel"
)

func TestBotPendingRequiresAdmittedLiveJob(t *testing.T) {
	for _, kind := range []string{"never queued", "full", "stopped", "unsupported", "expired"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				verifier := threatintel.NewAsyncBotVerifier(nil)
				classifier := newVerifyingClassifier(verifier, func(net.IP, string) (bool, bool) { return false, false })
				ip, ua := "203.0.113.99", "Googlebot/2.1"
				switch kind {
				case "never queued":
					if classifier.VerificationPending(ip, ua) {
						t.Fatal("cache miss without a job reported pending")
					}
					return
				case "full":
					for i := 0; i < 256; i++ {
						verifier.Enqueue(net.ParseIP(fmt.Sprintf("192.0.2.%d", i)), "googlebot")
					}
				case "stopped":
					stop := make(chan struct{})
					close(stop)
					verifier.Run(stop)
				case "unsupported":
					ua = "Twitterbot/1.0"
				case "expired":
					classifier.IsVerifiedBot(ip, ua)
					if !classifier.VerificationPending(ip, ua) {
						t.Fatal("admitted job lost initial pending treatment")
					}
					time.Sleep(time.Minute)
				}
				cfg := &config.Config{}
				cfg.Thresholds.HTTPFloodThreshold = 5
				stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
				rec, ok := parseAccessLogRecord(botUALine(ip, ua))
				if !ok {
					t.Fatal("parse failed")
				}
				for range 10 {
					stats.scan(rec, cfg, classifier)
				}
				if classifier.VerificationPending(ip, ua) {
					t.Error("unavailable or expired job reported pending")
				}
				findings := stats.emit(cfg)
				if !containsFindingCheck(findings, "http_request_flood") {
					t.Errorf("unverified flood bypassed ordinary controls: %+v", findings)
				}
				if containsFindingCheck(findings, "http_claimed_bot_unverified") || containsFindingCheck(findings, "http_ua_spoof") {
					t.Errorf("unresolved verification received pending or confirmed-spoof treatment: %+v", findings)
				}
			})
		})
	}
}
