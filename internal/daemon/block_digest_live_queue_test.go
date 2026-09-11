package daemon

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestBlockDigestAbandonUsesLiveDestinationPolicy(t *testing.T) {
	for _, enabledAfter := range []bool{false, true} {
		direction := "disabled_during_email"
		if enabledAfter {
			direction = "enabled_during_email_control"
		}
		for _, outcome := range []string{"returned_error", "panic", "goexit"} {
			t.Run(direction+"/"+outcome, func(t *testing.T) {
				previousActive := config.Active()
				config.SetActive(nil)
				t.Cleanup(func() { config.SetActive(previousActive) })
				previousEmail, previousWebhook := blockDigestSendEmail, blockDigestSendWebhookJSON
				t.Cleanup(func() { blockDigestSendEmail = previousEmail; blockDigestSendWebhookJSON = previousWebhook })
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				sentinel := errors.New("fixture email outcome after reload")
				emailCalls, webhookCalls := 0, 0
				blockDigestSendEmail = func(*config.Config, string, string) error {
					emailCalls++
					close(entered)
					<-release
					switch outcome {
					case "panic":
						panic(sentinel)
					case "goexit":
						runtime.Goexit()
					}
					return sentinel
				}
				blockDigestSendWebhookJSON = func(*config.Config, any) error { webhookCalls++; return nil }
				cfg := &config.Config{}
				cfg.Alerts.BlockDigest.Enabled = true
				cfg.Alerts.BlockDigest.Interval = "1h"
				cfg.Alerts.BlockDigest.SendOn = "any"
				cfg.Alerts.BlockDigest.MinBlock = 1
				cfg.Alerts.Email.Enabled = true
				cfg.Alerts.Webhook.Enabled = !enabledAfter
				d := New(cfg, nil, nil, "")
				d.blockDigest = d.buildBlockDigest(cfg)
				d.observeBlocks([]alert.Finding{{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK: 192.0.2.67 blocked (expires in 24h)", Details: "Reason: fixture customer block", Timestamp: time.Now()}})
				var gotPanic any
				returned := false
				go func() {
					defer close(done)
					defer func() { gotPanic = recover() }()
					d.blockDigest.Flush()
					returned = true
				}()
				t.Cleanup(func() {
					unblock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("email cleanup did not join")
					}
				})
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("actual email sink not entered")
				}
				if enabledAfter {
					row := d.queueStatuses(time.Now().Add(2 * time.Minute))["block_digest.webhook"]
					if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Status != "ok" {
						t.Errorf("initially disabled destination invented pending work: %+v", row)
					}
				}
				live := *cfg
				live.Alerts.Webhook.Enabled = enabledAfter
				config.SetActive(&live)
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("flush did not join")
				}
				if returned != (outcome == "returned_error") || (outcome == "panic" && gotPanic != sentinel) || (outcome != "panic" && gotPanic != nil) {
					t.Fatal("original abnormal-exit policy changed")
				}
				wantLoss := uint64(0)
				if enabledAfter && outcome != "returned_error" {
					wantLoss = 1
				}
				row := d.QueueStatuses()["block_digest.webhook"]
				if row.DroppedTotal != wantLoss || row.Depth != 0 || row.InFlight != 0 || row.DroppedLowerBound {
					t.Errorf("unattempted target must follow existing live policy: enabled_now=%v got=%+v want_lost=%d", enabledAfter, row, wantLoss)
				}
				wantCalls := 0
				if enabledAfter && outcome == "returned_error" {
					wantCalls = 1
				}
				if emailCalls != 1 || webhookCalls != wantCalls {
					t.Fatalf("callback order or live policy changed: email=%d webhook=%d", emailCalls, webhookCalls)
				}
			})
		}
	}
}
