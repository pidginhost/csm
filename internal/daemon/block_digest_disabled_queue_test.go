package daemon

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestBlockDigestDisabledDestinationIsNotLost(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		label := "disabled_webhook"
		if enabled {
			label = "enabled_webhook_control"
		}
		for _, outcome := range []string{"returned_error", "panic", "goexit"} {
			t.Run(label+"/"+outcome, func(t *testing.T) {
				previousActive := config.Active()
				config.SetActive(nil)
				t.Cleanup(func() { config.SetActive(previousActive) })
				previousEmail, previousWebhook := blockDigestSendEmail, blockDigestSendWebhookJSON
				t.Cleanup(func() { blockDigestSendEmail = previousEmail; blockDigestSendWebhookJSON = previousWebhook })
				emailCalls, webhookCalls := 0, 0
				fail := true
				sentinel := errors.New("fixture unavailable email")
				blockDigestSendEmail = func(*config.Config, string, string) error {
					emailCalls++
					if fail {
						switch outcome {
						case "returned_error":
							return sentinel
						case "panic":
							panic(sentinel)
						case "goexit":
							runtime.Goexit()
						}
					}
					return nil
				}
				blockDigestSendWebhookJSON = func(*config.Config, any) error { webhookCalls++; return nil }
				cfg := &config.Config{}
				cfg.Alerts.BlockDigest.Enabled = true
				cfg.Alerts.BlockDigest.Channel = ""
				cfg.Alerts.BlockDigest.Interval = "1h"
				cfg.Alerts.BlockDigest.SendOn = "any"
				cfg.Alerts.BlockDigest.MinBlock = 1
				cfg.Alerts.Email.Enabled = true
				cfg.Alerts.Webhook.Enabled = enabled
				d := New(cfg, nil, nil, "")
				d.blockDigest = d.buildBlockDigest(cfg)
				observe := func() {
					d.observeBlocks([]alert.Finding{{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK: 192.0.2.66 blocked (expires in 24h)", Details: "Reason: fixture customer block", Timestamp: time.Now()}})
				}
				observe()
				done := make(chan struct{})
				var gotPanic any
				returned := false
				go func() {
					defer close(done)
					defer func() { gotPanic = recover() }()
					d.blockDigest.Flush()
					returned = true
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("flush did not join")
				}
				if returned != (outcome == "returned_error") || (outcome == "panic" && gotPanic != sentinel) || (outcome != "panic" && gotPanic != nil) {
					t.Fatal("original abnormal-exit policy changed")
				}
				rows := d.QueueStatuses()
				wantLoss := uint64(0)
				if enabled && outcome != "returned_error" {
					wantLoss = 1
				}
				row := rows["block_digest.webhook"]
				if row.DroppedTotal != wantLoss || row.Depth != 0 || row.InFlight != 0 || row.DroppedLowerBound {
					t.Errorf("notification loss must reflect actual configured destination: enabled=%v got=%+v want_lost=%d", enabled, row, wantLoss)
				}
				wantCalls := 0
				if enabled && outcome == "returned_error" {
					wantCalls = 1
				}
				if emailCalls != 1 || webhookCalls != wantCalls {
					t.Fatalf("original actual sink calls changed: email=%d webhook=%d", emailCalls, webhookCalls)
				}
				fail = false
				observe()
				d.blockDigest.Flush()
				if enabled {
					wantCalls++
				}
				if emailCalls != 2 || webhookCalls != wantCalls {
					t.Fatalf("recovery called disabled sink or retried abandoned work: email=%d webhook=%d", emailCalls, webhookCalls)
				}
				row = d.QueueStatuses()["block_digest.webhook"]
				if row.DroppedTotal != wantLoss {
					t.Errorf("recovery retained false disabled-destination lifetime loss: %+v", row)
				}
			})
		}
	}
}

func TestBlockDigestDefaultPolicySelectsEachDestination(t *testing.T) {
	previousActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(previousActive) })
	previousEmail, previousWebhook := blockDigestSendEmail, blockDigestSendWebhookJSON
	t.Cleanup(func() { blockDigestSendEmail, blockDigestSendWebhookJSON = previousEmail, previousWebhook })
	for _, emailEnabled := range []bool{false, true} {
		for _, webhookEnabled := range []bool{false, true} {
			emailCalls, webhookCalls := 0, 0
			blockDigestSendEmail = func(*config.Config, string, string) error { emailCalls++; return nil }
			blockDigestSendWebhookJSON = func(*config.Config, any) error { webhookCalls++; return nil }
			cfg := &config.Config{}
			cfg.Alerts.BlockDigest.Enabled = true
			cfg.Alerts.BlockDigest.Interval = "1h"
			cfg.Alerts.BlockDigest.SendOn = "any"
			cfg.Alerts.BlockDigest.MinBlock = 0
			cfg.Alerts.Email.Enabled = emailEnabled
			cfg.Alerts.Webhook.Enabled = webhookEnabled
			d := New(cfg, nil, nil, "")
			collector := d.buildBlockDigest(cfg)
			collector.Flush()
			expectedEmail, expectedWebhook := 0, 0
			if emailEnabled {
				expectedEmail = 1
			}
			if webhookEnabled {
				expectedWebhook = 1
			}
			if emailCalls != expectedEmail || webhookCalls != expectedWebhook {
				t.Fatalf("default destination selection: email=%d/%d webhook=%d/%d", emailCalls, expectedEmail, webhookCalls, expectedWebhook)
			}
			rows := d.QueueStatuses()
			for _, name := range []string{"block_digest.email", "block_digest.webhook"} {
				if row, ok := rows[name]; !ok || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.DroppedLowerBound || row.Status != "ok" {
					t.Fatalf("completed or suppressed %s: found=%v row=%+v", name, ok, row)
				}
			}
		}
	}
}
