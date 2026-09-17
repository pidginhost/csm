package alert

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestLoginUpgradeEmailExclusions(t *testing.T) {
	for old, current := range map[string]string{
		"ftp_login_realtime": "ftp_login",
		"ssh_login_realtime": "ssh_login_unknown_ip",
	} {
		for _, disabled := range []string{old, current} {
			findings := []Finding{{Check: old}, {Check: current}, {Check: "ftp_login_after_bruteforce"}}
			got := filterChecks(findings, []string{disabled})
			if len(got) != 1 || got[0].Check != "ftp_login_after_bruteforce" {
				t.Errorf("exclusion %s lost across upgrade: %+v", disabled, got)
			}
		}
	}
}

func TestLoginUpgradeNotificationFilterKeepsObservers(t *testing.T) {
	previousDial, previousBus := smtpDial, FindingBus
	t.Cleanup(func() { smtpDial, FindingBus = previousDial, previousBus })
	smtpCalls := 0
	smtpDial = func(time.Duration, string) (net.Conn, error) {
		smtpCalls++
		return nil, errors.New("unexpected email")
	}
	bus := &stubBus{}
	FindingBus = bus
	notified := 0
	t.Cleanup(RegisterFindingObserver(func(Finding) { notified++ }))
	var webhook webhookBodies
	srv := webhook.server(t)
	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"ops@example.invalid"}
	cfg.Alerts.Email.From = "csm@example.invalid"
	cfg.Alerts.Email.SMTP = "192.0.2.20:25"
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL
	findings := []Finding{{Check: "ftp_login", Severity: Warning}}
	err := DispatchWithNotificationFilter(cfg, findings, findings, nil, func([]Finding) []Finding { return nil })
	if err != nil || smtpCalls != 0 || len(webhook.snapshot()) != 0 || notified != 0 {
		t.Fatalf("muted finding notified operator: err=%v smtp=%d webhook=%v observers=%d", err, smtpCalls, webhook.snapshot(), notified)
	}
	if got := bus.publishCount.Load(); got != 1 {
		t.Fatalf("observer received %d findings, want 1", got)
	}
}
