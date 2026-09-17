//go:build linux

package daemon

import (
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type phpanelQueueTestTransport struct{ entered, release chan struct{} }

func (tr phpanelQueueTestTransport) RoundTrip(*http.Request) (*http.Response, error) {
	close(tr.entered)
	<-tr.release
	return nil, errors.New("collector unavailable")
}

func TestDaemonReportsPhpanelQueueDuringBlockedSend(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	restore := alert.SetWebhookTransportForTest(phpanelQueueTestTransport{entered, release})
	t.Cleanup(restore)
	t.Cleanup(alert.ClosePhpanelQueues)
	defer close(release)
	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = "https://panel.invalid/findings"
	cfg.Alerts.Webhook.HMACSecret = rand.Text()
	if err := alert.ConfigurePhpanelQueue(cfg); err != nil {
		t.Fatal(err)
	}
	if err := alert.Dispatch(cfg, []alert.Finding{{Check: "test_alert", Severity: alert.Critical, DedupKey: t.Name()}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("panel delivery did not start")
	}
	d := &Daemon{}
	status, ok := d.queueStatuses(time.Now().Add(2 * time.Minute))["phpanel.spool"]
	if !ok || status.Status != "degraded" || status.Reason != "processing_lag" || status.Depth != 0 || status.InFlight != 1 || status.ProcessingSeconds < 120 {
		t.Fatalf("daemon did not publish stalled panel work: %+v present=%v", status, ok)
	}
}
