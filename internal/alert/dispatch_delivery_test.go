package alert

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestDispatchUrgentEmailDoesNotChargeFailedRoutineWebhook(t *testing.T) {
	for _, urgent := range []Finding{
		{Check: "critical_check", Severity: Critical, Message: "critical"},
		{Check: "ip_reputation", Severity: High, Message: "reputation"},
	} {
		t.Run(urgent.Check, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go runFakeSMTP(t, ln, done)
			t.Cleanup(func() {
				_ = ln.Close()
				<-done
			})

			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					http.Error(w, "temporary failure", http.StatusServiceUnavailable)
				}
			}))
			t.Cleanup(srv.Close)

			cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
			cfg.Alerts.MaxPerHour = 1
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"to@example.com"}
			cfg.Alerts.Email.From = "csm@example.com"
			cfg.Alerts.Email.SMTP = ln.Addr().String()
			cfg.Alerts.Email.DisabledChecks = []string{"routine_check"}
			cfg.Alerts.Webhook.Enabled = true
			cfg.Alerts.Webhook.URL = srv.URL
			routine := Finding{Check: "routine_check", Severity: Warning, Message: "routine"}

			err = Dispatch(cfg, []Finding{urgent, routine})
			if err == nil || !strings.Contains(err.Error(), "webhook:") || strings.Contains(err.Error(), "email:") {
				t.Fatalf("dispatch error = %v, want only a webhook failure", err)
			}
			if n := readRateLimitCount(t, cfg.StatePath); n != 0 {
				t.Errorf("budget after only urgent email succeeded = %d, want 0", n)
			}

			// The failed routine delivery must leave the last slot available.
			if err := Dispatch(cfg, []Finding{routine}); err != nil {
				t.Fatalf("retry routine webhook: %v", err)
			}
			if n := requests.Load(); n != 2 {
				t.Errorf("webhook requests = %d, want 2", n)
			}
			if n := readRateLimitCount(t, cfg.StatePath); n != 1 {
				t.Errorf("budget after routine webhook succeeded = %d, want 1", n)
			}
		})
	}
}

func TestDispatchDisabledRoutineDoesNotReserveBudget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go runFakeSMTP(t, ln, done)
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	// Hold an urgent-only email in flight while another dispatch needs the
	// last routine slot. Committed counts alone cannot detect a reservation.
	previousDial := smtpDial
	emailStarted := make(chan struct{})
	releaseEmail := make(chan struct{})
	var started sync.Once
	smtpDial = func(timeout time.Duration, addr string) (net.Conn, error) {
		started.Do(func() { close(emailStarted) })
		<-releaseEmail
		return previousDial(timeout, addr)
	}
	var release sync.Once
	unblock := func() { release.Do(func() { close(releaseEmail) }) }
	t.Cleanup(func() { smtpDial = previousDial })

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"to@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = ln.Addr().String()
	cfg.Alerts.Email.DisabledChecks = []string{"routine_check"}
	routine := Finding{Check: "routine_check", Severity: Warning, Message: "routine"}
	finished := make(chan error, 1)
	go func() {
		finished <- Dispatch(cfg, []Finding{
			{Check: "critical_check", Severity: Critical, Message: "critical"},
			routine,
		})
	}()
	t.Cleanup(func() {
		unblock()
		if err := <-finished; err != nil {
			t.Errorf("urgent email dispatch: %v", err)
		}
	})
	select {
	case <-emailStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("urgent email did not start")
	}

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(srv.Close)
	webhookCfg := *cfg
	webhookCfg.Alerts.Email.Enabled = false
	webhookCfg.Alerts.Webhook.Enabled = true
	webhookCfg.Alerts.Webhook.URL = srv.URL
	if err := Dispatch(&webhookCfg, []Finding{routine}); err != nil {
		t.Fatal(err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("concurrent routine webhook requests = %d, want 1", n)
	}
	if n := readRateLimitCount(t, cfg.StatePath); n != 1 {
		t.Fatalf("budget after routine webhook = %d, want 1", n)
	}
}
