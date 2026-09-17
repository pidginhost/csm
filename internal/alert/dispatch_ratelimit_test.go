package alert

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

type webhookBodies struct {
	mu     sync.Mutex
	bodies []string
}

func (w *webhookBodies) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.bodies = append(w.bodies, string(body))
		w.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (w *webhookBodies) snapshot() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.bodies...)
}

// The realtime dispatcher batches findings. A Critical in a batch used to lift
// the hourly cap for the whole batch, so every warning that happened to share
// a batch with a Critical was mailed regardless of the budget.
func TestDispatchCriticalDoesNotCarryRoutineFindingsPastCap(t *testing.T) {
	var got webhookBodies
	srv := got.server(t)

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL

	now := time.Now()
	batch := func(n string) []Finding {
		return []Finding{
			{Check: "crit_check", Message: "critical-" + n, Severity: Critical, Timestamp: now},
			{Check: "warn_check", Message: "routine-" + n, Severity: Warning, Timestamp: now},
		}
	}

	if err := Dispatch(cfg, batch("one")); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	if err := Dispatch(cfg, batch("two")); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}

	bodies := got.snapshot()
	if len(bodies) != 2 {
		t.Fatalf("webhook requests = %d, want 2 (criticals are never rate limited)", len(bodies))
	}
	if !strings.Contains(bodies[0], "critical-one") || !strings.Contains(bodies[0], "routine-one") {
		t.Errorf("first batch within budget must carry both findings: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], "critical-two") {
		t.Errorf("second batch must still deliver the critical: %s", bodies[1])
	}
	if strings.Contains(bodies[1], "routine-two") {
		t.Errorf("second batch delivered a routine finding past the hourly cap: %s", bodies[1])
	}
	if n := readRateLimitCount(t, cfg.StatePath); n != 1 {
		t.Errorf("rate-limit count = %d, want 1", n)
	}
}

// Routine findings no channel will carry must not spend the hourly budget.
func TestDispatchEmailDisabledRoutineFindingDoesNotSpendBudget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan struct{})
	go runFakeSMTP(t, ln, done)

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"to@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = ln.Addr().String()
	cfg.Alerts.Email.DisabledChecks = []string{"warn_check"}

	now := time.Now()
	err = Dispatch(cfg, []Finding{
		{Check: "crit_check", Message: "critical", Severity: Critical, Timestamp: now},
		{Check: "warn_check", Message: "routine", Severity: Warning, Timestamp: now},
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	<-done
	if n := readRateLimitCount(t, cfg.StatePath); n != 0 {
		t.Errorf("rate-limit count = %d, want 0 (the routine finding was never sent)", n)
	}
}
