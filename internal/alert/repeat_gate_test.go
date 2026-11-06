package alert

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// mapGate is a RepeatGate keyed like the alert state: Key to the delivered
// Fingerprint.
type mapGate struct {
	mu      sync.Mutex
	emailed map[string]string
	offered [][]Finding
}

func newMapGate() *mapGate { return &mapGate{emailed: make(map[string]string)} }

func (g *mapGate) BeginDelivery(findings []Finding) ([]Finding, func([]Finding)) {
	return g.FilterUnemailed(findings), g.MarkEmailed
}

func (g *mapGate) FilterUnemailed(findings []Finding) []Finding {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.offered = append(g.offered, append([]Finding(nil), findings...))
	var out []Finding
	for _, f := range findings {
		if g.emailed[f.Key()] != f.Fingerprint() {
			out = append(out, f)
		}
	}
	return out
}

func (g *mapGate) MarkEmailed(findings []Finding) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, f := range findings {
		g.emailed[f.Key()] = f.Fingerprint()
	}
}

func (g *mapGate) marked(f Finding) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.emailed[f.Key()] == f.Fingerprint()
}

// fakeMailer answers SMTP on an in-memory pipe and records delivered messages.
type fakeMailer struct {
	mu     sync.Mutex
	sent   int
	bodies []string
}

func installFakeMailer(t *testing.T) *fakeMailer {
	t.Helper()
	m := &fakeMailer{}
	previous := smtpDial
	smtpDial = func(time.Duration, string) (net.Conn, error) {
		client, server := net.Pipe()
		go m.serve(server)
		return client, nil
	}
	t.Cleanup(func() { smtpDial = previous })
	return m
}

func (m *fakeMailer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	reply := func(s string) { _, _ = io.WriteString(conn, s) }
	reply("220 ready\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch strings.ToUpper(strings.TrimSpace(line)) {
		case "DATA":
			reply("354 go ahead\r\n")
			var message strings.Builder
			for {
				body, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if body == ".\r\n" {
					break
				}
				message.WriteString(body)
			}
			m.mu.Lock()
			m.sent++
			m.bodies = append(m.bodies, message.String())
			m.mu.Unlock()
			reply("250 queued\r\n")
		case "QUIT":
			reply("221 bye\r\n")
			return
		default:
			reply("250 ok\r\n")
		}
	}
}

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sent
}

func (m *fakeMailer) messages() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.bodies...)
}

func repeatGateConfig(t *testing.T, webhookURL string) *config.Config {
	t.Helper()
	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host.example.com"}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"ops@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "192.0.2.25:25"
	if webhookURL != "" {
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = webhookURL
	}
	return cfg
}

var repeatGateFinding = Finding{Check: "webshell", Severity: High, Message: "shell in upload", Details: "path /home/example/public_html/x.php"}

func TestRepeatGateDeliversOnce(t *testing.T) {
	mailer := installFakeMailer(t)
	var hooks webhookBodies
	cfg := repeatGateConfig(t, hooks.server(t).URL)
	gate := newMapGate()

	for i := 0; i < 2; i++ {
		f := repeatGateFinding
		f.Timestamp = time.Unix(int64(100+i), 0)
		if err := DispatchWithNotificationFilter(cfg, []Finding{f}, nil, nil, []Finding{f}, nil, gate); err != nil {
			t.Fatalf("dispatch %d: %v", i, err)
		}
	}
	if got := mailer.count(); got != 1 {
		t.Errorf("emails = %d, want 1", got)
	}
	if got := len(hooks.snapshot()); got != 1 {
		t.Errorf("webhooks = %d, want 1", got)
	}
	// One gate call per dispatch, over the union of both channels by key.
	if len(gate.offered) != 2 || len(gate.offered[0]) != 1 || len(gate.offered[1]) != 1 {
		t.Fatalf("gate offered %v, want one call of one finding per dispatch", gate.offered)
	}
}

func TestRepeatGateMarksOnlyDelivered(t *testing.T) {
	for _, tc := range []struct {
		name string
		mark bool
		set  func(t *testing.T, cfg *config.Config)
	}{
		{"cap spent", false, func(t *testing.T, cfg *config.Config) {
			cfg.Alerts.MaxPerHour = 1
			hour := time.Date(2026, 1, 2, 10, 30, 0, 0, time.UTC)
			t.Cleanup(SetRateLimitClockForTest(func() time.Time { return hour }))
			spent, _ := json.Marshal(rateLimitState{Hour: hour.Format("2006-01-02T15"), Count: 1})
			if err := os.WriteFile(filepath.Join(cfg.StatePath, "ratelimit.json"), spent, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"email error, webhook off", false, func(t *testing.T, cfg *config.Config) {
			cfg.Alerts.Webhook.Enabled = false
			previous := smtpDial
			smtpDial = func(time.Duration, string) (net.Conn, error) { return nil, errors.New("smtp down") }
			t.Cleanup(func() { smtpDial = previous })
		}},
		{"email disabled, webhook ok", true, func(t *testing.T, cfg *config.Config) {
			cfg.Alerts.Email.Enabled = false
		}},
		{"check in disabled_checks, webhook ok", true, func(t *testing.T, cfg *config.Config) {
			cfg.Alerts.Email.DisabledChecks = []string{repeatGateFinding.Check}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installFakeMailer(t)
			var hooks webhookBodies
			cfg := repeatGateConfig(t, hooks.server(t).URL)
			tc.set(t, cfg)
			gate := newMapGate()
			_ = DispatchWithNotificationFilter(cfg, []Finding{repeatGateFinding}, nil, nil, []Finding{repeatGateFinding}, nil, gate)
			if got := gate.marked(repeatGateFinding); got != tc.mark {
				t.Fatalf("marked = %t, want %t", got, tc.mark)
			}
		})
	}
}

func TestRepeatGateRunsBeforeBudget(t *testing.T) {
	installFakeMailer(t)
	var hooks webhookBodies
	cfg := repeatGateConfig(t, hooks.server(t).URL)
	cfg.Alerts.MaxPerHour = 1
	gate := newMapGate()
	gate.MarkEmailed([]Finding{repeatGateFinding})

	if err := DispatchWithNotificationFilter(cfg, []Finding{repeatGateFinding}, nil, nil, []Finding{repeatGateFinding}, nil, gate); err != nil {
		t.Fatal(err)
	}
	if n := readRateLimitCount(t, cfg.StatePath); n != 0 {
		t.Fatalf("delivered finding spent the budget: count = %d", n)
	}
	if got := len(hooks.snapshot()); got != 0 {
		t.Fatalf("delivered finding sent again: %d webhooks", got)
	}

	// The slot it did not spend is still there for a new finding.
	fresh := Finding{Check: "webshell", Severity: High, Message: "another shell"}
	if err := DispatchWithNotificationFilter(cfg, []Finding{fresh}, nil, nil, []Finding{fresh}, nil, gate); err != nil {
		t.Fatal(err)
	}
	if got := len(hooks.snapshot()); got != 1 {
		t.Fatalf("new finding after a gated one: %d webhooks, want 1", got)
	}
}

func TestNilRepeatGateKeepsDirectNotices(t *testing.T) {
	mailer := installFakeMailer(t)
	cfg := repeatGateConfig(t, "")
	notice := Finding{Check: "auto_block", Severity: High, Message: "AUTO-BLOCK: 203.0.113.5"}
	for i := 0; i < 2; i++ {
		if err := DispatchNotices(cfg, []Finding{notice}); err != nil {
			t.Fatalf("notice %d: %v", i, err)
		}
	}
	if got := mailer.count(); got != 2 {
		t.Fatalf("emails = %d, want 2", got)
	}
}

func TestNoticeNotificationFilterRunsOnce(t *testing.T) {
	mailer := installFakeMailer(t)
	cfg := repeatGateConfig(t, "")
	calls := 0
	if err := DispatchNoticesWithNotificationFilter(cfg, []Finding{repeatGateFinding}, func(findings []Finding) []Finding {
		calls++
		return findings
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || mailer.count() != 1 {
		t.Fatalf("filter calls=%d emails=%d, want one each", calls, mailer.count())
	}
}

func TestRepeatCandidatesDoNotRepeatObservers(t *testing.T) {
	mailer := installFakeMailer(t)
	cfg := repeatGateConfig(t, "")
	gate := newMapGate()
	observed := 0
	t.Cleanup(RegisterFindingObserver(func(Finding) { observed++ }))
	if err := DispatchWithNotificationFilter(cfg, nil, nil, nil, []Finding{repeatGateFinding}, nil, gate); err != nil {
		t.Fatal(err)
	}
	if mailer.count() != 1 || observed != 0 || !gate.marked(repeatGateFinding) {
		t.Fatalf("retry: emails=%d observations=%d marked=%t", mailer.count(), observed, gate.marked(repeatGateFinding))
	}
}
