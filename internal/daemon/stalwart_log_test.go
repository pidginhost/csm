package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartlog"
)

// Synthetic Stalwart lines. Never paste a live log line.
const stalwartAuthSuccessLine = `2026-11-11T10:00:00Z INFO Authentication successful (auth.success) listenerId = "imaps", localPort = 993, remoteIp = 203.0.113.10, remotePort = 50123, accountName = "user@example.com", accountId = 7`

// newStalwartTestDaemon returns a daemon with Stalwart state over the
// default ports plus overrides.
func newStalwartTestDaemon(t *testing.T, cfg *config.Config, overrides ...string) *Daemon {
	t.Helper()
	d := New(cfg, nil, nil, "")
	ports, err := stalwartlog.ParsePorts(overrides)
	if err != nil {
		t.Fatal(err)
	}
	d.stalwart = newStalwartState(ports, time.Now())
	return d
}

func TestUseStalwartReader(t *testing.T) {
	if !useStalwartReader(platform.MTAStalwart) {
		t.Fatal("Stalwart hosts read the Stalwart log")
	}
	for _, mta := range []platform.MTAKind{platform.MTAExim, platform.MTAPostfix, platform.MTAUnknown} {
		if useStalwartReader(mta) {
			t.Errorf("%q host must keep the Postfix/Dovecot reader", mta)
		}
	}
}

func TestDispatchLogLineStampsProducer(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	line := maillog.Line{Source: "file", Message: "x", Position: maillog.Position{Stream: "file:1:2", Cursor: "10"}}
	handler := func(string, alert.Observation, *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "smtp_bruteforce", SourceIP: "203.0.113.5"}}
	}
	if !d.dispatchLogLine(checks.ProducerStalwartLog, line, handler) {
		t.Fatal("dispatch failed")
	}
	select {
	case f := <-d.alertCh:
		if f.Observation.Producer != string(checks.ProducerStalwartLog) || f.Observation.Stream != "file:1:2" {
			t.Fatalf("observation = %+v", f.Observation)
		}
	default:
		t.Fatal("finding not enqueued")
	}
}

func TestStalwartLineCountsParsed(t *testing.T) {
	d := newStalwartTestDaemon(t, &config.Config{})
	before := d.stalwart.stats.lastLine.Load()
	d.handleStalwartLine("garbage", alert.Observation{}, d.cfg)
	if r, p := d.stalwart.stats.read.Load(), d.stalwart.stats.parsed.Load(); r != 1 || p != 0 {
		t.Fatalf("after garbage: read=%d parsed=%d", r, p)
	}
	d.handleStalwartLine(stalwartAuthSuccessLine, alert.Observation{}, d.cfg)
	if r, p := d.stalwart.stats.read.Load(), d.stalwart.stats.parsed.Load(); r != 2 || p != 1 {
		t.Fatalf("after a valid line: read=%d parsed=%d", r, p)
	}
	if d.stalwart.stats.lastLine.Load() < before {
		t.Fatal("lastLine moved backwards")
	}
}

func TestStalwartLogGoneRaisesSourceFinding(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.MarkWatcher("stalwart_log", true)
	d.handleStalwartLogGone(errors.New("no stalwart.log file"))
	if d.WatcherStatuses()["stalwart_log"] {
		t.Fatal("stalwart_log watcher should be unhealthy")
	}
	select {
	case f := <-d.alertCh:
		if f.Check != "mail_log_source_unavailable" || !strings.HasPrefix(f.Message, "Stalwart log unavailable: no stalwart.log file") || f.SourceIP != "" {
			t.Fatalf("finding = %+v", f)
		}
	default:
		t.Fatal("expected a source finding")
	}
	d.handleStalwartLogRestored()
	if !d.WatcherStatuses()["stalwart_log"] {
		t.Fatal("stalwart_log watcher should be healthy after restore")
	}
}
