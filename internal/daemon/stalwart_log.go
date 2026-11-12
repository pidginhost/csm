package daemon

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartlog"
)

// stalwartLogWatcher is the watcher name the Stalwart log reader reports.
const stalwartLogWatcher = "stalwart_log"

// stalwartLogStats counts what the reader delivered, for the health check.
type stalwartLogStats struct {
	read     atomic.Int64 // lines delivered
	parsed   atomic.Int64 // lines in Stalwart's layout
	lastLine atomic.Int64 // unix seconds of the last delivered line, or the start
}

// stalwartState is what the Stalwart log handler keeps between lines.
type stalwartState struct {
	ports   stalwartlog.Ports
	stats   stalwartLogStats
	webmail *stalwartWebmailTracker
}

func newStalwartState(ports stalwartlog.Ports, start time.Time) *stalwartState {
	s := &stalwartState{ports: ports, webmail: newStalwartWebmailTracker()}
	s.stats.lastLine.Store(start.Unix())
	return s
}

// useStalwartReader reports whether this host reads the Stalwart log instead
// of the Postfix/Dovecot mail log. A Stalwart host has neither of those logs.
func useStalwartReader(mta platform.MTAKind) bool { return mta == platform.MTAStalwart }

// startStalwartLogReader follows the newest Stalwart log file and feeds each
// line to handleStalwartLine.
func (d *Daemon) startStalwartLogReader(cfg *config.Config) {
	ports, err := stalwartlog.ParsePorts(cfg.Stalwart.Ports)
	if err != nil {
		// Validation already refused bad entries; keep the standard ports.
		csmlog.Warn("stalwart port mapping ignored", "err", err)
		ports, _ = stalwartlog.ParsePorts(nil)
	}
	d.stalwart = newStalwartState(ports, time.Now())
	dir, prefix := cfg.Stalwart.LogDir, cfg.Stalwart.LogPrefix

	d.MarkWatcher(stalwartLogWatcher, false)
	queue := maillog.NewQueue()
	d.registerQueueSource("stalwart", queue)
	ctx, cancel := context.WithCancel(context.Background())
	d.wg.Add(2)
	obs.Go("stalwart-log-stop", func() {
		defer d.wg.Done()
		select {
		case <-d.stopCh:
		case <-ctx.Done():
		}
		cancel()
	})
	obs.Go("stalwart-log-supervisor", func() {
		defer d.wg.Done()
		defer cancel()
		defer d.MarkWatcher(stalwartLogWatcher, false)
		maillog.Supervise(ctx, func() (maillog.Reader, error) {
			return maillog.NewResolvedFileReader(func() (string, error) { return stalwartlog.NewestFile(dir, prefix) }, queue)
		}, func(err error) {
			if err != nil {
				csmlog.Warn("stalwart log unavailable; retrying", "err", err)
				d.handleStalwartLogGone(err)
			} else {
				d.handleStalwartLogRestored()
			}
		}, func(line maillog.Line) bool {
			return d.dispatchLogLine(checks.ProducerStalwartLog, line, d.handleStalwartLine)
		})
	})
}

// handleStalwartLine parses one Stalwart log line. Lines outside Stalwart's
// layout and events CSM does not use produce nothing.
func (d *Daemon) handleStalwartLine(line string, obs alert.Observation, cfg *config.Config) []alert.Finding {
	s := d.stalwart
	if s == nil {
		return nil
	}
	s.stats.read.Add(1)
	s.stats.lastLine.Store(time.Now().Unix())
	ev, ok := stalwartlog.Parse(line)
	if !ok {
		return nil
	}
	s.stats.parsed.Add(1)
	switch ev.Name {
	case "auth.failed", "auth.success":
		session, ok := ev.Session()
		if !ok {
			return nil
		}
		return d.stalwartAuth(ev, session, obs, cfg)
	}
	return nil
}

func (d *Daemon) handleStalwartLogGone(err error) {
	d.MarkWatcher(stalwartLogWatcher, false)
	finding := alert.Finding{
		Severity:  alert.Warning,
		Check:     "mail_log_source_unavailable",
		Message:   fmt.Sprintf("Stalwart log unavailable: %v; mail login and send detection paused while CSM retries", err),
		Timestamp: time.Now(),
	}
	select {
	case <-d.stopCh:
		return
	default:
	}
	if !alert.TryEnqueue(d.alertCh, finding) {
		atomic.AddInt64(&d.droppedAlerts, 1)
		fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping stalwart log source finding\n", ts())
	}
}

func (d *Daemon) handleStalwartLogRestored() {
	d.MarkWatcher(stalwartLogWatcher, true)
}
