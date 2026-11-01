package daemon

import (
	"context"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/config"
)

// rspamdLogReopenInterval matches LogWatcher.Run: a log rotated by rename
// is picked up on the next reopen.
const rspamdLogReopenInterval = 5 * time.Minute

// rspamdLogLoop reads scan records from the rspamd log file the last
// reconcile pass named on a Postfix host (spec section 5.2), following that
// file when a pass names another.
func (d *Daemon) rspamdLogLoop(ctx context.Context) {
	var w *LogWatcher
	defer func() {
		if w != nil {
			w.Stop()
		}
	}()
	poll := time.NewTicker(logWatcherPollInterval)
	defer poll.Stop()
	reopen := time.NewTicker(rspamdLogReopenInterval)
	defer reopen.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reopen.C:
			if w != nil {
				w.reopen()
			}
		case <-poll.C:
			w = d.followRspamdLog(w)
		}
	}
}

// followRspamdLog reads what rspamd logged since the last call and returns
// the watcher for the next: a new one when the log moved, nil while there
// is none to read. A missing file is tried again on the next call.
func (d *Daemon) followRspamdLog(w *LogWatcher) *LogWatcher {
	var path string
	if src := d.antispamScanSource.Load(); src != nil && d.currentCfg().EmailProtection.Antispam.Enabled {
		path = src.Log
	}
	if w != nil && w.path != path {
		w.Stop()
		w = nil
	}
	if w == nil {
		if path == "" {
			return nil
		}
		// Like every log CSM watches, a file is read from where it ends.
		next, err := NewLogWatcher(path, d.cfg, nil, d.alertCh)
		if err != nil {
			return nil
		}
		next.observed = d.handleRspamdLogLine
		return next
	}
	w.readNewLines()
	return w
}

// handleRspamdLogLine counts a scan record in rspamd's log like an Exim
// scan marker.
func (d *Daemon) handleRspamdLogLine(line string, obs alert.Observation, cfg *config.Config) []alert.Finding {
	s, ok := antispam.ParseRspamdScan(line)
	if !ok {
		return nil
	}
	return d.recordScan(s, line, lineReadAt(obs), cfg)
}

// postfixMilterFailure reports a postfix smtpd warning that it could not
// connect to or read from one of milters, named as smtpd_milters names
// them. The warning must open smtpd's message: smtpd quotes client text
// such as HELO and RCPT only after its own words.
func postfixMilterFailure(line string, milters []string) bool {
	_, msg := postfixSMTPDMessage(line)
	if msg == "" {
		return false
	}
	for _, m := range milters {
		if strings.HasPrefix(msg, "warning: milter "+m+": ") || strings.HasPrefix(msg, "warning: connect to Milter service "+m+": ") {
			return true
		}
	}
	return false
}
