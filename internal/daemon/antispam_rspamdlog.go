package daemon

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// rspamdLogReopenInterval matches LogWatcher.Run: a log rotated by rename
// is picked up on the next reopen.
const rspamdLogReopenInterval = 5 * time.Minute

// rspamdLogLoop reads scan records from the rspamd log file the last
// reconcile pass named on a Postfix host, following that
// file when a pass names another.
func (d *Daemon) rspamdLogLoop(ctx context.Context) {
	var tail rspamdLogTail
	defer tail.stop()
	poll := time.NewTicker(logWatcherPollInterval)
	defer poll.Stop()
	reopen := time.NewTicker(rspamdLogReopenInterval)
	defer reopen.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reopen.C:
			if tail.w != nil {
				tail.w.reopen()
			}
		case <-poll.C:
			d.followRspamdLog(&tail)
		}
	}
}

// rspamdLogTail is what rspamdLogLoop keeps between polls.
type rspamdLogTail struct {
	w *LogWatcher
	// missing is the log last found unreadable, so each outage of a log
	// is reported once.
	missing string
}

func (t *rspamdLogTail) stop() {
	if t.w != nil {
		t.w.Stop()
		t.w = nil
	}
}

// followRspamdLog reads what rspamd logged since the last poll, after
// switching to the log the last pass named, or stopping when there is none.
// A log CSM cannot open is tried again on the next poll.
func (d *Daemon) followRspamdLog(t *rspamdLogTail) {
	var path string
	if src := d.antispamScanSource.Load(); src != nil && d.currentCfg().EmailProtection.Antispam.Enabled {
		path = src.Log
	}
	if t.w != nil && t.w.path != path {
		t.stop()
	}
	if t.w != nil {
		t.w.readNewLines()
		return
	}
	if path == "" {
		t.missing = ""
		return
	}
	// Like every log CSM watches, a file is read from where it ends.
	w, err := newLogWatcher(path, d.cfg, nil, d.alertCh, openRspamdLog)
	if err != nil {
		if t.missing != path {
			t.missing = path
			csmlog.Warn("rspamd log not readable, will retry", "path", path, "err", err)
		}
		return
	}
	if t.missing == path {
		csmlog.Info("watching rspamd log (appeared after retry)", "path", path)
	}
	t.missing = ""
	w.observed = d.handleRspamdLogLine
	t.w = w
}

// openRspamdLog opens rspamd's log without following a symlink or blocking
// on a FIFO, and only as a regular file: rspamd's user owns the log
// directory and can put either there.
func openRspamdLog(path string) (*os.File, error) {
	// #nosec G304 -- rspamd's log file as its configuration names it; no-follow and the regular-file check below bound the open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", path)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// handleRspamdLogLine counts a scan record in rspamd's log for scan health
// and the Email Security page. Any local process can have rspamd log a
// genuine record naming a sender of its choice, through rspamd's scan
// listeners, so a record is never evidence about that sender: no attack DB
// verdict, no CSM_IP weight and no spam source report.
func (d *Daemon) handleRspamdLogLine(line string, obs alert.Observation, _ *config.Config) []alert.Finding {
	s, ok := antispam.ParseRspamdScan(line)
	if !ok {
		return nil
	}
	return d.recordScan(s, line, lineReadAt(obs))
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
