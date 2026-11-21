package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/obs"
)

// journalSource is a service log the daemon reads from the journal when
// syslog goes through journald. Only entries the service wrote reach its
// handler; a syslog file would take any local user's lines.
type journalSource struct {
	// name is the source's watcher and queue name.
	name  string
	units []string
	// identifiers also select entries, for instance units of a template.
	identifiers []string
	rules       []maillog.SenderRule
	producer    admission.ProducerID
	handler     LogLineHandler
}

// journalUsable probes the host once at start; a variable for tests.
var journalUsable = maillog.JournalUsable

// sshJournal reads sshd's entries: it logs every login from its privileged
// process, as root, in sshd.service or, on Debian, ssh.service, or in a
// per-connection instance of either when socket activation starts one.
var sshJournal = journalSource{
	name:        "ssh_journal",
	units:       []string{"sshd", "ssh", "sshd@", "ssh@"},
	identifiers: []string{"sshd", "sshd-session"},
	rules:       []maillog.SenderRule{{Units: []string{"sshd", "ssh", "sshd@", "ssh@"}, UIDs: []uint32{0}}},
	producer:    checks.ProducerSSHJournal,
	handler:     parseSecureLogLine,
}

// startJournalSource follows src's units from the journal tail.
func (d *Daemon) startJournalSource(src journalSource) {
	d.MarkWatcher(src.name, false)
	queue := maillog.NewQueue()
	d.registerQueueSource(src.name, queue)
	ctx, cancel := context.WithCancel(context.Background())
	d.wg.Add(2)
	obs.Go(src.name+"-stop", func() {
		defer d.wg.Done()
		select {
		case <-d.stopCh:
		case <-ctx.Done():
		}
		cancel()
	})
	obs.Go(src.name+"-supervisor", func() {
		defer d.wg.Done()
		defer cancel()
		defer d.MarkWatcher(src.name, false)
		maillog.Supervise(ctx, func() (maillog.Reader, error) {
			return maillog.NewJournalReaderFor(src.units, src.identifiers, queue), nil
		}, func(err error) {
			if err != nil {
				csmlog.Warn("journal source unavailable; retrying", "source", src.name, "err", err)
			}
			d.MarkWatcher(src.name, err == nil)
		}, func(line maillog.Line) bool {
			return d.dispatchJournalLine(src, line)
		})
	})
}

// dispatchJournalLine hands an entry src's service wrote to its handler;
// any other entry is dropped, which is not a delivery failure.
func (d *Daemon) dispatchJournalLine(src journalSource, line maillog.Line) bool {
	if !maillog.TrustedLine(line, src.rules) {
		return true
	}
	return d.dispatchLogLine(src.producer, line, func(msg string, _ alert.Observation, cfg *config.Config) []alert.Finding {
		findings := src.handler(msg, cfg)
		for i := range findings {
			if findings[i].Check == "ssh_login_unknown_ip" && line.Position.Cursor != "" {
				// PIDs and client ports can be reused; the journal cursor
				// names the login independently of its message text.
				findings[i].DedupKey = "journal:" + line.Position.Cursor
			}
		}
		return findings
	})
}
