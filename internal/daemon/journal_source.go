package daemon

import (
	"context"
	"fmt"
	"time"

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
	// session, when set, takes the entries its rules accept and rules do
	// not: lines the service wrote under a user's uid. That user can forge
	// one, so its producer must only alert.
	session *journalSource
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

// ftpJournal reads pure-ftpd's entries. It logs a failure as root before
// login and a session's lines, the login among them, as the logged-in user.
var ftpJournal = journalSource{
	name:        "ftp_journal",
	units:       []string{"pure-ftpd"},
	identifiers: []string{"pure-ftpd"},
	rules:       []maillog.SenderRule{{Units: []string{"pure-ftpd"}, UIDs: []uint32{0}}},
	producer:    checks.ProducerFTPJournal,
	session: &journalSource{
		rules:    []maillog.SenderRule{{Units: []string{"pure-ftpd"}, Executables: []string{"pure-ftpd"}}},
		producer: checks.ProducerFTPLog,
	},
}

// ftpJournalSource is ftpJournal with the daemon's handlers: root entries
// also count failures toward an FTP brute force.
func (d *Daemon) ftpJournalSource() journalSource {
	src := ftpJournal
	src.handler = d.handleFTPJournalLine
	session := *src.session
	session.handler = d.handleFTPSessionLine
	src.session = &session
	return src
}

// handleFTPSessionLine reports a pure-ftpd failure or login, a login after a
// brute force from its address at Critical.
func (d *Daemon) handleFTPSessionLine(line string, cfg *config.Config) []alert.Finding {
	findings := parseFTPLogLine(line, cfg)
	for i, f := range findings {
		if f.Check == "ftp_login" {
			if login, ok := d.ftpFails.LoginFinding(line, time.Now(), cfg); ok {
				findings[i] = login
			}
		}
	}
	return findings
}

// handleFTPJournalLine reports a pure-ftpd root entry and raises an FTP
// brute force when an address reaches the threshold, as the scan of the
// system log file does where the journal is not used.
func (d *Daemon) handleFTPJournalLine(line string, cfg *config.Config) []alert.Finding {
	findings := d.handleFTPSessionLine(line, cfg)
	for _, f := range findings {
		if f.Check != "ftp_auth_failure_realtime" || isPrivateOrLoopback(f.SourceIP) {
			continue
		}
		now := time.Now()
		at := customerLoginTime(line, now)
		n, windowMin, report := d.ftpFails.Failure(f.SourceIP, at, now, cfg)
		if report {
			findings = append(findings, alert.Finding{
				Severity: alert.High, Check: "ftp_bruteforce", SourceIP: f.SourceIP,
				Message:     fmt.Sprintf("FTP brute force from %s: %d failed attempts in %dm", f.SourceIP, n, windowMin),
				Attribution: admission.AttributionPeer,
			})
		}
		break
	}
	return findings
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

// dispatchJournalLine hands an entry src's service wrote to its handler, or
// to src's session handler under its producer; any other entry is dropped,
// which is not a delivery failure.
func (d *Daemon) dispatchJournalLine(src journalSource, line maillog.Line) bool {
	if !maillog.TrustedLine(line, src.rules) {
		if src.session == nil || !maillog.TrustedLine(line, src.session.rules) {
			return true
		}
		src = *src.session
	}
	return d.dispatchLogLine(src.producer, line, func(msg string, _ alert.Observation, cfg *config.Config) []alert.Finding {
		findings := src.handler(msg, cfg)
		for i := range findings {
			if src.producer == checks.ProducerFTPJournal {
				// Root FTP entries must not share notification history with
				// user-uid entries or file alerts saved before journal use.
				findings[i].DedupKey = "journal:" + findings[i].Key()
			}
			if findings[i].Check == "ssh_login_unknown_ip" && line.Position.Cursor != "" {
				// PIDs and client ports can be reused; the journal cursor
				// names the login independently of its message text.
				findings[i].DedupKey = "journal:" + line.Position.Cursor
			}
		}
		return findings
	})
}
