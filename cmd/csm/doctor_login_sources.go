package main

import (
	"strings"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/platform"
)

// Source selection is not a liveness check: watcher health reports failures
// opening or following the selected source, including Stalwart's own log.
// ftpMissing names pure-ftpd configuration sources that leave DontResolve
// off; FTP failures then only alert.
func loginSourcesDoctorCheck(syslogJournal bool, cfg *config.Config, mta platform.MTAKind, platformDefaultFile string, ftpMissing []string) DoctorCheck {
	c := DoctorCheck{Name: "login sources", Status: "ok"}
	var files, fixes []string
	syslogSource := "journal"
	if !syslogJournal {
		syslogSource = "syslog files"
		files = append(files, "SSH", "FTP")
		fixes = append(fixes, "use a build with journal support and run journald as the syslog socket (/dev/log) with journal storage enabled")
	}

	mailSource := "Stalwart service log"
	if mta != platform.MTAStalwart {
		journal, err := maillog.UsesJournal(cfg.MailLogs, platformDefaultFile)
		switch {
		case err != nil:
			mailSource = "unavailable (" + err.Error() + ")"
			c.Status = "warn"
			fixes = append(fixes, "correct mail_logs.source, mail_logs.file and mail_logs.units")
		case journal:
			mailSource = "journal"
			if !maillog.JournalSupported() {
				mailSource += " (unsupported by this build)"
				c.Status = "warn"
				fixes = append(fixes, "use a build with journal support")
			}
		default:
			mailSource = "syslog file"
			files = append(files, "mail")
			fixes = append(fixes, "configure Postfix and Dovecot to log through journald, list their units in mail_logs.units, and set mail_logs.source to auto or journal")
		}
	}
	c.Message = "Selected login sources: SSH and FTP: " + syslogSource + "; mail: " + mailSource
	if len(files) > 0 {
		c.Status = "warn"
		c.Message += ". " + joinServices(files) + " syslog lines only alert; they never block or count as customer logins"
	}
	if len(ftpMissing) > 0 {
		c.Status = "warn"
		c.Message += ". FTP failures only alert while pure-ftpd logs client host names"
		fixes = append(fixes, "set DontResolve yes in "+joinServices(ftpMissing)+" and restart pure-ftpd")
	}
	c.Message += ". Watcher health reports source availability"
	c.Fix = strings.Join(fixes, "; ")
	return c
}

// pureFTPDMissingDontResolve names the pure-ftpd configuration sources
// without DontResolve.
func pureFTPDMissingDontResolve() []string {
	_, missing := platform.PureFTPDDontResolve()
	return missing
}

// joinServices names services as "A", "A and B" or "A, B and C".
func joinServices(s []string) string {
	if len(s) < 2 {
		return strings.Join(s, "")
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}
