package main

import (
	"strings"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/platform"
)

// loginSourcesDoctorCheck says where SSH, mail and FTP logins come from. A
// journal entry the service wrote can block and counts as a login; a line
// read from a syslog file, which any local user can write under any program
// name, only alerts.
func loginSourcesDoctorCheck(syslogJournal, mailJournal bool) DoctorCheck {
	c := DoctorCheck{Name: "login sources", Status: "ok", Message: "SSH, mail and FTP logins come from entries the services wrote to the journal"}
	var files []string
	if !syslogJournal {
		files = append(files, "SSH")
	}
	if !mailJournal {
		files = append(files, "mail")
	}
	if !syslogJournal {
		files = append(files, "FTP")
	}
	if len(files) == 0 {
		return c
	}
	c.Status = "warn"
	c.Message = joinServices(files) + " logins are read from log files any local user can write: they alert but never block or count as logins"
	var fixes []string
	if !syslogJournal {
		fixes = append(fixes, "run journald as the syslog socket (/dev/log) with journal storage enabled")
	}
	if !mailJournal {
		fixes = append(fixes, "leave mail_logs.source as auto or set it to journal, and list every running Postfix and Dovecot unit in mail_logs.units")
	}
	c.Fix = strings.Join(fixes, "; ")
	return c
}

// joinServices names services as "A", "A and B" or "A, B and C".
func joinServices(s []string) string {
	if len(s) < 2 {
		return strings.Join(s, "")
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// mailLoginsFromJournal reports whether mail logins come from a source a
// local user cannot write: Stalwart's own log, or the journal as the daemon
// would choose it.
func mailLoginsFromJournal(cfg *config.Config) bool {
	if platform.DetectMTA() == platform.MTAStalwart {
		return true
	}
	return cfg != nil && maillog.UsesJournal(cfg.MailLogs)
}
