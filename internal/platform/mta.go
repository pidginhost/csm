package platform

// MTAIdents lists local users and process basenames belonging to the
// host's Mail Transfer Agent stack. Direct SMTP egress detection uses
// this allowlist to skip legitimate local MTA traffic instead of
// path-allowlisting a directory.
type MTAIdents struct {
	Users     []string
	Processes []string
}

// IsMTAUser reports whether name is one of the known MTA usernames.
// Match is exact and case-sensitive (Linux usernames are).
func (m MTAIdents) IsMTAUser(name string) bool {
	for _, u := range m.Users {
		if u == name {
			return true
		}
	}
	return false
}

// IsMTAProcess reports whether basename is one of the known MTA process
// basenames. Exact match; the caller passes comm or basename(exe), not
// a full path.
func (m MTAIdents) IsMTAProcess(basename string) bool {
	for _, p := range m.Processes {
		if p == basename {
			return true
		}
	}
	return false
}

// LocalMTAIdentities returns the MTA users and process basenames that
// should be considered legitimate on the detected platform. cPanel
// hosts get exim variants; non-cPanel hosts get the postfix/dovecot
// baseline.
func LocalMTAIdentities(info Info) MTAIdents {
	users := []string{
		"mail",
		"mailnull",
		"postfix",
		"dovecot",
		"dovenull",
		"mailman",
	}
	processes := []string{
		"postfix",
		"smtpd",
		"smtp",
		"qmgr",
		"pickup",
		"cleanup",
		"local",
		"dovecot",
		"imap-login",
		"pop3-login",
		"lmtp",
	}
	if info.IsCPanel() {
		users = append(users, "exim")
		processes = append(processes, "exim", "exim4")
	}
	return MTAIdents{Users: users, Processes: processes}
}
