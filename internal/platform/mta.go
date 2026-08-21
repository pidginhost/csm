package platform

import (
	"os"
	"os/exec"
)

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

// MTAKind identifies the Mail Transfer Agent installed on the host.
type MTAKind string

const (
	MTAUnknown MTAKind = ""
	MTAExim    MTAKind = "exim"
	MTAPostfix MTAKind = "postfix"
)

var (
	mtaLookPath = exec.LookPath
	mtaStat     = os.Stat
)

// DetectMTA reports which MTA is installed. Exim wins when both are
// present: cPanel ships exim as the delivery agent and leaves postfix
// binaries on disk.
func DetectMTA() MTAKind {
	if mtaInstalled([]string{"exim", "exim4"}, []string{"/usr/sbin/exim", "/usr/sbin/exim4"}) {
		return MTAExim
	}
	if mtaInstalled([]string{"postfix"}, []string{"/usr/sbin/postfix", "/usr/libexec/postfix/master"}) {
		return MTAPostfix
	}
	return MTAUnknown
}

// mtaInstalled reports whether any of the named binaries is on PATH or at
// one of the absolute locations. The daemon runs with a minimal PATH, so
// the absolute probes carry most installs.
func mtaInstalled(binaries, paths []string) bool {
	for _, b := range binaries {
		if _, err := mtaLookPath(b); err == nil {
			return true
		}
	}
	for _, p := range paths {
		if _, err := mtaStat(p); err == nil {
			return true
		}
	}
	return false
}
