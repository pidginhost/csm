package platform

import (
	"context"
	"os"
	"os/exec"
	"time"
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

// MTAKind identifies the host's Mail Transfer Agent.
type MTAKind string

const (
	MTAUnknown MTAKind = ""
	MTAExim    MTAKind = "exim"
	MTAPostfix MTAKind = "postfix"
)

var (
	mtaLookPath      = exec.LookPath
	mtaStat          = os.Stat
	mtaServiceActive = systemdMTAServiceActive
)

// DetectMTA reports the delivery agent rather than whichever package happens
// to leave a binary on disk. cPanel is authoritative because it runs Exim
// while retaining Postfix binaries; elsewhere an active service wins.
func DetectMTA() MTAKind {
	if mtaPathExists("/usr/local/cpanel/version") {
		return MTAExim
	}
	eximActive := mtaServiceActive("exim") || mtaServiceActive("exim4")
	postfixActive := mtaServiceActive("postfix")
	// When both are active, keep Exim-specific weaknesses visible instead of
	// dropping the checks behind an ambiguous result.
	if eximActive {
		return MTAExim
	}
	if postfixActive {
		return MTAPostfix
	}

	eximInstalled := mtaInstalled([]string{"exim", "exim4"}, []string{
		"/usr/sbin/exim",
		"/usr/sbin/exim4",
	})
	postfixInstalled := mtaInstalled([]string{"postfix"}, []string{
		"/usr/sbin/postfix",
		"/usr/libexec/postfix/master",
		"/usr/lib/postfix/sbin/master",
	})
	if eximInstalled == postfixInstalled {
		return MTAUnknown
	}
	if eximInstalled {
		return MTAExim
	}
	return MTAPostfix
}

func mtaPathExists(path string) bool {
	_, err := mtaStat(path)
	return err == nil
}

func systemdMTAServiceActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// #nosec G204 -- callers pass only the literal MTA unit names above.
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
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
		info, err := mtaStat(p)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return true
		}
	}
	return false
}
