package platform

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"time"
)

// EximMainLog is the Exim main log the daemon follows on cPanel hosts.
const EximMainLog = "/var/log/exim_mainlog"

// EximSpoolRoot is the Exim spool directory on cPanel hosts, holding input/
// and msglog/.
const EximSpoolRoot = "/var/spool/exim"

// EximLocalSkeleton is the full set of cPanel exim.conf.local section
// markers, written when a host has no exim.conf.local yet. cPanel's
// buildeximconf injects whatever follows each marker into exim.conf.
const EximLocalSkeleton = `@AUTH@

@BEGINACL@

@CONFIG@

@DIRECTOREND@

@DIRECTORMIDDLE@

@DIRECTORSTART@

@ENDACL@

@RETRYEND@

@RETRYSTART@

@REWRITE@

@ROUTEREND@

@ROUTERSTART@

@TRANSPORTEND@

@TRANSPORTMIDDLE@

@TRANSPORTSTART@
`

// MTAIdents lists local users and process basenames belonging to the
// host's Mail Transfer Agent stack. Direct SMTP egress detection uses
// this allowlist to skip legitimate local MTA traffic instead of
// path-allowlisting a directory.
type MTAIdents struct {
	Users       []string
	SystemUsers []string // Names that hosted accounts may also claim; require a system UID.
	Processes   []string
}

// IsMTAUser reports whether name and uid identify a known MTA account.
// Match is exact and case-sensitive (Linux usernames are).
func (m MTAIdents) IsMTAUser(name string, uid uint32) bool {
	return slices.Contains(m.Users, name) || (uid < 1000 && slices.Contains(m.SystemUsers, name))
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
// baseline plus Stalwart.
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
	var systemUsers []string
	if info.IsCPanel() {
		users = append(users, "exim")
		processes = append(processes, "exim", "exim4")
	} else {
		// Hosting accounts can claim these names on non-cPanel hosts too.
		systemUsers = []string{"stalwart", "stalwart-mail"}
	}
	return MTAIdents{Users: users, SystemUsers: systemUsers, Processes: processes}
}

// MTAKind identifies the host's Mail Transfer Agent.
type MTAKind string

const (
	MTAUnknown MTAKind = ""
	MTAExim    MTAKind = "exim"
	MTAPostfix MTAKind = "postfix"
	// MTAStalwart is Stalwart mail server, which writes its own log and is
	// detected only by its running service.
	MTAStalwart MTAKind = "stalwart"
)

var (
	mtaLookPath       = exec.LookPath
	mtaStat           = os.Stat
	mtaServiceActive  = systemdMTAServiceActive
	mtaServiceEnabled = systemdMTAServiceEnabled
)

// DetectMTA reports the delivery agent rather than whichever package happens
// to leave a binary on disk. cPanel is authoritative because it runs Exim
// while retaining Postfix binaries; elsewhere an active service wins.
func DetectMTA() MTAKind {
	if pathExists("/usr/local/cpanel/version") {
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
	if mtaServiceActive("stalwart") || mtaServiceActive("stalwart-mail") {
		return MTAStalwart
	}
	// CSM can start while Stalwart is still starting or restarting; an
	// enabled unit still names the mail server once Exim and Postfix are
	// not running.
	if mtaServiceEnabled("stalwart") || mtaServiceEnabled("stalwart-mail") {
		return MTAStalwart
	}

	eximInstalled := binaryInstalled([]string{"exim", "exim4"}, []string{
		"/usr/sbin/exim",
		"/usr/sbin/exim4",
	})
	postfixInstalled := binaryInstalled([]string{"postfix"}, []string{
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

// ServiceActive reports whether the systemd unit is active.
func ServiceActive(unit string) bool { return mtaServiceActive(unit) }

func pathExists(path string) bool {
	_, err := mtaStat(path)
	return err == nil
}

func systemdMTAServiceActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// #nosec G204 -- callers pass only the literal MTA unit names above.
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
}

func systemdMTAServiceEnabled(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// #nosec G204 -- callers pass only the literal MTA unit names above.
	return exec.CommandContext(ctx, "systemctl", "is-enabled", "--quiet", unit).Run() == nil
}

// binaryInstalled reports whether any of the named binaries is on PATH or at
// one of the absolute locations. The daemon runs with a minimal PATH, so
// the absolute probes carry most installs.
func binaryInstalled(binaries, paths []string) bool {
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
