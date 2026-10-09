package antispam

import (
	"fmt"
	"io/fs"
)

// Severity says what a failed precondition means for an installation
// (spec section 6.1).
type Severity int

const (
	// Temporary failures keep an installed integration and are retried.
	Temporary Severity = iota
	// Definite failures refuse a new install and remove an owned one.
	Definite
	// Warning failures are reported only.
	Warning
)

// Problem is one failed precondition. Code is stable for findings; Detail is
// for the operator and never carries file contents or secrets.
type Problem struct {
	Code     string
	Severity Severity
	Detail   string
}

// Problem codes.
const (
	CodePlatform       = "platform"
	CodeEximVersion    = "exim_version"
	CodeSpamAssassin   = "spamassassin_enabled"
	CodeGlobalEnable   = "global_enable"
	CodeSocket         = "rspamd_socket"
	CodeRspamdVersion  = "rspamd_version"
	CodeEximOptions    = "exim_options"
	CodeSpamScoreRules = "spam_score_rules"
	CodeCutthrough     = "cutthrough"
	CodeForeignScanner = "foreign_spamd_address"
	CodeMarkers        = "markers"
	CodeNamedList      = "named_list"
)

const (
	minEximMajor, minEximMinor = 4, 97
	minRspamdMajor             = 3
)

// CommandResult is one command's captured output.
type CommandResult struct {
	Stdout string
	Stderr string
	// Err is a start failure, timeout or non-zero exit.
	Err error
}

// PathFacts is one lstat result.
type PathFacts struct {
	Path string
	UID  int
	// Mode is the full lstat mode, including type bits.
	Mode fs.FileMode
	// ExtACL is true when the object carries POSIX ACL entries beyond its
	// mode bits.
	ExtACL bool
}

// SocketFacts describes the scan socket, its parent directories and a probe.
type SocketFacts struct {
	// Err is a stat failure other than absence.
	Err     error
	Missing bool
	Socket  PathFacts
	// Parents run from "/" down to the socket's directory.
	Parents []PathFacts
	// RspamdUID is the rspamd service user's uid, or -1 when unknown.
	RspamdUID int
	// PingErr is nil when GET /ping over the socket answered pong.
	PingErr error
	// PeerUID is the listener's SO_PEERCRED uid, read during the probe.
	PeerUID int
}

// HostFacts is everything CheckHost reads. A collector fills it; the checks
// stay pure.
type HostFacts struct {
	CPanel  bool
	MTAExim bool
	// EximVersion is `exim -bV`.
	EximVersion CommandResult
	// EximOptions is `exim -bP prdr_enable chunking_advertise_hosts`.
	EximOptions   CommandResult
	GeneratedConf string // /etc/exim.conf
	GeneratedErr  error
	LocalConf     string // /etc/exim.conf.local; "" when absent
	LocalErr      error
	// NamedLists holds one result per NamedListProbes entry, in order.
	NamedLists    []CommandResult
	SpamdDisabled bool // /etc/spamddisable exists
	GlobalEnable  bool // /etc/global_spamassassin_enable exists
	// RspamdVersion is `rspamd --version`; RspamadmVersion `rspamadm --version`.
	RspamdVersion   CommandResult
	RspamadmVersion CommandResult
	Socket          SocketFacts
}

// CheckHost evaluates the host preconditions of spec section 6.2 that hold
// before CSM writes anything. Staged rspamd settings are checked separately
// with CheckRspamd.
func CheckHost(f HostFacts) []Problem {
	var out []Problem
	add := func(code string, sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: code, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}

	if !f.CPanel || !f.MTAExim {
		add(CodePlatform, Definite, "antispam needs a cPanel host running Exim")
	}

	switch v, err := ParseEximVersion(f.EximVersion.Stdout); {
	case f.EximVersion.Err != nil:
		add(CodeEximVersion, Temporary, "exim -bV failed: %v", f.EximVersion.Err)
	case err != nil:
		add(CodeEximVersion, Definite, "%v", err)
	case !v.AtLeast(minEximMajor, minEximMinor) || !v.ContentScanning:
		add(CodeEximVersion, Definite, "Exim %d.%d.%d (content scanning: %t) is unsupported; need 4.97 or later with content scanning",
			v.Major, v.Minor, v.Patch, v.ContentScanning)
	}

	if !f.SpamdDisabled {
		add(CodeSpamAssassin, Definite, "SpamAssassin is enabled; disable spamd in WHM so /etc/spamddisable exists")
	}
	if f.GlobalEnable {
		add(CodeGlobalEnable, Warning, "/etc/global_spamassassin_enable exists, so no account can opt out")
	}

	out = append(out, checkSocket(f.Socket)...)
	out = append(out, checkRspamdVersions(f.RspamdVersion, f.RspamadmVersion)...)

	if f.EximOptions.Err != nil {
		add(CodeEximOptions, Temporary, "exim -bP failed: %v", f.EximOptions.Err)
	} else {
		opts := ParseEximOptions(f.EximOptions.Stdout)
		prdr, okPRDR := opts["prdr_enable"]
		chunking, okChunking := opts["chunking_advertise_hosts"]
		switch {
		case !okPRDR || !okChunking:
			add(CodeEximOptions, Temporary, "exim -bP did not report prdr_enable and chunking_advertise_hosts")
		default:
			if prdr != "false" {
				add(CodeEximOptions, Definite, "prdr_enable must be off; per-recipient DATA handling is untested with these hooks")
			}
			if !ChunkingOff(chunking) {
				add(CodeEximOptions, Definite, "chunking_advertise_hosts must be empty; BDAT is untested with these hooks")
			}
		}
	}

	if f.GeneratedErr != nil {
		add(CodeSpamScoreRules, Temporary, "cannot read the generated Exim configuration: %v", f.GeneratedErr)
	} else {
		if lines := UngatedSpamUses(f.GeneratedConf); len(lines) > 0 {
			add(CodeSpamScoreRules, Definite, "Exim ACL statements at lines %v act on spam scores outside cPanel's SpamAssassin gate; turn off cPanel's spam-score deny, ratelimit, forwarding and outgoing-scan options", lines)
		}
		if HasCutthrough(f.GeneratedConf) {
			add(CodeCutthrough, Definite, "cutthrough delivery is enabled; DATA-time header changes need it off")
		}
		if _, err := LocateBlocks(f.GeneratedConf); err != nil {
			add(CodeMarkers, Definite, "generated Exim configuration: %v", err)
		}
	}

	if f.LocalErr != nil {
		add(CodeForeignScanner, Temporary, "cannot read /etc/exim.conf.local: %v", f.LocalErr)
	} else {
		if ForeignSpamdAddress(f.LocalConf) {
			add(CodeForeignScanner, Definite, "/etc/exim.conf.local sets its own spamd_address; remove it so CSM's scanner is the only one")
		}
		if _, err := LocateBlocks(f.LocalConf); err != nil {
			add(CodeMarkers, Definite, "/etc/exim.conf.local: %v", err)
		}
	}

	probes := NamedListProbes()
	if len(f.NamedLists) != len(probes) {
		add(CodeNamedList, Temporary, "named-list checks incomplete: %d of %d results", len(f.NamedLists), len(probes))
	} else {
		for i, r := range f.NamedLists {
			if r.Err != nil {
				add(CodeNamedList, Temporary, "exim -be %s failed: %v", probes[i], r.Err)
				continue
			}
			if err := ParseBeResult(r.Stdout, r.Stderr); err != nil {
				add(CodeNamedList, Definite, "%s: %v", probes[i], err)
			}
		}
	}
	return out
}

func checkSocket(s SocketFacts) []Problem {
	var out []Problem
	add := func(sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: CodeSocket, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	switch {
	case s.Err != nil:
		add(Temporary, "cannot stat the rspamd socket: %v", s.Err)
		return out
	case s.Missing:
		add(Temporary, "rspamd socket %s does not exist; is rspamd running with CSM's bind_socket?", s.Socket.Path)
		return out
	case s.RspamdUID < 0:
		add(Temporary, "the rspamd service user is unknown")
		return out
	}
	trusted := func(uid int) bool { return uid == 0 || uid == s.RspamdUID }
	if s.Socket.Mode.Type() != fs.ModeSocket {
		add(Definite, "%s is not a socket", s.Socket.Path)
	}
	if !trusted(s.Socket.UID) {
		add(Definite, "%s is owned by uid %d; want root or the rspamd user", s.Socket.Path, s.Socket.UID)
	}
	if len(s.Parents) == 0 {
		add(Temporary, "the socket's parent directories were not checked")
	}
	for _, p := range s.Parents {
		switch {
		case !p.Mode.IsDir():
			add(Definite, "%s is not a directory", p.Path)
		case !trusted(p.UID):
			add(Definite, "%s is owned by uid %d; want root or the rspamd user", p.Path, p.UID)
		case p.Mode.Perm()&0o022 != 0:
			add(Definite, "%s is writable by group or others", p.Path)
		case p.ExtACL:
			add(Definite, "%s carries extra ACL entries", p.Path)
		}
	}
	if s.PingErr != nil {
		add(Temporary, "rspamd did not answer /ping on the socket: %v", s.PingErr)
	} else if !trusted(s.PeerUID) {
		add(Definite, "the socket listener runs as uid %d; want root or the rspamd user", s.PeerUID)
	}
	return out
}

func checkRspamdVersions(daemon, adm CommandResult) []Problem {
	fail := func(sev Severity, format string, args ...any) []Problem {
		return []Problem{{Code: CodeRspamdVersion, Severity: sev, Detail: fmt.Sprintf(format, args...)}}
	}
	if daemon.Err != nil || adm.Err != nil {
		return fail(Temporary, "rspamd --version or rspamadm --version failed")
	}
	dv, major, err := ParseRspamdVersion(daemon.Stdout)
	if err != nil {
		return fail(Definite, "rspamd: %v", err)
	}
	av, _, err := ParseRspamdVersion(adm.Stdout)
	if err != nil {
		return fail(Definite, "rspamadm: %v", err)
	}
	if major < minRspamdMajor {
		return fail(Definite, "rspamd %s is unsupported; need 3 or later", dv)
	}
	if dv != av {
		return fail(Definite, "rspamd %s and rspamadm %s differ", dv, av)
	}
	return nil
}
