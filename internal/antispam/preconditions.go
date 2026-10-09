package antispam

import (
	"errors"
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
	CodeUnverifiable   = "exim_config_unverifiable"
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
	GID  int
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
	// PeerUID is the listener's SO_PEERCRED uid, read during the probe, or -1
	// when unavailable. A failed /ping does not invalidate known credentials.
	PeerUID int
	// EximUID and EximGID are Exim's runtime user and group (exim_user and
	// exim_group, mailnull and mail on cPanel), or -1 when unknown.
	EximUID int
	EximGID int
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
	// SystemFilter is the file `exim -bP system_filter` names; "" when none.
	SystemFilter    string
	SystemFilterErr error
	// NamedLists holds one result per NamedListProbes entry, in order.
	NamedLists    []CommandResult
	SpamdDisabled bool // /etc/spamddisable exists
	// SpamdDisabledErr is a stat failure other than absence.
	SpamdDisabledErr error
	GlobalEnable     bool // /etc/global_spamassassin_enable exists
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
		add(CodeEximVersion, Temporary, "exim -bV failed; check Exim availability and configuration")
	case err != nil:
		add(CodeEximVersion, Temporary, "exim -bV did not report a readable version")
	case !v.AtLeast(minEximMajor, minEximMinor) || !v.ContentScanning:
		add(CodeEximVersion, Definite, "Exim %d.%d.%d (content scanning: %t) is unsupported; need 4.97 or later with content scanning",
			v.Major, v.Minor, v.Patch, v.ContentScanning)
	}

	switch {
	case f.SpamdDisabledErr != nil:
		add(CodeSpamAssassin, Temporary, "cannot check /etc/spamddisable; check file access")
	case !f.SpamdDisabled:
		add(CodeSpamAssassin, Definite, "SpamAssassin is enabled; disable spamd in WHM so /etc/spamddisable exists")
	}
	if f.GlobalEnable {
		add(CodeGlobalEnable, Warning, "/etc/global_spamassassin_enable exists, so no account can opt out")
	}

	out = append(out, checkSocket(f.Socket)...)
	out = append(out, checkRspamdVersions(f.RspamdVersion, f.RspamadmVersion)...)

	if f.EximOptions.Err != nil {
		add(CodeEximOptions, Temporary, "exim -bP failed; check Exim availability and configuration")
	} else {
		opts := ParseEximOptions(f.EximOptions.Stdout)
		prdr, okPRDR := opts["prdr_enable"]
		chunking, okChunking := opts["chunking_advertise_hosts"]
		if !okPRDR || !okChunking {
			add(CodeEximOptions, Temporary, "exim -bP did not report prdr_enable and chunking_advertise_hosts")
		}
		if okPRDR && prdr != "false" {
			add(CodeEximOptions, Definite, "prdr_enable must be off; per-recipient DATA handling is untested with these hooks")
		}
		if okChunking && !ChunkingOff(chunking) {
			add(CodeEximOptions, Definite, "chunking_advertise_hosts must be empty; BDAT is untested with these hooks")
		}
	}

	if f.GeneratedErr != nil {
		add(CodeSpamScoreRules, Temporary, "cannot read the generated Exim configuration; check file access")
	} else {
		lines, errU := UngatedSpamUses(f.GeneratedConf)
		cut, errC := HasCutthrough(f.GeneratedConf)
		_, errL := LocateBlocks(f.GeneratedConf)
		if err := firstUnverifiable(errU, errC, errL); err != nil {
			add(CodeUnverifiable, Temporary, "cannot verify the generated Exim configuration: %v", err)
		}
		if len(lines) > 0 {
			add(CodeSpamScoreRules, Definite, "Exim configuration lines %v act on spam scores outside cPanel's SpamAssassin gate; turn off cPanel's spam-score deny, ratelimit, forwarding and outgoing-scan options", lines)
		}
		if cut {
			add(CodeCutthrough, Definite, "cutthrough delivery is enabled; DATA-time header changes need it off")
		}
		if errL != nil && !errors.Is(errL, ErrUnverifiable) {
			add(CodeMarkers, Definite, "generated Exim configuration: %v", errL)
		}
	}

	if f.SystemFilterErr != nil {
		add(CodeSpamScoreRules, Temporary, "cannot read Exim's system filter; check file access")
	} else if lines := FilterSpamUses(f.SystemFilter); len(lines) > 0 {
		add(CodeSpamScoreRules, Definite, "Exim's system filter reads spam scores at lines %v; remove those rules so opted-out accounts are not affected", lines)
	}

	if f.LocalErr != nil {
		add(CodeForeignScanner, Temporary, "cannot read /etc/exim.conf.local; check file access")
	} else {
		found, errF := ForeignSpamdAddress(f.LocalConf)
		blocks, errL := LocateBlocks(f.LocalConf)
		if err := firstUnverifiable(errF, errL); err != nil {
			add(CodeUnverifiable, Temporary, "cannot verify /etc/exim.conf.local: %v", err)
		}
		if found {
			add(CodeForeignScanner, Definite, "/etc/exim.conf.local sets its own spamd_address; remove it so CSM's scanner is the only one")
		}
		if errL != nil {
			if !errors.Is(errL, ErrUnverifiable) {
				add(CodeMarkers, Definite, "/etc/exim.conf.local: %v", errL)
			}
		} else if len(blocks) > 1 {
			add(CodeMarkers, Definite, "/etc/exim.conf.local has multiple CSM blocks; only one scanner block is allowed")
		}
	}

	probes := NamedListProbes()
	if len(f.NamedLists) != len(probes) {
		add(CodeNamedList, Temporary, "named-list checks incomplete: %d of %d results", len(f.NamedLists), len(probes))
	}
	for i, r := range f.NamedLists[:min(len(f.NamedLists), len(probes))] {
		if r.Err != nil {
			add(CodeNamedList, Temporary, "exim -be %s failed; check Exim availability and configuration", probes[i])
			continue
		}
		switch err := ParseBeResult(r.Stdout, r.Stderr); {
		case errors.Is(err, ErrUndefinedList):
			add(CodeNamedList, Definite, "exim -be %s: a named list it uses is undefined", probes[i])
		case err != nil:
			add(CodeNamedList, Temporary, "exim -be %s printed an unexpected result", probes[i])
		}
	}
	return out
}

// firstUnverifiable returns the first error that marks an Exim file CSM
// cannot check, so one unparseable file yields one temporary problem.
func firstUnverifiable(errs ...error) error {
	for _, err := range errs {
		if errors.Is(err, ErrUnverifiable) {
			return err
		}
	}
	return nil
}

func checkSocket(s SocketFacts) []Problem {
	var out []Problem
	add := func(sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: CodeSocket, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	trusted := func(uid int) bool { return uid == 0 || uid == s.RspamdUID }
	eximKnown := s.EximUID >= 0 && s.EximGID >= 0
	switch {
	case s.Err != nil:
		add(Temporary, "cannot stat the rspamd socket; check file access")
	case s.Missing:
		add(Temporary, "rspamd socket %s does not exist; is rspamd running with CSM's bind_socket?", s.Socket.Path)
	default:
		if s.RspamdUID < 0 {
			add(Temporary, "the rspamd service user is unknown")
		}
		if s.Socket.Mode.Type() != fs.ModeSocket {
			add(Definite, "%s is not a socket", s.Socket.Path)
		}
		if s.RspamdUID >= 0 && !trusted(s.Socket.UID) {
			add(Definite, "%s is owned by uid %d; want root or the rspamd user", s.Socket.Path, s.Socket.UID)
		}
		if len(s.Parents) == 0 {
			add(Temporary, "the socket's parent directories were not checked")
		}
		switch {
		case !eximKnown:
			add(Temporary, "Exim's runtime user is unknown")
		case s.Socket.ExtACL:
			add(Temporary, "Exim's access to the socket cannot be verified from mode bits while extra ACL entries are present")
		case !permits(s.Socket, s.EximUID, s.EximGID, 0o2):
			add(Definite, "Exim's runtime user (uid %d) cannot write to %s; bind it with mode=0666", s.EximUID, s.Socket.Path)
		}
	}
	for _, p := range s.Parents {
		switch {
		case !p.Mode.IsDir():
			add(Definite, "%s is not a directory", p.Path)
		case s.RspamdUID >= 0 && !trusted(p.UID):
			add(Definite, "%s is owned by uid %d; want root or the rspamd user", p.Path, p.UID)
		case p.Mode.Perm()&0o022 != 0:
			add(Definite, "%s is writable by group or others", p.Path)
		case p.ExtACL:
			add(Definite, "%s carries extra ACL entries", p.Path)
		case eximKnown && !permits(p, s.EximUID, s.EximGID, 0o1):
			add(Definite, "Exim's runtime user (uid %d) cannot search %s", s.EximUID, p.Path)
		}
	}
	if s.Err != nil || s.Missing {
		return out
	}
	if s.PingErr != nil {
		add(Temporary, "rspamd did not answer /ping on the socket; check the rspamd service")
	}
	if s.PeerUID < 0 {
		if s.PingErr == nil {
			add(Temporary, "the socket listener's peer credentials are unavailable")
		}
	} else if s.RspamdUID >= 0 && !trusted(s.PeerUID) {
		add(Definite, "the socket listener runs as uid %d; want root or the rspamd user", s.PeerUID)
	}
	return out
}

// permits reports whether uid and gid get the want bits (2 write, 1 search)
// on p from its mode bits. CSM's own probe runs as root, so this is how it
// knows Exim's user can connect. Extra ACL entries are not read here.
func permits(p PathFacts, uid, gid int, want fs.FileMode) bool {
	perm := p.Mode.Perm()
	switch {
	case uid == 0:
		return true
	case uid == p.UID:
		return perm>>6&want == want
	case gid == p.GID:
		return perm>>3&want == want
	default:
		return perm&want == want
	}
}

func checkRspamdVersions(daemon, adm CommandResult) []Problem {
	var out []Problem
	add := func(sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: CodeRspamdVersion, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	if daemon.Err != nil || adm.Err != nil {
		add(Temporary, "rspamd --version or rspamadm --version failed; check both commands are available")
	}
	version := func(r CommandResult, name string) (string, int) {
		if r.Err != nil {
			return "", 0
		}
		v, major, err := ParseRspamdVersion(r.Stdout)
		if err != nil {
			add(Temporary, "%s --version did not report a readable version", name)
			return "", 0
		}
		return v, major
	}
	dv, dm := version(daemon, "rspamd")
	av, am := version(adm, "rspamadm")
	if dv != "" && dm < minRspamdMajor {
		add(Definite, "rspamd %s is unsupported; need 3 or later", dv)
	} else if av != "" && am < minRspamdMajor {
		add(Definite, "rspamadm %s is unsupported; need 3 or later", av)
	}
	if dv != "" && av != "" && dv != av {
		// A package upgrade replaces the two binaries one after the other.
		add(Temporary, "rspamd %s and rspamadm %s differ; wait for any upgrade to finish", dv, av)
	}
	return out
}
