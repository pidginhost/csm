package antispam

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// GeneratedEximConfPath is the configuration cPanel's buildeximconf writes.
const GeneratedEximConfPath = "/etc/exim.conf"

// Files CSM writes on a cPanel host (spec section 4.1).
const (
	HookRCPTPath      = "/usr/local/cpanel/etc/exim/acls/ACL_SPAM_SCAN_CHECK_BLOCK/custom_begin_spam_scan_check"
	HookScanPath      = "/usr/local/cpanel/etc/exim/acls/ACL_SPAM_SCAN_BLOCK/custom_begin_spam_scan"
	HookPostPath      = "/usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_POST_BLOCK/custom_begin_check_message_post"
	LocalEximConfPath = "/etc/exim.conf.local"
	RspamdLocalDir    = "/etc/rspamd/local.d"
)

// TargetKind says which ownership rule a mutation target follows.
type TargetKind int

const (
	// TargetRspamd is a local.d file CSM owns outright.
	TargetRspamd TargetKind = iota
	// TargetEximHook is a shared cPanel ACL hook file: at most one CSM block.
	TargetEximHook
	// TargetEximLocal is /etc/exim.conf.local: shared, with one @CONFIG@ line.
	TargetEximLocal
)

// Target is one file CSM writes.
type Target struct {
	Path string
	Kind TargetKind
}

// MutationTargets lists every file CSM writes, rspamd first as in the apply
// transaction (spec section 6.3).
func MutationTargets() []Target {
	out := make([]Target, 0, len(RspamdFiles)+4)
	for _, name := range RspamdFiles {
		out = append(out, Target{Path: path.Join(RspamdLocalDir, name), Kind: TargetRspamd})
	}
	return append(out,
		Target{Path: HookRCPTPath, Kind: TargetEximHook},
		Target{Path: HookScanPath, Kind: TargetEximHook},
		Target{Path: HookPostPath, Kind: TargetEximHook},
		Target{Path: LocalEximConfPath, Kind: TargetEximLocal},
	)
}

// TargetFacts describes one mutation target before CSM writes it.
type TargetFacts struct {
	Target
	// Err is a failure other than the target's absence. It wraps
	// fs.ErrNotExist when a parent directory is missing.
	Err error
	// Missing is true when the target does not exist; CSM creates it.
	Missing bool
	// File is the target's own lstat, including Path, set after a successful
	// stat. It remains available if reading Content then fails.
	File PathFacts
	// Parents run from "/" down to the target's directory, without following
	// symbolic links. The walk stops at the first entry that is not a directory.
	Parents []PathFacts
	// Content is the text of an existing regular file.
	Content string
}

// checkTargets applies spec section 6.2 item 9: every file CSM writes is a
// regular root-owned file without symlinks, in root-owned directories nobody
// else can write, and its content belongs to CSM or has room for CSM's block.
func checkTargets(targets []TargetFacts) []Problem {
	var out []Problem
	add := func(code string, sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: code, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	if len(targets) != len(MutationTargets()) {
		add(CodeTargets, Temporary, "the files CSM writes were not checked")
	}
	reported := make(map[string]bool)
	for _, t := range targets {
		safe := true
		for _, p := range t.Parents {
			problem := unprotected(p)
			if !p.Mode.IsDir() {
				problem = "is not a directory; CSM does not write through symbolic links"
			}
			if problem == "" {
				continue
			}
			safe = false
			if !reported[p.Path] {
				reported[p.Path] = true
				add(CodeTargets, Definite, "%s %s", p.Path, problem)
			}
		}
		if !safe {
			continue
		}
		// A later read error must not hide unsafe metadata already collected.
		if !t.Missing && t.File.Path != "" {
			if !t.File.Mode.IsRegular() {
				add(CodeTargets, Definite, "%s is not a regular file; CSM does not write through symbolic links", t.Path)
				continue
			}
			if problem := unprotected(t.File); problem != "" {
				add(CodeTargets, Definite, "%s %s", t.Path, problem)
				continue
			}
		}
		switch {
		case errors.Is(t.Err, fs.ErrNotExist):
			add(CodeTargets, Definite, "the directory for %s is missing", t.Path)
			continue
		case t.Err != nil:
			add(CodeTargets, Temporary, "cannot check %s; check file access", t.Path)
			continue
		case len(t.Parents) == 0:
			add(CodeTargets, Temporary, "the parent directories for %s were not checked", t.Path)
			continue
		case t.Missing:
			continue
		case t.File.Path == "":
			add(CodeTargets, Temporary, "the file metadata for %s was not checked", t.Path)
			continue
		}
		switch t.Kind {
		case TargetRspamd:
			if !IsManaged(t.Content) {
				add(CodeTargets, Definite, "%s is not managed by CSM; remove or rename it so CSM can write its own", t.Path)
			}
		case TargetEximHook:
			// Hook files are ACL fragments, so trailing options can extend
			// CSM's last statement even without a section header in the file.
			switch blocks, err := locateBlocks(t.Content, "acl", "csm_hook"); {
			case errors.Is(err, ErrUnverifiable):
				add(CodeUnverifiable, Temporary, "cannot verify %s: %v", t.Path, err)
			case err != nil:
				add(CodeMarkers, Definite, "%s: %v", t.Path, err)
			case len(blocks) > 1:
				add(CodeMarkers, Definite, "%s has multiple CSM blocks; only one is allowed", t.Path)
			}
		case TargetEximLocal:
			if !oneConfigSection(t.Content) {
				add(CodeTargets, Definite, "%s must hold exactly one @CONFIG@ line, alone and unindented", t.Path)
			}
		}
	}
	return out
}

// unprotected returns why another user could change p, or "".
func unprotected(p PathFacts) string {
	switch {
	case p.UID != 0:
		return fmt.Sprintf("is owned by uid %d; want root", p.UID)
	case p.Mode.Perm()&0o022 != 0:
		return "is writable by group or others"
	case p.ExtACL:
		return "carries extra ACL entries"
	}
	return ""
}

// oneConfigSection reports whether conf has exactly one line that reads
// @CONFIG@ once surrounding blanks are trimmed, and that line is exact.
func oneConfigSection(conf string) bool {
	n, exact := 0, false
	for _, line := range strings.Split(conf, "\n") {
		if strings.TrimSpace(line) == "@CONFIG@" {
			n++
			exact = line == "@CONFIG@"
		}
	}
	return n == 1 && exact
}
