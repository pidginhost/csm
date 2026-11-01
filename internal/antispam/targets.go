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

// Files CSM writes only on a Postfix host (spec section 5.1): the headers
// rspamd's milter adds and removes, and the Lua that scopes enforcement.
const (
	MilterHeadersPath   = RspamdLocalDir + "/milter_headers.conf"
	PostfixScopeLuaPath = RspamdLuaDir + "/csm_scope.lua"
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
	// TargetRspamdOptional is an rspamd file CSM owns outright while a feed
	// or map redirect needs it. A file CSM cannot own never blocks core: the
	// daemon leaves the feed or redirect out instead (feeds spec 5.3). On a
	// Postfix host actions.conf is one too, needed only to enforce.
	TargetRspamdOptional
	// TargetLuaOptional is an rspamd Lua plugin CSM owns outright while
	// learning needs it. Its marker is a Lua comment.
	TargetLuaOptional
	// TargetRoundcube is the webmail include CSM owns outright while
	// learning sets the Junk button's folder. It needs no service reload.
	TargetRoundcube
	// TargetRspamdLua is an rspamd Lua file CSM owns outright on every
	// install. Its marker is a Lua comment.
	TargetRspamdLua
)

// RoundcubeIncludePath is the Roundcube include that points the Junk button
// at the Spam folder learning reads (spec 6.4).
const RoundcubeIncludePath = "/usr/local/cpanel/base/3rdparty/roundcube/config/inc.d/zz-csm-antispam.inc.php"

// WholeFile reports whether CSM owns the target's entire content.
func (k TargetKind) WholeFile() bool {
	return k == TargetRspamd || k == TargetRspamdLua || k.Optional()
}

// Optional reports whether CSM writes the target only while a feature
// needs it; the daemon decides whether it may (OptionalUsable).
func (k TargetKind) Optional() bool {
	return k == TargetRspamdOptional || k == TargetLuaOptional || k == TargetRoundcube
}

// ReloadsRspamd reports whether a change to the target needs an rspamd
// reload.
func (k TargetKind) ReloadsRspamd() bool {
	return k == TargetRspamd || k == TargetRspamdOptional || k == TargetLuaOptional || k == TargetRspamdLua
}

// ManagedFor reports whether content is a whole file CSM wrote for a target
// of kind k, by the marker that kind's syntax allows. Shared Exim files
// carry blocks, never a whole-file marker.
func ManagedFor(k TargetKind, content string) bool {
	switch k {
	case TargetRspamd, TargetRspamdOptional:
		return IsManaged(content)
	case TargetLuaOptional, TargetRspamdLua:
		first, _, _ := strings.Cut(content, "\n")
		return first == LuaManagedHeader
	case TargetRoundcube:
		first, rest, _ := strings.Cut(content, "\n")
		second, _, _ := strings.Cut(rest, "\n")
		return first == "<?php" && second == ManagedHeader
	}
	return false
}

// Target is one file CSM writes.
type Target struct {
	Path string
	Kind TargetKind
}

// MutationTargets lists every file CSM writes on a host of stack, rspamd
// first as in the apply transaction (spec section 6.3). A Postfix host gets
// the milter headers and the scope Lua and no cPanel file; its actions.conf
// is optional, because a dry run leaves it to the host (spec 9.2). Any other
// stack gets the cPanel list.
func MutationTargets(stack MailStack) []Target {
	postfix := stack == StackPostfix
	optional := OptionalRspamdPaths()
	learning := LearningPaths()
	out := make([]Target, 0, len(RspamdFiles)+len(optional)+len(learning)+5)
	for _, name := range RspamdFiles {
		kind := TargetRspamd
		if postfix && name == "actions.conf" {
			kind = TargetRspamdOptional
		}
		out = append(out, Target{Path: path.Join(RspamdLocalDir, name), Kind: kind})
	}
	if postfix {
		out = append(out, Target{Path: MilterHeadersPath, Kind: TargetRspamd}, Target{Path: PostfixScopeLuaPath, Kind: TargetRspamdLua})
	}
	for _, p := range optional {
		out = append(out, Target{Path: p, Kind: TargetRspamdOptional})
	}
	for _, p := range learning {
		kind := TargetRspamdOptional
		if p == LearningLuaPath {
			kind = TargetLuaOptional
		}
		out = append(out, Target{Path: p, Kind: kind})
	}
	if postfix {
		return out
	}
	return append(out,
		Target{Path: RoundcubeIncludePath, Kind: TargetRoundcube},
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
	// Content is the text of an existing protected regular file. Unsafe
	// targets are rejected from their path facts without reading content.
	Content string
}

// CheckRemoval applies the target rules that still hold when CSM removes its
// integration (spec section 6.4): it never writes through an unsafe path or
// edits a file whose markers it cannot identify. A foreign local.d file stays
// in place and a missing directory has nothing to remove. targets must be
// the facts of MutationTargets(stack).
func CheckRemoval(stack MailStack, targets []TargetFacts) []Problem {
	if stack != StackExim && stack != StackPostfix {
		return []Problem{stackUnknown}
	}
	return checkTargets(stack, targets, true)
}

// stackUnknown stops changes to an installed integration on a host whose
// mail stack CSM cannot tell. A cPanel host always runs Exim, so this is a
// Postfix host, for example one with both MTAs installed while postfix
// restarts. Removal needs the stack's own files, and the Exim path would
// rebuild a configuration the host does not have.
var stackUnknown = Problem{Code: CodePlatform, Severity: Temporary, Detail: "CSM cannot tell which mail server this host runs, for example while Postfix restarts"}

// checkTargets applies spec section 6.2 item 9: every file CSM writes is a
// regular root-owned file without symlinks, in root-owned directories nobody
// else can write, and a shared file has room for CSM's block. A whole file
// that is not CSM's is backed up and replaced by the worker (spec 5.5).
// For removal only the rules that protect an edit apply.
func checkTargets(stack MailStack, targets []TargetFacts, removal bool) []Problem {
	var out []Problem
	add := func(code string, sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: code, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	if len(targets) != len(MutationTargets(stack)) {
		add(CodeTargets, Temporary, "the files CSM writes were not checked")
	}
	reported := make(map[string]bool)
	for _, t := range targets {
		// Optional files are the daemon's to judge (OptionalUsable). Removal
		// edits only files CSM wrote, and must not do so through an unsafe path.
		if t.Kind.Optional() && (!removal || !ManagedFor(t.Kind, t.Content)) {
			continue
		}
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
		// Removal only deletes an optional file, which needs a safe
		// directory, not a safe file: a loosened one must still go.
		if !t.Missing && t.File.Path != "" && (!removal || !t.Kind.Optional()) {
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
			if dir := path.Dir(t.Path); !removal && !reported[dir] {
				reported[dir] = true
				add(CodeTargets, Definite, "the directory %s is missing", dir)
			}
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
		case TargetEximLocal:
			if !removal {
				// A blank file is filled with cPanel's skeleton, as forward
				// guard does.
				if strings.TrimSpace(t.Content) != "" && !oneConfigSection(t.Content) {
					add(CodeTargets, Definite, "%s must hold exactly one @CONFIG@ line, alone and unindented", t.Path)
				}
				continue
			}
			fallthrough
		case TargetEximHook:
			// Hook files are ACL fragments, so trailing options can extend
			// CSM's last statement even without a section header in the file.
			switch blocks, err := fileBlocks(t.Kind, t.Content); {
			case errors.Is(err, ErrUnverifiable):
				add(CodeUnverifiable, Temporary, "cannot verify %s: %v", t.Path, err)
			case err != nil:
				add(CodeMarkers, Definite, "%s: %v", t.Path, err)
			case len(blocks) > 1:
				add(CodeMarkers, Definite, "%s has multiple CSM blocks; only one is allowed", t.Path)
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
