package daemon

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// dropperCandidate captures the fstat/read state of a file at close-write
// time. The fanotify fd is not retained: everything needed for the later
// TTL probe is copied here while the fd is still open, so probe decisions
// never race the attacker deleting or swapping the file.
type dropperCandidate struct {
	Path       string
	Docroot    string
	Observed   time.Time
	Birth      time.Time
	BirthKnown bool
	Inode      uint64
	Size       int64
	UID        uint32
	Mode       uint32
	PID        int32
	ProcInfo   string
	Head       []byte
}

// shouldTrackDropper reports whether a close-write event is a freshly
// created PHP or executable file inside a web document root, i.e. a
// candidate for self-deleting-dropper tracking. Modifications of
// pre-existing files are excluded via the statx birth time: without a
// verified recent birth the event is a rewrite (cache churn, config
// updates) and the periodic scanners already cover the surviving file.
func shouldTrackDropper(c dropperCandidate, selfPID int32, freshFor time.Duration) bool {
	if c.Docroot == "" {
		return false
	}
	if c.PID == selfPID {
		return false
	}
	if c.Mode&unixSIFMT != unixSIFREG {
		return false
	}
	name := strings.ToLower(filepath.Base(c.Path))
	if looksLikeAtomicWriteStage(filepath.Base(c.Path)) {
		return false
	}
	if !checks.IsExecutablePHPName(name) && c.Mode&0o111 == 0 {
		return false
	}
	if !c.BirthKnown || c.Observed.Sub(c.Birth) > freshFor {
		return false
	}
	return true
}

// S_IFMT constants mirrored from the unix package so this file stays free
// of //go:build linux and the decision logic remains testable on any OS.
const (
	unixSIFMT  = 0o170000
	unixSIFREG = 0o100000
)

// dropperMaxTracked bounds the tracker map. A cPanel package restore can
// close-write thousands of PHP files in seconds; entries beyond the cap are
// dropped (and counted) rather than evicting older candidates, because the
// oldest entries are the ones closest to their probe and losing them would
// blind the detector exactly when a bulk write storm provides cover.
const dropperMaxTracked = 4096

// dropperTracker holds candidates between their close-write observation and
// the TTL probe. All methods are safe for concurrent use by the analyzer
// workers and the probe loop.
type dropperTracker struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxTracked int
	entries    map[string]dropperCandidate
	pending    []dropperGone
	overflow   uint64
}

func newDropperTracker(ttl time.Duration) *dropperTracker {
	return &dropperTracker{
		ttl:        ttl,
		maxTracked: dropperMaxTracked,
		entries:    make(map[string]dropperCandidate),
	}
}

// Observe records a candidate. Re-observing a path keeps the first-seen
// time (so rewrites cannot postpone the probe) but refreshes the metadata
// snapshot to the latest write.
func (t *dropperTracker) Observe(c dropperCandidate) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if prev, ok := t.entries[c.Path]; ok {
		c.Observed = prev.Observed
		t.entries[c.Path] = c
		return
	}
	if len(t.entries) >= t.maxTracked {
		t.overflow++
		return
	}
	t.entries[c.Path] = c
}

// Due removes and returns every candidate whose TTL has elapsed at now.
func (t *dropperTracker) Due(now time.Time) []dropperCandidate {
	t.mu.Lock()
	defer t.mu.Unlock()
	var due []dropperCandidate
	for path, c := range t.entries {
		if now.Sub(c.Observed) > t.ttl {
			due = append(due, c)
			delete(t.entries, path)
		}
	}
	return due
}

func (t *dropperTracker) trackedCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

func (t *dropperTracker) overflowDropped() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.overflow
}

// dropperProbe is what the TTL probe learned about a vanished candidate.
// The linux wiring fills it from os.Stat/quarantine-ledger lookups; the
// verdict logic below stays platform-free.
type dropperProbe struct {
	Exists      bool
	DocrootGone bool
	RenamedTo   string
	Quarantined bool
}

type dropperVerdict int

const (
	dropperBenign dropperVerdict = iota
	// dropperDemoted: the file vanished but its content matched a
	// compiled-template artifact (Twig/Smarty cache churn). Reported at
	// Warning, never suppressed: an attacker can fake the header, so the
	// signal must stay visible for correlation.
	dropperDemoted
	dropperSuspect
)

// assessDropper turns a probe result into a verdict for one candidate.
func assessDropper(c dropperCandidate, p dropperProbe) dropperVerdict {
	if p.Exists || p.DocrootGone || p.RenamedTo != "" || p.Quarantined {
		return dropperBenign
	}
	if looksLikeCompiledTemplate(c.Head) {
		return dropperDemoted
	}
	return dropperSuspect
}

// looksLikeCompiledTemplate recognises template-engine compile artifacts
// (Twig class caches as written by phpMyAdmin/Symfony/Drupal, Smarty
// compile dirs). These are legitimately created and unlinked in short
// windows during cache rebuilds.
func looksLikeCompiledTemplate(head []byte) bool {
	s := string(head)
	if strings.Contains(s, "__TwigTemplate_") {
		return true
	}
	if strings.Contains(s, "/* Smarty version ") {
		return true
	}
	return false
}

// wpUpgradeRenameCandidates maps a path inside a WordPress upgrade staging
// dir (wp-content/upgrade/<staging>/<package>/<rest>) to the destinations
// WordPress moves it to on success: the plugin and theme dirs, or the
// docroot itself for core packages. The fanotify mask has no FAN_MOVED_TO,
// so a successful rename-based install makes the staged path vanish; the
// probe checks these destinations before calling it a self-deleting drop.
func wpUpgradeRenameCandidates(path string) []string {
	const marker = "/wp-content/upgrade/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return nil
	}
	docroot := path[:idx]
	rest := path[idx+len(marker):]
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 {
		// A file directly under upgrade/<staging>/ has no package dir and
		// therefore no predictable install destination.
		return nil
	}
	pkg, tail := parts[1], parts[2]
	if pkg == "wordpress" {
		return []string{docroot + "/" + tail}
	}
	return []string{
		docroot + "/wp-content/plugins/" + pkg + "/" + tail,
		docroot + "/wp-content/themes/" + pkg + "/" + tail,
	}
}

// dropperRenameMatch reports whether a stat of a rename-destination path
// identifies the same file as the tracked candidate: identical inode
// (rename(2) within a filesystem) or identical size plus identical leading
// bytes (WordPress's copy+delete fallback across filesystems).
func dropperRenameMatch(c dropperCandidate, destSize int64, destInode uint64, destHead []byte) bool {
	if destInode == c.Inode {
		return true
	}
	return destSize == c.Size && string(destHead) == string(c.Head)
}

// dropperGraceWindow is how long a vanished candidate is held before its
// finding flushes. The hold lets a bulk operation (plugin upgrade fallback,
// cache purge, deploy rollback) accumulate its siblings so the whole batch
// collapses into one Warning instead of paging per file.
const dropperGraceWindow = 45 * time.Second

// dropperBurstThreshold is the group size at which held candidates from one
// docroot are reported as a single bulk-churn aggregate instead of
// individual findings.
const dropperBurstThreshold = 8

type dropperGone struct {
	Cand    dropperCandidate
	Verdict dropperVerdict
	held    time.Time
}

// dropperFinding is one flush decision: either a single vanished file or a
// per-docroot aggregate of a create/delete burst.
type dropperFinding struct {
	Aggregate bool
	Docroot   string
	Items     []dropperGone
}

// HoldGone parks a vanished candidate until FlushDue decides whether it is
// reported alone or as part of a bulk-churn aggregate.
func (t *dropperTracker) HoldGone(c dropperCandidate, v dropperVerdict, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = append(t.pending, dropperGone{Cand: c, Verdict: v, held: now})
}

// FlushDue emits findings for docroot groups whose oldest held entry has
// aged past the grace window. The whole group flushes together so entries
// arriving late in a burst still fold into the aggregate.
func (t *dropperTracker) FlushDue(now time.Time) []dropperFinding {
	t.mu.Lock()
	defer t.mu.Unlock()

	oldest := make(map[string]time.Time)
	for _, g := range t.pending {
		if first, ok := oldest[g.Cand.Docroot]; !ok || g.held.Before(first) {
			oldest[g.Cand.Docroot] = g.held
		}
	}

	groups := make(map[string][]dropperGone)
	var keep []dropperGone
	for _, g := range t.pending {
		if now.Sub(oldest[g.Cand.Docroot]) > dropperGraceWindow {
			groups[g.Cand.Docroot] = append(groups[g.Cand.Docroot], g)
		} else {
			keep = append(keep, g)
		}
	}
	t.pending = keep

	var out []dropperFinding
	for docroot, items := range groups {
		out = append(out, dropperFinding{
			Aggregate: len(items) >= dropperBurstThreshold,
			Docroot:   docroot,
			Items:     items,
		})
	}
	return out
}

// dropperHeadExcerptMax caps how many leading file bytes a finding's
// details reproduce as evidence. The full head stays in memory only until
// the flush; findings carry just enough to triage without a file (the file
// is gone by definition).
const dropperHeadExcerptMax = 160

// dropperAggregateSampleMax caps how many member paths an aggregate
// finding lists before truncating with a count.
const dropperAggregateSampleMax = 10

// dropperAlertParams renders one flush decision into alert parameters:
// severity, message, details and the finding path.
func dropperAlertParams(f dropperFinding) (alert.Severity, string, string, string) {
	if f.Aggregate {
		var b strings.Builder
		fmt.Fprintf(&b, "Files created and removed within the tracking TTL (bulk churn, likely an upgrade, deploy or cache purge):\n")
		for i, g := range f.Items {
			if i == dropperAggregateSampleMax {
				fmt.Fprintf(&b, "... and %d more", len(f.Items)-dropperAggregateSampleMax)
				break
			}
			fmt.Fprintf(&b, "%s (uid=%d size=%d)\n", g.Cand.Path, g.Cand.UID, g.Cand.Size)
		}
		msg := fmt.Sprintf("%d short-lived PHP/executable files created and removed under %s", len(f.Items), f.Docroot)
		return alert.Warning, msg, strings.TrimRight(b.String(), "\n"), f.Docroot
	}

	g := f.Items[0]
	c := g.Cand
	lifetime := "unknown"
	if c.BirthKnown {
		lifetime = c.Observed.Sub(c.Birth).Truncate(time.Second).String()
	}
	details := fmt.Sprintf(
		"File appeared and was removed before the TTL probe. uid=%d size=%d mode=%04o write-age=%s",
		c.UID, c.Size, c.Mode&0o7777, lifetime)
	if c.ProcInfo != "" {
		details += " writer=[" + c.ProcInfo + "]"
	}
	sev := alert.Critical
	if g.Verdict == dropperDemoted {
		sev = alert.Warning
		details += "\nDemoted: content matches a compiled-template artifact (Twig/Smarty cache churn)."
	}
	if len(c.Head) > 0 {
		details += "\nLeading bytes: " + dropperPrintable(c.Head, dropperHeadExcerptMax)
	}
	msg := fmt.Sprintf("Self-deleting file under web root: %s", c.Path)
	return sev, msg, details, c.Path
}

// dropperPrintable renders up to max bytes of b with control and non-ASCII
// bytes replaced by '.' so binary heads (ELF droppers) cannot corrupt
// alert transports or terminal output.
func dropperPrintable(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

// dropperDocrootFor returns the longest configured web document root that
// contains path, or "" when the path is not inside any docroot. Matching is
// component-safe: /home/a/public_html_old is not inside /home/a/public_html.
func dropperDocrootFor(path string, docroots []string) string {
	best := ""
	for _, root := range docroots {
		if len(path) <= len(root) || !strings.HasPrefix(path, root) || path[len(root)] != '/' {
			continue
		}
		if len(root) > len(best) {
			best = root
		}
	}
	return best
}
