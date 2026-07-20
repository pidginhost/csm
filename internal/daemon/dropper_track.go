package daemon

import (
	"bytes"
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
	Created    bool
	Device     uint64
	Inode      uint64
	Size       int64
	UID        uint32
	Mode       uint32
	PID        int32
	ProcInfo   string
	// PHPExecutable is set by the Linux analyzer when an inherited
	// .htaccess handler makes a non-standard extension executable as PHP.
	PHPExecutable bool
	// ContentSuspicious prevents FP heuristics from demoting a file whose
	// realtime content/signature pass already found malicious structure.
	ContentSuspicious bool
	Digest            [32]byte
	DigestKnown       bool
	Head              []byte
}

// shouldTrackDropper reports whether a close-write event is a freshly
// created PHP or executable file inside a web document root, i.e. a
// candidate for self-deleting-dropper tracking. Modifications of
// pre-existing files are excluded via either a FAN_CREATE observation or a
// recent statx birth time. The explicit create bit keeps the detector useful
// on filesystems that do not expose STATX_BTIME; the Linux event path must
// preserve FAN_CREATE rather than throwing the event mask away.
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
	if !checks.IsExecutablePHPName(name) && !c.PHPExecutable && c.Mode&0o111 == 0 {
		return false
	}
	if !c.Created {
		age := c.Observed.Sub(c.Birth)
		if !c.BirthKnown || age < 0 || age > freshFor {
			return false
		}
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

// Keep enough leading content to recognise generated template artifacts and
// show useful evidence without allowing a burst of large files to retain
// hundreds of MiB until the probe and grace windows expire.
const dropperTrackedHeadMax = 4096

type dropperCandidateKey struct {
	path       string
	device     uint64
	inode      uint64
	birthNanos int64
	birthKnown bool
}

func candidateKey(c dropperCandidate) dropperCandidateKey {
	key := dropperCandidateKey{
		path:       c.Path,
		device:     c.Device,
		inode:      c.Inode,
		birthKnown: c.BirthKnown,
	}
	if c.BirthKnown {
		key.birthNanos = c.Birth.UnixNano()
	}
	return key
}

func ownDropperCandidate(c dropperCandidate) dropperCandidate {
	if len(c.Head) > dropperTrackedHeadMax {
		c.Head = c.Head[:dropperTrackedHeadMax]
	}
	c.Head = bytes.Clone(c.Head)
	return c
}

func mergeDropperCandidate(prev, next dropperCandidate) dropperCandidate {
	merged := next
	if next.Observed.Before(prev.Observed) {
		merged = prev
		merged.Observed = next.Observed
	} else {
		merged.Observed = prev.Observed
	}
	merged.Created = prev.Created || next.Created
	merged.PHPExecutable = prev.PHPExecutable || next.PHPExecutable
	merged.ContentSuspicious = prev.ContentSuspicious || next.ContentSuspicious
	if !merged.BirthKnown {
		switch {
		case prev.BirthKnown:
			merged.Birth = prev.Birth
			merged.BirthKnown = true
		case next.BirthKnown:
			merged.Birth = next.Birth
			merged.BirthKnown = true
		}
	}
	return merged
}

// dropperTracker holds candidates between their close-write observation and
// the TTL probe. All methods are safe for concurrent use by the analyzer
// workers and the probe loop.
type dropperTracker struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxTracked int
	entries    map[dropperCandidateKey]dropperCandidate
	pending    []dropperGone
	overflow   uint64
}

func newDropperTracker(ttl time.Duration) *dropperTracker {
	return &dropperTracker{
		ttl:        ttl,
		maxTracked: dropperMaxTracked,
		entries:    make(map[dropperCandidateKey]dropperCandidate),
	}
}

// Observe records a candidate. Re-observing the same file identity keeps the
// earliest event time (so rewrites cannot postpone the probe) and the newest
// metadata snapshot. A replacement inode at the same path is a separate
// candidate; otherwise an attacker could overwrite a vanished drop with a
// benign survivor before the probe. The return value reports whether the
// candidate was retained rather than rejected by the capacity bound. A false
// result is detection coverage loss and the Linux wiring must surface it as
// a metric and operator-facing warning.
func (t *dropperTracker) Observe(c dropperCandidate) bool {
	c = ownDropperCandidate(c)
	key := candidateKey(c)
	t.mu.Lock()
	defer t.mu.Unlock()
	if prev, ok := t.entries[key]; ok {
		t.entries[key] = mergeDropperCandidate(prev, c)
		return true
	}
	if len(t.entries) >= t.maxTracked {
		t.overflow++
		return false
	}
	t.entries[key] = c
	return true
}

// Refresh updates a previously admitted candidate without creating a new
// entry. The Linux wiring uses this for a CLOSE_WRITE that follows a separate
// FAN_CREATE event: the create proves freshness, while the close supplies the
// final size, digest, head, and content verdict. CLOSE_WRITE handlers should
// call Refresh first, then use shouldTrackDropper plus Observe only when no
// prior create entry matched. A birth-time availability change between the
// two events is allowed only when path, device, and inode still match.
func (t *dropperTracker) Refresh(c dropperCandidate) bool {
	c = ownDropperCandidate(c)
	key := candidateKey(c)
	t.mu.Lock()
	defer t.mu.Unlock()
	if prev, ok := t.entries[key]; ok {
		t.entries[key] = mergeDropperCandidate(prev, c)
		return true
	}
	if c.Inode == 0 {
		return false
	}
	for prevKey, prev := range t.entries {
		if prev.Path != c.Path || prev.Device != c.Device || prev.Inode != c.Inode {
			continue
		}
		// Exact known/known and unknown/unknown identities were handled by
		// the direct key lookup. Only strengthen unknown -> known here;
		// weakening a known identity could merge an inode-reuse generation.
		if prev.BirthKnown || !c.BirthKnown {
			continue
		}
		merged := mergeDropperCandidate(prev, c)
		delete(t.entries, prevKey)
		mergedKey := candidateKey(merged)
		if existing, ok := t.entries[mergedKey]; ok {
			merged = mergeDropperCandidate(existing, merged)
		}
		t.entries[mergedKey] = merged
		return true
	}
	return false
}

// Due removes and returns every candidate whose TTL has elapsed at now.
func (t *dropperTracker) Due(now time.Time) []dropperCandidate {
	t.mu.Lock()
	defer t.mu.Unlock()
	var due []dropperCandidate
	for key, c := range t.entries {
		if now.Sub(c.Observed) >= t.ttl {
			due = append(due, c)
			delete(t.entries, key)
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

// dropperFileState is the identity and content evidence captured when the
// probe opens a path. All fields must come from the same open fd. Device plus
// inode handles rename(2); birth time guards against inode reuse; a full
// digest handles copy-delete moves across filesystems. Head bytes are
// deliberately not identity evidence.
type dropperFileState struct {
	Path        string
	Device      uint64
	Inode       uint64
	Size        int64
	Birth       time.Time
	BirthKnown  bool
	Digest      [32]byte
	DigestKnown bool
}

// dropperProbe is what the TTL probe learned about a candidate. AtPath and
// RenameTarget carry enough evidence for this platform-free core to validate
// identity. A bare path-exists or destination-exists boolean would let a
// replacement file hide the vanished inode.
type dropperProbe struct {
	// Conclusive is set only after the probe distinguished absence from a
	// permission, I/O, or other transient failure.
	Conclusive bool
	AtPath     *dropperFileState
	// DocrootRemoved is true only for a confirmed ENOENT on the document
	// root, not for permission or transient I/O failures.
	DocrootRemoved bool
	RenamedTo      string
	RenameTarget   *dropperFileState
	// QuarantineMatched requires an exact ledger identity/fingerprint match,
	// not merely a prior quarantine entry for the same path.
	QuarantineMatched bool
}

type dropperVerdict int

const (
	dropperBenign dropperVerdict = iota
	dropperInconclusive
	dropperDemotedTemplate
	dropperDemotedAtomicWrite
	dropperDemotedWPUpgrade
	dropperDemotedDocroot
	dropperSuspect
)

func dropperVerdictDemoted(v dropperVerdict) bool {
	return v >= dropperDemotedTemplate && v <= dropperDemotedDocroot
}

func dropperSameIdentity(c dropperCandidate, current dropperFileState) bool {
	if c.Inode == 0 || current.Inode == 0 || c.Device != current.Device || c.Inode != current.Inode {
		return false
	}
	if c.BirthKnown != current.BirthKnown {
		return false
	}
	return !c.BirthKnown || c.Birth.Equal(current.Birth)
}

// assessDropper turns a probe result into a verdict for one candidate.
func assessDropper(c dropperCandidate, p dropperProbe) dropperVerdict {
	if !p.Conclusive {
		// Due removed this candidate from the tracker. The probe loop should
		// reinsert it with Observe and handle a false capacity result.
		return dropperInconclusive
	}
	if p.QuarantineMatched {
		return dropperBenign
	}
	if p.AtPath != nil {
		if p.AtPath.Path != c.Path {
			return dropperSuspect
		}
		if dropperSameIdentity(c, *p.AtPath) {
			return dropperBenign
		}
	}
	if p.RenamedTo != "" || p.RenameTarget != nil {
		if p.RenamedTo == "" || p.RenameTarget == nil || p.RenameTarget.Path != p.RenamedTo {
			return dropperSuspect
		}
		if dropperRenameTargetAllowed(c, p.RenamedTo) && dropperRenameMatch(c, *p.RenameTarget) {
			return dropperBenign
		}
	}
	if c.ContentSuspicious {
		return dropperSuspect
	}
	if p.DocrootRemoved {
		return dropperDemotedDocroot
	}
	if atomicWriteRenameCandidate(c.Path) != "" {
		return dropperDemotedAtomicWrite
	}
	if len(wpUpgradeRenameCandidates(c.Path, c.Docroot)) > 0 {
		return dropperDemotedWPUpgrade
	}
	if looksLikeCompiledTemplate(c.Head) {
		return dropperDemotedTemplate
	}
	return dropperSuspect
}

// looksLikeCompiledTemplate recognises template-engine compile artifacts
// (Twig class caches as written by phpMyAdmin/Symfony/Drupal, Smarty
// compile dirs). These are legitimately created and unlinked in short
// windows during cache rebuilds.
func looksLikeCompiledTemplate(head []byte) bool {
	head = bytes.TrimSpace(bytes.TrimPrefix(head, []byte{0xef, 0xbb, 0xbf}))
	if !bytes.HasPrefix(head, []byte("<?php")) {
		return false
	}
	if bytes.Contains(head, []byte("class __TwigTemplate_")) &&
		bytes.Contains(head, []byte(" extends Template")) {
		return true
	}
	if bytes.Contains(head, []byte("/* Smarty version ")) &&
		bytes.Contains(head, []byte(", created on ")) &&
		bytes.Contains(head, []byte("from '")) {
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
func wpUpgradeRenameCandidates(path, configuredDocroot string) []string {
	const marker = "/wp-content/upgrade/"
	if !filepath.IsAbs(path) || !filepath.IsAbs(configuredDocroot) ||
		filepath.Clean(path) != path || filepath.Clean(configuredDocroot) != configuredDocroot {
		return nil
	}
	idx := strings.Index(path, marker)
	if idx < 0 {
		return nil
	}
	wpRoot := path[:idx]
	if wpRoot != configuredDocroot && !strings.HasPrefix(wpRoot, configuredDocroot+string(filepath.Separator)) {
		return nil
	}
	rest := path[idx+len(marker):]
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 || parts[1] == "" || parts[1] == "." || parts[1] == ".." ||
		parts[2] == "" || filepath.Clean(parts[2]) != parts[2] {
		// A file directly under upgrade/<staging>/ has no package dir and
		// therefore no predictable install destination.
		return nil
	}
	pkg, tail := parts[1], parts[2]
	if pkg == "wordpress" {
		return []string{filepath.Join(wpRoot, tail)}
	}
	return []string{
		filepath.Join(wpRoot, "wp-content", "plugins", pkg, tail),
		filepath.Join(wpRoot, "wp-content", "themes", pkg, tail),
	}
}

// atomicWriteRenameCandidate maps cPanel's .temp.<timestamp>.<name> staging
// path to its intended final path. It is only a location hint: the probe must
// still validate the destination with dropperRenameMatch.
func atomicWriteRenameCandidate(path string) string {
	base := filepath.Base(path)
	if !looksLikeAtomicWriteStage(base) {
		return ""
	}
	rest := strings.TrimPrefix(base, ".temp.")
	dot := strings.IndexByte(rest, '.')
	if dot < 0 || dot == len(rest)-1 {
		return ""
	}
	return filepath.Join(filepath.Dir(path), rest[dot+1:])
}

func dropperRenameTargetAllowed(c dropperCandidate, target string) bool {
	if atomicTarget := atomicWriteRenameCandidate(c.Path); atomicTarget != "" && target == atomicTarget {
		return true
	}
	for _, candidate := range wpUpgradeRenameCandidates(c.Path, c.Docroot) {
		if target == candidate {
			return true
		}
	}
	return false
}

// dropperRenameMatch reports whether a probe of a rename-destination path
// identifies the same file as the tracked candidate: identical device,
// inode, and birth time for rename(2), or identical size plus a full SHA-256
// digest for a copy-delete fallback across filesystems.
func dropperRenameMatch(c dropperCandidate, dest dropperFileState) bool {
	if dropperSameIdentity(c, dest) {
		return true
	}
	return c.DigestKnown && dest.DigestKnown && c.Size == dest.Size && c.Digest == dest.Digest
}

// dropperGraceWindow is how long a vanished candidate is held before its
// finding flushes. The hold lets a bulk operation (plugin upgrade fallback,
// cache purge, deploy rollback) accumulate its siblings so the whole batch
// collapses into one Warning for classified churn or one High signal for an
// unclassified burst, instead of paging Critical per file.
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
	if v == dropperBenign || v == dropperInconclusive {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = append(t.pending, dropperGone{Cand: ownDropperCandidate(c), Verdict: v, held: now})
}

// FlushDue emits findings for docroot groups whose oldest held entry has
// aged past the grace window. The whole group flushes together so entries
// arriving late in a burst still fold into the aggregate.
func (t *dropperTracker) FlushDue(now time.Time) []dropperFinding {
	t.mu.Lock()
	defer t.mu.Unlock()

	type groupKey struct {
		docroot string
		demoted bool
	}
	keyFor := func(g dropperGone) groupKey {
		return groupKey{docroot: g.Cand.Docroot, demoted: dropperVerdictDemoted(g.Verdict)}
	}

	oldest := make(map[groupKey]time.Time)
	for _, g := range t.pending {
		key := keyFor(g)
		if first, ok := oldest[key]; !ok || g.held.Before(first) {
			oldest[key] = g.held
		}
	}

	groups := make(map[groupKey][]dropperGone)
	var keep []dropperGone
	for _, g := range t.pending {
		key := keyFor(g)
		if now.Sub(oldest[key]) >= dropperGraceWindow {
			groups[key] = append(groups[key], g)
		} else {
			keep = append(keep, g)
		}
	}
	t.pending = keep

	var out []dropperFinding
	for key, items := range groups {
		if len(items) >= dropperBurstThreshold {
			out = append(out, dropperFinding{
				Aggregate: true,
				Docroot:   key.docroot,
				Items:     items,
			})
			continue
		}
		for _, item := range items {
			out = append(out, dropperFinding{
				Docroot: key.docroot,
				Items:   []dropperGone{item},
			})
		}
	}
	return out
}

// dropperHeadExcerptMax caps how many leading file bytes a finding's
// details reproduce as evidence. The bounded tracked head stays in memory
// only until the flush; findings carry just enough to triage without a file
// (the file is gone by definition).
const dropperHeadExcerptMax = 160

// dropperAggregateSampleMax caps how many member paths an aggregate
// finding lists before truncating with a count.
const dropperAggregateSampleMax = 10

const (
	dropperPathExcerptMax = 512
	dropperProcExcerptMax = 256
)

// dropperAlertParams renders one flush decision into alert parameters:
// severity, message, details and the finding path.
func dropperAlertParams(f dropperFinding) (alert.Severity, string, string, string) {
	if f.Aggregate {
		severity := alert.Warning
		unclassified := 0
		for _, g := range f.Items {
			if !dropperVerdictDemoted(g.Verdict) {
				unclassified++
			}
		}
		if unclassified > 0 {
			severity = alert.High
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Files created and removed within the tracking TTL; %d remained unclassified after false-positive checks:\n", unclassified)
		for i, g := range f.Items {
			if i == dropperAggregateSampleMax {
				fmt.Fprintf(&b, "... and %d more", len(f.Items)-dropperAggregateSampleMax)
				break
			}
			fmt.Fprintf(&b, "%s (uid=%d size=%d)\n",
				dropperPrintable([]byte(g.Cand.Path), dropperPathExcerptMax), g.Cand.UID, g.Cand.Size)
		}
		displayDocroot := dropperPrintable([]byte(f.Docroot), dropperPathExcerptMax)
		msg := fmt.Sprintf("%d short-lived PHP/executable files created and removed under %s", len(f.Items), displayDocroot)
		return severity, msg, strings.TrimRight(b.String(), "\n"), f.Docroot
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
		details += " writer=[" + dropperPrintable([]byte(c.ProcInfo), dropperProcExcerptMax) + "]"
	}
	sev := alert.Critical
	if dropperVerdictDemoted(g.Verdict) {
		sev = alert.Warning
		switch g.Verdict {
		case dropperDemotedTemplate:
			details += "\nDemoted: content matches a compiled-template artifact (Twig/Smarty cache churn)."
		case dropperDemotedAtomicWrite:
			details += "\nDemoted: filename matches an atomic-write staging artifact."
		case dropperDemotedWPUpgrade:
			details += "\nDemoted: path is structurally inside a WordPress upgrade staging tree."
		case dropperDemotedDocroot:
			details += "\nDemoted: the containing document root was removed before the probe."
		}
	}
	if len(c.Head) > 0 {
		details += "\nLeading bytes: " + dropperPrintable(c.Head, dropperHeadExcerptMax)
	}
	msg := fmt.Sprintf("Self-deleting file under web root: %s",
		dropperPrintable([]byte(c.Path), dropperPathExcerptMax))
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
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return ""
	}
	best := ""
	for _, configuredRoot := range docroots {
		root := filepath.Clean(configuredRoot)
		if !filepath.IsAbs(root) {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if len(root) > len(best) {
			best = root
		}
	}
	return best
}
