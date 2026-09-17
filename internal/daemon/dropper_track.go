package daemon

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/queuehealth"
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
	// A create event can precede the writer's first bytes. Retain its
	// freshness evidence until a close-write supplies the payload.
	WritePending bool
	// Sticky across refreshes: truncating a previously executable snapshot
	// must not turn its later deletion into a harmless empty guard.
	ContentMayExecute bool
	Digest            [32]byte
	DigestKnown       bool
	Head              []byte
	// Parent identifies the real, non-symlink directory that contained the
	// candidate while its event fd was open. The later probe uses this stable
	// identity instead of inferring directory removal from two path stats.
	Parent dropperParentIdentity
	ticket queuehealth.Ticket
}

// dropperParentIdentity is deliberately compact because one is retained for
// every tracked candidate. BirthNanos disambiguates inode reuse when statx
// exposes it; without birth time, a reused identity is treated as unchanged
// and cannot earn a false-positive demotion.
type dropperParentIdentity struct {
	Device     uint64
	Inode      uint64
	BirthNanos int64
	BirthKnown bool
	Conflicted bool
}

func (i dropperParentIdentity) known() bool {
	return !i.Conflicted && i.Device != 0 && i.Inode != 0
}

func mergeDropperParentIdentity(a, b dropperParentIdentity) dropperParentIdentity {
	switch {
	case a.Conflicted || b.Conflicted:
		return dropperParentIdentity{Conflicted: true}
	case !a.known():
		return b
	case !b.known():
		return a
	case a.Device != b.Device || a.Inode != b.Inode:
		return dropperParentIdentity{Conflicted: true}
	case a.BirthKnown && b.BirthKnown && a.BirthNanos != b.BirthNanos:
		return dropperParentIdentity{Conflicted: true}
	case b.BirthKnown:
		return b
	default:
		return a
	}
}

func dropperParentChanged(observed, current dropperParentIdentity) bool {
	if !observed.known() || !current.known() {
		return false
	}
	if observed.Device != current.Device || observed.Inode != current.Inode {
		return true
	}
	return observed.BirthKnown && current.BirthKnown && observed.BirthNanos != current.BirthNanos
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
	if !contenttype.IsExecutablePHPName(name) && !c.PHPExecutable && c.Mode&0o111 == 0 {
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

// dropperMaxTracked bounds the tracker map. A cPanel package restore or a
// WP Toolkit site clone can close-write tens of thousands of PHP files in
// seconds, and every one stays tracked for the whole unlink TTL; entries
// beyond the cap are dropped (and counted) rather than evicting older
// candidates, because the oldest entries are the ones closest to their probe
// and losing them would blind the detector exactly when a bulk write storm
// provides cover.
const dropperMaxTracked = 16384

// Keep each waiting or detached batch's head-byte budget at 16 MiB.
// Candidate/map/path metadata is additional bounded memory and grows with the
// entry cap; this constant only accounts for copied content. Representative
// Twig and Smarty headers place all required markers inside this window.
const (
	dropperTrackedHeadBudget = 16 << 20
	dropperTrackedHeadMax    = dropperTrackedHeadBudget / dropperMaxTracked
)

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
	c.ContentMayExecute = c.ContentMayExecute || !dropperCandidateIsInert(c)
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
	merged.ContentMayExecute = prev.ContentMayExecute || next.ContentMayExecute
	merged.Parent = mergeDropperParentIdentity(prev.Parent, next.Parent)
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
	merged.ticket = prev.ticket
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
	now        func() time.Time
	healthOnce sync.Once
	health     *queuehealth.Tracker
	heldHealth *queuehealth.Tracker
}

func newDropperTracker(ttl time.Duration) *dropperTracker {
	return &dropperTracker{
		ttl:        ttl,
		maxTracked: dropperMaxTracked,
		entries:    make(map[dropperCandidateKey]dropperCandidate),
		now:        time.Now,
	}
}

func (t *dropperTracker) initQueueHealth() {
	t.healthOnce.Do(func() {
		t.health = queuehealth.New(t.maxTracked, time.Minute)
		t.heldHealth = queuehealth.New(dropperMaxTracked, time.Minute)
	})
}

func (t *dropperTracker) queueStatuses(now time.Time) (queuehealth.Status, queuehealth.Status) {
	t.initQueueHealth()
	return t.health.Snapshot(now), t.heldHealth.Snapshot(now)
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
	t.initQueueHealth()
	c = ownDropperCandidate(c)
	key := candidateKey(c)
	t.mu.Lock()
	defer t.mu.Unlock()
	if prev, ok := t.entries[key]; ok {
		t.entries[key] = mergeDropperCandidate(prev, c)
		prev.ticket.RetainQueuedAt(c.Observed.Add(t.ttl))
		return true
	}
	if len(t.entries) >= t.maxTracked {
		t.overflow++
		t.health.Lose(t.now(), 1)
		return false
	}
	c.ticket = t.health.BeginAt(c.Observed.Add(t.ttl), t.now())
	t.entries[key] = c
	return true
}

// Retry returns a detached probe to the waiting set. A new observation may
// already occupy its identity or the available slot, so this transfer must
// share the admission lock with Observe.
func (t *dropperTracker) Retry(c dropperCandidate) (queuehealth.Ticket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := candidateKey(c)
	now := t.now()
	if waiting, ok := t.entries[key]; ok {
		waiting.ticket.MergeRunning(c.ticket, now)
		t.entries[key] = mergeDropperCandidate(waiting, c)
		return waiting.ticket, true
	}
	if len(t.entries) >= t.maxTracked {
		t.overflow++
		c.ticket.Reject(now)
		return queuehealth.Ticket{}, false
	}
	c.ticket.Requeue(now)
	t.entries[key] = c
	return c.ticket, true
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
		prev.ticket.RetainQueuedAt(c.Observed.Add(t.ttl))
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
		prev.ticket.RetainQueuedAt(c.Observed.Add(t.ttl))
		delete(t.entries, prevKey)
		mergedKey := candidateKey(merged)
		t.entries[mergedKey] = merged
		return true
	}
	return false
}

// Due removes and returns every candidate whose TTL has elapsed at now.
func (t *dropperTracker) Due(now time.Time) []dropperCandidate {
	t.mu.Lock()
	defer t.mu.Unlock()
	started := t.now()
	var due []dropperCandidate
	for key, c := range t.entries {
		if now.Sub(c.Observed) >= t.ttl {
			c.ticket.Start(started)
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

// discardPending runs after both the probe loop and analyzer workers join.
// Analyzer work finishing during shutdown can still admit fresh candidates.
func (t *dropperTracker) discardPending(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.entries {
		c.ticket.Reject(now)
	}
	clear(t.entries)
	for _, g := range t.pending {
		g.ticket.Reject(now)
	}
	t.pending = nil
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
	// IsRegular distinguishes a file that took over the path from a directory
	// or symlink left behind there. Only a regular file can be the result of
	// an atomic write.
	IsRegular bool
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
	// ParentRemoved is true only when a snapshotted, non-symlink parent is now
	// absent or a different directory identity. A file whose whole directory
	// went away was not singled out for deletion.
	ParentRemoved bool
	RenamedTo     string
	RenameTarget  *dropperFileState
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
	dropperDemotedDirRemoved
	dropperDemotedReplaced
	dropperSuspect
)

func dropperVerdictDemoted(v dropperVerdict) bool {
	return v >= dropperDemotedTemplate && v <= dropperDemotedReplaced
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

// dropperReplacedInPlace reports whether the file now at the candidate's path
// is a regular file that came into existence after the candidate was observed.
// That is an atomic write completing (write temp, rename over the live path),
// which repeats every few minutes for WAF and cache state files. The successor
// stays on disk and is scanned in its own right, and the candidate's own bytes
// were already read by the content pass, so the evidence loss that makes a
// self-delete Critical does not apply.
//
// This does not weaken the detector against an attacker who leaves a benign
// file behind: overwriting the same inode already returns dropperBenign above,
// which is both cheaper and quieter than unlink plus rename. A birth time is
// required, so a filesystem without STATX_BTIME keeps the suspect verdict.
func dropperReplacedInPlace(c dropperCandidate, current dropperFileState) bool {
	if !current.IsRegular || !current.BirthKnown {
		return false
	}
	return !current.Birth.Before(c.Observed)
}

// assessDropper turns a probe result into a verdict for one candidate.
func assessDropper(c dropperCandidate, p dropperProbe) dropperVerdict {
	if !p.Conclusive {
		// Due removed this candidate from the tracker. The probe loop should
		// reinsert it with Retry and handle a false capacity result.
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
	if !c.WritePending && !c.ContentMayExecute && dropperCandidateIsInert(c) {
		return dropperBenign
	}
	if p.AtPath != nil && dropperReplacedInPlace(c, *p.AtPath) {
		return dropperDemotedReplaced
	}
	if p.DocrootRemoved {
		return dropperDemotedDocroot
	}
	if p.ParentRemoved {
		return dropperDemotedDirRemoved
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

// wpUpgradeStagedPath splits a clean absolute path under
// <wpRoot>/wp-content/upgrade/ into the WordPress root and the part below
// upgrade/. The root must be the configured docroot or inside it.
func wpUpgradeStagedPath(path, configuredDocroot string) (wpRoot, rest string, ok bool) {
	const marker = "/wp-content/upgrade/"
	if !filepath.IsAbs(path) || !filepath.IsAbs(configuredDocroot) ||
		filepath.Clean(path) != path || filepath.Clean(configuredDocroot) != configuredDocroot {
		return "", "", false
	}
	idx := strings.Index(path, marker)
	if idx < 0 {
		return "", "", false
	}
	wpRoot = path[:idx]
	if wpRoot != configuredDocroot && !strings.HasPrefix(wpRoot, configuredDocroot+string(filepath.Separator)) {
		return "", "", false
	}
	return wpRoot, path[idx+len(marker):], true
}

// wpUpgradeRenameCandidates maps a path inside a WordPress upgrade staging
// dir (wp-content/upgrade/<staging>/<package>/<rest>) to the destinations
// WordPress moves it to on success: the plugin and theme dirs, or the
// docroot itself for core packages. The fanotify mask has no FAN_MOVED_TO,
// so a successful rename-based install makes the staged path vanish; the
// probe checks these destinations before calling it a self-deleting drop.
func wpUpgradeRenameCandidates(path, configuredDocroot string) []string {
	wpRoot, rest, ok := wpUpgradeStagedPath(path, configuredDocroot)
	if !ok {
		return nil
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 || parts[1] == "" || parts[1] == "." || parts[1] == ".." ||
		parts[2] == "" || filepath.Clean(parts[2]) != parts[2] {
		// A file directly under upgrade/<staging>/ has no package dir to
		// move. The flat language-pack copy is handled by
		// wpUpgradeInstallDestinations.
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

// wpUpgradeInstallDestinations lists every place the WordPress updater puts
// the bytes of a file it wrote under wp-content/upgrade/ before removing it:
// the package-tree moves above, plus two copy-then-delete steps that leave no
// package directory behind. Language packs unzip flat into
// upgrade/<working>/ and are copied into wp-content/languages/ (plugins/ and
// themes/ for those pack types). A core update copies the staged
// wp-includes/version.php to upgrade/version-current.php, reads it, deletes
// it, and later installs the same file as wp-includes/version.php.
//
// These paths only say where to look. A vanished file is cleared only when a
// destination holds its exact bytes (same inode, or same size and full
// SHA-256), so its content still sits on disk where every scan covers it. An
// attacker who drops and deletes a file in the same places without leaving an
// identical copy at the destination is still reported at full severity: the
// new shapes deliberately do not join the structural demotion that the
// package-tree shape gets in assessDropper.
func wpUpgradeInstallDestinations(path, configuredDocroot string) []string {
	if dests := wpUpgradeRenameCandidates(path, configuredDocroot); dests != nil {
		return dests
	}
	wpRoot, rest, ok := wpUpgradeStagedPath(path, configuredDocroot)
	if !ok {
		return nil
	}
	parts := strings.Split(rest, "/")
	switch {
	case len(parts) == 1 && parts[0] == "version-current.php":
		return []string{filepath.Join(wpRoot, "wp-includes", "version.php")}
	case len(parts) == 2:
		// Clean already rejected empty, "." and ".." components.
		languages := filepath.Join(wpRoot, "wp-content", "languages")
		return []string{
			filepath.Join(languages, parts[1]),
			filepath.Join(languages, "plugins", parts[1]),
			filepath.Join(languages, "themes", parts[1]),
		}
	}
	return nil
}

func dropperRenameTargetAllowed(c dropperCandidate, target string) bool {
	if atomicTarget := atomicWriteRenameCandidate(c.Path); atomicTarget != "" && target == atomicTarget {
		return true
	}
	for _, candidate := range wpUpgradeInstallDestinations(c.Path, c.Docroot) {
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
	ticket  queuehealth.Ticket
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
	t.initQueueHealth()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pending) >= dropperMaxTracked {
		t.heldHealth.Lose(t.now(), 1)
		return
	}
	c.ticket = queuehealth.Ticket{}
	t.pending = append(t.pending, dropperGone{
		Cand: ownDropperCandidate(c), Verdict: v, held: now,
		ticket: t.heldHealth.BeginAt(now.Add(dropperGraceWindow), t.now()),
	})
}

// FlushDue emits findings for docroot groups whose oldest held entry has
// aged past the grace window. The whole group flushes together so entries
// arriving late in a burst still fold into the aggregate.
func (t *dropperTracker) FlushDue(now time.Time) []dropperFinding {
	t.mu.Lock()
	defer t.mu.Unlock()
	started := t.now()

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
			g.ticket.Start(started)
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
		case dropperDemotedDirRemoved:
			details += "\nDemoted: the original containing directory was removed before the probe."
		case dropperDemotedReplaced:
			details += "\nDemoted: the path was replaced in place by a newer file (atomic write), not emptied."
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
