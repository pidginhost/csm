package checks

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/yara"
)

// companionPlantWindow is how far another file's change time may lie from the
// detected file's and still count as planted in the same session. A dropper or
// a scripted upload writes a whole kit within seconds; a person driving a
// webshell's file manager uploads a handful of files within a few minutes. Ten
// minutes either side covers both with margin and stays short enough that
// unrelated writes to the directory, hours or days apart, fall outside it.
// Change time is used because an unprivileged writer cannot set it; kits
// backdate modification times.
const companionPlantWindow = 10 * time.Minute

// companionClaimTTL is how long a swept plant window stays claimed. A finding
// that persists is alerted again after a day, and the sweep repeats with it.
const companionClaimTTL = 24 * time.Hour

// companionSampleLimit bounds how many files one report names. The report
// always states the full count.
const companionSampleLimit = 25

// companionBackdateGap is how much older than its change time a modification
// time must be before the report marks it. Unpacking an archive keeps old
// modification times too, so the mark is a hint, not proof.
const companionBackdateGap = 24 * time.Hour

// companionReadDirBatch is how many entries one directory read returns, so a
// huge directory is streamed rather than held in memory.
const companionReadDirBatch = 512

// companionSweepTriggers are the findings that prove one file malicious by its
// content, a scanner rule or a known backdoor name. Only a Critical one starts
// a sweep. Findings that rest on location alone are left out: their file may
// be legitimate, and so would its neighbours be.
var companionSweepTriggers = map[string]bool{
	"backdoor_binary":           true,
	"cgi_backdoor_realtime":     true,
	"js_keylogger_dataflow":     true,
	"new_webshell_file":         true,
	"obfuscated_php":            true,
	"obfuscated_php_realtime":   true,
	"php_dropper_realtime":      true,
	"php_in_image_realtime":     true,
	"php_in_uploads_realtime":   true,
	"php_remote_taint":          true,
	"signature_match_realtime":  true,
	"suspicious_php_content":    true,
	"webshell":                  true,
	"webshell_content_realtime": true,
	"webshell_realtime":         true,
	"yara_match_realtime":       true,
	"yara_match_scheduled":      true,
}

// companionSweeps is the daemon's queue. Detections and quarantines feed it;
// RunCompanionSweeps drains it.
var companionSweeps = newCompanionSweepQueue()

// QueueCompanionSweeps queues a sweep for every confirmed malicious file in
// findings that is still present. A file already moved to quarantine was
// queued by the quarantine itself, with the stat taken before the move.
func QueueCompanionSweeps(findings []alert.Finding) {
	companionSweeps.observe(findings, time.Now())
}

// RunCompanionSweeps sweeps queued directories until ctx ends, one at a time,
// and hands each result to emit.
func RunCompanionSweeps(ctx context.Context, cfg func() *config.Config, emit func([]alert.Finding)) {
	companionSweeps.run(ctx, cfg, emit)
}

// companionSweepFindings sweeps at once for every confirmed detection in
// findings, for a scan that returns a report instead of alerting.
func companionSweepFindings(ctx context.Context, cfg *config.Config, findings []alert.Finding) []alert.Finding {
	q := newCompanionSweepQueue()
	q.observe(findings, time.Now())
	var out []alert.Finding
	for _, a := range q.pending {
		out = append(out, sweepCompanions(ctx, cfg, *a)...)
	}
	return out
}

// companionAnchor is one detected file and the plant window around it.
type companionAnchor struct {
	path    string
	info    os.FileInfo
	changed time.Time
	due     time.Time
	// detected holds other detections in the same window; they have their own
	// findings and are not reported again.
	detected []os.FileInfo
	claim    *companionClaim
}

func newCompanionAnchor(path string, info os.FileInfo, now time.Time) (companionAnchor, bool) {
	changed, ok := changeTimeOf(info)
	if !ok || !filepath.IsAbs(path) || !info.Mode().IsRegular() {
		return companionAnchor{}, false
	}
	// A file caught as it is written may be the first of its kit to land, so
	// its sweep waits for the window to close. A change time in the future
	// (clock step) cannot postpone it past one window from now.
	due := changed.Add(companionPlantWindow)
	if limit := now.Add(companionPlantWindow); due.After(limit) {
		due = limit
	}
	return companionAnchor{path: filepath.Clean(path), info: info, changed: changed, due: due}, true
}

func (a companionAnchor) isDetected(info os.FileInfo) bool {
	if sameDetectedFile(a.info, info) {
		return true
	}
	for _, d := range a.detected {
		if sameDetectedFile(d, info) {
			return true
		}
	}
	return false
}

// sameDetectedFile also compares size and modification time: the detected file
// may be gone, and a new file can reuse its inode number.
func sameDetectedFile(a, b os.FileInfo) bool {
	return sameFileIdentity(a, b) && sameContentShape(a, b)
}

type companionClaim struct {
	changed time.Time
	at      time.Time
	// pending is the queued sweep for this window, nil once it has started.
	pending *companionAnchor
}

// companionSweepQueue holds sweeps until their window closes and claims each
// plant window of a directory once, so the other members of a kit, repeated
// alerts and the quarantine of a detected file do not sweep it again.
type companionSweepQueue struct {
	mu      sync.Mutex
	pending companionHeap
	claims  map[string][]*companionClaim
	pruned  time.Time
	wake    chan struct{}
}

func newCompanionSweepQueue() *companionSweepQueue {
	return &companionSweepQueue{claims: map[string][]*companionClaim{}, wake: make(chan struct{}, 1)}
}

func (q *companionSweepQueue) observe(findings []alert.Finding, now time.Time) {
	for _, f := range findings {
		if f.Severity != alert.Critical || !companionSweepTriggers[f.Check] || f.FilePath == "" {
			continue
		}
		info, err := osFS.Lstat(f.FilePath)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		q.add(f.FilePath, info, now)
	}
}

// add queues a sweep for path unless its directory already has one claimed
// for an overlapping window. It reports whether a sweep was queued.
func (q *companionSweepQueue) add(path string, info os.FileInfo, now time.Time) bool {
	a, ok := newCompanionAnchor(path, info, now)
	if !ok {
		return false
	}
	dir := filepath.Dir(a.path)
	q.mu.Lock()
	defer q.mu.Unlock()
	claims := q.claims[dir]
	live := claims[:0]
	claimed := false
	for _, c := range claims {
		if now.Sub(c.at) > companionClaimTTL {
			continue
		}
		live = append(live, c)
		if gap := a.changed.Sub(c.changed); !claimed && gap <= companionPlantWindow && gap >= -companionPlantWindow {
			claimed = true
			if c.pending != nil {
				c.pending.detected = append(c.pending.detected, info)
			}
		}
	}
	if claimed {
		q.claims[dir] = live
		return false
	}
	queued := &a
	queued.claim = &companionClaim{changed: a.changed, at: now, pending: queued}
	q.claims[dir] = append(live, queued.claim)
	heap.Push(&q.pending, queued)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// next returns the earliest sweep that is due. Otherwise it returns how long
// until one is, or zero when nothing is queued.
func (q *companionSweepQueue) next(now time.Time) (companionAnchor, time.Duration, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pruneLocked(now)
	if len(q.pending) == 0 {
		return companionAnchor{}, 0, false
	}
	top := q.pending[0]
	if top.due.After(now) {
		return companionAnchor{}, top.due.Sub(now), false
	}
	heap.Pop(&q.pending)
	top.claim.pending = nil
	return *top, 0, true
}

// pruneLocked drops expired claims of directories that saw no new detection.
// It runs at most once per window so a burst of detections stays linear.
func (q *companionSweepQueue) pruneLocked(now time.Time) {
	if now.Sub(q.pruned) < companionPlantWindow {
		return
	}
	q.pruned = now
	for dir, claims := range q.claims {
		live := claims[:0]
		for _, c := range claims {
			if now.Sub(c.at) <= companionClaimTTL {
				live = append(live, c)
			}
		}
		if len(live) == 0 {
			delete(q.claims, dir)
		} else {
			q.claims[dir] = live
		}
	}
}

func (q *companionSweepQueue) run(ctx context.Context, cfg func() *config.Config, emit func([]alert.Finding)) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for ctx.Err() == nil {
		a, wait, ok := q.next(time.Now())
		if ok {
			if findings := sweepCompanions(ctx, cfg(), a); len(findings) > 0 && ctx.Err() == nil {
				emit(findings)
			}
			continue
		}
		var due <-chan time.Time
		if wait > 0 {
			timer.Reset(wait)
			due = timer.C
		}
		select {
		case <-ctx.Done():
		case <-q.wake:
		case <-due:
		}
	}
}

type companionHeap []*companionAnchor

func (h companionHeap) Len() int           { return len(h) }
func (h companionHeap) Less(i, j int) bool { return h[i].due.Before(h[j].due) }
func (h companionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *companionHeap) Push(x any)        { *h = append(*h, x.(*companionAnchor)) }
func (h *companionHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return last
}

// plantedFile is one unmatched file of a plant window.
type plantedFile struct {
	name     string
	kind     string
	note     string
	size     int64
	changed  time.Time
	modified time.Time
}

// sweepCompanions examines the detected file's own directory, without
// descending. The first pass only stats entries: the content scan is bounded
// to files written in the plant window, which an attacker had to write and the
// normal scans read anyway, plus the directory's .htaccess. Matches are
// ordinary findings; files that match nothing but are of a kind a kit carries
// are named together in one report. Nothing is quarantined here.
func sweepCompanions(ctx context.Context, cfg *config.Config, a companionAnchor) []alert.Finding {
	slot := scanBudgetFrom(ctx).acquire(ctx)
	if slot == nil {
		return nil
	}
	defer slot.release()

	dir := filepath.Dir(a.path)
	dirInfo, err := osFS.Lstat(dir)
	if err != nil || !dirInfo.IsDir() {
		return nil
	}
	d, err := openTenantDirectory(dir)
	if err != nil {
		return nil
	}
	defer func() { _ = d.Close() }()
	if opened, statErr := d.Stat(); statErr != nil || !opened.IsDir() || !sameFileIdentity(dirInfo, opened) {
		return nil
	}

	from, to := a.changed.Add(-companionPlantWindow), a.changed.Add(companionPlantWindow)
	maxBytes := FullScanMaxFileBytes(cfg)
	respectIgnores := scanRespectsIgnores(ctx, cfg)
	var findings []alert.Finding
	var planted []plantedFile
	total := 0
	for {
		entries, readErr := d.ReadDir(companionReadDirBatch)
		for _, entry := range entries {
			if ctx.Err() != nil {
				return findings
			}
			if !entry.Type().IsRegular() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if respectIgnores && PathMatchesIgnore(path, cfg.Suppressions.IgnorePaths) {
				continue
			}
			info, err := osFS.Lstat(path)
			// An unprivileged writer can only create files it owns, so a file
			// of another owner cannot be part of the same drop.
			if err != nil || !info.Mode().IsRegular() || !sameFileOwner(info, a.info) || a.isDetected(info) {
				continue
			}
			changed, _ := changeTimeOf(info)
			inWindow := !changed.Before(from) && !changed.After(to)
			if !inWindow && entry.Name() != ".htaccess" {
				continue
			}
			matches, file := scanCompanionFile(ctx, cfg, path, info, maxBytes)
			findings = append(findings, matches...)
			if inWindow && len(matches) == 0 && file.kind != "" {
				total++
				if len(planted) < companionSampleLimit {
					planted = append(planted, file)
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	if total > 0 && ctx.Err() == nil {
		findings = append(findings, plantedFilesFinding(a, planted, total))
	}
	return findings
}

// scanCompanionFile runs the content engines over one file regardless of any
// scan cache or modification-time skip.
func scanCompanionFile(ctx context.Context, cfg *config.Config, path string, info os.FileInfo, maxBytes int64) ([]alert.Finding, plantedFile) {
	name := filepath.Base(path)
	changed, _ := changeTimeOf(info)
	file := plantedFile{name: name, size: info.Size(), changed: changed, modified: info.ModTime()}
	data, note := readCompanionFile(path, info, maxBytes)
	file.kind = companionKind(name, info, data)
	if note != "" {
		file.note = note
		return nil, file
	}
	digest := sha256.Sum256(data)
	contentSHA256 := hex.EncodeToString(digest[:])

	var findings []alert.Finding
	if backend := activeYARABackend(); backend != nil && backend.RuleCount() > 0 && !yaraDeepConsumerDisabled(cfg) {
		// #nosec G115 -- FullScanMaxFileBytes is at most a few GiB; it fits int on the 64-bit hosts CSM supports.
		matches, scannedSHA256, err := yara.ScanContentOrPathChecked(backend, path, data, int(maxBytes))
		if err != nil {
			file.note = "YARA could not scan it"
		}
		if scannedSHA256 == "" {
			scannedSHA256 = contentSHA256
		}
		for _, m := range matches {
			findings = append(findings, scheduledYARAFinding(m, path, data, scannedSHA256))
		}
	}
	if contenttype.IsPHPSourceName(strings.ToLower(name)) && !runnerDisabled(cfg, "php_content") {
		if result := analyzePHPContentReaderAt(path, bytes.NewReader(data), int64(len(data))); result.severity >= 0 {
			findings = append(findings, phpContentFinding(path, result, info, contentSHA256))
		}
	}
	if len(data) <= phptaint.MaxSourceBytes && !phpTaintDeepConsumerDisabled(cfg) && phpTaintAnalyzerReady() {
		findings = append(findings, analyzePHPTaintSnapshot(ctx, path, contentSHA256, data, newPHPTaintGapCollector())...)
	}
	if name == ".htaccess" && !runnerDisabled(cfg, "htaccess") {
		if len(data) > htaccessMaxFileBytes {
			file.note = "too large to audit"
		} else {
			audit, _ := AuditHtaccessContent(path, data)
			findings = append(findings, audit...)
		}
	}
	return findings, file
}

// readCompanionFile reads the file the stat pass selected, refusing a symlink,
// a special file or a different object swapped into its place.
func readCompanionFile(path string, info os.FileInfo, maxBytes int64) ([]byte, string) {
	f, err := openTenantRegularFile(path)
	if err != nil {
		return nil, "could not be opened"
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !sameDetectedFile(info, opened) {
		return nil, "changed while it was read"
	}
	if opened.Size() > maxBytes {
		return nil, "larger than the scan limit, not scanned"
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(data)) != opened.Size() {
		return nil, "could not be read whole"
	}
	return data, ""
}

// companionKind names the kinds of file a kit carries. Anything else in the
// window, such as images or stylesheets, is not reported. Content decides
// where a name would mislead. A binary is named before PHP: droppers carry the
// PHP they write.
func companionKind(name string, info os.FileInfo, data []byte) string {
	lower := strings.ToLower(name)
	ext := filepath.Ext(lower)
	switch {
	case name == ".htaccess":
		return "htaccess"
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		return "executable"
	case contenttype.IsPHPSourceName(lower) || contenttype.HasPHPOpenTag(data):
		return "php"
	case info.Mode().Perm()&0o111 != 0:
		return "executable"
	case contenttype.IsArchiveExt(ext) || contenttype.IsCompressedArchive(data):
		return "archive"
	case ext == "":
		return "no extension"
	}
	return ""
}

func plantedFilesFinding(a companionAnchor, planted []plantedFile, total int) alert.Finding {
	sort.Slice(planted, func(i, j int) bool { return planted[i].name < planted[j].name })
	var b strings.Builder
	fmt.Fprintf(&b, "Detected file: %s\n", a.path)
	fmt.Fprintf(&b, "Detected file changed: %s\n", a.changed.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Window: %s either side\n", companionPlantWindow)
	fmt.Fprintf(&b, "Planted files: %d\n", total)
	for _, p := range planted {
		fmt.Fprintf(&b, "- %s: %s, %d bytes, changed %s, modified %s",
			strconv.QuoteToASCII(p.name), p.kind, p.size,
			p.changed.UTC().Format(time.RFC3339), p.modified.UTC().Format(time.RFC3339))
		if gap := p.changed.Sub(p.modified); gap > companionBackdateGap {
			fmt.Fprintf(&b, ", modified %d days before its change, possible backdating", int(gap/(24*time.Hour)))
		}
		if p.note != "" {
			fmt.Fprintf(&b, ", %s", p.note)
		}
		b.WriteString("\n")
	}
	if extra := total - len(planted); extra > 0 {
		fmt.Fprintf(&b, "... and %d more\n", extra)
	}
	b.WriteString("No scanner matched these files. Review them before removal; CSM never quarantines them automatically.")
	return alert.Finding{
		Severity: alert.High,
		Check:    "malware_companion_files",
		Message:  "Files planted alongside detected malware: " + a.path,
		Details:  b.String(),
		FilePath: filepath.Dir(a.path),
	}
}

// changeTimeOf returns the inode change time recorded in info.
func changeTimeOf(info os.FileInfo) (time.Time, bool) {
	id, ok := selfWriteIdentityFromFileInfo(info)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(id.ChangeSec, id.ChangeNsec), true
}

func sameFileOwner(a, b os.FileInfo) bool {
	as, aok := a.Sys().(*syscall.Stat_t)
	bs, bok := b.Sys().(*syscall.Stat_t)
	return aok && bok && as.Uid == bs.Uid
}

// runnerDisabled reports whether the operator disabled a check runner, by its
// own name or one of its finding names.
func runnerDisabled(cfg *config.Config, runner string) bool {
	_, disabled := splitDisabledChecks(cfg, []namedCheck{{name: runner}})
	return len(disabled) > 0
}
