//go:build linux

package daemon

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// dropperDigestMax bounds how many bytes the admission hash covers. A
// self-deleting dropper is small; this cap keeps a large legitimate PHP file
// from stalling the analyzer worker while still giving a full digest for
// realistic candidates. Files past the cap keep DigestKnown=false and rely on
// device/inode identity for rename matching.
const dropperDigestMax = 8 << 20

const dropperDigestChunk = 64 << 10

const dropperPHPHandlerCacheMax = 4096

const dropperPHPHandlerCacheTTL = 15 * time.Second

type dropperPHPHandlerCacheEntry struct {
	generation uint64
	overlay    checks.PHPExecutionOverlay
	loaded     time.Time
}

// dropperProbeInterval derives the probe cadence from the tracking TTL so the
// loop reacts within a fraction of the window without busy-spinning.
func dropperProbeInterval(ttl time.Duration) time.Duration {
	iv := ttl / 4
	if iv < 5*time.Second {
		return 5 * time.Second
	}
	if iv > time.Minute {
		return time.Minute
	}
	return iv
}

func (fm *FileMonitor) initDropperDetector(cfg *config.Config) {
	if cfg == nil || !cfg.Thresholds.DropperDetection {
		return
	}
	ttl := time.Duration(cfg.Thresholds.DropperUnlinkTTLSec) * time.Second
	if ttl <= 0 {
		ttl = time.Duration(config.DefaultDropperUnlinkTTLSec) * time.Second
	}
	// #nosec G115 -- os.Getpid returns this process's PID, bounded by
	// /proc/sys/kernel/pid_max (<= 2^22 on Linux), so it always fits in int32.
	selfPID := int32(os.Getpid())
	e := newDropperEngine(dropperEngineConfig{ttl: ttl, selfPID: selfPID})
	e.emit = func(sev alert.Severity, check, msg, details, path string) {
		fm.sendAlertWithPath(sev, check, msg, details, path, "")
	}
	fm.dropper = e
	fm.dropperQuarantines = newDropperQuarantineLedger(
		ttl + time.Duration(maxDropperProbeAttempts)*dropperProbeInterval(ttl) + dropperGraceWindow,
	)
	fm.dropperHandlerCache = make(map[string]dropperPHPHandlerCacheEntry)
	fm.dropperDocroots.Store(checks.ResolveWebRoots(cfg))
}

func (fm *FileMonitor) currentDropperDocroots() []string {
	if v, ok := fm.dropperDocroots.Load().([]string); ok {
		return v
	}
	return nil
}

// isDropperInteresting admits paths that the normal content filter deliberately
// excludes but the dropper detector still needs: atomic-write PHP staging
// names, inherited .htaccess PHP handlers, and regular files carrying an
// executable mode under a document root. It does not take ownership of fd.
func (fm *FileMonitor) isDropperInteresting(path string, fd int) (interesting, phpExecutable bool) {
	if fm.dropper == nil {
		return false, false
	}
	docroot := dropperDocrootFor(path, fm.currentDropperDocroots())
	if docroot == "" {
		return false, false
	}
	name := strings.ToLower(filepath.Base(path))
	if checks.IsExecutablePHPName(name) {
		return true, false
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, false
	}
	if st.Mode&0o111 != 0 {
		return true, false
	}
	phpExecutable = fm.dropperPHPHandlerFor(docroot, filepath.Dir(path)).Executes(name)
	return phpExecutable, phpExecutable
}

func (fm *FileMonitor) invalidateDropperPHPHandlerCache(path string) {
	if fm.dropper != nil && strings.EqualFold(filepath.Base(path), ".htaccess") {
		atomic.AddUint64(&fm.dropperHandlerGeneration, 1)
	}
}

func (fm *FileMonitor) dropperPHPHandlerFor(docroot, dir string) checks.PHPExecutionOverlay {
	key := docroot + "\x00" + dir
	generation := atomic.LoadUint64(&fm.dropperHandlerGeneration)
	fm.dropperHandlerMu.Lock()
	entry, ok := fm.dropperHandlerCache[key]
	fm.dropperHandlerMu.Unlock()
	if ok && entry.generation == generation && time.Since(entry.loaded) < dropperPHPHandlerCacheTTL {
		return entry.overlay
	}

	overlay := checks.ResolvePHPExecutionOverlay(docroot, dir)
	// A .htaccess event that arrived while the filesystem snapshot was being
	// rebuilt invalidates this result. Do not cache it; the next event retries.
	if atomic.LoadUint64(&fm.dropperHandlerGeneration) != generation {
		return checks.ResolvePHPExecutionOverlay(docroot, dir)
	}
	fm.dropperHandlerMu.Lock()
	if len(fm.dropperHandlerCache) >= dropperPHPHandlerCacheMax {
		fm.dropperHandlerCache = make(map[string]dropperPHPHandlerCacheEntry)
	}
	fm.dropperHandlerCache[key] = dropperPHPHandlerCacheEntry{
		generation: generation,
		overlay:    overlay,
		loaded:     time.Now(),
	}
	fm.dropperHandlerMu.Unlock()
	return overlay
}

// observeDropperCandidate snapshots an admitted write into the tracker. It
// runs on the analyzer worker while the event fd is still open. Fstat, statx,
// and Pread do not change the shared file offset, and this function never
// closes the event fd. The returned copy lets downstream content checks add a
// suspicious-content verdict without reading or hashing the file again.
func (fm *FileMonitor) observeDropperCandidate(event fileEvent, procInfo string) *dropperCandidate {
	if fm.dropper == nil {
		return nil
	}
	docroot := dropperDocrootFor(event.path, fm.currentDropperDocroots())
	if docroot == "" {
		return nil
	}
	var st unix.Stat_t
	if err := unix.Fstat(event.fd, &st); err != nil {
		return nil
	}
	c := dropperCandidate{
		Path:          event.path,
		Docroot:       docroot,
		Observed:      time.Now(),
		Device:        uint64(st.Dev),
		Inode:         st.Ino,
		Size:          st.Size,
		UID:           st.Uid,
		Mode:          uint32(st.Mode),
		PID:           event.pid,
		ProcInfo:      procInfo,
		Created:       event.mask&FAN_CREATE != 0,
		PHPExecutable: event.phpExecutable,
	}
	if birth, ok := statxBirthFromFD(event.fd); ok {
		c.Birth = birth
		c.BirthKnown = true
	}

	// Reject non-regular and non-executable names before allocating a head or
	// hashing content. HTML, archives, and credential logs also reach the
	// analyzer, but they are not dropper candidates.
	name := strings.ToLower(filepath.Base(event.path))
	if c.Mode&unix.S_IFMT != unix.S_IFREG ||
		(!checks.IsExecutablePHPName(name) && !c.PHPExecutable && c.Mode&0o111 == 0) ||
		c.PID == fm.dropper.selfPID {
		return nil
	}

	trackFresh := shouldTrackDropper(c, fm.dropper.selfPID, fm.dropper.ttl)
	// A known old birth time proves this CLOSE_WRITE is not the completion of
	// a fresh create entry. Filesystems without birth time still need the full
	// snapshot so Refresh can join a separate FAN_CREATE event to its close.
	if !trackFresh && c.BirthKnown {
		return nil
	}
	c.Head = readFromFd(event.fd, dropperTrackedHeadMax)
	// Only known install/atomic staging shapes need a digest for cross-filesystem
	// copy-delete matching. A separate CLOSE_WRITE refresh normally follows
	// FAN_CREATE with the final bytes, so create-only snapshots keep identity
	// and a bounded head without hashing the same file twice.
	needsDigest := atomicWriteRenameCandidate(c.Path) != "" ||
		len(wpUpgradeRenameCandidates(c.Path, c.Docroot)) > 0
	if needsDigest && (event.mask&FAN_CREATE == 0 || event.mask&FAN_CLOSE_WRITE != 0) {
		c.Digest, c.DigestKnown = digestFromFD(event.fd, st.Size)
	}

	// FAN_CREATE and FAN_CLOSE_WRITE normally arrive as separate records. The
	// create proves freshness on filesystems without STATX_BTIME; the close
	// supplies the final bytes. Worker scheduling may deliver either one first,
	// so Refresh is attempted for every non-create snapshot before admission.
	if !c.Created && fm.dropper.tr.Refresh(c) {
		return &c
	}
	if !trackFresh || !fm.dropper.admit(c) {
		return nil
	}
	return &c
}

// dropperProbeLoop probes overdue candidates for deletion and flushes findings.
// It also refreshes the cached docroot set so account changes are picked up.
func (fm *FileMonitor) dropperProbeLoop() {
	defer fm.wg.Done()
	prober := &dropperFSProbe{quarantines: fm.dropperQuarantines}
	ticker := time.NewTicker(dropperProbeInterval(fm.dropper.ttl))
	defer ticker.Stop()
	refresh := time.NewTicker(5 * time.Minute)
	defer refresh.Stop()

	for {
		select {
		case <-fm.stopCh:
			return
		case <-refresh.C:
			fm.dropperDocroots.Store(checks.ResolveWebRoots(fm.currentCfg()))
		case <-ticker.C:
			now := time.Now()
			fm.dropper.probeStep(now, prober, now)
			fm.reportDropperOverflow()
		}
	}
}

// reportDropperOverflow surfaces only capacity losses that occurred since the
// previous report and limits a sustained storm to one warning per minute. The
// tracker counter is cumulative for diagnostics.
func (fm *FileMonitor) reportDropperOverflow() {
	total := fm.dropper.tr.overflowDropped()
	if total <= fm.dropperOverflowReported {
		return
	}
	now := time.Now()
	if !fm.lastDropperOverflowReport.IsZero() && now.Sub(fm.lastDropperOverflowReport) < time.Minute {
		return
	}
	dropped := total - fm.dropperOverflowReported
	fm.dropperOverflowReported = total
	fm.lastDropperOverflowReport = now
	fm.sendAlert(alert.Warning, "self_deleting_dropper_overflow",
		"self-deleting-dropper tracker is full; some short-lived files were not tracked",
		fmt.Sprintf("A create/delete storm exceeded the tracker capacity. %d candidate(s) were dropped since the prior report; those files are only covered by the next scheduled deep scan.", dropped))
}

// statxBirthFromFD returns the file birth time for an open fd when the
// filesystem records it (ext4, xfs, btrfs). Returns ok=false on filesystems
// without STATX_BTIME so the caller falls back to the create-event signal.
func statxBirthFromFD(fd int) (time.Time, bool) {
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &stx); err != nil {
		return time.Time{}, false
	}
	if stx.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}, false
	}
	return time.Unix(stx.Btime.Sec, int64(stx.Btime.Nsec)), true
}

// digestFromFD hashes up to dropperDigestMax bytes of the open fd. Files larger
// than the cap return ok=false; rename matching then relies on device/inode
// identity, which still covers rename(2) within a filesystem.
func digestFromFD(fd int, size int64) ([32]byte, bool) {
	if size < 0 || size > dropperDigestMax {
		return [32]byte{}, false
	}
	h := sha256.New()
	if !hashFDRange(h, fd, size) {
		return [32]byte{}, false
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Size != size {
		return [32]byte{}, false
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, true
}

func hashFDRange(h hash.Hash, fd int, size int64) bool {
	if size == 0 {
		return true
	}
	bufSize := int64(dropperDigestChunk)
	if size < bufSize {
		bufSize = size
	}
	buf := make([]byte, int(bufSize))
	for offset := int64(0); offset < size; {
		want := size - offset
		if want > int64(len(buf)) {
			want = int64(len(buf))
		}
		n, err := unix.Pread(fd, buf[:int(want)], offset)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			offset += int64(n)
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return false
		}
		if n == 0 && err == nil {
			return false
		}
	}
	return true
}

type dropperPathState struct {
	file dropperFileState
	mode uint32
}

// statPathToFileState opens path first, then derives identity, birth time,
// size, and an optional digest from that one fd. O_PATH is a fallback for
// symlinks or unreadable objects; it still provides stable identity without
// pretending a digest was available.
func statPathToFileState(path string, includeDigest bool) (dropperPathState, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	readable := err == nil
	if err != nil {
		fd, err = unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return dropperPathState{}, err
		}
	}
	defer func() { _ = unix.Close(fd) }()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return dropperPathState{}, err
	}
	state := dropperPathState{
		file: dropperFileState{
			Path: path, Device: uint64(st.Dev), Inode: st.Ino, Size: st.Size,
		},
		mode: uint32(st.Mode),
	}
	if birth, ok := statxBirthFromFD(fd); ok {
		state.file.Birth = birth
		state.file.BirthKnown = true
	}
	if includeDigest && readable && st.Mode&unix.S_IFMT == unix.S_IFREG {
		if digest, ok := digestFromFD(fd, st.Size); ok {
			state.file.Digest = digest
			state.file.DigestKnown = true
		}
	}
	return state, nil
}

const dropperQuarantineLedgerMax = 4096

type dropperQuarantineRecord struct {
	state   dropperFileState
	expires time.Time
}

type dropperQuarantineLedger struct {
	mu      sync.Mutex
	keepFor time.Duration
	count   int
	byPath  map[string][]dropperQuarantineRecord
}

func newDropperQuarantineLedger(keepFor time.Duration) *dropperQuarantineLedger {
	return &dropperQuarantineLedger{
		keepFor: keepFor,
		byPath:  make(map[string][]dropperQuarantineRecord),
	}
}

func (l *dropperQuarantineLedger) record(originalPath string, state dropperFileState, now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	if l.count >= dropperQuarantineLedgerMax {
		return
	}
	l.byPath[originalPath] = append(l.byPath[originalPath], dropperQuarantineRecord{
		state: state, expires: now.Add(l.keepFor),
	})
	l.count++
}

func (l *dropperQuarantineLedger) matched(c dropperCandidate, now time.Time) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	records := l.byPath[c.Path]
	for i, record := range records {
		// Require the same inode generation. Digest-only matching would let a
		// later identical drop at the same path consume an older quarantine
		// record and evade detection. Cross-filesystem quarantine may therefore
		// produce a duplicate alert, which is safer than suppressing a replay.
		if !dropperSameIdentity(c, record.state) {
			continue
		}
		records = append(records[:i], records[i+1:]...)
		if len(records) == 0 {
			delete(l.byPath, c.Path)
		} else {
			l.byPath[c.Path] = records
		}
		l.count--
		return true
	}
	return false
}

func (l *dropperQuarantineLedger) pruneLocked(now time.Time) {
	for path, records := range l.byPath {
		keep := records[:0]
		for _, record := range records {
			if now.Before(record.expires) {
				keep = append(keep, record)
			} else {
				l.count--
			}
		}
		if len(keep) == 0 {
			delete(l.byPath, path)
		} else {
			l.byPath[path] = keep
		}
	}
}

func (fm *FileMonitor) recordDropperQuarantine(originalPath, quarantinePath string) {
	if fm.dropperQuarantines == nil {
		return
	}
	state, err := statPathToFileState(quarantinePath, false)
	if err != nil || state.mode&unix.S_IFMT != unix.S_IFREG {
		return
	}
	state.file.Path = originalPath
	fm.dropperQuarantines.record(originalPath, state.file, time.Now())
}
