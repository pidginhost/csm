//go:build linux

package daemon

import (
	"crypto/sha256"
	"os"
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
	e := newDropperEngine(dropperEngineConfig{ttl: ttl, selfPID: int32(os.Getpid())})
	e.emit = func(sev alert.Severity, check, msg, details, path string) {
		fm.sendAlertWithPath(sev, check, msg, details, path, "")
	}
	fm.dropper = e
	fm.dropperDocroots.Store(checks.ResolveWebRoots(cfg))
}

func (fm *FileMonitor) currentDropperDocroots() []string {
	if v, ok := fm.dropperDocroots.Load().([]string); ok {
		return v
	}
	return nil
}

// observeDropperCandidate snapshots an admitted write into the tracker. It runs
// on the analyzer worker (fd still open) and only reads positionally, so it
// never disturbs the downstream content checks that share the fd.
func (fm *FileMonitor) observeDropperCandidate(event fileEvent, procInfo string) {
	if fm.dropper == nil {
		return
	}
	docroot := dropperDocrootFor(event.path, fm.currentDropperDocroots())
	if docroot == "" {
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(event.fd, &st); err != nil {
		return
	}
	c := dropperCandidate{
		Path:     event.path,
		Docroot:  docroot,
		Observed: time.Now(),
		Device:   uint64(st.Dev),
		Inode:    st.Ino,
		Size:     st.Size,
		UID:      st.Uid,
		Mode:     uint32(st.Mode),
		PID:      event.pid,
		ProcInfo: procInfo,
	}
	if birth, ok := statxBirthFromFD(event.fd); ok {
		c.Birth = birth
		c.BirthKnown = true
	}
	c.Head = readFromFd(event.fd, dropperTrackedHeadMax)
	c.Digest, c.DigestKnown = digestFromFD(event.fd, st.Size)
	// admit applies the freshness/type gate; a false return is either a
	// non-candidate or a tracker overflow, and the latter is surfaced
	// separately by reportDropperOverflow.
	fm.dropper.admit(c)
}

// dropperProbeLoop probes overdue candidates for deletion and flushes findings.
// It also refreshes the cached docroot set so account changes are picked up.
func (fm *FileMonitor) dropperProbeLoop() {
	defer fm.wg.Done()
	prober := &dropperFSProbe{}
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

// reportDropperOverflow surfaces tracker capacity loss the same way the
// analyzer-queue overflow is surfaced: an operator-facing Warning, rate limited
// to once per minute by the alert dedup on check+path.
func (fm *FileMonitor) reportDropperOverflow() {
	if n := fm.dropper.tr.overflowDropped(); n > 0 {
		fm.sendAlertWithPath(alert.Warning, "self_deleting_dropper_overflow",
			"self-deleting-dropper tracker is full; some short-lived files were not tracked",
			"A create/delete storm exceeded the tracker capacity. Untracked files are only covered by the next scheduled deep scan.",
			"/", "")
	}
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
	if size > dropperDigestMax {
		return [32]byte{}, false
	}
	data := readFromFd(fd, dropperDigestMax)
	if data == nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(data), true
}

func statToFileState(path string, st *unix.Stat_t) dropperFileState {
	fs := dropperFileState{
		Path:   path,
		Device: uint64(st.Dev),
		Inode:  st.Ino,
		Size:   st.Size,
	}
	if fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0); err == nil {
		if birth, ok := statxBirthFromFD(fd); ok {
			fs.Birth = birth
			fs.BirthKnown = true
		}
		if digest, ok := digestFromFD(fd, st.Size); ok {
			fs.Digest = digest
			fs.DigestKnown = true
		}
		_ = unix.Close(fd)
	}
	return fs
}
