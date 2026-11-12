//go:build linux

package daemon

import (
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/queuehealth"
)

const (
	// fidCreateSettle is how long a create waits for its own close-write.
	// open(O_CREAT) raises FAN_CREATE and then CLOSE_WRITE; a hard link
	// raises only FAN_CREATE.
	fidCreateSettle = 2 * time.Second
	// fidPendingCap bounds creates waiting out their window. A busy host
	// creates thousands of files a second; past the cap the oldest create
	// is analysed early, which costs at most a duplicate analysis.
	fidPendingCap = 16384
	// maxFileHandleSize is the kernel's MAX_HANDLE_SZ.
	maxFileHandleSize = 128
	// fidPollMillis bounds how late an expired create is released.
	fidPollMillis = 250
)

var errFIDMalformed = errors.New("malformed fanotify FID record")

// fidRecord is one event from a FAN_REPORT_DFID_NAME group: an entry Name
// in the directory Handle identifies on the filesystem Fsid. Handle aliases
// the read buffer.
type fidRecord struct {
	Mask       uint64
	PID        int32
	Fsid       unix.Fsid
	HandleType int32
	Handle     []byte
	Name       string
}

// parseFIDRecord decodes the event at the start of b. size is the event's
// length whenever the metadata frames it, so a caller can skip a record it
// rejects; 0 means the rest of b cannot be framed.
func parseFIDRecord(b []byte) (rec fidRecord, size int, err error) {
	ne := binary.NativeEndian
	if len(b) < metadataSize || b[4] != unix.FANOTIFY_METADATA_VERSION {
		return rec, 0, errFIDMalformed
	}
	size = int(ne.Uint32(b[0:4]))
	if size < metadataSize || size > len(b) {
		return rec, 0, errFIDMalformed
	}
	metaLen := int(ne.Uint16(b[6:8]))
	if metaLen < metadataSize || metaLen > size {
		return rec, size, errFIDMalformed
	}
	rec.Mask = ne.Uint64(b[8:16])
	rec.PID = int32(ne.Uint32(b[20:24])) // #nosec G115 -- the kernel writes a pid_t
	if rec.Mask&unix.FAN_Q_OVERFLOW != 0 {
		return rec, size, nil
	}
	found := false
	for off := metaLen; off < size; {
		if size-off < 4 {
			return rec, size, errFIDMalformed
		}
		infoLen := int(ne.Uint16(b[off+2 : off+4]))
		if infoLen < 4 || infoLen > size-off {
			return rec, size, errFIDMalformed
		}
		if b[off] == unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
			if found || rec.decodeDirName(b[off:off+infoLen]) != nil {
				return rec, size, errFIDMalformed
			}
			found = true
		}
		off += infoLen
	}
	if !found {
		return rec, size, errFIDMalformed
	}
	return rec, size, nil
}

// decodeDirName reads a DFID_NAME info record: header, fsid, struct
// file_handle, then the NUL-terminated entry name.
func (rec *fidRecord) decodeDirName(info []byte) error {
	ne := binary.NativeEndian
	const fixed = 4 + 8 + 8
	if len(info) < fixed {
		return errFIDMalformed
	}
	rec.Fsid = unix.Fsid{Val: [2]int32{
		int32(ne.Uint32(info[4:8])),  // #nosec G115 -- __kernel_fsid_t holds two ints
		int32(ne.Uint32(info[8:12])), // #nosec G115 -- __kernel_fsid_t holds two ints
	}}
	n := int(ne.Uint32(info[12:16]))
	rec.HandleType = int32(ne.Uint32(info[16:20])) // #nosec G115 -- handle_type is an int
	if n == 0 || n > maxFileHandleSize || n > len(info)-fixed {
		return errFIDMalformed
	}
	rec.Handle = info[fixed : fixed+n]
	name := info[fixed+n:]
	end := bytes.IndexByte(name, 0)
	if end <= 0 {
		return errFIDMalformed
	}
	rec.Name = string(name[:end])
	// The name is joined under a resolved directory: anything but one
	// component would place the event at a different path.
	if rec.Name == "." || rec.Name == ".." || strings.Contains(rec.Name, "/") {
		return errFIDMalformed
	}
	return nil
}

type createKey struct {
	dev, ino uint64
	path     string
}

type pendingCreate struct {
	ev     placementEvent
	held   time.Time
	ticket queuehealth.Ticket
}

// createSettler holds creates until their window ends. The close-write path
// settles a create by dev+inode+path; reader and close-write goroutines share it.
type createSettler struct {
	mu      sync.Mutex
	cap     int
	order   *list.List // *pendingCreate, oldest first
	pending map[createKey]*list.Element
	// A drop here is a create analysed before its window ended, never one
	// skipped, except at shutdown.
	health *queuehealth.Tracker
}

func newCreateSettler(capacity int) *createSettler {
	return &createSettler{
		cap: capacity, order: list.New(), pending: make(map[createKey]*list.Element),
		health: queuehealth.New(capacity, time.Minute),
	}
}

// add holds ev and returns the create the cap pushed out, if any.
func (s *createSettler) add(ev placementEvent, now time.Time) (placementEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := createKey{ev.Dev, ev.Ino, ev.Path}
	if old, ok := s.pending[key]; ok {
		// Repeated publication of the same inode must not postpone its scan.
		old.Value.(*pendingCreate).ev = ev
		return placementEvent{}, false
	}
	var released placementEvent
	full := s.order.Len() >= s.cap
	if full {
		oldest := s.removeLocked(s.order.Front())
		oldest.ticket.Reject(now)
		released = oldest.ev
	}
	s.pending[key] = s.order.PushBack(&pendingCreate{ev: ev, held: now, ticket: s.health.Begin(now)})
	return released, full
}

func (s *createSettler) removeLocked(e *list.Element) *pendingCreate {
	p := s.order.Remove(e).(*pendingCreate)
	delete(s.pending, createKey{p.ev.Dev, p.ev.Ino, p.ev.Path})
	return p
}

// settle drops a create whose own close-write analyses the file.
func (s *createSettler) settle(key createKey, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.pending[key]; ok {
		s.removeLocked(e).ticket.Finish(now)
	}
}

// expire returns the creates whose window ended without a close-write.
func (s *createSettler) expire(now time.Time) []placementEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var due []placementEvent
	for e := s.order.Front(); e != nil; e = s.order.Front() {
		p := e.Value.(*pendingCreate)
		if now.Sub(p.held) < fidCreateSettle {
			break
		}
		s.removeLocked(e).ticket.Finish(now)
		due = append(due, p.ev)
	}
	return due
}

func (s *createSettler) discard(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for e := s.order.Front(); e != nil; e = s.order.Front() {
		s.removeLocked(e).ticket.Reject(now)
	}
}

// noteClosedWrite settles only the name the close-write analyses. Another
// hard link can have different admission and location-dependent checks.
func (fm *FileMonitor) noteClosedWrite(dev, ino uint64, path string) {
	if s := fm.placementCreates.Load(); s != nil {
		s.settle(createKey{dev, ino, path}, time.Now())
	}
}

type fidMount struct {
	fd   int
	path string
	// dev keys the unresolved-placement cooldown, as the BPF path does.
	dev uint64
}

// placementFID reports placements through a second fanotify group that
// reports directory handles and entry names. It needs kernel 5.9.
type placementFID struct {
	fd int
	// Handles identify an inode, not the watched mount path. Keep each
	// watched view so a bind alias gets its own location-dependent analysis.
	mounts map[unix.Fsid][]fidMount
	// roots uses resolved names, as /proc/self/fd does for delivered events.
	roots   []watchRootMark
	fm      *FileMonitor
	handle  func(placementEvent)
	out     *queuehealth.Channel[placementEvent]
	creates *createSettler
	openDir func(int, unix.FileHandle, int) (int, error)
	// kernel counts FAN_Q_OVERFLOW: placements the kernel dropped unseen.
	kernel *queuehealth.Tracker
	// unresolved counts records that could not be turned into a path.
	unresolved *queuehealth.Tracker
	count      atomic.Uint64
}

func newPlacementFID(fm *FileMonitor, fd int, mounts map[unix.Fsid][]fidMount) *placementFID {
	return &placementFID{
		fd: fd, mounts: mounts, roots: slices.Clone(fm.watchRoots), fm: fm, handle: fm.handlePlacement,
		out:        queuehealth.NewChannel[placementEvent](256, time.Minute),
		creates:    newCreateSettler(fidPendingCap),
		openDir:    unix.OpenByHandleAt,
		kernel:     queuehealth.New(0, time.Minute),
		unresolved: queuehealth.New(0, time.Minute),
	}
}

// startPlacementFID marks each watched filesystem once. An error (EINVAL
// before 5.9, EPERM without CAP_SYS_ADMIN) leaves no group behind.
func startPlacementFID(_ context.Context, fm *FileMonitor) (*placementFID, error) {
	fd, err := unix.FanotifyInit(FAN_CLASS_NOTIF|FAN_CLOEXEC|FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, fidInitError(err)
	}
	p := newPlacementFID(fm, fd, make(map[unix.Fsid][]fidMount))
	all, err := readMountinfo()
	if err != nil {
		p.close()
		return nil, fmt.Errorf("read mountinfo: %w", err)
	}
	skipped, err := p.markFilesystemsWith(all, unix.FanotifyMark)
	if err != nil {
		p.close()
		return nil, err
	}
	p.reportCoverage(all, skipped)
	return p, nil
}

// reportCoverage names the roots the running group cannot see: those on a
// filesystem this kernel cannot mark (one Warning), and any root left out of
// the marked mounts (a High each).
func (p *placementFID) reportCoverage(all, skipped []mountEntry) {
	p.fm.reportUnmarkablePlacementRoots(all, skipped, p.roots)
	p.fm.reportUncoveredPlacementRoots(all, append(p.markedMounts(all), skipped...), p.roots)
}

// markedMounts returns the mounts the group resolves handles through. Today
// every root's own mount is marked or the start fails; the report guards
// against a root left out.
func (p *placementFID) markedMounts(all []mountEntry) []mountEntry {
	var marked []mountEntry
	for _, mounts := range p.mounts {
		for _, m := range mounts {
			if i := visibleMount(all, m.path); i >= 0 {
				marked = append(marked, all[i])
			}
		}
	}
	return marked
}

// fidInitError marks the errors a kernel without directory-entry reports
// returns (EINVAL before 5.9, ENOSYS without fanotify) as missing support.
func fidInitError(err error) error {
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("%w: fanotify_init with directory handles: %w", errPlacementFIDUnsupported, err)
	}
	return fmt.Errorf("fanotify_init with directory handles: %w", err)
}

// markFilesystemsWith marks the filesystem under every watch root. A root on
// a filesystem this kernel cannot report handles for (tmpfs before 6.7 gives
// ENODEV or EOPNOTSUPP; some btrfs subvolumes give EXDEV) is skipped and
// returned; any other failure, or skipping every root, fails the group.
func (p *placementFID) markFilesystemsWith(all []mountEntry, mark markFunc) ([]mountEntry, error) {
	// statDevice and fanotify_mark follow watch-root symlinks. Mountinfo
	// does not contain those aliases, and resolved event fds do not use them.
	for i := range p.roots {
		path, err := filepath.EvalSymlinks(p.roots[i].path)
		if err != nil {
			return nil, fmt.Errorf("resolve watch root %s: %w", p.roots[i].path, err)
		}
		p.roots[i].path = path
	}
	var skipped []mountEntry
	var skipErr error
	seen := make(map[mountEntry]bool)
	devices := make(map[unix.Fsid]uint64)
	for _, r := range p.roots {
		i := placementVisibleMount(all, r)
		if i < 0 {
			return nil, fmt.Errorf("watch root %s has no visible mount on its recorded device", r.path)
		}
		m := all[i]
		if seen[m] {
			continue
		}
		seen[m] = true
		anchor := m.MountPoint
		// Not O_PATH: fanotify_mark and, on older kernels,
		// open_by_handle_at reject an O_PATH descriptor with EBADF.
		dirfd, err := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", anchor, err)
		}
		var st unix.Stat_t
		if err = unix.Fstat(dirfd, &st); err != nil || uint64(st.Dev) != r.device {
			_ = unix.Close(dirfd)
			return nil, fmt.Errorf("watch mount %s changed or could not be inspected: %v", anchor, err)
		}
		var sfs unix.Statfs_t
		if err = unix.Fstatfs(dirfd, &sfs); err != nil {
			_ = unix.Close(dirfd)
			return nil, fmt.Errorf("statfs %s: %w", r.path, err)
		}
		device, marked := devices[sfs.Fsid]
		if marked && device != r.device {
			_ = unix.Close(dirfd)
			return nil, fmt.Errorf("watch root %s shares a filesystem id with another device", r.path)
		}
		if !marked {
			err = mark(p.fd, FAN_MARK_ADD|FAN_MARK_FILESYSTEM, unix.FAN_MOVED_TO|unix.FAN_CREATE|unix.FAN_ONDIR, dirfd, "")
			if err != nil {
				_ = unix.Close(dirfd)
				err = fmt.Errorf("mark %s for placements: %w", r.path, err)
				if !errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EXDEV) {
					return nil, err
				}
				skipped, skipErr = append(skipped, m), err
				continue
			}
			devices[sfs.Fsid] = r.device
		}
		p.mounts[sfs.Fsid] = append(p.mounts[sfs.Fsid], fidMount{fd: dirfd, path: anchor, dev: r.device})
	}
	if len(p.mounts) == 0 {
		if skipErr != nil {
			return nil, fmt.Errorf("%w: no watched filesystem accepts directory-entry marks: %w", errPlacementFIDUnsupported, skipErr)
		}
		return nil, errors.New("no watch root to mark")
	}
	return skipped, nil
}

func (p *placementFID) close() {
	for _, mounts := range p.mounts {
		for _, m := range mounts {
			_ = unix.Close(m.fd)
		}
	}
	_ = unix.Close(p.fd)
}

func (p *placementFID) Mode() string       { return "legacy" }
func (p *placementFID) EventCount() uint64 { return p.count.Load() }

func (p *placementFID) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{
		"output":        p.out.Snapshot(now),
		"create_settle": p.creates.health.Snapshot(now),
		"kernel":        p.kernel.Snapshot(now),
		"unresolved":    p.unresolved.Snapshot(now),
	}
}

// Run reads until ctx ends. Records resolve on this goroutine; handlePlacement
// runs on the shared workers, which may wait on a pending rename.
func (p *placementFID) Run(ctx context.Context) {
	p.fm.placementCreates.Store(p.creates)
	waitWorkers := startPlacementWorkers(ctx, p.fm, p.out.Items(), func(ev placementEvent) (placementEvent, bool) { return ev, true }, p.handle)
	p.read(ctx)
	p.fm.placementCreates.CompareAndSwap(p.creates, nil)
	waitWorkers()
	now := time.Now()
	p.out.Close()
	p.out.DiscardPending()
	p.creates.discard(now)
	p.close()
}

func (p *placementFID) read(ctx context.Context) {
	buf := make([]byte, 64*1024)
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}} // #nosec G115 -- POSIX fd fits in int32
	for ctx.Err() == nil {
		p.expire(time.Now())
		if _, err := unix.Poll(fds, fidPollMillis); err != nil && !errors.Is(err, unix.EINTR) {
			csmlog.Warn("placement: fanotify poll failed", "err", err)
			time.Sleep(time.Second)
			continue
		}
		for ctx.Err() == nil {
			n, err := unix.Read(p.fd, buf)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil || n <= 0 {
				if err != nil && !errors.Is(err, unix.EAGAIN) {
					csmlog.Warn("placement: fanotify read failed", "err", err)
					time.Sleep(time.Second)
				}
				break
			}
			now := time.Now()
			p.dispatch(buf[:n], now)
			p.expire(now)
		}
	}
}

func (p *placementFID) dispatch(buf []byte, now time.Time) {
	for len(buf) > 0 {
		rec, size, err := parseFIDRecord(buf)
		if size == 0 {
			p.unresolved.Lose(now, 1)
			return
		}
		buf = buf[size:]
		if err != nil {
			p.unresolved.Lose(now, 1)
			continue
		}
		p.count.Add(1)
		if rec.Mask&unix.FAN_Q_OVERFLOW != 0 {
			p.kernel.Lose(now, 1)
			p.fm.reportPlacementOverflow()
			continue
		}
		mounts := p.mounts[rec.Fsid]
		if len(mounts) == 0 {
			p.unresolved.Lose(now, 1)
			continue
		}
		for _, m := range mounts {
			ev, ok, err := p.resolve(rec, m, now)
			if err != nil {
				p.unresolved.Lose(now, 1)
				// A systematic failure, such as a refused open_by_handle_at,
				// would otherwise hide every placement on this filesystem.
				p.fm.reportUnresolvedOnDevice(m.dev, func() string {
					return fmt.Sprintf("Realtime protection did not check entry %q in %s because it could not open the directory or the entry: %v. Placed by PID %d. The next deep scan covers it.",
						rec.Name, m.path, err, rec.PID)
				})
				continue
			}
			if ok {
				p.route(ev, now)
			}
		}
	}
}

// resolve finds the entry a record names. ok is false, with no error, when
// nothing analysable is left there: the entry or its directory is gone, it
// is not a regular file or directory, or it is outside the watch roots.
func (p *placementFID) resolve(rec fidRecord, mount fidMount, at time.Time) (ev placementEvent, ok bool, err error) {
	dirfd, err := p.openDir(mount.fd, unix.NewFileHandle(rec.HandleType, rec.Handle), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOENT) {
		return ev, false, nil
	}
	if err != nil {
		return ev, false, err
	}
	defer func() { _ = unix.Close(dirfd) }()
	// Raw, not eventFDPath: a live directory can be named "x (deleted)".
	// A removed one is empty, so the lookup below finds nothing in it.
	dir, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", dirfd))
	if err != nil {
		return ev, false, err
	}
	path := filepath.Join(dir, rec.Name)
	if !pathWithin(dir, mount.path) || !p.withinWatchRoots(path) {
		return ev, false, nil
	}
	var st unix.Stat_t
	if err = unix.Fstatat(dirfd, rec.Name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return ev, false, nil
		}
		return ev, false, err
	}
	ev = placementEvent{
		Path: path, Dev: uint64(st.Dev), Ino: st.Ino, // #nosec G115 -- device ids are non-negative on Linux
		PID: rec.PID, Kind: placementRename, At: at,
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		// A new directory is empty; its files raise their own events.
		ev.IsDir = true
		return ev, rec.Mask&unix.FAN_MOVED_TO != 0, nil
	case unix.S_IFREG:
	default:
		return ev, false, nil
	}
	if rec.Mask&unix.FAN_MOVED_TO == 0 {
		// A second name identifies a hard link, which needs no settle window.
		ev.Kind = placementCreate
		if st.Nlink > 1 {
			ev.Kind = placementLink
		}
	}
	return ev, true, nil
}

func (p *placementFID) withinWatchRoots(path string) bool {
	for _, r := range p.roots {
		if pathWithin(path, r.path) {
			return true
		}
	}
	return false
}

// route holds creates for their own close-write and queues the rest. A full
// output queue drops and counts, as the BPF ring reader does.
func (p *placementFID) route(ev placementEvent, now time.Time) {
	if ev.Kind == placementCreate {
		if released, ok := p.creates.add(ev, now); ok {
			p.out.TrySend(released)
		}
		return
	}
	p.out.TrySend(ev)
}

func (p *placementFID) expire(now time.Time) {
	for _, ev := range p.creates.expire(now) {
		p.out.TrySend(ev)
	}
}

// reportPlacementOverflow tells the operator that the kernel dropped
// placement events: no path survives an overflow, so no recovery can
// rescan them.
func (fm *FileMonitor) reportPlacementOverflow() {
	const check = "fanotify_kernel_overflow"
	if !fm.shouldAlert(check, "placement") {
		return
	}
	fm.sendAlert(alert.Warning, check,
		"fanotify placement event queue overflowed; files moved or linked into watched trees during the overflow were not checked",
		"The kernel queue for rename and hard-link events filled and dropped events before the reader could drain them. Files placed during the overflow are only covered by the next scheduled deep scan.")
}
