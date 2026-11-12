//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// capturedCreate is one FAN_CREATE record from a FAN_REPORT_DFID_NAME group
// on a little-endian host: metadata, then a DFID_NAME info record holding the
// fsid, an 8-byte FILEID_INO32_GEN handle and "shell.php", padded to 4 bytes.
var capturedCreate = []byte{
	0x40, 0x00, 0x00, 0x00, 0x03, 0x00, 0x18, 0x00, // event_len 64, vers 3, metadata_len 24
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mask FAN_CREATE
	0xff, 0xff, 0xff, 0xff, 0x92, 0x10, 0x00, 0x00, // fd FAN_NOFD, pid 4242
	0x02, 0x00, 0x28, 0x00, // info DFID_NAME, len 40
	0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x0a, // fsid
	0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // handle_bytes 8, handle_type 1
	0x0c, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // inode 12, generation 42
	's', 'h', 'e', 'l', 'l', '.', 'p', 'h', 'p', 0x00, 0x00, 0x00,
}

func fidInfoRecord(infoType uint8, body []byte) []byte {
	n := (4 + len(body) + 3) &^ 3
	b := make([]byte, n)
	b[0] = infoType
	binary.NativeEndian.PutUint16(b[2:4], uint16(n)) // #nosec G115 -- test records are small
	copy(b[4:], body)
	return b
}

func dfidNameBody(handleBytes uint32, handle []byte, name string) []byte {
	b := make([]byte, 16, 16+len(handle)+len(name)+1)
	binary.NativeEndian.PutUint32(b[0:4], 7)
	binary.NativeEndian.PutUint32(b[4:8], 9)
	binary.NativeEndian.PutUint32(b[8:12], handleBytes)
	binary.NativeEndian.PutUint32(b[12:16], 1)
	b = append(b, handle...)
	b = append(b, name...)
	return append(b, 0)
}

func fidEventRecord(mask uint64, infos ...[]byte) []byte {
	b := make([]byte, metadataSize)
	b[4] = unix.FANOTIFY_METADATA_VERSION
	binary.NativeEndian.PutUint16(b[6:8], uint16(metadataSize))
	binary.NativeEndian.PutUint64(b[8:16], mask)
	binary.NativeEndian.PutUint32(b[16:20], 0xffffffff)
	binary.NativeEndian.PutUint32(b[20:24], 77)
	for _, info := range infos {
		b = append(b, info...)
	}
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b))) // #nosec G115 -- test records are small
	return b
}

func TestParseFIDRecordDirName(t *testing.T) {
	rec, size, err := parseFIDRecord(capturedCreate)
	if err != nil || size != len(capturedCreate) {
		t.Fatalf("captured record: size %d err %v", size, err)
	}
	if rec.Mask != unix.FAN_CREATE || rec.PID != 4242 || rec.Name != "shell.php" ||
		rec.Fsid != (unix.Fsid{Val: [2]int32{0x12345678, 0x0abcdef0}}) || rec.HandleType != 1 ||
		!bytes.Equal(rec.Handle, []byte{0x0c, 0, 0, 0, 0x2a, 0, 0, 0}) {
		t.Fatalf("captured record decoded as %+v", rec)
	}

	handle := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	// A pidfd record ahead of the name and an unknown one after it are skipped.
	multi := fidEventRecord(unix.FAN_MOVED_TO|unix.FAN_ONDIR,
		fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_PIDFD, []byte{5, 0, 0, 0}),
		fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, handle, "plugin")),
		fidInfoRecord(200, []byte{1, 2}))
	stream := append(append([]byte{}, multi...), capturedCreate...)
	rec, size, err = parseFIDRecord(stream)
	if err != nil || size != len(multi) || rec.Name != "plugin" || rec.Mask != unix.FAN_MOVED_TO|unix.FAN_ONDIR || !bytes.Equal(rec.Handle, handle) || rec.PID != 77 {
		t.Fatalf("multi-record event: %+v size %d err %v", rec, size, err)
	}
	if rec, _, err = parseFIDRecord(stream[size:]); err != nil || rec.Name != "shell.php" {
		t.Fatalf("second event in the buffer: %+v err %v", rec, err)
	}

	overflow := fidEventRecord(unix.FAN_Q_OVERFLOW)
	if rec, size, err = parseFIDRecord(overflow); err != nil || size != metadataSize || rec.Mask != unix.FAN_Q_OVERFLOW {
		t.Fatalf("overflow event: %+v size %d err %v", rec, size, err)
	}

	withLen := func(b []byte, off int, v uint16) []byte {
		b = append([]byte{}, b...)
		binary.NativeEndian.PutUint16(b[off:off+2], v)
		return b
	}
	good := fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, handle, "x.php"))
	for name, tc := range map[string]struct {
		b []byte
		// framed: the event length is sound, so the caller can skip it.
		framed bool
	}{
		"short buffer":            {capturedCreate[:metadataSize-1], false},
		"event past buffer":       {capturedCreate[:len(capturedCreate)-4], false},
		"event shorter than meta": {append(binary.NativeEndian.AppendUint32(nil, 8), capturedCreate[4:]...), false},
		"wrong version":           {append(append([]byte{}, capturedCreate[:4]...), append([]byte{2}, capturedCreate[5:]...)...), false},
		"metadata past event":     {withLen(capturedCreate, 6, 80), true},
		"metadata too short":      {withLen(capturedCreate, 6, 8), true},
		"info length zero":        {fidEventRecord(unix.FAN_CREATE, withLen(good, 2, 0)), true},
		"info past event":         {fidEventRecord(unix.FAN_CREATE, withLen(good, 2, uint16(len(good)+4))), true},
		"info header truncated":   {fidEventRecord(unix.FAN_CREATE, good, []byte{2, 0}), true},
		"handle past record":      {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(64, handle, "x.php"))), true},
		"handle empty":            {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(0, nil, "x.php"))), true},
		"handle over max":         {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(129, make([]byte, 129), "x.php"))), true},
		"record too short":        {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, make([]byte, 8))), true},
		"name not terminated":     {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, handle, "abcd")[:28])), true},
		"name empty":              {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, handle, ""))), true},
		"name dot":                {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, handle, "."))), true},
		"name dotdot":             {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, handle, ".."))), true},
		"name with slash":         {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, handle, "../etc/x.php"))), true},
		"two names":               {fidEventRecord(unix.FAN_CREATE, good, good), true},
		"no name record":          {fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID, dfidNameBody(8, handle, "")[:24])), true},
	} {
		_, size, err := parseFIDRecord(tc.b)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if want := map[bool]int{true: len(tc.b), false: 0}[tc.framed]; size != want {
			t.Errorf("%s: size %d, want %d", name, size, want)
		}
	}
}

func newTestPlacementFID(t *testing.T, fm *FileMonitor) *placementFID {
	t.Helper()
	p := newPlacementFID(fm, -1, nil)
	fm.placementCreates.Store(p.creates)
	return p
}

func routedPlacements(p *placementFID) []placementEvent {
	var out []placementEvent
	for {
		select {
		case work := <-p.out.Items():
			work.Process(func(ev placementEvent) { out = append(out, ev) })
		default:
			return out
		}
	}
}

func closeWriteVia(t *testing.T, fm *FileMonitor, fd int) {
	t.Helper()
	fm.handleEvent(fd, 0, unix.FAN_CLOSE_WRITE)
	queuedPlacements(t, fm)
}

func TestFIDCreateSettlesBehindCloseWrite(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	p := newTestPlacementFID(t, fm)
	dir := t.TempDir()
	now := time.Now()

	// An ordinary open(O_CREAT): its own close-write analyses the file.
	written := filepath.Join(dir, "written.php")
	if err := os.WriteFile(written, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	created := placementOf(t, written, 0)
	created.Kind = placementCreate
	p.route(created, now)
	fd, err := unix.Open(written, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeWriteVia(t, fm, fd)
	p.expire(now.Add(fidCreateSettle))
	if got := routedPlacements(p); len(got) != 0 {
		t.Fatalf("create settled by its close-write was analysed again: %+v", got)
	}

	// A create with no close-write (a hard link) is analysed once, after the window.
	linked := filepath.Join(dir, "linked.php")
	if err = os.WriteFile(linked, []byte("<?php echo 2;"), 0o644); err != nil {
		t.Fatal(err)
	}
	alone := placementOf(t, linked, 0)
	alone.Kind = placementCreate
	p.route(alone, now)
	p.expire(now.Add(fidCreateSettle - time.Millisecond))
	if got := routedPlacements(p); len(got) != 0 {
		t.Fatalf("create analysed before its window ended: %+v", got)
	}
	p.expire(now.Add(fidCreateSettle))
	if got := routedPlacements(p); len(got) != 1 || got[0] != alone {
		t.Fatalf("lone create routed %+v, want exactly %+v", got, alone)
	}
	p.expire(now.Add(2 * fidCreateSettle))
	if got := routedPlacements(p); len(got) != 0 {
		t.Fatalf("create analysed twice: %+v", got)
	}

	// A close-write through a name that is gone wrote the inode somewhere
	// this create never saw analysed: it must not settle the create.
	source, target := filepath.Join(dir, "source.txt"), filepath.Join(dir, "target.php")
	if err = os.WriteFile(source, []byte("<?php echo 3;"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err = unix.Open(source, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Link(source, target); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(source); err != nil {
		t.Fatal(err)
	}
	unlinked := placementOf(t, target, 0)
	unlinked.Kind = placementCreate
	p.route(unlinked, now)
	closeWriteVia(t, fm, fd)
	p.expire(now.Add(fidCreateSettle))
	if got := routedPlacements(p); len(got) != 1 || got[0] != unlinked {
		t.Fatalf("close-write through an unlinked name settled the create: %+v", got)
	}

	// Renames are never held.
	moved := placementOf(t, written, 0)
	p.route(moved, now)
	if got := routedPlacements(p); len(got) != 1 || got[0] != moved {
		t.Fatalf("rename routed %+v, want immediately %+v", got, moved)
	}
}

// A create flood must not grow the pending set: past its cap the oldest
// create is analysed at once, counted, never skipped.
func TestFIDCreateSettleOverflowAnalysesOldest(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	p := newTestPlacementFID(t, fm)
	p.creates = newCreateSettler(2)
	now := time.Now()
	evs := make([]placementEvent, 3)
	for i := range evs {
		evs[i] = placementEvent{Path: "/home/user/f" + string(rune('a'+i)), Dev: 1, Ino: uint64(10 + i), Kind: placementCreate}
		p.route(evs[i], now)
	}
	if got := routedPlacements(p); len(got) != 1 || got[0] != evs[0] {
		t.Fatalf("overflow routed %+v, want the oldest create %+v", got, evs[0])
	}
	if st := p.QueueStatuses(now)["create_settle"]; st.DroppedTotal != 1 || st.Depth != 2 || st.Capacity != 2 {
		t.Fatalf("create_settle status %+v, want 1 overflow, 2 waiting of 2", st)
	}
	p.expire(now.Add(fidCreateSettle))
	if got := routedPlacements(p); len(got) != 2 || got[0] != evs[1] || got[1] != evs[2] {
		t.Fatalf("expired creates %+v, want the two still waiting", got)
	}
}

// fidPipe stands in for the fanotify group: Run polls and reads it the same way.
func fidPipe(t *testing.T) (readFD, writeFD int) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	return fds[0], fds[1]
}

func TestPlacementFIDOverflowIsCountedReportedAndShutdownDiscards(t *testing.T) {
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	readFD, writeFD := fidPipe(t)
	p := newPlacementFID(fm, readFD, nil)
	handled := make(chan placementEvent, 4)
	p.handle = func(ev placementEvent) { handled <- ev }
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { p.Run(ctx); close(stopped) }()
	defer func() {
		cancel()
		<-stopped
	}()

	unknown := fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, []byte{1, 2, 3, 4, 5, 6, 7, 8}, "x.php")))
	if _, err := unix.Write(writeFD, append(fidEventRecord(unix.FAN_Q_OVERFLOW), unknown...)); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		st := p.QueueStatuses(time.Now())
		if st["kernel"].DroppedTotal == 1 && st["unresolved"].DroppedTotal == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("overflow or unknown filesystem not counted: %+v", st)
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case f := <-alerts:
		if f.Check != "fanotify_kernel_overflow" || !strings.Contains(f.Message, "moved or linked") {
			t.Fatalf("overflow finding %+v", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("placement overflow raised no finding")
	}

	// Routed placements reach handle on a worker, not on the reader.
	ev := placementEvent{Path: "/home/user/moved.php", Dev: 1, Ino: 2, Kind: placementRename}
	p.route(ev, time.Now())
	select {
	case got := <-handled:
		if got != ev {
			t.Fatalf("handled %+v, want %+v", got, ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("routed placement never handled")
	}

	if fm.placementCreates.Load() != p.creates {
		t.Fatal("close-write path cannot reach the running backend's pending creates")
	}
	p.route(placementEvent{Path: "/home/user/new.php", Dev: 1, Ino: 3, Kind: placementCreate}, time.Now())
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if fm.placementCreates.Load() != nil {
		t.Fatal("stopped backend still receives close-writes")
	}
	if st := p.QueueStatuses(time.Now())["create_settle"]; st.DroppedTotal != 1 || st.Depth != 0 {
		t.Fatalf("shutdown left or hid a pending create: %+v", st)
	}
}

// A start that cannot mark anything returns an error for the selection to
// fall back on, and holds no descriptor afterwards.
func TestStartPlacementFIDFailureLeavesNothingOpen(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	p, err := startPlacementFID(context.Background(), &FileMonitor{})
	if err == nil || p != nil {
		t.Fatalf("start with no watch roots returned %v, %v", p, err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("failed start left %d descriptors open", len(after)-len(before))
	}
}

// Only a kernel that cannot create the group at all counts as lacking
// support; any other failure is unexpected and stays loud.
func TestFIDInitErrorMarksMissingKernelSupport(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EINVAL, unix.ENOSYS} {
		err := fidInitError(errno)
		if !errors.Is(err, errPlacementFIDUnsupported) || !errors.Is(err, errno) {
			t.Errorf("%v: %v does not mark missing support and keep the errno", errno, err)
		}
	}
	if err := fidInitError(unix.EPERM); errors.Is(err, errPlacementFIDUnsupported) || !errors.Is(err, unix.EPERM) {
		t.Errorf("EPERM classified as missing kernel support: %v", err)
	}
}

// A directory handle that will not open for a reason other than a removed
// entry hides every placement on that filesystem, so it is reported once per
// device cooldown; a removed directory is ordinary churn and stays silent.
func TestFIDResolveErrorRaisesUnresolvedFinding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		dropped uint64
		alerts  int
	}{
		{"permission", unix.EPERM, 2, 1},
		{"stale handle", unix.ESTALE, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alerts := make(chan alert.Finding, 8)
			fm := placementTestMonitor(alerts)
			p := newTestPlacementFID(t, fm)
			p.mounts = map[unix.Fsid][]fidMount{{Val: [2]int32{7, 9}}: {{fd: -1, path: t.TempDir(), dev: unix.Mkdev(8, 3)}}}
			p.openDir = func(int, unix.FileHandle, int) (int, error) { return -1, tc.err }
			// A create, not a move: the finding must not say how it got there.
			rec := fidEventRecord(unix.FAN_CREATE, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, []byte{1, 2, 3, 4, 5, 6, 7, 8}, "x.php")))
			now := time.Now()
			p.dispatch(rec, now)
			p.dispatch(rec, now)

			if got := p.QueueStatuses(now)["unresolved"].DroppedTotal; got != tc.dropped {
				t.Fatalf("unresolved losses %d, want %d", got, tc.dropped)
			}
			var got []alert.Finding
			for len(alerts) > 0 {
				got = append(got, <-alerts)
			}
			if len(got) != tc.alerts {
				t.Fatalf("findings %+v, want %d", got, tc.alerts)
			}
			for _, f := range got {
				if f.Check != placementUnresolvedCheck || f.Severity != alert.High || !strings.Contains(f.Message, "file or directory placed on device 8:3") {
					t.Fatalf("finding %+v", f)
				}
			}
		})
	}
}

// A rename flood fills the output queue. Placements it refuses go to overflow
// recovery instead of being lost: a file's directory is rescanned in
// placement mode, a moved-in directory is queued for its walk. That holds for
// creates the settle cap pushes out and for creates whose window ends.
func TestFIDFullOutputQueueRecoversPlacements(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	p := newTestPlacementFID(t, fm)
	p.out = queuehealth.NewChannel[placementEvent](1, time.Minute)
	p.creates = newCreateSettler(1)
	now := time.Now()
	p.route(placementEvent{Path: "/home/user/queued.php", Dev: 1, Ino: 10, Kind: placementRename}, now)
	p.route(placementEvent{Path: "/home/user/a/moved.php", Dev: 1, Ino: 11, Kind: placementRename}, now)
	p.route(placementEvent{Path: "/home/user/b/plugin", Dev: 1, Ino: 12, IsDir: true, Kind: placementRename}, now)
	p.route(placementEvent{Path: "/home/user/c/first.php", Dev: 1, Ino: 13, Kind: placementCreate}, now)
	// The settle cap pushes the first create out at once.
	p.route(placementEvent{Path: "/home/user/d/second.php", Dev: 1, Ino: 14, Kind: placementCreate}, now)
	p.expire(now.Add(fidCreateSettle))

	fm.reconcileMu.Lock()
	var rescans []string
	for dir, work := range fm.reconcileDirs {
		if work.placements {
			rescans = append(rescans, dir)
		}
	}
	fm.reconcileMu.Unlock()
	slices.Sort(rescans)
	if want := []string{"/home/user/a", "/home/user/c", "/home/user/d"}; !slices.Equal(rescans, want) {
		t.Fatalf("placement rescans %v, want %v", rescans, want)
	}
	fm.placedDirMu.Lock()
	walks := slices.Clone(fm.placedDirs)
	fm.placedDirMu.Unlock()
	if len(walks) != 1 || walks[0].path != "/home/user/b/plugin" || walks[0].ino != 12 {
		t.Fatalf("queued walks %+v, want the dropped directory", walks)
	}
	if out := p.QueueStatuses(now)["output"]; out.DroppedTotal != 4 {
		t.Fatalf("output queue status %+v, want four drops counted", out)
	}
}

// The fanotify backend reads the identity from the entry after the event, so
// a mismatch is a replacement made since, which no wait undoes. Its workers
// must never sleep on the retries the BPF backend needs.
func TestFIDPlacementNeverWaitsOnIdentityRetries(t *testing.T) {
	setPlacementRetryDelays(t, time.Hour)
	dir := t.TempDir()
	reported, path := filepath.Join(dir, "reported.php"), filepath.Join(dir, "x.php")
	for _, name := range []string{reported, path} {
		if err := os.WriteFile(name, []byte("<?php echo 1;"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ev := placementOf(t, reported, 0)
	ev.Path = path
	fm := placementTestMonitor(make(chan alert.Finding, 4))
	p := newTestPlacementFID(t, fm)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handle(ev)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("fanotify placement waited on identity retries")
	}
	if stats := fm.EventStats(); stats.PlacementUnverified != 1 || stats.Received != 0 {
		t.Fatalf("stats = %+v, want one unverified placement", stats)
	}
}
