//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// tmpExecEvidence returns what the writer's ancestry proved: the capture taken
// when the event was admitted, else a walk now. A file that is not root-owned
// or has no writer PID proves nothing and is never walked.
func tmpExecEvidence(event fileEvent, uid uint32) ancestryEvidence {
	if uid != 0 || event.pid <= 0 {
		return ancestryEvidence{}
	}
	if event.tmpCaptured {
		var st unix.Stat_t
		if event.tmpStat == nil || unix.Fstat(event.fd, &st) != nil || !sameTmpSnapshot(*event.tmpStat, st) {
			return ancestryEvidence{}
		}
	}
	if event.tmpAncestry != nil {
		return *event.tmpAncestry
	}
	return tmpExecAncestry(event.pid)
}

// captureTmpExecAncestry reads the writer's ancestry while the event is being
// admitted. Copy and link tools exit within moments of closing the file, long
// before an analyzer worker reaches the event. Only a root-owned file can be
// demoted, so nothing else pays for the walk.
func captureTmpExecAncestry(event *fileEvent) {
	if event.pid <= 0 || !underTempRoot(event.path) {
		return
	}
	event.tmpCaptured = true
	var st unix.Stat_t
	if unix.Fstat(event.fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return
	}
	event.tmpStat = &st
	ev := tmpExecAncestry(event.pid)
	event.tmpAncestry = &ev
}

const (
	// tmpVouchTTL is how long a work directory stays vouched after the last
	// proven writer. Builds prove themselves again every few seconds.
	tmpVouchTTL = 2 * time.Minute
	// tmpVouchCap bounds the table. Concurrent maintenance uses a handful of
	// work directories.
	tmpVouchCap = 32
)

// sameTmpSnapshot binds captured ancestry to the unchanged file. Ctime also
// catches an ownership change away from root and back while the event waited.
func sameTmpSnapshot(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Mode == b.Mode && a.Size == b.Size && a.Ctim == b.Ctim && a.Mtim == b.Mtim
}

// tmpVouches pins each vouched inode until expiry or eviction, so removing a
// directory cannot transfer its proof to a new directory that reuses its inode.
// The path is also bound: renames and mount aliases do not carry proof with them.
type tmpVouches struct {
	mu      sync.Mutex
	entries []tmpVouch
}

type tmpVouch struct {
	dir      *os.File
	path     string
	dev, ino uint64
	reason   string
	until    time.Time
}

// tmpVouchDirectory follows only root-controlled directories, without symlinks
// or mounts below the temporary root. The final file must be the event's open
// file, not a replacement at its old name. O_PATH never opens a FIFO or device
// for IO. Mount IDs from fdinfo also work on the supported older kernels.
func tmpVouchDirectory(event fileEvent) *os.File {
	work := tmpWorkDir(event.path)
	if !strings.HasSuffix(work, "/") || filepath.Clean(event.path) != event.path {
		return nil
	}
	temp := filepath.Dir(strings.TrimSuffix(work, "/"))
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer func() { _ = unix.Close(fd) }()
	var workFD *os.File
	defer func() {
		if workFD != nil {
			_ = workFD.Close()
		}
	}()
	current := ""
	tempMount := ""
	parts := strings.Split(strings.TrimPrefix(event.path, "/"), "/")
	for i, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil
		}
		_ = unix.Close(fd)
		fd = next
		if tempMount != "" && tmpMountID(fd) != tempMount {
			return nil
		}
		current += "/" + part
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 {
			return nil
		}
		if i == len(parts)-1 {
			var original unix.Stat_t
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o022 != 0 || tmpMountID(event.fd) != tempMount ||
				unix.Fstat(event.fd, &original) != nil || !sameTmpSnapshot(st, original) {
				return nil
			}
			result := workFD
			workFD = nil
			return result
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil
		}
		if current == temp {
			// Shared roots need sticky semantics; all children must be root-private.
			if st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
				return nil
			}
			tempMount = tmpMountID(fd)
			if tempMount == "" {
				return nil
			}
		} else if st.Mode&0o022 != 0 {
			return nil
		}
		if current+"/" == work {
			pin, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				return nil
			}
			workFD = os.NewFile(uintptr(pin), current)
		}
	}
	return nil
}

// fdinfo belongs to our own pinned O_PATH descriptor, not to the writer.
func tmpMountID(fd int) string {
	// #nosec G304 -- fixed procfs metadata path for a descriptor opened by this process.
	data, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (v *tmpVouches) prune(now time.Time) {
	kept := v.entries[:0]
	for _, e := range v.entries {
		if now.Before(e.until) {
			kept = append(kept, e)
		} else {
			_ = e.dir.Close()
		}
	}
	clear(v.entries[len(kept):])
	v.entries = kept
}

// grant accepts only direct ancestry proof, dated when that proof was captured.
func (v *tmpVouches) grant(event fileEvent, reason string, now time.Time) {
	at := event.at
	if at.IsZero() {
		at = now
	}
	if !now.Before(at.Add(tmpVouchTTL)) {
		return
	}
	dir := tmpVouchDirectory(event)
	if dir == nil {
		return
	}
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil {
		_ = dir.Close()
		return
	}
	work := tmpWorkDir(event.path)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.prune(now)
	for i, e := range v.entries {
		if e.path == work {
			// Workers may finish out of order. Older evidence cannot replace newer proof.
			if e.until.After(at.Add(tmpVouchTTL)) {
				_ = dir.Close()
				return
			}
			_ = e.dir.Close()
			v.entries = append(v.entries[:i], v.entries[i+1:]...)
			break
		}
	}
	if len(v.entries) >= tmpVouchCap {
		_ = v.entries[0].dir.Close()
		v.entries = v.entries[1:]
	}
	v.entries = append(v.entries, tmpVouch{dir: dir, path: work, dev: uint64(st.Dev), ino: st.Ino, reason: reason, until: at.Add(tmpVouchTTL)})
}

func (v *tmpVouches) covers(event fileEvent, now time.Time) (string, bool) {
	dir := tmpVouchDirectory(event)
	if dir == nil {
		return "", false
	}
	defer func() { _ = dir.Close() }()
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil {
		return "", false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.prune(now)
	for _, e := range v.entries {
		if e.path == tmpWorkDir(event.path) && e.dev == uint64(st.Dev) && e.ino == st.Ino {
			return e.reason, true
		}
	}
	return "", false
}

func (v *tmpVouches) close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, e := range v.entries {
		_ = e.dir.Close()
	}
	v.entries = nil
}
