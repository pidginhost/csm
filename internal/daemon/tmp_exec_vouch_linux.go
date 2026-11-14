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
		if event.tmpStat == nil || unix.Fstat(event.fd, &st) != nil || !sameTmpFile(*event.tmpStat, st) {
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
	// tmpOccupantScanGap spaces out process-table scans for one work
	// directory in which no running maintenance process was found.
	tmpOccupantScanGap = 5 * time.Second
)

// sameTmpFile reports whether two stats name the same file under the same
// owner. Size, mode and times are left out on purpose: a build goes on
// writing, re-moding and hard-linking a file after the close that raised the
// event, and each of those moves its ctime. Only root can change the owner of a
// root-owned file, so an owner changed away and back is not what this guards.
func sameTmpFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid
}

// tmpVouches pins each vouched inode until expiry or eviction, so removing a
// directory cannot transfer its proof to a new directory that reuses its inode.
// The path is also bound: renames and mount aliases do not carry proof with them.
type tmpVouches struct {
	mu      sync.Mutex
	entries []tmpVouch
	// scanMu admits one occupant scan at a time; scanned holds, per work
	// directory, when the next scan may run after one that found nothing.
	scanMu  sync.Mutex
	scanned map[string]time.Time
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
//
// Mount IDs are compared only along this walk. The event descriptor belongs to
// the writer's mount, and a daemon that systemd gave its own mount namespace
// never shares a mount ID with the processes it watches; the descriptor is
// bound to the walked file by device and inode instead.
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
		if i == len(parts)-1 {
			if tempMount == "" || !tmpEventFilePlaced(fd, part, event.fd, tempMount) {
				return nil
			}
			result := workFD
			workFD = nil
			return result
		}
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

// tmpEventFilePlaced reports whether the event's open file is the root-owned
// regular file that name refers to in dir, or was until it was removed. An
// installer may create a file, remove it and have a copy tool write it again:
// the removed file has no name left to compare, its path was reported by the
// kernel when the write was seen, and only root can remove a name from a
// directory that passed the checks above.
func tmpEventFilePlaced(dir int, name string, eventFD int, mount string) bool {
	var original, parent unix.Stat_t
	if unix.Fstat(eventFD, &original) != nil || unix.Fstat(dir, &parent) != nil {
		return false
	}
	if original.Mode&unix.S_IFMT != unix.S_IFREG || original.Uid != 0 || original.Mode&0o022 != 0 ||
		original.Dev != parent.Dev {
		return false
	}
	if original.Nlink == 0 {
		return true
	}
	fd, err := unix.Openat(dir, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	return tmpMountID(fd) == mount && unix.Fstat(fd, &st) == nil && sameTmpFile(st, original)
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
	v.grantAt(event, reason, at, now)
}

// grantAt records proof read at the given time for the event's work directory.
func (v *tmpVouches) grantAt(event fileEvent, reason string, at, now time.Time) {
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

// occupied looks for a running maintenance process working inside the event's
// work directory and vouches for the directory when it finds one. A build
// driver such as make stays in its work directory while the short-lived tools
// it starts write the files, so no writer there may ever be proven.
func (v *tmpVouches) occupied(event fileEvent, now time.Time) (string, bool) {
	dir := tmpVouchDirectory(event)
	if dir == nil {
		return "", false
	}
	defer func() { _ = dir.Close() }()
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil {
		return "", false
	}
	work := tmpWorkDir(event.path)
	// Workers that queue behind a scan find the vouch it left.
	v.scanMu.Lock()
	defer v.scanMu.Unlock()
	if reason, ok := v.covers(event, now); ok {
		return reason, true
	}
	v.mu.Lock()
	for path, until := range v.scanned {
		if !now.Before(until) {
			delete(v.scanned, path)
		}
	}
	// Never evict an active cooldown: a burst across more directories than
	// the table holds would otherwise turn every write into a process scan.
	wait := now.Before(v.scanned[work]) || len(v.scanned) >= tmpVouchCap
	v.mu.Unlock()
	if wait {
		return "", false
	}
	reason, ok := provenOccupant(uint64(st.Dev), st.Ino, now)
	v.mu.Lock()
	if v.scanned == nil {
		v.scanned = make(map[string]time.Time)
	}
	if ok {
		delete(v.scanned, work)
	} else {
		v.scanned[work] = now.Add(tmpOccupantScanGap)
	}
	v.mu.Unlock()
	if !ok {
		return "", false
	}
	v.grantAt(event, reason, now, now)
	return reason, true
}

// provenOccupant reports the reason a running root process with proven
// maintenance ancestry gives, when its working directory is inside the work
// directory with this device and inode. The directory is matched by identity,
// so a second mount of the same temporary filesystem does not hide it.
func provenOccupant(dev, ino uint64, now time.Time) (string, bool) {
	entries, err := os.ReadDir(procRootDir)
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil || pid <= 1 {
			continue
		}
		cwdPath := filepath.Join(procRootDir, entry.Name(), "cwd")
		cwd, err := os.Readlink(cwdPath)
		if err != nil || !underTempRoot(cwd+"/") {
			continue
		}
		var st unix.Stat_t
		work := strings.TrimSuffix(tmpWorkDir(cwd+"/"), "/")
		if unix.Lstat(work, &st) != nil || uint64(st.Dev) != dev || st.Ino != ino {
			continue
		}
		if !tmpOccupantInside(cwdPath, dev, ino) || !procIsRoot(int32(pid)) {
			continue
		}
		if ok, reason := tmpExecDemote(0, tmpExecAncestry(int32(pid)), now); ok {
			return reason, true
		}
	}
	return "", false
}

// tmpOccupantInside follows the kernel's cwd reference, not just its printed
// name. Every directory back to the event's work directory must be controlled
// by root. A writable child cannot lend its occupant's proof to safe siblings.
func tmpOccupantInside(cwdPath string, dev, ino uint64) bool {
	fd, err := unix.Open(cwdPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	mount := tmpMountID(fd)
	if mount == "" {
		return false
	}
	for {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0o022 != 0 {
			return false
		}
		if uint64(st.Dev) == dev && st.Ino == ino {
			return true
		}
		parent, err := unix.Openat(fd, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return false
		}
		_ = unix.Close(fd)
		fd = parent
		var up unix.Stat_t
		if tmpMountID(fd) != mount || unix.Fstat(fd, &up) != nil || (st.Dev == up.Dev && st.Ino == up.Ino) {
			return false
		}
	}
}

// procIsRoot reports whether pid runs as root by real and effective user.
func procIsRoot(pid int32) bool {
	// #nosec G304 -- procfs pseudo-file under a fixed root; pid is a numeric procfs entry.
	status, err := os.ReadFile(filepath.Join(procRootDir, strconv.Itoa(int(pid)), "status"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			return statusUIDIsRoot(line)
		}
	}
	return false
}
