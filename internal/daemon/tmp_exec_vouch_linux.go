//go:build linux

package daemon

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// tmpExecEvidence returns what the writer's ancestry proved: the capture taken
// when the event was admitted, else a walk now. A file that is not root-owned
// or has no writer PID proves nothing and is never walked.
func tmpExecEvidence(event fileEvent, uid uint32) ancestryEvidence {
	if event.tmpAncestry != nil {
		return *event.tmpAncestry
	}
	if uid != 0 || event.pid <= 0 {
		return ancestryEvidence{}
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
	var st unix.Stat_t
	if unix.Fstat(event.fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return
	}
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

// tmpVouches remembers the work directories a proven maintenance writer wrote
// an executable into. A build copies most files with tools that have exited
// before their ancestry can be read; those files are judged by the proven
// writer beside them instead of each raising a Critical.
//
// A vouch names the directory by device and inode, never by path, and is
// honoured only while nobody but root can write to that directory. It covers
// root-owned files alone, so what it adds is trust in other root processes
// writing into a root-private build directory during the build.
type tmpVouches struct {
	mu      sync.Mutex
	entries []tmpVouch
}

type tmpVouch struct {
	dev, ino uint64
	reason   string
	until    time.Time
}

// rootPrivateDir identifies workDir when it is a real directory owned by root
// that neither its group nor others can write to. workDir is tmpWorkDir's
// result: without a trailing slash it is a file in a temp root, not a
// directory, and nothing identifies it.
func rootPrivateDir(workDir string) (dev, ino uint64, ok bool) {
	if !strings.HasSuffix(workDir, "/") {
		return 0, 0, false
	}
	var st unix.Stat_t
	if unix.Lstat(strings.TrimSuffix(workDir, "/"), &st) != nil {
		return 0, 0, false
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
		return 0, 0, false
	}
	return uint64(st.Dev), st.Ino, true
}

// grant records that a proven writer wrote into workDir.
func (v *tmpVouches) grant(workDir, reason string, now time.Time) {
	dev, ino, ok := rootPrivateDir(workDir)
	if !ok {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	kept := v.entries[:0]
	for _, e := range v.entries {
		if now.Before(e.until) && (e.dev != dev || e.ino != ino) {
			kept = append(kept, e)
		}
	}
	if len(kept) >= tmpVouchCap {
		kept = kept[len(kept)-tmpVouchCap+1:]
	}
	kept = append(kept, tmpVouch{dev: dev, ino: ino, reason: reason, until: now.Add(tmpVouchTTL)})
	v.entries = kept
}

// covers reports the reason workDir was vouched for, if it still is.
func (v *tmpVouches) covers(workDir string, now time.Time) (string, bool) {
	dev, ino, ok := rootPrivateDir(workDir)
	if !ok {
		return "", false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, e := range v.entries {
		if e.dev == dev && e.ino == ino && now.Before(e.until) {
			return e.reason, true
		}
	}
	return "", false
}
