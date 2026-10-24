//go:build linux

package workerproc

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// watchOOM starts following the cgroup's OOM notifications: on cgroup v1 an
// eventfd registered for memory.oom_control, on v2 inotify on memory.events,
// whose every change the kernel reports as a modification. Each watch ends
// when the cgroup goes away, or at stop.
func (c memoryCgroup) watchOOM() (*oomWatch, error) {
	if c.v2 {
		return c.watchOOMv2()
	}
	return c.watchOOMv1()
}

func (c memoryCgroup) watchOOMv1() (*oomWatch, error) {
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("oom eventfd: %w", err)
	}
	ev := os.NewFile(uintptr(efd), "oom eventfd") // #nosec G115 -- eventfd returned a non-negative descriptor.
	ctl, err := os.Open(filepath.Join(c.dir, "memory.oom_control"))
	if err != nil {
		_ = ev.Close()
		return nil, err
	}
	// The kernel takes its own references at registration.
	reg := fmt.Sprintf("%d %d", efd, ctl.Fd())
	err = os.WriteFile(filepath.Join(c.dir, "cgroup.event_control"), []byte(reg), 0)
	_ = ctl.Close()
	if err != nil {
		_ = ev.Close()
		return nil, fmt.Errorf("register oom eventfd: %w", err)
	}
	w := &oomWatch{done: make(chan struct{}), stop: func() { _ = ev.Close() }}
	go func() {
		defer close(w.done)
		var buf [8]byte
		for {
			if _, err := ev.Read(buf[:]); err != nil {
				return
			}
			alive := isDir(c.dir)
			if oomFromV1Event(binary.NativeEndian.Uint64(buf[:]), alive) {
				w.seen.Store(true)
			}
			if !alive {
				return
			}
		}
	}()
	return w, nil
}

func (c memoryCgroup) watchOOMv2() (*oomWatch, error) {
	ifd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("oom inotify: %w", err)
	}
	in := os.NewFile(uintptr(ifd), "oom inotify") // #nosec G115 -- inotify_init1 returned a non-negative descriptor.
	if _, err := unix.InotifyAddWatch(ifd, filepath.Join(c.dir, "memory.events"), unix.IN_MODIFY|unix.IN_DELETE_SELF); err != nil {
		_ = in.Close()
		return nil, fmt.Errorf("watch memory.events: %w", err)
	}
	w := &oomWatch{done: make(chan struct{}), stop: func() { _ = in.Close() }}
	go func() {
		defer close(w.done)
		buf := make([]byte, 4096)
		for {
			if _, err := in.Read(buf); err != nil {
				return
			}
			n, err := c.oomKills()
			if err != nil {
				return // The cgroup is gone.
			}
			if n > 0 {
				w.seen.Store(true)
				return
			}
		}
	}()
	return w, nil
}

// oomFromV1Event reads a cgroup v1 OOM eventfd wake-up. The eventfd fires at
// an OOM and once more at cgroup removal, which the kernel signals after the
// directory is gone. While the directory exists, any wake-up is an OOM; once
// it is gone, a count above one means an OOM came before the removal.
func oomFromV1Event(count uint64, alive bool) bool {
	return alive || count > 1
}
