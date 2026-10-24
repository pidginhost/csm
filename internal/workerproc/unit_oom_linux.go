//go:build linux

package workerproc

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// watchOOM starts following the cgroup's OOM notifications: on cgroup v1 an
// eventfd registered for memory.oom_control, on v2 inotify on memory.events,
// whose every change the kernel reports as a modification. After cgroup
// removal the caller bounds any remaining wait with stop.
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
		w.readOOMv1(ev, func() bool { return isDir(c.dir) })
	}()
	return w, nil
}

func (w *oomWatch) readOOMv1(ev io.Reader, alive func() bool) {
	var buf [8]byte
	var count uint64
	for {
		if _, err := ev.Read(buf[:]); err != nil {
			return
		}
		count += binary.NativeEndian.Uint64(buf[:])
		if oomFromV1Event(count, alive()) {
			w.seen.Store(true)
			return
		}
		// The directory may disappear between read and stat, before its
		// removal notification arrives. Keep reading until a second event
		// proves an OOM or the post-exit grace period closes the eventfd.
	}
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
			n, err := c.oomEventsV2()
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
// it is gone, a total count above one means an OOM came before the removal.
func oomFromV1Event(count uint64, alive bool) bool {
	return alive || count > 1
}

// oomEventsV2 counts OOMs in a cgroup v2 memory.events: the oom counter, which
// rises before the kill, and oom_kill. A worker is one process, so an OOM in
// its cgroup is what kills it; waiting for oom_kill alone can wake before the
// kill and then find the cgroup gone.
func (c memoryCgroup) oomEventsV2() (uint64, error) {
	data, err := os.ReadFile(filepath.Join(c.dir, "memory.events")) // #nosec G304 -- a file in the worker unit's own cgroup.
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok || (key != "oom" && key != "oom_kill") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}
