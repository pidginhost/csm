//go:build linux

package workerproc

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// watchOOM follows a cgroup v1 memory cgroup's OOM notifications through an
// eventfd registered for memory.oom_control. On v2 the unit's slice counts
// the kills instead (unitSlice). After cgroup removal the caller bounds any
// remaining wait with stop.
func (c memoryCgroup) watchOOM() (*oomWatch, error) {
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

// oomFromV1Event reads a cgroup v1 OOM eventfd wake-up. The eventfd fires at
// an OOM and once more at cgroup removal, which the kernel signals after the
// directory is gone. While the directory exists, any wake-up is an OOM; once
// it is gone, a total count above one means an OOM came before the removal.
func oomFromV1Event(count uint64, alive bool) bool {
	return alive || count > 1
}
