// Package processhandle signals verified Linux processes through kernel handles.
package processhandle

import (
	"context"
	"errors"
	"fmt"
	"math"
	"syscall"
)

var ErrUnsupported = errors.New("safe process signaling requires kernel pidfd support")

// Signal acquires a process handle before running verify. Verification may read
// numeric procfs paths: exit checks surrounding it reject a recycled PID. The
// final signal uses the captured handle even if the process exits afterward.
func Signal(ctx context.Context, pid int, sig syscall.Signal, verify func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pid <= 1 || pid > math.MaxInt32 {
		return fmt.Errorf("refuse to signal PID %d", pid)
	}
	handle, err := openHandle(pid)
	if err != nil {
		return err
	}
	defer handle.close()
	if err := handle.alive(); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if err := handle.alive(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return handle.signal(sig)
}

// Available reports whether this kernel can pin and signal a process handle.
// Probe each snapshot: descriptor pressure or service restrictions can change
// while the daemon runs, even though the kernel itself remains the same.
func Available() error {
	return probe()
}
