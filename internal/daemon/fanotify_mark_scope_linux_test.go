//go:build linux

package daemon

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

type markCall struct {
	flags uint
	mask  uint64
	path  string
}

// A mount mark covers one vfsmount. Every CloudLinux CageFS account reaches the
// same files through a bind mount, so a write inside a cage produced no event
// at all: the realtime scanner was blind for exactly the accounts most likely
// to be compromised.
func TestMarkWatchRoot_PrefersFilesystemScope(t *testing.T) {
	var calls []markCall
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		calls = append(calls, markCall{flags: flags, mask: mask, path: path})
		return nil
	}

	scope, err := markWatchRoot(3, "/home", mark)
	if err != nil {
		t.Fatalf("markWatchRoot: %v", err)
	}
	if scope != markScopeFilesystem {
		t.Errorf("scope = %v, want filesystem", scope)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want one", len(calls))
	}
	if calls[0].flags&FAN_MARK_FILESYSTEM == 0 {
		t.Errorf("flags = %#x, want FAN_MARK_FILESYSTEM", calls[0].flags)
	}
}

// EL8 backported FAN_MARK_FILESYSTEM but not FAN_CREATE. The filesystem scope
// must survive that: dropping to a mount mark there would give up cage coverage
// for an event type the kernel never had.
func TestMarkWatchRoot_KeepsFilesystemScopeWithoutCreate(t *testing.T) {
	var calls []markCall
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		calls = append(calls, markCall{flags: flags, mask: mask, path: path})
		if mask&FAN_CREATE != 0 {
			return unix.EINVAL
		}
		return nil
	}

	scope, err := markWatchRoot(3, "/home", mark)
	if err != nil {
		t.Fatalf("markWatchRoot: %v", err)
	}
	if scope != markScopeFilesystem {
		t.Errorf("scope = %v, want filesystem", scope)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want the create attempt then the close-write retry", len(calls))
	}
	if calls[1].mask&FAN_CREATE != 0 {
		t.Errorf("retry mask = %#x, still carries FAN_CREATE", calls[1].mask)
	}
}

// A kernel without FAN_MARK_FILESYSTEM must still be watched, exactly as before.
func TestMarkWatchRoot_FallsBackToMountScope(t *testing.T) {
	var calls []markCall
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		calls = append(calls, markCall{flags: flags, mask: mask, path: path})
		if flags&FAN_MARK_FILESYSTEM != 0 {
			return unix.EINVAL
		}
		return nil
	}

	scope, err := markWatchRoot(3, "/home", mark)
	if err != nil {
		t.Fatalf("markWatchRoot: %v", err)
	}
	if scope != markScopeMount {
		t.Errorf("scope = %v, want mount", scope)
	}
	last := calls[len(calls)-1]
	if last.flags&FAN_MARK_MOUNT == 0 {
		t.Errorf("final flags = %#x, want FAN_MARK_MOUNT", last.flags)
	}
}

// Every attempt failing is a watch that does not exist; the caller counts these
// and refuses to start when none succeeded.
func TestMarkWatchRoot_ReportsFailure(t *testing.T) {
	mark := func(int, uint, uint64, int, string) error { return unix.ENOSPC }

	scope, err := markWatchRoot(3, "/home", mark)
	if scope != markScopeNone {
		t.Errorf("scope = %v, want none", scope)
	}
	if !errors.Is(err, unix.ENOSPC) {
		t.Errorf("err = %v, want ENOSPC", err)
	}
}
