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
	if calls[0].mask != FAN_CLOSE_WRITE {
		t.Errorf("mask = %#x, want FAN_CLOSE_WRITE only", calls[0].mask)
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
	want := []markCall{
		{flags: FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask: FAN_CLOSE_WRITE, path: "/home"},
		{flags: FAN_MARK_ADD | FAN_MARK_MOUNT, mask: FAN_CLOSE_WRITE, path: "/home"},
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %+v, want %+v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("call %d = %+v, want %+v", i, calls[i], want[i])
		}
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
