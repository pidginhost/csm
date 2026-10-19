//go:build linux

package learnwatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/learn"
)

type changingRegistry struct {
	fakeSource
	onPasswd func()
}

func (s *changingRegistry) Passwd() ([]byte, error) {
	if s.onPasswd != nil {
		s.onPasswd()
	}
	return s.fakeSource.Passwd()
}

type reservationLookupHook struct {
	*fakeEngine
	afterLookup func()
}

func (e reservationLookupHook) ReportUIDs(ctx context.Context) ([]int, error) {
	uids, err := e.fakeEngine.ReportUIDs(ctx)
	e.afterLookup()
	return uids, err
}

type cancellationHook struct {
	*fakeEngine
	beforeCancel func(int)
}

func (e cancellationHook) CancelUnsent(ctx context.Context, uid int, confirm func() (bool, error)) error {
	e.beforeCancel(uid)
	return e.fakeEngine.CancelUnsent(ctx, uid, confirm)
}

func TestSchedulerRemovedRechecksEachCancellation(t *testing.T) {
	for _, change := range []string{"reassigned", "registry_unreadable", "passwd_unreadable"} {
		t.Run(change, func(t *testing.T) {
			f := newWatch(t, 1)
			src := &changingRegistry{fakeSource: f.cfg.Source.(fakeSource)}
			f.cfg.Source = src
			f.engine.held = []int{1500, 1600}
			f.cfg.Engine = cancellationHook{fakeEngine: f.engine, beforeCancel: func(uid int) {
				if uid != 1600 {
					return
				}
				switch change {
				case "reassigned":
					src.users = append(slices.Clone(src.users), "tenant9")
					src.passwd += "tenant9:x:1600:1600::relative/home:/bin/bash\n"
				case "registry_unreadable":
					src.usersErr = errors.New("registry unavailable")
				case "passwd_unreadable":
					src.passwdErr = errors.New("password database unavailable")
				}
			}}
			f.restart()
			r := f.pass()
			if got := f.engine.cancelled(); !slices.Equal(got, []int{1500}) {
				t.Fatalf("cancelled %v, want only the confirmed removal", got)
			}
			if change != "reassigned" && (r.Skipped[SkipRegistryUnreadable] != 1 || !r.Unfinished) {
				t.Fatalf("registry failure not reported: %+v", r)
			}
		})
	}
}

func TestSchedulerRemovedRechecksReservationHolders(t *testing.T) {
	for _, change := range []string{"created", "uid_reused", "registry_unreadable", "passwd_unreadable"} {
		t.Run(change, func(t *testing.T) {
			f := newWatch(t, 1)
			if change == "registry_unreadable" || change == "passwd_unreadable" {
				if err := os.Remove(filepath.Join(f.accounts[0].Home, optInName)); err != nil {
					t.Fatal(err)
				}
			}
			src := &changingRegistry{fakeSource: f.cfg.Source.(fakeSource)}
			f.cfg.Source = src
			f.engine.held = []int{1500}
			f.cfg.Engine = reservationLookupHook{fakeEngine: f.engine, afterLookup: func() {
				switch change {
				case "created":
					src.users = append(slices.Clone(src.users), "tenant9")
					src.passwd += "tenant9:x:1500:1500::relative/home:/bin/bash\n"
				case "uid_reused":
					src.passwd = "tenant1:x:1500:1500::" + f.accounts[0].Home + ":/bin/bash\n"
				case "registry_unreadable":
					src.usersErr = errors.New("registry unavailable")
				case "passwd_unreadable":
					src.passwdErr = errors.New("password database unavailable")
				}
			}}
			f.restart()
			r := f.pass()
			if got := f.engine.cancelled(); len(got) != 0 {
				t.Fatalf("cancelled %v using stale registry data", got)
			}
			if (src.usersErr != nil || src.passwdErr != nil) && (r.Skipped[SkipRegistryUnreadable] != 1 || !r.Unfinished) {
				t.Fatalf("registry recheck failure not reported: %+v", r)
			}
		})
	}
}

// A UID can remain held throughout a rename even though joining an old
// account list to the new passwd contents makes it appear unassigned.
func TestSchedulerRemovedRejectsTornRegistry(t *testing.T) {
	f := newWatch(t, 1)
	src := &changingRegistry{fakeSource: f.cfg.Source.(fakeSource)}
	src.onPasswd = func() {
		src.users = []string{"tenant9"}
		src.passwd = "tenant9:x:1001:1001::relative/home:/bin/bash\n"
		src.onPasswd = nil
	}
	f.cfg.Source = src
	f.engine.held = []int{1001}
	f.restart()
	r := f.pass()
	if got := f.engine.cancelled(); len(got) != 0 {
		t.Fatalf("cancelled %v from a torn registry read", got)
	}
	if r.Skipped[SkipRegistryUnreadable] != 1 || !r.Unfinished {
		t.Fatalf("changing registry not reported: %+v", r)
	}
}

// Spec 7.4: unsent reservations cancel on loss of eligibility, and a
// removed account has lost it. Only UIDs no registry account holds count.
func TestSchedulerDeletedAccountCancelsReservations(t *testing.T) {
	f := newWatch(t, 2)
	f.engine.held = []int{1001, 1500}
	f.pass()
	if got := f.engine.cancelled(); !slices.Equal(got, []int{1500}) {
		t.Fatalf("cancelled %v, want only the removed account", got)
	}
}

func TestSchedulerRemovedAccountLosesEligibility(t *testing.T) {
	for _, removed := range []string{"registry", "passwd"} {
		t.Run(removed, func(t *testing.T) {
			f := newWatch(t, 1)
			f.engine.held = []int{1001}
			f.pass()
			if got := f.engine.cancelled(); len(got) != 0 {
				t.Fatalf("existing account cancelled: %v", got)
			}
			src := f.cfg.Source.(fakeSource)
			if removed == "registry" {
				src.users = nil
			} else {
				src.passwd = ""
			}
			f.cfg.Source = src
			f.restart()
			f.pass()
			if got := f.engine.cancelled(); !slices.Equal(got, []int{1001}) {
				t.Fatalf("removed account not cancelled: %v", got)
			}
		})
	}
}

func TestSchedulerUnreadableRegistryCancelsNothing(t *testing.T) {
	f := newWatch(t, 1)
	src := f.cfg.Source.(fakeSource)
	src.passwdErr = errors.New("password database busy")
	f.cfg.Source = src
	f.restart()
	f.engine.held = []int{1001, 1500}
	if r := f.pass(); r.Skipped[SkipRegistryUnreadable] != 1 {
		t.Fatalf("registry failure not reported: %+v", r)
	}
	if got := f.engine.cancelled(); len(got) != 0 {
		t.Fatalf("cancelled %v from an unreadable registry", got)
	}
}

// An account CSM cannot read is not a removed one.
func TestSchedulerUnusableHomeKeepsReservations(t *testing.T) {
	f := newWatch(t, 1)
	src := f.cfg.Source.(fakeSource)
	src.users = append(slices.Clone(src.users), "tenant9")
	src.passwd += "tenant9:x:1009:1009::relative/home:/bin/bash\n"
	f.cfg.Source = src
	f.restart()
	f.engine.held = []int{1009}
	if r := f.pass(); r.Skipped[SkipBadHome] != 1 {
		t.Fatalf("unusable home not reported: %+v", r)
	}
	if got := f.engine.cancelled(); len(got) != 0 {
		t.Fatalf("cancelled %v for an existing account", got)
	}
}

func TestSchedulerDeletedAccountCancelFailureRetries(t *testing.T) {
	f := newWatch(t, 1)
	f.engine.held = []int{1500}
	f.engine.mu.Lock()
	f.engine.cancelErr = learn.ErrStateIO
	f.engine.mu.Unlock()
	if r := f.pass(); r.Skipped[SkipStateUnavailable] != 1 || !r.Unfinished {
		t.Fatalf("failed cancel not reported: %+v", r)
	}
	f.engine.mu.Lock()
	f.engine.cancelErr = nil
	f.engine.mu.Unlock()
	f.pass()
	if got := f.engine.cancelled(); !slices.Equal(got, []int{1500, 1500}) {
		t.Fatalf("cancel not retried: %v", got)
	}
}
