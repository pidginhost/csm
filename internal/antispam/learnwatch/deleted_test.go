//go:build linux

package learnwatch

import (
	"errors"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/learn"
)

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
