package adapter

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/eximlock"
	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

// Forward guard and the antispam worker share one lock: while another
// transaction holds it, forward guard reports busy and touches nothing.
func TestLockedAdapterSharesTheEximMutationLock(t *testing.T) {
	a, side := testAdapter(t)
	locked := lockedEximAdapter{a}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- eximlock.With(filepath.Dir(a.badIPsPath), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	applyErr := locked.Apply(policy.Config{Enabled: true}, nil)
	removeErr := locked.Remove()
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(applyErr, eximlock.ErrBusy) || !errors.Is(removeErr, eximlock.ErrBusy) || side.rebuilds != 0 {
		t.Fatalf("apply=%v remove=%v rebuilds=%d", applyErr, removeErr, side.rebuilds)
	}
}
