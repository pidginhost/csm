//go:build linux

package learnwatch

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/learn"
)

func TestPassStopsWhenDiscoveryCloses(t *testing.T) {
	f := newWatch(t, 2)
	open := true
	f.cfg.CanDiscover = func() bool { return open }
	f.restart()
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	f.deliver(1, "new", 1, spamBody)
	f.engine.onSubmit = func(learn.Candidate) { open = false }
	p := f.pass()
	if !p.Unfinished || p.Submitted != 1 || len(f.engine.submitted()) != 1 || f.pending(1) != 0 {
		t.Fatalf("closed discovery continued: pass %+v, submissions %v, second account pending %d", p, f.engine.submitted(), f.pending(1))
	}
	open = true
	f.engine.onSubmit = nil
	if p = f.pass(); p.Unfinished || p.Submitted != 1 || len(f.engine.submitted()) != 2 {
		t.Fatalf("reopened pass: %+v, submissions %v", p, f.engine.submitted())
	}
}

func TestPassRechecksDiscoveryBeforeAccount(t *testing.T) {
	f := newWatch(t, 1)
	open := true
	f.cfg.CanDiscover = func() bool { return open }
	f.restart()
	turnHook = func(_ int, kind string) {
		if kind == "turn" {
			open = false
		}
	}
	if p := f.pass(); p.Accounts != 0 || !p.Unfinished {
		t.Fatalf("closed discovery still opened the account: %+v", p)
	}
}

func TestPassRechecksGateBeforeContentRead(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	turnHook = func(_ int, kind string) {
		if kind == "attempt" {
			f.submit = false
		}
	}
	reads := 0
	saved := afterRead
	t.Cleanup(func() { afterRead = saved })
	afterRead = func() { reads++ }
	p := f.pass()
	if reads != 0 || p.Pending != 1 || len(f.engine.submitted()) != 0 {
		t.Fatalf("closed submission gate: reads %d, pass %+v, submissions %v", reads, p, f.engine.submitted())
	}
}

func TestPassRechecksGateAfterContentRead(t *testing.T) {
	for _, cancelPass := range []bool{false, true} {
		name := "gate closed"
		if cancelPass {
			name = "canceled"
		}
		t.Run(name, func(t *testing.T) {
			f := newWatch(t, 1)
			f.pass()
			f.deliver(0, "new", 1, spamBody)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			saved := afterRead
			t.Cleanup(func() { afterRead = saved })
			afterRead = func() {
				if cancelPass {
					cancel()
				} else {
					f.submit = false
				}
			}
			p := f.w.Pass(ctx)
			if p.Pending != 1 || p.Submitted != 0 || len(f.engine.submitted()) != 0 {
				t.Fatalf("suspended report was consumed: pass %+v, submissions %v", p, f.engine.submitted())
			}
			afterRead = saved
			f.submit = true
			if p = f.pass(); p.Pending != 0 || p.Submitted != 1 || len(f.engine.submitted()) != 1 {
				t.Fatalf("resumed report: pass %+v, submissions %v", p, f.engine.submitted())
			}
		})
	}
}
