//go:build linux

package learnwatch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/learn"
)

// Failure in the learner must not preserve folder history across an
// observed opt-out. Mail received before re-entry belongs to its baseline.
func TestSchedulerFailedCancelStillResetsBaseline(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.submit = false
	f.deliver(0, "new", 1, spamBody)
	f.pass()
	if f.pending(0) != 1 {
		t.Fatal("report was not queued")
	}
	flag := filepath.Join(f.accounts[0].Home, ".spamassassinenable")
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	f.engine.cancelErr = learn.ErrStateIO
	if r := f.pass(); r.Skipped[SkipStateUnavailable] != 1 || !r.Unfinished {
		t.Fatalf("failed cancellation was not reported: %+v", r)
	}
	if f.pending(0) != 0 {
		t.Error("observed opt-out retained queued reports")
	}
	f.deliver(0, "new", 1, spamBody)
	writeMsg(t, flag, nil)
	f.engine.cancelErr = nil
	f.submit = true
	f.restart()
	f.pass()
	if got := f.engine.submitted(); len(got) != 0 {
		t.Fatalf("re-entry learned mail from before its baseline: %v", got)
	}
	f.deliver(0, "new", 1, spamBody)
	f.pass()
	if got := f.engine.submitted(); countUID(got, 1001) != 1 {
		t.Fatalf("new mail after re-entry was not learned once: %v", got)
	}
}
