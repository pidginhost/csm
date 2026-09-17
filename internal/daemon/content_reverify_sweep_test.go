package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

type fakeContentLogicVersionStore struct {
	stored   string
	readErr  error
	writeErr error
	reads    int
	writes   int
	token    string
}

func (s *fakeContentLogicVersionStore) ContentLogicVersionChanged(token string) (bool, error) {
	s.reads++
	s.token = token
	return s.stored != token, s.readErr
}

func (s *fakeContentLogicVersionStore) SetContentLogicVersion(token string) error {
	s.writes++
	if s.writeErr == nil {
		s.stored = token
	}
	return s.writeErr
}

func TestStartContentReverifySweepIfChangedSkipsOnStoreError(t *testing.T) {
	db := &fakeContentLogicVersionStore{readErr: errors.New("read failed")}
	d := &Daemon{}
	ran := false

	d.startContentReverifySweepIfChanged(db, "php=1;sig=2;yara=3", func() ([]checks.ContentReverifyDismissal, checks.ReverifySweepStats, bool) {
		ran = true
		return nil, checks.ReverifySweepStats{}, true
	})

	if db.reads != 1 {
		t.Fatalf("ContentLogicVersionChanged calls = %d, want 1", db.reads)
	}
	if db.token != "php=1;sig=2;yara=3" {
		t.Fatalf("ContentLogicVersionChanged token = %q", db.token)
	}
	if ran {
		t.Fatal("content reverify sweep ran after store version error")
	}
	waitDone := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("wait group should not track a skipped sweep")
	}
}

func TestStartContentReverifySweepIfChangedTracksWorker(t *testing.T) {
	db := &fakeContentLogicVersionStore{stored: "php=0"}
	d := &Daemon{}
	entered := make(chan struct{})
	release := make(chan struct{})

	d.startContentReverifySweepIfChanged(db, "php=1;sig=2;yara=3", func() ([]checks.ContentReverifyDismissal, checks.ReverifySweepStats, bool) {
		close(entered)
		<-release
		return nil, checks.ReverifySweepStats{}, true
	})

	if db.reads != 1 {
		t.Fatalf("ContentLogicVersionChanged calls = %d, want 1", db.reads)
	}

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("content reverify sweep did not start")
	}

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("wait group finished while content reverify sweep was still running")
	case <-time.After(20 * time.Millisecond):
	}
	if db.writes != 0 {
		t.Fatalf("version marker was recorded before the sweep completed: writes=%d", db.writes)
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wait group did not finish after content reverify sweep exited")
	}
	if db.writes != 1 || db.stored != "php=1;sig=2;yara=3" {
		t.Fatalf("completed sweep marker writes=%d stored=%q", db.writes, db.stored)
	}
}

func TestStartContentReverifySweepRetriesAfterInterruptedRun(t *testing.T) {
	db := &fakeContentLogicVersionStore{stored: "php=0"}
	d := &Daemon{}
	runs := 0
	run := func() ([]checks.ContentReverifyDismissal, checks.ReverifySweepStats, bool) {
		runs++
		return nil, checks.ReverifySweepStats{}, false
	}

	d.startContentReverifySweepIfChanged(db, "php=1", run)
	d.wg.Wait()
	if runs != 1 || db.writes != 0 || db.stored != "php=0" {
		t.Fatalf("interrupted run=%d writes=%d stored=%q", runs, db.writes, db.stored)
	}

	d.startContentReverifySweepIfChanged(db, "php=1", run)
	d.wg.Wait()
	if runs != 2 {
		t.Fatalf("interrupted sweep was not retried: runs=%d", runs)
	}
}

func TestStartContentReverifySweepRetriesAfterMarkerWriteFailure(t *testing.T) {
	db := &fakeContentLogicVersionStore{stored: "php=0", writeErr: errors.New("write failed")}
	d := &Daemon{}
	runs := 0
	run := func() ([]checks.ContentReverifyDismissal, checks.ReverifySweepStats, bool) {
		runs++
		return nil, checks.ReverifySweepStats{}, true
	}

	d.startContentReverifySweepIfChanged(db, "php=1", run)
	d.wg.Wait()
	d.startContentReverifySweepIfChanged(db, "php=1", run)
	d.wg.Wait()
	if runs != 2 || db.writes != 2 || db.stored != "php=0" {
		t.Fatalf("marker failure runs=%d writes=%d stored=%q", runs, db.writes, db.stored)
	}
}

func TestContentReverifyOutcomeMessageDistinguishesRestoration(t *testing.T) {
	tests := []struct {
		name    string
		outcome checks.ContentReverifyDismissal
		want    string
	}{
		{name: "cleared", want: "stale finding auto-cleared"},
		{name: "demoted", outcome: checks.ContentReverifyDismissal{Demoted: true}, want: "remediated finding demoted"},
		{name: "promoted", outcome: checks.ContentReverifyDismissal{Promoted: true}, want: "finding severity restored after re-verification"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := contentReverifyOutcomeMessage(tc.outcome); got != tc.want {
				t.Fatalf("message = %q, want %q", got, tc.want)
			}
		})
	}
}
