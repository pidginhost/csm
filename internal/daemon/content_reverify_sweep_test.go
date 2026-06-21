package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

type fakeContentLogicVersionStore struct {
	changed bool
	err     error
	calls   int
	token   string
}

func (s *fakeContentLogicVersionStore) EnsureContentLogicVersion(token string) (bool, error) {
	s.calls++
	s.token = token
	return s.changed, s.err
}

func TestStartContentReverifySweepIfChangedSkipsOnStoreError(t *testing.T) {
	db := &fakeContentLogicVersionStore{err: errors.New("write failed")}
	d := &Daemon{}
	ran := false

	d.startContentReverifySweepIfChanged(db, "php=1;sig=2;yara=3", func() []checks.ContentReverifyDismissal {
		ran = true
		return nil
	})

	if db.calls != 1 {
		t.Fatalf("EnsureContentLogicVersion calls = %d, want 1", db.calls)
	}
	if db.token != "php=1;sig=2;yara=3" {
		t.Fatalf("EnsureContentLogicVersion token = %q", db.token)
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
	db := &fakeContentLogicVersionStore{changed: true}
	d := &Daemon{}
	entered := make(chan struct{})
	release := make(chan struct{})

	d.startContentReverifySweepIfChanged(db, "php=1;sig=2;yara=3", func() []checks.ContentReverifyDismissal {
		close(entered)
		<-release
		return nil
	})

	if db.calls != 1 {
		t.Fatalf("EnsureContentLogicVersion calls = %d, want 1", db.calls)
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

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wait group did not finish after content reverify sweep exited")
	}
}
