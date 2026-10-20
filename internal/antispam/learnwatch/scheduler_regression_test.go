//go:build linux

package learnwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/store"
)

func TestSchedulerTallyKeepsFinishedAccounts(t *testing.T) {
	f := newWatch(t, 2)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	f.deliver(1, "new", 3, spamBody)
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		if c.UID == f.accounts[0].UID {
			return learn.Outcome{Deferred: true}, nil
		}
		return learn.Outcome{Committed: []uint64{1}}, nil
	}
	r := f.pass()
	if r.Pending != 1 || !r.OldestPending.Equal(t0) || r.Submitted != 3 || r.Unfinished {
		t.Fatalf("lost finished account's pending report: %+v", r)
	}
}

func TestSchedulerReportsOwnTheirSkipMaps(t *testing.T) {
	f := newWatch(t, 1)
	r := f.pass()
	r.Skipped["caller"] = 1
	last, _ := f.w.Last()
	if last.Skipped["caller"] != 0 {
		t.Fatal("Pass returned the stored report's map")
	}
	last.Skipped["reader"] = 1
	last, _ = f.w.Last()
	if last.Skipped["reader"] != 0 {
		t.Fatal("Last returned the stored report's map")
	}
}

func TestSchedulerCappedBaselineDoesNotLearnOldCorpus(t *testing.T) {
	f := newWatch(t, 1)
	f.cfg.SeenAllowance = 1
	f.restart()
	f.deliver(0, "new", 2, spamBody)
	r := f.pass()
	if !r.Unfinished {
		t.Errorf("capped baseline reported complete: %+v", r)
	}
	f.cfg.SeenAllowance = 3
	f.restart()
	f.pass()
	if got := len(f.engine.submitted()); got != 0 {
		t.Fatalf("learned %d messages from an incomplete baseline", got)
	}
	f.deliver(0, "new", 1, spamBody)
	f.pass()
	if got := len(f.engine.submitted()); got != 1 {
		t.Fatalf("post-baseline arrival: %d submissions, want 1", got)
	}
}

func TestSchedulerReplacementCancelsSiblingPending(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.submit = false
	f.deliver(0, "new", 1, spamBody)
	f.pass()
	cur := filepath.Join(f.accounts[0].Home, "mail/.spam/cur")
	if err := os.Rename(cur, cur+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cur, 0o700); err != nil {
		t.Fatal(err)
	}
	f.submit = true
	f.pass()
	if got := len(f.engine.submitted()); got != 0 || f.pending(0) != 0 {
		t.Fatalf("new baseline replayed old sibling work: submitted=%d pending=%d", got, f.pending(0))
	}
}

func TestSchedulerRechecksGlobalOptIn(t *testing.T) {
	f := newWatch(t, 1)
	if err := os.Remove(filepath.Join(f.accounts[0].Home, optInName)); err != nil {
		t.Fatal(err)
	}
	writeMsg(t, f.cfg.GlobalPath, nil)
	f.pass()
	f.deliver(0, "new", 2, spamBody)
	f.engine.onSubmit = func(learn.Candidate) {
		if err := os.Remove(f.cfg.GlobalPath); err != nil {
			t.Error(err)
		}
	}
	f.pass()
	if got := len(f.engine.submitted()); got != 1 || f.pending(0) != 0 {
		t.Fatalf("global opt-out ignored: submitted=%d pending=%d", got, f.pending(0))
	}
}

func TestSchedulerRechecksSubmissionGateAfterRead(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	old := afterRead
	t.Cleanup(func() { afterRead = old })
	afterRead = func() { f.submit = false }
	r := f.pass()
	if got := len(f.engine.submitted()); got != 0 || r.Pending != 1 {
		t.Fatalf("closed gate ignored: submitted=%d report=%+v", got, r)
	}
	afterRead = old
	f.submit = true
	f.pass()
	if got := len(f.engine.submitted()); got != 1 {
		t.Fatalf("held message was not retried: %d submissions", got)
	}
}

func TestSchedulerRetriesOutcomeErrors(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
		return learn.Outcome{Err: errors.New("state unavailable")}, nil
	}
	r := f.pass()
	if r.Submitted != 0 || r.Pending != 1 || f.pending(0) != 1 {
		t.Fatalf("failed outcome discarded: %+v", r)
	}
	f.engine.respond = nil
	f.pass()
	if got := len(f.engine.submitted()); got != 2 || f.pending(0) != 0 {
		t.Fatalf("retry: submitted=%d pending=%d", got, f.pending(0))
	}
}

// rollbackKV fails a real transaction after fn to exercise commit failures,
// including the in-memory counters updated inside fn.
type rollbackKV struct {
	kv
	fail func(store.LearnTx) bool
}

func (db rollbackKV) LearnUpdate(fn func(store.LearnTx) error) error {
	return db.kv.LearnUpdate(func(tx store.LearnTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if db.fail(tx) {
			return errors.New("injected commit failure")
		}
		return nil
	})
}

func TestSchedulerFailedObservationDoesNotFinishBaseline(t *testing.T) {
	f := newWatch(t, 1)
	f.deliver(0, "new", 1, spamBody)
	failed := false
	f.cfg.State.db = rollbackKV{kv: f.db, fail: func(tx store.LearnTx) bool {
		count := 0
		if err := tx.ForEach(store.LearnWatchSeenBucket, func(_, _ []byte) error { count++; return nil }); err != nil {
			t.Fatal(err)
		}
		if count > 0 && !failed {
			failed = true
			return true
		}
		return false
	}}
	r := f.pass()
	if !failed || !r.Unfinished {
		t.Errorf("failed discovery reported complete: failed=%v report=%+v", failed, r)
	}
	f.now = f.now.Add(FullRescanEvery)
	f.pass()
	if got := len(f.engine.submitted()); got != 0 {
		t.Fatalf("failed baseline learned %d old messages", got)
	}
}

func TestSchedulerFailedMarkStaysPending(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	f.cfg.State.db = rollbackKV{kv: f.db, fail: func(tx store.LearnTx) bool {
		found := false
		if err := tx.ForEach(store.LearnWatchSeenBucket, func(_, v []byte) error {
			var e SeenEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			found = found || e.Status == StatusSubmitted
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return found
	}}
	r := f.pass()
	if !r.Unfinished || r.Pending != 1 || f.pending(0) != 1 {
		t.Fatalf("failed mark disappeared from report: %+v", r)
	}
}

func TestSchedulerCancellationStopsBeforeSubmit(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := afterRead
	t.Cleanup(func() { afterRead = old })
	afterRead = cancel
	r := f.w.Pass(ctx)
	if got := len(f.engine.submitted()); got != 0 || !r.Unfinished || r.Pending != 1 {
		t.Fatalf("cancellation ignored: submitted=%d report=%+v", got, r)
	}
}

func TestSchedulerExpiredDeadlineStopsBeforeSubmit(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	old := afterRead
	t.Cleanup(func() { afterRead = old })
	afterRead = func() { f.now = f.now.Add(PassDeadline + time.Second) }
	r := f.pass()
	if got := len(f.engine.submitted()); got != 0 || !r.Unfinished || r.Pending != 1 {
		t.Fatalf("deadline ignored: submitted=%d report=%+v", got, r)
	}
}

func TestSchedulerAlternatesFreshAndRetriesPerFolder(t *testing.T) {
	r := &accountRun{queues: []*folderQueue{
		{fresh: []PendingItem{{Base: "fresh-a"}, {Base: "fresh-b"}}, retry: []PendingItem{{Base: "retry-a"}}},
		{fresh: []PendingItem{{Base: "fresh-c"}}, retry: []PendingItem{{Base: "retry-b"}, {Base: "retry-c"}}},
	}}
	want := []string{"fresh-a", "fresh-c", "retry-a", "retry-b"}
	for _, base := range want {
		_, it := r.next()
		if it.Base != base {
			t.Errorf("next=%q, want %q", it.Base, base)
		}
	}
}

func TestSchedulerDiscoveryDoesNotExhaustLaterFolderBudget(t *testing.T) {
	f := newWatch(t, 1)
	f.cfg.Chunk = 1
	f.restart()
	for _, sub := range Subdirs {
		if err := os.MkdirAll(filepath.Join(f.accounts[0].Home, "mail/.Junk", sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.pass()
	f.deliver(0, "new", MaxAttempts+1, spamBody)
	for i := range MaxAttempts + 1 {
		writeMsg(t, filepath.Join(f.accounts[0].Home, "mail/.Junk/new", fmt.Sprintf("junk-%d", i)), []byte("Subject: junk\r\n\r\nsecond folder"))
	}
	second := 0
	f.engine.onSubmit = func(c learn.Candidate) {
		if strings.Contains(string(c.Snapshot), "second folder") {
			second++
		}
	}
	f.pass()
	if got := len(f.engine.submitted()); got != MaxAttempts || second != MaxAttempts/2 {
		t.Fatalf("folder fairness: total=%d second=%d", got, second)
	}
}

func TestSchedulerReplacedDirectoryBeforeReadStartsBaseline(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	newDir := filepath.Join(f.accounts[0].Home, "mail/.spam/new")
	entries, err := os.ReadDir(newDir)
	if err != nil {
		t.Fatal(err)
	}
	replaced := false
	turnHook = func(_ int, kind string) {
		if kind != "attempt" || replaced {
			return
		}
		replaced = true
		if err := os.Rename(newDir, newDir+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(newDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeMsg(t, filepath.Join(newDir, entries[0].Name()), []byte(spamBody))
	}
	f.pass()
	f.pass()
	if got := len(f.engine.submitted()); !replaced || got != 0 {
		t.Fatalf("replacement bypassed baseline: replaced=%v submitted=%d", replaced, got)
	}
}

func TestSchedulerPrunesOnlyVerifiedFolders(t *testing.T) {
	f := newWatch(t, 1)
	f.deliver(0, "new", 1, spamBody)
	f.pass()
	mail := filepath.Join(f.accounts[0].Home, "mail")
	if err := os.Rename(mail, mail+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mail+"-saved", mail); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(SeenRetention + time.Hour)
	r := f.pass()
	if !r.Unfinished {
		t.Errorf("unreadable folders reported complete: %+v", r)
	}
	if err := os.Remove(mail); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(mail+"-saved", mail); err != nil {
		t.Fatal(err)
	}
	f.pass()
	if got := len(f.engine.submitted()); got != 0 {
		t.Fatalf("forgot unverified history and learned %d old messages", got)
	}
}

func TestSchedulerRotatesFoldersAcrossPasses(t *testing.T) {
	f := newWatch(t, 1)
	home := f.accounts[0].Home
	var passwd strings.Builder
	for i := range MaxAttempts + 1 {
		box := fmt.Sprintf("box%02d", i)
		fmt.Fprintf(&passwd, "%s:x\n", box)
		for _, sub := range Subdirs {
			if err := os.MkdirAll(filepath.Join(home, "mail/example.test", box, ".spam", sub), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(home, "etc/example.test"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeMsg(t, filepath.Join(home, "etc/example.test/passwd"), []byte(passwd.String()))
	f.pass()
	for i := range MaxAttempts + 1 {
		box := fmt.Sprintf("box%02d", i)
		writeMsg(t, filepath.Join(home, "mail/example.test", box, ".spam/new/message"), []byte("Subject: "+box+"\r\n\r\nbody"))
	}
	seen := map[string]bool{}
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		seen[string(c.Snapshot)] = true
		return learn.Outcome{Deferred: true}, nil
	}
	f.now = f.now.Add(PassEvery)
	f.pass()
	f.now = f.now.Add(PassEvery)
	f.pass()
	if len(seen) != MaxAttempts+1 {
		t.Fatalf("only %d of %d folders got a turn across passes", len(seen), MaxAttempts+1)
	}
}

func TestSchedulerPruningFreesSeenAllowance(t *testing.T) {
	f := newWatch(t, 1)
	f.cfg.SeenAllowance = 1
	f.restart()
	f.deliver(0, "new", 1, spamBody)
	f.pass()
	dir := filepath.Join(f.accounts[0].Home, "mail/.spam/new")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, entries[0].Name())); err != nil {
		t.Fatal(err)
	}
	f.deliver(0, "new", 1, spamBody)
	f.now = f.now.Add(SeenRetention + time.Hour)
	f.pass()
	f.pass()
	if got := len(f.engine.submitted()); got != 1 {
		t.Fatalf("expired history did not release allowance: submitted=%d", got)
	}
}

func TestSchedulerReplacedSiblingBeforeReadStartsBaseline(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	cur := filepath.Join(f.accounts[0].Home, "mail/.spam/cur")
	replaced := false
	turnHook = func(_ int, kind string) {
		if kind != "attempt" || replaced {
			return
		}
		replaced = true
		if err := os.Rename(cur, cur+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(cur, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.pass()
	f.pass()
	if got := len(f.engine.submitted()); !replaced || got != 0 {
		t.Fatalf("sibling replacement bypassed baseline: replaced=%v submitted=%d", replaced, got)
	}
}

func TestSchedulerGateClosesDuringIdentityCheck(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	attempting := false
	turnHook = func(_ int, kind string) { attempting = attempting || kind == "attempt" }
	f.cfg.State.db = rollbackKV{kv: f.db, fail: func(store.LearnTx) bool {
		if attempting {
			f.submit = false
		}
		return false
	}}
	reads := 0
	old := afterRead
	t.Cleanup(func() { afterRead = old })
	afterRead = func() { reads++ }
	r := f.pass()
	if !attempting || reads != 0 || r.Pending != 1 || len(f.engine.submitted()) != 0 {
		t.Fatalf("closed gate read content: attempting=%v reads=%d report=%+v", attempting, reads, r)
	}
}

func TestSchedulerOptOutDuringIdentityCheck(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	attempting, removed := false, false
	turnHook = func(_ int, kind string) { attempting = attempting || kind == "attempt" }
	f.cfg.State.db = rollbackKV{kv: f.db, fail: func(store.LearnTx) bool {
		if attempting && !removed {
			if err := os.Remove(filepath.Join(f.accounts[0].Home, optInName)); err != nil {
				t.Fatal(err)
			}
			removed = true
		}
		return false
	}}
	reads := 0
	old := afterRead
	t.Cleanup(func() { afterRead = old })
	afterRead = func() { reads++ }
	r := f.pass()
	if !removed || reads != 0 || r.Pending != 0 || f.pending(0) != 0 || len(f.engine.submitted()) != 0 {
		t.Fatalf("withdrawn consent read content: removed=%v reads=%d report=%+v", removed, reads, r)
	}
}
