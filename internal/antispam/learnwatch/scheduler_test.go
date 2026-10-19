//go:build linux

package learnwatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/store"
)

type fakeEngine struct {
	mu       sync.Mutex
	calls    []int
	respond  func(c learn.Candidate) (learn.Outcome, error)
	onSubmit func(c learn.Candidate)
}

func (e *fakeEngine) Submit(_ context.Context, c learn.Candidate) (learn.Outcome, error) {
	e.mu.Lock()
	e.calls = append(e.calls, c.UID)
	respond, hook := e.respond, e.onSubmit
	e.mu.Unlock()
	if hook != nil {
		hook(c)
	}
	if respond != nil {
		return respond(c)
	}
	return learn.Outcome{Ref: c.Ref, Committed: []uint64{1}}, nil
}

func (e *fakeEngine) submitted() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.calls)
}

type watchFixture struct {
	t        *testing.T
	accounts []Account
	db       *store.DB
	engine   *fakeEngine
	cfg      WatcherConfig
	w        *Watcher
	now      time.Time
	submit   bool
	mu       sync.Mutex
	events   []string
}

// newWatch builds n opted-in accounts with UIDs 1001.. whose homes the
// test process owns.
func newWatch(t *testing.T, n int) *watchFixture {
	t.Helper()
	old := ownerUID
	t.Cleanup(func() { ownerUID = old })
	ownerUID = func(Account) int { return os.Getuid() }
	f := &watchFixture{t: t, engine: &fakeEngine{}, now: t0, submit: true}
	root := t.TempDir()
	var users []string
	var pw strings.Builder
	for i := range n {
		name := fmt.Sprintf("tenant%d", i+1)
		home := filepath.Join(root, name)
		for _, d := range []string{"mail/.spam/cur", "mail/.spam/new"} {
			if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		writeMsg(t, filepath.Join(home, ".spamassassinenable"), nil)
		uid := 1001 + i
		f.accounts = append(f.accounts, Account{Name: name, UID: uid, GID: uid, Home: home})
		users = append(users, name)
		fmt.Fprintf(&pw, "%s:x:%d:%d::%s:/bin/bash\n", name, uid, uid, home)
	}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f.db = db
	f.cfg = WatcherConfig{
		Source:     fakeSource{users: users, passwd: pw.String()},
		GlobalPath: filepath.Join(root, "global_spamassassin_enable"),
		State:      NewState(db, func() time.Time { return f.clock() }),
		Engine:     f.engine,
		Now:        f.clock,
		CanSubmit:  func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.submit },
	}
	f.w = NewWatcher(f.cfg)
	oldHook := turnHook
	t.Cleanup(func() { turnHook = oldHook })
	turnHook = func(uid int, kind string) {
		f.mu.Lock()
		f.events = append(f.events, fmt.Sprintf("%s%d", kind, uid))
		f.mu.Unlock()
	}
	return f
}

func (f *watchFixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *watchFixture) restart() { f.w = NewWatcher(f.cfg) }

func (f *watchFixture) pass() PassReport {
	f.t.Helper()
	f.mu.Lock()
	f.events = nil
	f.mu.Unlock()
	return f.w.Pass(context.Background())
}

func (f *watchFixture) trace() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}

var msgSeq int

func (f *watchFixture) deliver(i int, sub string, n int, body string) {
	f.t.Helper()
	for range n {
		msgSeq++
		name := fmt.Sprintf("%d.M%d.host", 1700000000+msgSeq, msgSeq)
		if sub == "cur" {
			name += ":2,S"
		}
		writeMsg(f.t, filepath.Join(f.accounts[i].Home, "mail/.spam", sub, name), []byte(body))
	}
}

const spamBody = "Subject: offer\r\n\r\nbuy now"

func countUID(uids []int, uid int) int {
	n := 0
	for _, u := range uids {
		if u == uid {
			n++
		}
	}
	return n
}

func (f *watchFixture) pending(i int) int {
	f.t.Helper()
	n := 0
	k := FolderKey{UID: f.accounts[i].UID, Folder: ".spam"}
	if err := f.cfg.State.View(func(tx StateTx) error {
		items, err := tx.Pending(k)
		n = len(items)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestSchedulerTwentyAttemptsPerAccount(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 30, spamBody)
	if r := f.pass(); r.Submitted != MaxAttempts || len(f.engine.submitted()) != MaxAttempts {
		t.Fatalf("first pass submitted %d (report %+v)", len(f.engine.submitted()), r)
	}
	f.pass()
	if got := len(f.engine.submitted()); got != 30 {
		t.Fatalf("two passes submitted %d", got)
	}
}

func TestSchedulerRoundRobin(t *testing.T) {
	f := newWatch(t, 2)
	f.cfg.Chunk = 2
	f.restart()
	f.pass()
	f.deliver(0, "new", 6, spamBody)
	f.deliver(1, "new", 6, spamBody)
	f.pass()
	if got := f.engine.submitted(); fmt.Sprint(got[:6]) != "[1001 1002 1001 1002 1001 1002]" {
		t.Fatalf("submit order %v", got)
	}
	var chunks []string
	for _, e := range f.trace() {
		if strings.HasPrefix(e, "chunk") {
			chunks = append(chunks, e)
		}
	}
	if len(chunks) < 4 || fmt.Sprint(chunks[:4]) != "[chunk1001 chunk1002 chunk1001 chunk1002]" {
		t.Fatalf("discovery order %v", chunks)
	}
}

func TestSchedulerFloodDoesNotStarveSecondAccount(t *testing.T) {
	f := newWatch(t, 2)
	f.pass()
	cur := filepath.Join(f.accounts[0].Home, "mail/.spam/cur")
	for i := range 51217 {
		writeMsg(t, filepath.Join(cur, fmt.Sprintf("%d.M%d.flood:2,S", 1600000000+i, i)), nil)
	}
	f.deliver(1, "new", 1, spamBody)
	f.pass()
	if countUID(f.engine.submitted(), 1002) != 1 {
		t.Fatalf("second account's report not submitted: %v", f.engine.submitted())
	}
	trace := f.trace()
	submit := slices.Index(trace, "submit1002")
	floodChunks := 0
	for _, e := range trace[:submit] {
		if e == "chunk1001" {
			floodChunks++
		}
	}
	if submit < 0 || floodChunks > 2 {
		t.Fatalf("second account waited for %d flood chunks", floodChunks)
	}
}

func TestSchedulerRetryQueueDoesNotStarveFresh(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 25, spamBody)
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		return learn.Outcome{Ref: c.Ref, Deferred: true}, nil
	}
	f.pass()
	if got := len(f.engine.submitted()); got != MaxAttempts {
		t.Fatalf("first pass attempted %d", got)
	}
	f.deliver(0, "new", 5, "Subject: fresh\r\n\r\nfresh")
	var fresh int
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		if strings.Contains(string(c.Snapshot), "fresh") {
			fresh++
			return learn.Outcome{Ref: c.Ref, Committed: []uint64{2}}, nil
		}
		return learn.Outcome{Ref: c.Ref, Deferred: true}, nil
	}
	f.pass()
	if fresh != 5 {
		t.Fatalf("fresh candidates attempted %d of 5 behind a retry queue", fresh)
	}
}

func TestSchedulerFailedItemOncePerPass(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
		return learn.Outcome{Deferred: true}, errors.New("backend down")
	}
	f.pass()
	if got := len(f.engine.submitted()); got != 1 {
		t.Fatalf("one failing item attempted %d times in one pass", got)
	}
	f.pass()
	if got := len(f.engine.submitted()); got != 2 {
		t.Fatalf("failing item not retried next pass: %d", got)
	}
	if f.pending(0) != 1 {
		t.Fatal("failed item left the pending set")
	}
}

// cutAfter ends the pass deadline once n turns have run.
func (f *watchFixture) cutAfter(n int) {
	turns := 0
	turnHook = func(uid int, kind string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, fmt.Sprintf("%s%d", kind, uid))
		if kind == "turn" {
			if turns++; turns == n {
				f.now = f.now.Add(PassDeadline + time.Second)
			}
		}
	}
}

func TestSchedulerCursorSurvivesRestart(t *testing.T) {
	f := newWatch(t, 3)
	f.pass()
	f.cutAfter(1)
	if r := f.pass(); !r.Unfinished {
		t.Fatalf("cut pass reported finished: %+v", r)
	}
	if tr := f.trace(); !slices.Contains(tr, "turn1001") || slices.Contains(tr, "turn1002") {
		t.Fatalf("cut pass trace %v", tr)
	}
	f.restart()
	f.cutAfter(1)
	f.pass()
	if tr := f.trace(); !slices.Contains(tr, "turn1002") || slices.Contains(tr, "turn1001") {
		t.Fatalf("restarted pass did not resume at the next account: %v", tr)
	}
}

func TestSchedulerPassDeadlineYields(t *testing.T) {
	f := newWatch(t, 2)
	f.pass()
	f.deliver(0, "new", 3, spamBody)
	f.deliver(1, "new", 3, spamBody)
	f.cutAfter(3)
	r := f.pass()
	if !r.Unfinished || len(f.engine.submitted()) >= 6 {
		t.Fatalf("deadline ignored: report %+v, %d submitted", r, len(f.engine.submitted()))
	}
	turnHook = func(int, string) {}
	if r = f.pass(); r.Unfinished {
		t.Fatalf("second pass unfinished: %+v", r)
	}
	if got := f.engine.submitted(); countUID(got, 1001) != 3 || countUID(got, 1002) != 3 {
		t.Fatalf("submitted %v", got)
	}
}

func TestSchedulerOneActivePass(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	entered, release := make(chan struct{}), make(chan struct{})
	f.engine.onSubmit = func(learn.Candidate) {
		close(entered)
		<-release
	}
	done := make(chan PassReport)
	go func() { done <- f.w.Pass(context.Background()) }()
	<-entered
	if r := f.w.Pass(context.Background()); !r.Busy {
		t.Fatalf("second concurrent pass ran: %+v", r)
	}
	close(release)
	if r := <-done; r.Busy || r.Submitted != 1 {
		t.Fatalf("first pass %+v", r)
	}
}

func TestSchedulerRechecksOptInBeforeRead(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 2, spamBody)
	f.engine.onSubmit = func(learn.Candidate) {
		_ = os.Remove(filepath.Join(f.accounts[0].Home, ".spamassassinenable"))
	}
	f.pass()
	if got := len(f.engine.submitted()); got != 1 {
		t.Fatalf("submitted %d after the account opted out", got)
	}
	if f.pending(0) != 0 {
		t.Fatal("opt-out kept unsent work")
	}
}

func TestSchedulerAccountAllowancePausesOnlyThatAccount(t *testing.T) {
	f := newWatch(t, 2)
	f.cfg.SeenAllowance = 5
	f.restart()
	f.pass()
	f.deliver(0, "new", 8, spamBody)
	f.deliver(1, "new", 1, spamBody)
	r := f.pass()
	got := f.engine.submitted()
	if countUID(got, 1001) != 5 || countUID(got, 1002) != 1 {
		t.Fatalf("submitted %v", got)
	}
	if r.Skipped[learn.SkipAccountCapacity] == 0 {
		t.Fatalf("allowance not reported: %+v", r)
	}
}

func TestSchedulerOptOutCancelsUnsent(t *testing.T) {
	f := newWatch(t, 2)
	f.pass()
	f.submit = false
	f.deliver(0, "new", 3, spamBody)
	f.deliver(1, "new", 1, spamBody)
	f.pass()
	if f.pending(0) != 3 || len(f.engine.submitted()) != 0 {
		t.Fatalf("discovery without submission: %d pending, %v", f.pending(0), f.engine.submitted())
	}
	if err := os.Remove(filepath.Join(f.accounts[0].Home, ".spamassassinenable")); err != nil {
		t.Fatal(err)
	}
	f.submit = true
	r := f.pass()
	if got := f.engine.submitted(); countUID(got, 1001) != 0 || countUID(got, 1002) != 1 {
		t.Fatalf("submitted %v", got)
	}
	if f.pending(0) != 0 || r.Skipped[SkipOptedOut] != 1 {
		t.Fatalf("opt-out: %d pending, report %+v", f.pending(0), r)
	}
}

func TestSchedulerOutcomeStatuses(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, "X-Spam-Status: Yes, score=9\r\n\r\ntagged")
	f.deliver(0, "new", 1, " bad\r\n\r\nmalformed")
	f.deliver(0, "new", 1, "Subject: x\r\n\r\ndup")
	f.deliver(0, "new", 1, "Subject: x\r\n\r\ncapacity")
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		switch {
		case strings.Contains(string(c.Snapshot), "dup"):
			return learn.Outcome{Duplicates: []uint64{3}}, nil
		case strings.Contains(string(c.Snapshot), "capacity"):
			return learn.Outcome{Skips: []learn.Skip{{Reason: learn.SkipAccountCapacity}}}, nil
		}
		return learn.Outcome{Committed: []uint64{1}}, nil
	}
	r := f.pass()
	if len(f.engine.submitted()) != 2 {
		t.Fatalf("submitted %d; tagged or malformed mail reached the engine", len(f.engine.submitted()))
	}
	if r.Skipped["tagged"] != 1 || r.Skipped["malformed"] != 1 || r.Submitted != 1 {
		t.Fatalf("report %+v", r)
	}
	if f.pending(0) != 1 {
		t.Fatalf("%d pending; a capacity skip must stay pending", f.pending(0))
	}
}

func TestSchedulerForgetsPendingOfVanishedFolder(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.submit = false
	f.deliver(0, "new", 2, spamBody)
	f.pass()
	if f.pending(0) != 2 {
		t.Fatalf("%d pending before the folder vanished", f.pending(0))
	}
	if err := os.RemoveAll(filepath.Join(f.accounts[0].Home, "mail/.spam")); err != nil {
		t.Fatal(err)
	}
	f.submit = true
	f.pass()
	if len(f.engine.submitted()) != 0 || f.pending(0) != 0 {
		t.Fatalf("vanished folder: %d submitted, %d pending", len(f.engine.submitted()), f.pending(0))
	}
}
