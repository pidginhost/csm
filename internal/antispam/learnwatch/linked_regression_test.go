//go:build linux

package learnwatch

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/store"
)

// Old pending work must not turn the link/unlink window of a move out of
// Spam into a report, even if another mailbox already shares the inode.
func TestSchedulerPendingMoveOutOfSpam(t *testing.T) {
	for _, linked := range []bool{false, true} {
		for _, duringAttempt := range []bool{false, true} {
			t.Run(fmt.Sprintf("linked=%t/during_attempt=%t", linked, duringAttempt), func(t *testing.T) {
				f := newWatch(t, 1)
				f.pass()
				home := f.accounts[0].Home
				msg := filepath.Join(home, "mail/.spam/cur/message:2,S")
				writeMsg(t, msg, []byte(spamBody))
				if linked {
					if err := os.Link(msg, filepath.Join(home, "mail/shared")); err != nil {
						t.Fatal(err)
					}
				}
				f.submit = false
				if r := f.pass(); r.Pending != 1 || len(f.engine.submitted()) != 0 {
					t.Fatalf("did not queue report: %+v", r)
				}
				f.now = f.now.Add(PassEvery)
				f.submit = true
				started := false
				startMove := func() {
					if err := os.Link(msg, filepath.Join(home, "mail/inbox")); err != nil {
						t.Fatal(err)
					}
					started = true
				}
				if duringAttempt {
					turnHook = func(_ int, kind string) {
						if kind == "attempt" && !started {
							startMove()
						}
					}
				} else {
					startMove()
					// Relisting must not hide the metadata change either.
					if err := os.Chtimes(filepath.Dir(msg), f.now, f.now); err != nil {
						t.Fatal(err)
					}
				}
				if r := f.pass(); !started || r.Submitted != 0 || r.Pending != 1 || len(f.engine.submitted()) != 0 {
					t.Fatalf("move out of Spam was reported: started=%t report=%+v", started, r)
				}
				if err := os.Remove(msg); err != nil {
					t.Fatal(err)
				}
				f.now = f.now.Add(PassEvery)
				f.restart()
				if r := f.pass(); r.Pending != 0 || f.pending(0) != 0 || len(f.engine.submitted()) != 0 {
					t.Fatalf("completed move out of Spam was reported: %+v", r)
				}
			})
		}
	}
}

func TestSchedulerLinkedChangeRestartsSettleWait(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	home := f.accounts[0].Home
	msg := filepath.Join(home, "mail/.spam/cur/message:2,S")
	writeMsg(t, msg, []byte(spamBody))
	if err := os.Link(msg, filepath.Join(home, "mail/shared")); err != nil {
		t.Fatal(err)
	}
	if r := f.pass(); r.Pending != 1 || len(f.engine.submitted()) != 0 {
		t.Fatalf("did not queue linked report: %+v", r)
	}
	f.now = f.now.Add(PassEvery)
	if err := os.Link(msg, filepath.Join(home, "mail/another")); err != nil {
		t.Fatal(err)
	}
	if r := f.pass(); r.Pending != 1 || len(f.engine.submitted()) != 0 {
		t.Fatalf("changed links did not restart settle wait: %+v", r)
	}
	f.now = f.now.Add(PassEvery - time.Second)
	f.restart()
	if r := f.pass(); r.Pending != 1 || len(f.engine.submitted()) != 0 {
		t.Fatalf("restart lost settle wait: %+v", r)
	}
	f.now = f.now.Add(time.Second)
	if r := f.pass(); r.Submitted != 1 || r.Pending != 0 || len(f.engine.submitted()) != 1 {
		t.Fatalf("stable linked report did not resume: %+v", r)
	}
}

func TestSchedulerLinkedSettleWriteFailureKeepsReport(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	home := f.accounts[0].Home
	msg := filepath.Join(home, "mail/.spam/cur/message:2,S")
	writeMsg(t, msg, []byte(spamBody))
	if err := os.Link(msg, filepath.Join(home, "mail/shared")); err != nil {
		t.Fatal(err)
	}
	f.pass()
	f.now = f.now.Add(PassEvery)
	if err := os.Link(msg, filepath.Join(home, "mail/another")); err != nil {
		t.Fatal(err)
	}
	old := afterRead
	t.Cleanup(func() { afterRead = old })
	failed := false
	afterRead = func() {
		f.cfg.State.db = rollbackKV{kv: f.db, fail: func(store.LearnTx) bool {
			failed = true
			return true
		}}
	}
	r := f.pass()
	if !failed || !r.Unfinished || r.Skipped[SkipStateUnavailable] == 0 || r.Pending != 1 || f.pending(0) != 1 || len(f.engine.submitted()) != 0 {
		t.Fatalf("failed settle write lost the report: failed=%t report=%+v", failed, r)
	}
	afterRead, f.cfg.State.db = old, f.db
	f.restart()
	if r = f.pass(); r.Pending != 1 || len(f.engine.submitted()) != 0 {
		t.Fatalf("failed settle write counted toward wait: %+v", r)
	}
	f.now = f.now.Add(PassEvery)
	if r = f.pass(); r.Pending != 0 || r.Submitted != 1 || len(f.engine.submitted()) != 1 {
		t.Fatalf("settled report did not recover: %+v", r)
	}
}

// The watcher forwards every folder's candidate under the account UID.
// The engine's per-UID cluster vote guard must receive that same identity
// for copies in another Spam folder or another mailbox of the account.
func TestSchedulerLinkedCopiesKeepAccountIdentity(t *testing.T) {
	for _, other := range []string{"mail/.Junk", "mail/example.com/user/.spam"} {
		t.Run(other, func(t *testing.T) {
			f := newWatch(t, 1)
			f.addMailbox(0, "example.com", "user")
			home := f.accounts[0].Home
			for _, sub := range Subdirs {
				if err := os.MkdirAll(filepath.Join(home, other, sub), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			f.pass()
			msg := filepath.Join(home, "mail/.spam/cur/message:2,S")
			writeMsg(t, msg, []byte(spamBody))
			if err := os.Link(msg, filepath.Join(home, other, "cur/message:2,S")); err != nil {
				t.Fatal(err)
			}
			f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
				if c.UID != f.accounts[0].UID || string(c.Snapshot) != spamBody {
					t.Errorf("linked copy changed account or content: UID=%d", c.UID)
				}
				return learn.Outcome{}, nil
			}
			if r := f.pass(); r.Pending != 2 || len(f.engine.submitted()) != 0 {
				t.Fatalf("linked copies did not wait: %+v", r)
			}
			f.now = f.now.Add(PassEvery)
			if r := f.pass(); r.Pending != 0 || r.Submitted != 2 || len(f.engine.submitted()) != 2 {
				t.Fatalf("linked copies did not reach the vote guard: %+v", r)
			}
			f.restart()
			if r := f.pass(); r.Submitted != 0 || len(f.engine.submitted()) != 2 {
				t.Fatalf("submitted copies replayed: %+v", r)
			}
		})
	}
}

func TestSchedulerLinkedLegacyStateWaitsForStableVersion(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	home := f.accounts[0].Home
	msg := filepath.Join(home, "mail/.spam/cur/message:2,S")
	writeMsg(t, msg, []byte(spamBody))
	if err := os.Link(msg, filepath.Join(home, "mail/shared")); err != nil {
		t.Fatal(err)
	}
	f.pass()
	if err := f.cfg.State.Update(func(tx StateTx) error {
		k := FolderKey{UID: f.accounts[0].UID, Folder: ".spam"}
		e, found, err := tx.Seen(k, "message")
		if err != nil || !found {
			t.Fatalf("missing pending report: found=%t error=%v", found, err)
		}
		e.StableSince = time.Time{}
		return tx.putSeen(k, "message", e)
	}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(PassEvery)
	f.restart()
	if r := f.pass(); r.Pending != 1 || len(f.engine.submitted()) != 0 {
		t.Fatalf("legacy queue age bypassed settling: %+v", r)
	}
	f.now = f.now.Add(PassEvery)
	if r := f.pass(); r.Pending != 0 || r.Submitted != 1 || len(f.engine.submitted()) != 1 {
		t.Fatalf("legacy linked report did not resume: %+v", r)
	}
}

func TestLinkedSettleReplacementGetsOwnErrorAllowance(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	f.observe(t, spamKey, "message", meta(200))
	f.do(t, func(tx StateTx) error {
		_, err := tx.Fail(spamKey, "message")
		return err
	})
	f.now = f.now.Add(PassEvery)
	replacement := meta(201)
	replacement.Nlink = 2
	f.do(t, func(tx StateTx) error {
		settled, err := tx.LinkedSettled(spamKey, "message", replacement)
		if settled {
			t.Error("replacement inherited the previous inode's settle wait")
		}
		return err
	})
	e, found := f.entry(t, spamKey, "message")
	if !found || e.Ino != replacement.Ino || e.Errors != 0 || e.Attempts != 0 || !e.FirstSeen.Equal(f.now) {
		t.Fatalf("replacement inherited previous retry history: %+v, found=%t", e, found)
	}
}
