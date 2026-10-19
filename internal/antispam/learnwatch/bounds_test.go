//go:build linux

package learnwatch

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/store"
)

// countingKV counts write transactions; each one is an fsync of csm.db.
type countingKV struct {
	*store.DB
	updates atomic.Int64
}

func (c *countingKV) LearnUpdate(fn func(store.LearnTx) error) error {
	c.updates.Add(1)
	return c.DB.LearnUpdate(fn)
}

// addMailbox gives account i a domain mailbox with a Spam folder.
func (f *watchFixture) addMailbox(i int, domain, box string) {
	f.t.Helper()
	home := f.accounts[i].Home
	p := filepath.Join(home, "etc", domain, "passwd")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		f.t.Fatal(err)
	}
	old, _ := os.ReadFile(p)
	writeMsg(f.t, p, append(old, []byte(box+":x:1:1::/x:/x\n")...))
	for _, sub := range []string{"cur", "new"} {
		if err := os.MkdirAll(filepath.Join(home, "mail", domain, box, ".spam", sub), 0o700); err != nil {
			f.t.Fatal(err)
		}
	}
}

func TestSchedulerUnchangedPassWritesNothing(t *testing.T) {
	f := newWatch(t, 3)
	for i := range f.accounts {
		f.addMailbox(i, "example.com", "user")
	}
	counter := &countingKV{DB: f.db}
	f.cfg.State = NewState(counter, f.clock)
	f.restart()
	for range 3 {
		f.pass()
	}
	counter.updates.Store(0)
	if r := f.pass(); r.Unfinished {
		t.Fatalf("pass %+v", r)
	}
	if n := counter.updates.Load(); n != 0 {
		t.Fatalf("a pass over unchanged folders made %d write transactions", n)
	}
}

func TestSchedulerBoundsFolderOpensPerTurn(t *testing.T) {
	f := newWatch(t, 2)
	for j := range 40 {
		f.addMailbox(0, fmt.Sprintf("d%02d.example.com", j), "user")
	}
	f.cfg.FolderOpens = 8
	f.restart()
	f.pass()
	f.deliver(1, "new", 1, spamBody)
	f.pass()
	opens := 0
	trace := f.trace()
	for _, e := range trace {
		switch e {
		case "turn1001", "turn1002":
			opens = 0
		case "open1001":
			if opens++; opens > 8 {
				t.Fatalf("one turn opened more than 8 folders: %v", trace)
			}
		}
	}
	submit := slices.Index(trace, "submit1002")
	last := -1
	for i, e := range trace {
		if e == "open1001" {
			last = i
		}
	}
	if submit < 0 || submit > last {
		t.Fatalf("the second account waited for all of the first account's folders: submit at %d, last open at %d", submit, last)
	}
}

func TestParseMailboxPasswdCountsEmptyLines(t *testing.T) {
	data := append(bytes.Repeat([]byte("\n"), 20000), "user:x:1:1::/x:/x\n"...)
	names, skips := ParseMailboxPasswd(data, MaxMailboxes)
	if len(names) != 0 || !slices.Equal(skips, []Skip{{Reason: SkipMailboxLimit}}) {
		t.Fatalf("names %v, skips %+v", names, skips)
	}
}

func TestMailboxesBoundAccountBytes(t *testing.T) {
	a, h := openTenant(t)
	line := "user:" + strings.Repeat("x", 1000) + "\n"
	size := MaxMailboxListBytes - 100
	file := bytes.Repeat([]byte(line), size/len(line))
	file = append(file, bytes.Repeat([]byte("#"), size-len(file)-1)...)
	file = append(file, '\n')
	for j := range 6 {
		writeFile(t, filepath.Join(a.Home, fmt.Sprintf("etc/d%d.example.com/passwd", j)), file)
	}
	got, skips, err := h.Mailboxes()
	if err != nil {
		t.Fatal(err)
	}
	var domains []string
	for _, m := range got[1:] {
		domains = append(domains, m.Domain)
	}
	if fmt.Sprint(domains) != "[d0.example.com d1.example.com d2.example.com d3.example.com]" {
		t.Fatalf("served %v", domains)
	}
	if !slices.Contains(skips, Skip{Reason: SkipMailboxLimit}) {
		t.Fatalf("skips %+v", skips)
	}
}

func TestPruneAbsentFoldersAfter90Days(t *testing.T) {
	f := newWatch(t, 1)
	f.addMailbox(0, "example.com", "gone")
	f.pass()
	gone := filepath.Join(f.accounts[0].Home, "mail/example.com/gone/.spam/cur")
	writeMsg(t, filepath.Join(gone, "1.M1.host:2,S"), []byte(spamBody))
	f.deliver(0, "cur", 1, spamBody)
	f.pass()
	before := f.seenCount()
	if before != 2 {
		t.Fatalf("%d seen entries before removal", before)
	}
	if err := os.RemoveAll(filepath.Join(f.accounts[0].Home, "etc/example.com")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(f.accounts[0].Home, "mail/example.com")); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.now = t0.Add(SeenRetention + 48*time.Hour)
	f.mu.Unlock()
	f.pass()
	if n := f.seenCount(); n != 1 {
		t.Fatalf("%d seen entries after the mailbox was gone for 90 days; want the present one only", n)
	}
}

func (f *watchFixture) seenCount() int {
	f.t.Helper()
	var n int
	if err := f.cfg.State.View(func(tx StateTx) (err error) {
		n, err = tx.CountSeen(f.accounts[0].UID)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestSchedulerBackendErrorStopsSubmissionsForPass(t *testing.T) {
	for _, outcomeError := range []bool{false, true} {
		t.Run(fmt.Sprintf("outcome=%t", outcomeError), func(t *testing.T) {
			f := newWatch(t, 2)
			f.pass()
			f.deliver(0, "new", 2, spamBody)
			f.deliver(1, "new", 2, spamBody)
			f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
				err := errors.New("controller timed out")
				if outcomeError {
					return learn.Outcome{Err: err}, nil
				}
				return learn.Outcome{}, err
			}
			r := f.pass()
			if got := len(f.engine.submitted()); got != 1 {
				t.Fatalf("a failing backend took %d requests in one pass", got)
			}
			if r.Pending != 4 {
				t.Fatalf("discovery stopped with submissions: %+v", r)
			}
			f.engine.respond = nil
			f.pass()
			if got := len(f.engine.submitted()); got != 5 {
				t.Fatalf("after recovery %d requests in total", got)
			}
		})
	}
}

func TestSchedulerCapacityCountsAccountsOnce(t *testing.T) {
	f := newWatch(t, 1)
	f.cfg.SeenAllowance = 1
	f.restart()
	f.pass()
	f.deliver(0, "new", 2, spamBody)
	f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
		return learn.Outcome{Skips: []learn.Skip{{Reason: learn.SkipAccountCapacity}}}, nil
	}
	r := f.pass()
	if n := r.Skipped[learn.SkipAccountCapacity]; n != 1 {
		t.Fatalf("one account hit both allowances but was counted %d times", n)
	}
}

func TestSchedulerRejectedMessageDoesNotStopOtherAccounts(t *testing.T) {
	f := newWatch(t, 2)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	f.deliver(1, "new", 1, spamBody)
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		if c.UID == f.accounts[0].UID {
			_, err := learn.ParseInspection([]byte(`{"results":{},"errors":["too many digests"],"complete":false,"distinct":65}`), nil)
			if err == nil {
				t.Fatal("rejected message accepted as an inspection")
			}
			return learn.Outcome{Err: fmt.Errorf("%w: %w", learn.ErrReadFailed, err)}, nil
		}
		return learn.Outcome{Committed: []uint64{1}}, nil
	}
	if r := f.pass(); r.Submitted != 1 || r.Pending != 1 || countUID(f.engine.submitted(), 1002) != 1 {
		t.Fatalf("one rejected message stopped other accounts: %+v, calls %v", r, f.engine.submitted())
	}
}

func TestSchedulerPrunePreservesUncheckedFolders(t *testing.T) {
	for _, block := range []string{"home", "mailboxes", "folder"} {
		t.Run(block, func(t *testing.T) {
			f := newWatch(t, 2)
			f.addMailbox(0, "example.com", "user")
			f.pass()
			f.submit = false
			mail := filepath.Join(f.accounts[0].Home, "mail/example.com/user/.spam")
			writeMsg(t, filepath.Join(mail, "new/report"), []byte(spamBody))
			f.pass()
			f.now = t0.Add(SeenRetention + 48*time.Hour)
			var path string
			switch block {
			case "home":
				path = f.accounts[0].Home
			case "mailboxes":
				path = filepath.Join(f.accounts[0].Home, "etc/example.com/passwd")
			case "folder":
				path = mail
			}
			if err := os.Rename(path, path+"-saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+"-saved", path); err != nil {
				t.Fatal(err)
			}
			// A different, deleted account can still be pruned while this
			// account's inventory cannot establish absence.
			f.cfg.Source = fakeSource{users: []string{f.accounts[0].Name}, passwd: fmt.Sprintf("%s:x:1001:1001::%s:/bin/bash\n", f.accounts[0].Name, f.accounts[0].Home)}
			f.restart()
			if r := f.pass(); !r.Unfinished {
				t.Fatalf("unchecked folder reported complete: %+v", r)
			}
			k := FolderKey{UID: 1001, Domain: "example.com", Box: "user", Folder: ".spam"}
			if err := f.cfg.State.View(func(tx StateTx) error {
				items, err := tx.Pending(k)
				if err != nil {
					return err
				}
				if len(items) != 1 || items[0].Base != "report" {
					t.Errorf("unchecked folder lost pending report: %+v", items)
				}
				_, found, err := tx.Folder(FolderKey{UID: 1002, Folder: ".spam"})
				if found {
					t.Error("deleted account was not pruned")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSchedulerPrunePreservesUnresolvedAccounts(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.submit = false
	f.deliver(0, "new", 1, spamBody)
	f.pass()
	f.now = t0.Add(SeenRetention + 48*time.Hour)
	f.cfg.Source = fakeSource{users: []string{f.accounts[0].Name}}
	f.restart()
	if r := f.pass(); r.Skipped[SkipNoPasswd] != 1 {
		t.Fatalf("missing passwd entry was not reported: %+v", r)
	}
	if n := f.pending(0); n != 1 {
		t.Fatalf("unresolved account lost pending report: %d", n)
	}
}

// A message that times out the controller every time stops one pass at a
// time, rotates the next pass past its account, and is given up after
// MaxEntryErrors errors.
func TestSchedulerRepeatedBackendErrorEntryIsBounded(t *testing.T) {
	f := newWatch(t, 2)
	f.pass()
	f.deliver(0, "new", 1, "Subject: x\r\n\r\nslow")
	f.deliver(1, "new", 1, spamBody)
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		if strings.Contains(string(c.Snapshot), "slow") {
			return learn.Outcome{}, fmt.Errorf("%w: %w", learn.ErrReadFailed, learn.ErrUncertain)
		}
		return learn.Outcome{Committed: []uint64{1}}, nil
	}
	f.pass()
	f.pass()
	if got := countUID(f.engine.submitted(), 1002); got != 1 {
		t.Fatalf("the next pass did not rotate past the failing account: %v", f.engine.submitted())
	}
	for range MaxEntryErrors + 2 {
		f.pass()
	}
	if got := countUID(f.engine.submitted(), 1001); got != MaxEntryErrors {
		t.Fatalf("a failing entry was tried %d times", got)
	}
	if err := f.cfg.State.View(func(tx StateTx) (err error) {
		items, err := tx.Pending(FolderKey{UID: 1001, Folder: ".spam"})
		if len(items) != 0 {
			t.Errorf("failing entry still pending: %+v", items)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
