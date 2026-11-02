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

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/dovecot"
	"github.com/pidginhost/csm/internal/antispam/learn"
)

// fakeDovecot serves a Snapshot and the identity-only listing it implies.
type fakeDovecot struct {
	mu        sync.Mutex
	snap      dovecot.Snapshot
	err       error
	users     []string
	usersErr  error
	snapshots int
	listings  int
}

func (d *fakeDovecot) Snapshot(context.Context) (dovecot.Snapshot, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.snapshots++
	if d.err != nil {
		return dovecot.Snapshot{}, d.err
	}
	s := d.snap
	s.Mailboxes, s.Skips = slices.Clone(s.Mailboxes), slices.Clone(s.Skips)
	return s, nil
}

func (d *fakeDovecot) Users(context.Context) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.listings++
	if d.usersErr != nil {
		return nil, d.usersErr
	}
	if d.users != nil {
		return slices.Clone(d.users), nil
	}
	var names []string
	for _, m := range d.snap.Mailboxes {
		names = append(names, m.User)
	}
	for _, s := range d.snap.Skips {
		if s.User != "" {
			names = append(names, s.User)
		}
	}
	slices.Sort(names)
	return names, nil
}

// mailUID is the userdb uid of the test mailboxes; foreignUID's files
// belong to someone else.
const (
	mailUID    = 5000
	foreignUID = 5001
)

type postfixFixture struct {
	*watchFixture
	dove  *fakeDovecot
	root  string
	boxes map[string]dovecot.DovecotMailbox
}

// newPostfixWatch builds a Postfix watcher over Dovecot users with one
// Maildir++ Junk folder each. Domainless users get uid mailUID+2. Every
// mailbox uid, 0 included, maps to the test process; foreignUID and the
// reporter ids own nothing.
func newPostfixWatch(t *testing.T, mode string, users ...string) *postfixFixture {
	t.Helper()
	f := &postfixFixture{watchFixture: newWatch(t, 0), dove: &fakeDovecot{}, root: t.TempDir(), boxes: map[string]dovecot.DovecotMailbox{}}
	ownerUID = func(a Account) int {
		if a.UID == foreignUID || a.UID >= minReporterID {
			return os.Getuid() + 1
		}
		return os.Getuid()
	}
	for _, u := range users {
		uid := mailUID
		if !strings.Contains(u, "@") {
			uid = mailUID + 2
		}
		f.add(u, uid)
	}
	f.cfg.Postfix = &Postfix{Dovecot: f.dove, Reporter: mode}
	f.restart()
	return f
}

func (f *postfixFixture) add(user string, uid int) {
	f.t.Helper()
	local, domain, _ := strings.Cut(user, "@")
	home := filepath.Join(f.root, domain, local)
	junk := filepath.Join(home, "Maildir", ".Junk")
	for _, sub := range Subdirs {
		if err := os.MkdirAll(filepath.Join(junk, sub), 0o700); err != nil {
			f.t.Fatal(err)
		}
	}
	m := dovecot.DovecotMailbox{User: user, Domain: domain, UID: uid, GID: uid, Home: home, Junk: []string{junk}}
	f.boxes[user] = m
	f.dove.snap.Mailboxes = append(f.dove.snap.Mailboxes, m)
	f.dove.snap.Complete = true
}

// skip turns user into a skipped one, as a failed lookup does.
func (f *postfixFixture) skip(user, reason string) {
	f.dove.mu.Lock()
	defer f.dove.mu.Unlock()
	f.dove.snap.Mailboxes = slices.DeleteFunc(f.dove.snap.Mailboxes, func(m dovecot.DovecotMailbox) bool { return m.User == user })
	f.dove.snap.Skips = append(f.dove.snap.Skips, dovecot.Skip{User: user, Reason: reason})
}

func (f *postfixFixture) remove(user string) {
	f.dove.mu.Lock()
	defer f.dove.mu.Unlock()
	f.dove.snap.Mailboxes = slices.DeleteFunc(f.dove.snap.Mailboxes, func(m dovecot.DovecotMailbox) bool { return m.User == user })
}

func (f *postfixFixture) junk(user, sub string, n int, body string) {
	f.t.Helper()
	for range n {
		msgSeq++
		name := fmt.Sprintf("%d.M%d.host", 1700000000+msgSeq, msgSeq)
		if sub == "cur" {
			name += ":2,S"
		}
		writeMsg(f.t, filepath.Join(f.boxes[user].Junk[0], sub, name), []byte(body))
	}
}

func (f *postfixFixture) id(user string) int {
	m := f.boxes[user]
	if m.Domain == "" {
		return m.UID
	}
	return ReporterID(f.cfg.Postfix.Reporter, m.Domain, m.User)
}

// junkState reports whether user's Junk folder has watcher state.
func (f *postfixFixture) junkState(user string) bool {
	f.t.Helper()
	m := f.boxes[user]
	var ok bool
	if err := f.cfg.State.View(func(tx StateTx) (e error) {
		_, ok, e = tx.Folder(FolderKey{UID: f.id(user), Domain: m.Domain, Box: m.User, Folder: m.Junk[0]})
		return e
	}); err != nil {
		f.t.Fatal(err)
	}
	return ok
}

func TestSchedulerPostfixLearnsFromJunk(t *testing.T) {
	f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com", "bob@example.com")
	f.junk("alice@example.com", "cur", 1, spamBody) // there before learning: never a report
	f.pass()
	f.junk("alice@example.com", "cur", 1, spamBody) // an IMAP move into Junk
	f.junk("bob@example.com", "new", 1, spamBody)
	r := f.pass()
	domain := ReporterID(antispam.ReporterDomain, "example.com", "")
	if got := f.engine.submitted(); !slices.Equal(got, []int{domain, domain}) || r.Submitted != 2 || r.Accounts != 1 {
		t.Fatalf("submitted %v, report %+v", got, r)
	}
	if f.dove.snapshots != 2 {
		t.Fatalf("snapshots %d", f.dove.snapshots)
	}
}

func TestReporterModeMailboxSplitsVotes(t *testing.T) {
	for _, mode := range []string{antispam.ReporterDomain, antispam.ReporterMailbox} {
		f := newPostfixWatch(t, mode, "alice@example.com", "bob@example.com", "carol@example.net")
		f.pass()
		for _, u := range []string{"alice@example.com", "bob@example.com", "carol@example.net"} {
			f.junk(u, "cur", 1, spamBody)
		}
		f.pass()
		got := f.engine.submitted()
		slices.Sort(got)
		want := []int{f.id("alice@example.com"), f.id("bob@example.com"), f.id("carol@example.net")}
		slices.Sort(want)
		distinct := len(slices.Compact(slices.Clone(want)))
		if !slices.Equal(got, want) || mode == antispam.ReporterDomain && distinct != 2 || mode == antispam.ReporterMailbox && distinct != 3 {
			t.Errorf("%s: submitted %v, want %v", mode, got, want)
		}
	}
}

// A3: a system user without a domain votes under its own userdb uid.
func TestReporterDomainlessUserKeepsUID(t *testing.T) {
	for _, mode := range []string{antispam.ReporterDomain, antispam.ReporterMailbox} {
		f := newPostfixWatch(t, mode, "dave", "alice@example.com")
		f.pass()
		f.junk("dave", "cur", 1, spamBody)
		f.pass()
		if got := f.engine.submitted(); !slices.Equal(got, []int{mailUID + 2}) {
			t.Errorf("%s: submitted %v", mode, got)
		}
	}
}

func TestSchedulerPostfixRegistryErrorCancelsNothing(t *testing.T) {
	for name, fail := range map[string]func(*postfixFixture){
		"doveadm":         func(f *postfixFixture) { f.dove.err = errors.New("doveadm: exit status 75") },
		"timeout":         func(f *postfixFixture) { f.dove.err = fmt.Errorf("doveadm: %w", context.DeadlineExceeded) },
		"cannot iterate":  func(f *postfixFixture) { f.dove.err = dovecot.ErrCannotIterate },
		"dovecot 2.4":     func(f *postfixFixture) { f.dove.err = dovecot.ErrDovecot24 },
		"empty":           func(f *postfixFixture) { f.dove.snap = dovecot.Snapshot{} },
		"recheck fails":   func(f *postfixFixture) { f.remove("bob@example.net"); f.dove.usersErr = dovecot.ErrCannotIterate },
		"recheck refused": func(f *postfixFixture) { f.remove("bob@example.net"); f.dove.users = []string{} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com", "bob@example.net")
			f.pass()
			f.junk("alice@example.com", "cur", 1, spamBody)
			f.engine.held = []int{f.id("alice@example.com"), f.id("bob@example.net")}
			fail(f)
			f.now = f.now.Add(SeenRetention + 48*time.Hour)
			r := f.pass()
			if got := f.engine.cancelled(); len(got) != 0 {
				t.Fatalf("cancelled %v on a registry failure", got)
			}
			if got := f.engine.submitted(); len(got) != 0 {
				t.Fatalf("submitted %v on a registry failure", got)
			}
			if !f.junkState("alice@example.com") || !f.junkState("bob@example.net") {
				t.Fatal("folder state pruned on a registry failure")
			}
			if r.Skipped[SkipRegistryUnreadable] != 1 || !r.Unfinished || r.RegistryErr == nil {
				t.Fatalf("registry failure not reported: %+v", r)
			}
			if f.dove.err != nil && !errors.Is(r.RegistryErr, f.dove.err) || f.dove.usersErr != nil && !errors.Is(r.RegistryErr, f.dove.usersErr) {
				t.Fatalf("registry error %v", r.RegistryErr)
			}
		})
	}
}

func TestSchedulerPostfixIncompleteSnapshotSubmitsNothing(t *testing.T) {
	f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com")
	f.pass()
	f.junk("alice@example.com", "cur", 1, spamBody)
	f.engine.held = []int{1 << 40}
	f.dove.snap.Complete = false
	r := f.pass()
	if len(f.engine.submitted()) != 0 || len(f.engine.cancelled()) != 0 || r.Skipped[SkipRegistryUnreadable] != 1 || r.RegistryErr == nil {
		t.Fatalf("incomplete snapshot used: submitted %v, cancelled %v, report %+v", f.engine.submitted(), f.engine.cancelled(), r)
	}
	f.dove.snap.Complete = true
	f.pass()
	if got := f.engine.submitted(); len(got) != 1 {
		t.Fatalf("report lost after an incomplete snapshot: %v", got)
	}
}

// A removed reporter's unsent work is cancelled only once a fresh listing
// confirms it is gone.
func TestSchedulerPostfixRemovedReporterRechecked(t *testing.T) {
	for name, c := range map[string]struct {
		mode    string
		gone    string
		users   []string
		cancel  bool
		cleanup bool
	}{
		"domain removed":     {antispam.ReporterDomain, "bob@example.net", []string{"alice@example.com"}, true, true},
		"domain recreated":   {antispam.ReporterDomain, "bob@example.net", []string{"alice@example.com", "eve@example.net"}, false, true},
		"mailbox recreated":  {antispam.ReporterMailbox, "bob@example.net", []string{"alice@example.com", "bob@example.net"}, false, true},
		"mailbox removed":    {antispam.ReporterMailbox, "bob@example.net", []string{"alice@example.com", "eve@example.net"}, true, true},
		"system user gone":   {antispam.ReporterDomain, "dave", []string{"alice@example.com", "erin"}, true, true},
		"system user listed": {antispam.ReporterDomain, "dave", []string{"alice@example.com", "dave"}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPostfixWatch(t, c.mode, "alice@example.com", "bob@example.net", "dave")
			f.add("erin", mailUID+3)
			f.pass()
			gone := f.id(c.gone)
			f.remove(c.gone)
			// Neither a refused name nor root holds a reporter.
			f.dove.snap.Skips = []dovecot.Skip{{Reason: dovecot.SkipInvalidName}, {User: "root", Reason: dovecot.SkipUIDRoot}}
			f.dove.users = append(slices.Clone(c.users), "root")
			f.engine.held = []int{f.id("alice@example.com"), gone}
			f.now = f.now.Add(SeenRetention + 48*time.Hour)
			r := f.pass()
			if got := f.engine.cancelled(); c.cancel != slices.Equal(got, []int{gone}) || !c.cancel && len(got) != 0 {
				t.Fatalf("cancelled %v", got)
			}
			if f.junkState(c.gone) == c.cleanup || !f.junkState("alice@example.com") {
				t.Fatalf("absent folder pruned %v, want %v", !f.junkState(c.gone), c.cleanup)
			}
			if r.Skipped[SkipRegistryUnreadable] != 0 || !c.cleanup && r.Skipped[SkipCancelUnconfirmed] != 1 {
				t.Fatalf("report %+v", r)
			}
		})
	}
}

// A removal the recheck cannot settle stops every later cancellation and
// the absent-folder prune of that pass.
func TestSchedulerPostfixUnconfirmedRemovalStopsCleanup(t *testing.T) {
	f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com", "bob@example.net", "dave")
	f.pass()
	f.engine.held = []int{f.id("dave"), f.id("bob@example.net")}
	f.remove("dave")
	f.remove("bob@example.net")
	f.dove.users = []string{"alice@example.com", "zed"}
	f.now = f.now.Add(SeenRetention + 48*time.Hour)
	r := f.pass()
	if got := f.engine.cancelled(); len(got) != 0 || r.Skipped[SkipCancelUnconfirmed] != 1 || r.Skipped[SkipRegistryUnreadable] != 0 {
		t.Fatalf("cancelled %v, report %+v", got, r)
	}
	if !f.junkState("dave") || !f.junkState("bob@example.net") {
		t.Fatal("absent folders pruned after an unconfirmed removal")
	}
}

func TestSchedulerPostfixRegistryReadOncePerPass(t *testing.T) {
	f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com", "bob@example.net", "carol@example.org")
	f.pass()
	f.remove("bob@example.net")
	f.remove("carol@example.org")
	f.engine.held = []int{f.id("bob@example.net"), f.id("carol@example.org")}
	f.dove.snapshots, f.dove.listings = 0, 0
	f.pass()
	if f.dove.snapshots != 1 || f.dove.listings != 2 || len(f.engine.cancelled()) != 2 {
		t.Fatalf("%d snapshots, %d listings, cancelled %v", f.dove.snapshots, f.dove.listings, f.engine.cancelled())
	}
}

func TestSchedulerPostfixExemptMailboxNotWatched(t *testing.T) {
	f := newPostfixWatch(t, antispam.ReporterMailbox, "alice@example.com", "bob@example.com", "carol@example.net")
	f.cfg.Postfix.Exempt = []string{"bob@example.com", "example.net"}
	f.restart()
	f.pass()
	for _, u := range []string{"alice@example.com", "bob@example.com", "carol@example.net"} {
		f.junk(u, "cur", 1, spamBody)
	}
	f.dove.snap.Skips = []dovecot.Skip{{User: "dan@example.net", Reason: dovecot.SkipLookupFailed}}
	dan := ReporterID(antispam.ReporterMailbox, "example.net", "dan@example.net")
	f.engine.held = []int{f.id("carol@example.net"), dan}
	r := f.pass()
	if got := f.engine.submitted(); !slices.Equal(got, []int{f.id("alice@example.com")}) || r.Accounts != 1 {
		t.Fatalf("submitted %v, report %+v", got, r)
	}
	if f.junkState("bob@example.com") || f.junkState("carol@example.net") {
		t.Fatal("exempt mailbox opened")
	}
	// Exempting a reporter withdraws its unsent work, as an opt-out does.
	if got := f.engine.cancelled(); !slices.Equal(got, []int{f.id("carol@example.net"), dan}) {
		t.Fatalf("cancelled %v", got)
	}
}

// Postfix has no Spam Filters switch: no opt-in file is read or needed.
func TestSchedulerPostfixNoOptInFile(t *testing.T) {
	f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com")
	blocker := filepath.Join(t.TempDir(), "file")
	writeMsg(t, blocker, nil)
	f.cfg.GlobalPath = filepath.Join(blocker, "global_spamassassin_enable")
	f.restart()
	f.pass()
	f.junk("alice@example.com", "cur", 1, spamBody)
	r := f.pass()
	if len(f.engine.submitted()) != 1 || len(f.engine.cancelled()) != 0 || r.Skipped[SkipOptInUnreadable] != 0 || r.Skipped[SkipOptedOut] != 0 {
		t.Fatalf("submitted %v, cancelled %v, report %+v", f.engine.submitted(), f.engine.cancelled(), r)
	}
}

// L8: a mailbox's files belong to its userdb uid; another owner and uid 0
// are refused.
func TestSchedulerPostfixWrongOwnerSkipped(t *testing.T) {
	f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com")
	f.add("bob@example.com", foreignUID)
	f.add("zero@example.com", 0)
	f.restart()
	f.pass()
	f.junk("alice@example.com", "cur", 1, spamBody)
	f.junk("bob@example.com", "cur", 1, spamBody)
	f.junk("zero@example.com", "cur", 1, spamBody)
	r := f.pass()
	if got := f.engine.submitted(); len(got) != 1 || r.Skipped[SkipUnsafePath] == 0 || r.Skipped[dovecot.SkipUIDRoot] != 1 {
		t.Fatalf("submitted %v, report %+v", got, r)
	}
}

func TestSchedulerPostfixDomainAllowancePausesOnlyThatDomain(t *testing.T) {
	f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com", "bob@example.com", "carol@example.net")
	f.cfg.SeenAllowance = 5
	f.restart()
	f.pass()
	f.junk("alice@example.com", "new", 4, spamBody)
	f.junk("bob@example.com", "new", 4, spamBody)
	f.junk("carol@example.net", "new", 1, spamBody)
	r := f.pass()
	got := f.engine.submitted()
	if countUID(got, f.id("alice@example.com")) != 5 || countUID(got, f.id("carol@example.net")) != 1 {
		t.Fatalf("submitted %v", got)
	}
	if r.Skipped[learn.SkipAccountCapacity] != 1 {
		t.Fatalf("allowance not reported once: %+v", r)
	}
}

// A2: a skipped mailbox is present, not removed: its reporter keeps its
// reservations and its folders keep their state. A domainless user's
// reporter is a uid the skip does not carry, so no absent folder is pruned.
func TestSchedulerPostfixSkippedMailboxKeepsState(t *testing.T) {
	for name, c := range map[string]struct {
		user, reason string
		held         bool
	}{
		"domain":             {"bob@example.net", dovecot.SkipLookupFailed, true},
		"domain shared path": {"bob@example.net", dovecot.SkipSharedPath, true},
		"domainless held":    {"dave", dovecot.SkipLookupFailed, true},
		"domainless unheld":  {"dave", dovecot.SkipLookupFailed, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPostfixWatch(t, antispam.ReporterDomain, "alice@example.com", "bob@example.net", "dave")
			f.pass()
			f.submit = false
			f.junk(c.user, "cur", 1, spamBody)
			f.pass()
			f.skip(c.user, c.reason)
			if c.held {
				f.engine.held = []int{f.id(c.user)}
			}
			f.now = f.now.Add(SeenRetention + 48*time.Hour)
			f.submit = true
			f.dove.listings = 0
			r := f.pass()
			if len(f.engine.cancelled()) != 0 || len(f.engine.submitted()) != 0 || r.Skipped[c.reason] != 1 {
				t.Fatalf("cancelled %v, submitted %v, report %+v", f.engine.cancelled(), f.engine.submitted(), r)
			}
			// A reporter a skip holds needs no recheck.
			if c.user == "bob@example.net" && f.dove.listings != 0 {
				t.Fatalf("%d rechecks of a held reporter", f.dove.listings)
			}
			if !f.junkState(c.user) {
				t.Fatal("skipped mailbox lost its state")
			}
			f.add(c.user, f.boxes[c.user].UID)
			f.dove.snap.Skips = nil
			f.pass()
			if got := f.engine.submitted(); !slices.Equal(got, []int{f.id(c.user)}) {
				t.Fatalf("pending report lost: %v", got)
			}
		})
	}
}

// OpenJunk pins the mail root, refuses links anywhere on the way, a folder
// that is not Maildir++ and a root another uid owns. A missing folder is
// only absent.
func TestOpenJunkRefusesUnsafeLayouts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Maildir")
	for _, d := range []string{".Junk/cur", ".spambox/cur", "real/.Junk/cur"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{".Linked": ".spambox", "linkroot": "real"} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	uid := os.Getuid()
	if f, err := OpenJunk(filepath.Join(root, ".Junk"), "cur", uid); err != nil {
		t.Fatalf("plain Junk folder: %v", err)
	} else {
		_ = f.Close()
	}
	for _, c := range []struct {
		path, sub string
		uid       int
	}{
		{"Maildir/.Junk", "cur", uid},
		{root + "/./.Junk", "cur", uid},
		{root + "/real", "cur", uid},
		{root + "/.Junk", "tmp", uid},
		{root + "/.Linked", "cur", uid},
		{root + "/linkroot/.Junk", "cur", uid},
		{root + "/.Junk", "cur", uid + 1},
	} {
		if f, err := OpenJunk(c.path, c.sub, c.uid); !errors.Is(err, ErrUnsafePath) {
			if err == nil {
				_ = f.Close()
			}
			t.Errorf("%s/%s as uid %d: err %v, want ErrUnsafePath", c.path, c.sub, c.uid, err)
		}
	}
	if _, err := OpenJunk(root+"/.Missing", "cur", uid); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing folder: err %v", err)
	}
}
