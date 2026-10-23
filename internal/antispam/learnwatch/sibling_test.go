//go:build linux

package learnwatch

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/learn"
)

// The original no-follow lookup can fail just before a mailbox or its link
// disappears. The retry must report the current lookup failure.
func TestSiblingRetryPreservesLookupErrors(t *testing.T) {
	a, _ := siblingSpam(t, func(string) string { return ".spambox" })
	h, err := OpenHome(a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	for _, tc := range []struct {
		name, rel, folder string
		want              error
	}{
		{"missing mailbox", "mail/example.com/missing", ".spam", fs.ErrNotExist},
		{"missing link", "mail", ".Junk", fs.ErrNotExist},
		{"plain folder", "mail/example.com/user", ".Junk", syscall.ENOTDIR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := h.openSibling(tc.rel, tc.folder, "cur", syscall.ENOTDIR)
			if d != nil {
				_ = d.Close()
				t.Fatal("failed lookup returned a directory")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("retry error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSiblingRetryPreservesResourceError(t *testing.T) {
	if os.Getenv("CSM_LEARNWATCH_SIBLING_NOFILE") != "1" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(self, "-test.run=^TestSiblingRetryPreservesResourceError$")
		cmd.Env = append(os.Environ(), "CSM_LEARNWATCH_SIBLING_NOFILE=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("limited sibling lookup: %v\n%s", err, out)
		}
		return
	}
	a, m := siblingSpam(t, func(string) string { return ".spambox" })
	h, err := OpenHome(a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	var limit syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	limited := limit
	limited.Cur = 0
	if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limited); err != nil {
		t.Fatal(err)
	}
	// Model descriptors being exhausted after the initial no-follow failure.
	d, openErr := h.openSibling("mail/example.com/user", ".spam", "cur", syscall.ENOTDIR)
	if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	if d != nil {
		_ = d.Close()
		t.Fatal("opened sibling without an available descriptor")
	}
	if !errors.Is(openErr, syscall.EMFILE) || errors.Is(openErr, ErrUnsafePath) {
		t.Fatalf("resource failure must stay retryable: %v", openErr)
	}
	f, err := h.OpenFolder(m, ".spam", "cur")
	if err != nil {
		t.Fatalf("lookup did not recover: %v", err)
	}
	_ = f.Close()
}

func TestSiblingLinkRejectsDifferentHomeSpelling(t *testing.T) {
	for _, spelling := range []string{"trailing slash", "alternate home"} {
		t.Run(spelling, func(t *testing.T) {
			a, m := siblingSpam(t, func(box string) string { return box + "/.spambox" })
			if spelling == "trailing slash" {
				a.Home += "/"
			} else {
				alias := filepath.Join(filepath.Dir(a.Home), "alternate")
				if err := os.Rename(a.Home, alias); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(a.Home, "mail/example.com/user/.spambox/cur")
				if err := os.MkdirAll(outside, 0o700); err != nil {
					t.Fatal(err)
				}
				writeMsg(t, filepath.Join(outside, "outside"), []byte("Subject: outside\n\nother mailbox"))
				a.Home = alias
			}
			h, err := OpenHome(a)
			if spelling == "trailing slash" {
				if err == nil {
					_ = h.Close()
					t.Fatal("unclean home spelling was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = h.Close() }()
			f, err := h.OpenFolder(m, ".spam", "cur")
			if f != nil {
				_ = f.Close()
				t.Fatal("absolute link with a different home spelling opened")
			}
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("different home spelling: %v", err)
			}
		})
	}
}

func TestSiblingLinkRejectsSymlinkedSubdirectory(t *testing.T) {
	a, m := siblingSpam(t, func(string) string { return ".spambox" })
	box := filepath.Join(a.Home, "mail/example.com/user")
	if err := os.Rename(filepath.Join(box, ".spambox/cur"), filepath.Join(box, ".saved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.saved", filepath.Join(box, ".spambox/cur")); err != nil {
		t.Fatal(err)
	}
	h, err := OpenHome(a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	f, err := h.OpenFolder(m, ".spam", "cur")
	if f != nil {
		_ = f.Close()
		t.Fatal("second link was followed")
	}
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlinked subdirectory: %v", err)
	}
}

func TestSchedulerSiblingLinkRebaselinesTarget(t *testing.T) {
	for _, tc := range []struct {
		name, folder      string
		virtual, absolute bool
	}{
		{"main spam relative", ".spam", false, false},
		{"main spam absolute", ".spam", false, true},
		{"main junk relative", ".Junk", false, false},
		{"main junk absolute", ".Junk", false, true},
		{"virtual spam relative", ".spam", true, false},
		{"virtual spam absolute", ".spam", true, true},
		{"virtual junk relative", ".Junk", true, false},
		{"virtual junk absolute", ".Junk", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWatch(t, 1)
			box := filepath.Join(f.accounts[0].Home, "mail")
			if tc.virtual {
				f.addMailbox(0, "example.com", "user")
				box = filepath.Join(box, "example.com/user")
			}
			link := filepath.Join(box, tc.folder)
			if tc.folder == ".spam" {
				if err := os.Rename(link, filepath.Join(box, ".original")); err != nil {
					t.Fatal(err)
				}
			}
			for _, target := range []string{".first", ".second"} {
				for _, sub := range Subdirs {
					dir := filepath.Join(box, target, sub)
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					writeMsg(t, filepath.Join(dir, "old-"+sub), []byte(spamBody))
				}
			}
			retarget := func(target string) {
				if tc.absolute {
					target = filepath.Join(box, target)
				}
				tmp := filepath.Join(box, ".replacement")
				if err := os.Symlink(target, tmp); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, link); err != nil {
					t.Fatal(err)
				}
			}
			var snapshots []string
			f.engine.onSubmit = func(c learn.Candidate) { snapshots = append(snapshots, string(c.Snapshot)) }
			retarget(".first")
			if r := f.pass(); r.Unfinished || r.Submitted != 0 || len(snapshots) != 0 {
				t.Fatalf("initial target was not baselined: %+v, snapshots %q", r, snapshots)
			}
			for _, sub := range Subdirs {
				writeMsg(t, filepath.Join(link, sub, "fresh-"+sub), []byte("Subject: first "+sub+"\r\n\r\nfresh"))
			}
			if r := f.pass(); r.Unfinished || r.Submitted != 2 || len(snapshots) != 2 {
				t.Fatalf("fresh reports not learned: %+v, snapshots %q", r, snapshots)
			}
			for _, sub := range Subdirs {
				if !slices.Contains(snapshots, "Subject: first "+sub+"\r\n\r\nfresh") {
					t.Fatalf("wrong reports learned: %q", snapshots)
				}
			}
			f.submit = false
			writeMsg(t, filepath.Join(link, "cur/pending"), []byte(spamBody))
			if r := f.pass(); r.Submitted != 0 || r.Pending != 1 {
				t.Fatalf("report was not held for retargeting: %+v", r)
			}
			writeMsg(t, filepath.Join(box, ".second/cur/pending"), []byte(spamBody))
			retarget(".second")
			f.submit = true
			f.restart()
			for range 2 {
				if r := f.pass(); r.Unfinished || r.Submitted != 0 || len(snapshots) != 2 {
					t.Fatalf("retargeted old corpus was learned: %+v, snapshots %q", r, snapshots)
				}
			}
			writeMsg(t, filepath.Join(link, "cur/fresh"), []byte("Subject: second\r\n\r\nfresh"))
			if r := f.pass(); r.Unfinished || r.Submitted != 1 || len(snapshots) != 3 || snapshots[2] != "Subject: second\r\n\r\nfresh" {
				t.Fatalf("new target arrival not learned: %+v, snapshots %q", r, snapshots)
			}
		})
	}
}
