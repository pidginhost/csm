//go:build linux

package learnwatch

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// tenantHome builds a home owned by the test's own UID with the main
// mailbox's .spam/cur and one virtual mailbox's .Junk/new.
func tenantHome(t *testing.T) Account {
	t.Helper()
	home := filepath.Join(t.TempDir(), "tenant1")
	for _, d := range []string{"mail/.spam/cur", "mail/.spam/new", "mail/example.com/user/.Junk/new"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return Account{Name: "tenant1", UID: os.Getuid(), GID: os.Getgid(), Home: home}
}

func openSpam(t *testing.T, a Account, sub string) *Folder {
	t.Helper()
	h, err := OpenHome(a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	f, err := h.OpenFolder(Mailbox{}, ".spam", sub)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func writeMsg(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenHomeChecksOwner(t *testing.T) {
	a := tenantHome(t)
	a.UID++
	if h, err := OpenHome(a); err == nil {
		_ = h.Close()
		t.Fatal("home owned by another UID opened")
	}
	link := filepath.Join(filepath.Dir(a.Home), "link")
	if err := os.Symlink(a.Home, link); err != nil {
		t.Fatal(err)
	}
	a.UID, a.Home = os.Getuid(), link
	if h, err := OpenHome(a); err == nil {
		_ = h.Close()
		t.Fatal("symlinked home opened")
	}
}

func TestTreeRefusesSymlinkedFolder(t *testing.T) {
	a := tenantHome(t)
	other := t.TempDir()
	cur := filepath.Join(a.Home, "mail/.spam/cur")
	if err := os.Remove(cur); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, cur); err != nil {
		t.Fatal(err)
	}
	h, err := OpenHome(a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	f, err := h.OpenFolder(Mailbox{}, ".spam", "cur")
	if err == nil {
		_ = f.Close()
		t.Fatal("symlinked folder opened")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("symlinked folder reported as missing: %v", err)
	}
}

func TestTreeRefusesSymlinkedMailboxDir(t *testing.T) {
	a := tenantHome(t)
	other := filepath.Join(t.TempDir(), "victim")
	if err := os.MkdirAll(filepath.Join(other, "user/.Junk/new"), 0o700); err != nil {
		t.Fatal(err)
	}
	dom := filepath.Join(a.Home, "mail/example.com")
	if err := os.RemoveAll(dom); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, dom); err != nil {
		t.Fatal(err)
	}
	h, err := OpenHome(a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	if f, err := h.OpenFolder(Mailbox{Domain: "example.com", Box: "user"}, ".Junk", "new"); err == nil {
		_ = f.Close()
		t.Fatal("symlinked mailbox directory opened")
	}
}

func TestTreeRefusesUnsafeComponents(t *testing.T) {
	a := tenantHome(t)
	h, err := OpenHome(a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	for _, c := range []struct {
		m           Mailbox
		folder, sub string
	}{
		{Mailbox{Domain: "../..", Box: "x"}, ".spam", "cur"},
		{Mailbox{Domain: "example.com", Box: "a/b"}, ".spam", "cur"},
		{Mailbox{Domain: "example.com"}, ".spam", "cur"},
		{Mailbox{}, ".Trash", "cur"},
		{Mailbox{}, ".spam", "tmp"},
	} {
		if f, err := h.OpenFolder(c.m, c.folder, c.sub); err == nil {
			_ = f.Close()
			t.Errorf("opened %+v %s/%s", c.m, c.folder, c.sub)
		}
	}
}

func TestReadMessageRefusesSymlinkSwap(t *testing.T) {
	a := tenantHome(t)
	cur := filepath.Join(a.Home, "mail/.spam/cur")
	writeMsg(t, filepath.Join(cur, "1.M1.host:2,S"), []byte("Subject: x\r\n\r\nbody"))
	f := openSpam(t, a, "cur")
	names, err := f.Next(10)
	if err != nil || len(names) != 1 {
		t.Fatalf("names %v, error %v", names, err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	writeMsg(t, secret, []byte("other account's mail"))
	if err = os.Remove(filepath.Join(cur, names[0])); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(secret, filepath.Join(cur, names[0])); err != nil {
		t.Fatal(err)
	}
	snap, _, status, err := f.ReadMessage(names[0], a.UID)
	if status != ReadSkipSymlink || snap != nil || err != nil {
		t.Fatalf("status %v, %d bytes, error %v", status, len(snap), err)
	}
}

func TestReadMessageFIFODoesNotBlock(t *testing.T) {
	a := tenantHome(t)
	if err := syscall.Mkfifo(filepath.Join(a.Home, "mail/.spam/cur/fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := openSpam(t, a, "cur")
	done := make(chan ReadStatus, 1)
	go func() {
		_, _, status, _ := f.ReadMessage("fifo", a.UID)
		done <- status
	}()
	select {
	case status := <-done:
		if status != ReadSkipNotRegular {
			t.Fatalf("status %v", status)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("reading a FIFO blocked")
	}
}

func TestReadMessageLinkCountTwoPending(t *testing.T) {
	a := tenantHome(t)
	msg := filepath.Join(a.Home, "mail/.spam/cur/1.M1.host:2,")
	writeMsg(t, msg, []byte("body"))
	if err := os.Link(msg, filepath.Join(a.Home, "mail/.spam/new/1.M1.host")); err != nil {
		t.Fatal(err)
	}
	f := openSpam(t, a, "cur")
	snap, _, status, err := f.ReadMessage("1.M1.host:2,", a.UID)
	if status != ReadPendingLinked || snap != nil || err != nil {
		t.Fatalf("status %v, %d bytes, error %v", status, len(snap), err)
	}
}

func TestReadMessageChangedWhileReading(t *testing.T) {
	a := tenantHome(t)
	msg := filepath.Join(a.Home, "mail/.spam/cur/1.M1.host:2,")
	writeMsg(t, msg, []byte("original body"))
	f := openSpam(t, a, "cur")
	old := afterRead
	t.Cleanup(func() { afterRead = old })
	afterRead = func() {
		w, err := os.OpenFile(msg, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.WriteString(" and more")
		_ = w.Close()
	}
	snap, _, status, err := f.ReadMessage("1.M1.host:2,", a.UID)
	if status != ReadPendingChanged || snap != nil || err != nil {
		t.Fatalf("status %v, %d bytes, error %v", status, len(snap), err)
	}
}

func TestReadMessageOK(t *testing.T) {
	a := tenantHome(t)
	body := []byte("Subject: x\r\n\r\nbody")
	msg := filepath.Join(a.Home, "mail/.spam/cur/1.M1.host:2,S")
	writeMsg(t, msg, body)
	f := openSpam(t, a, "cur")
	snap, meta, status, err := f.ReadMessage("1.M1.host:2,S", a.UID)
	if status != ReadOK || err != nil || !bytes.Equal(snap, body) {
		t.Fatalf("status %v, snapshot %q, error %v", status, snap, err)
	}
	var st syscall.Stat_t
	if err = syscall.Stat(msg, &st); err != nil {
		t.Fatal(err)
	}
	if meta.Ino != st.Ino || meta.Size != int64(len(body)) || meta.UID != a.UID || meta.Nlink != 1 || meta.MtimeNs == 0 || meta.CtimeNs == 0 {
		t.Fatalf("meta %+v", meta)
	}
	stat, status, err := f.Stat("1.M1.host:2,S")
	if status != ReadOK || err != nil || stat != meta {
		t.Fatalf("stat %+v, status %v, error %v", stat, status, err)
	}
}

func TestReadMessageWrongOwner(t *testing.T) {
	a := tenantHome(t)
	writeMsg(t, filepath.Join(a.Home, "mail/.spam/cur/1.M1.host:2,"), []byte("body"))
	f := openSpam(t, a, "cur")
	if _, _, status, err := f.ReadMessage("1.M1.host:2,", a.UID+1); status != ReadSkipWrongOwner || err != nil {
		t.Fatalf("status %v, error %v", status, err)
	}
}

func TestReadMessageOversize(t *testing.T) {
	a := tenantHome(t)
	writeMsg(t, filepath.Join(a.Home, "mail/.spam/cur/big"), bytes.Repeat([]byte("a"), 10<<20+1))
	f := openSpam(t, a, "cur")
	if snap, _, status, err := f.ReadMessage("big", a.UID); status != ReadSkipOversize || snap != nil || err != nil {
		t.Fatalf("status %v, %d bytes, error %v", status, len(snap), err)
	}
}

func TestReadMessageGone(t *testing.T) {
	a := tenantHome(t)
	f := openSpam(t, a, "cur")
	if _, _, status, err := f.ReadMessage("missing", a.UID); status != ReadGone || err != nil {
		t.Fatalf("status %v, error %v", status, err)
	}
}

func TestNextChunks(t *testing.T) {
	a := tenantHome(t)
	cur := filepath.Join(a.Home, "mail/.spam/cur")
	for i := range 1100 {
		writeMsg(t, filepath.Join(cur, fmt.Sprintf("%d.M1.host:2,", i)), nil)
	}
	f := openSpam(t, a, "cur")
	var sizes []int
	seen := map[string]bool{}
	for {
		names, err := f.Next(512)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(names))
		for _, n := range names {
			seen[n] = true
		}
	}
	if fmt.Sprint(sizes) != "[512 512 76]" || len(seen) != 1100 {
		t.Fatalf("chunks %v, %d distinct", sizes, len(seen))
	}
}

func TestFolderIdentity(t *testing.T) {
	a := tenantHome(t)
	f := openSpam(t, a, "cur")
	dev, ino, mtime, ctime := f.Identity()
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(a.Home, "mail/.spam/cur"), &st); err != nil {
		t.Fatal(err)
	}
	if dev != uint64(st.Dev) || ino != st.Ino || mtime != st.Mtim.Nano() || ctime != st.Ctim.Nano() {
		t.Fatalf("identity %d %d %d %d", dev, ino, mtime, ctime)
	}
}

func TestBaseNameParsing(t *testing.T) {
	for name, want := range map[string]string{
		"1.M1.host:2,S": "1.M1.host",
		"1.M1.host:2,":  "1.M1.host",
		"1.M1.host":     "1.M1.host",
		"a:b:2,FS":      "a:b",
		"":              "",
		":2,S":          "",
		".":             "",
		"..":            "",
		"..:2,":         "",
		"a/b":           "",
		"a\x00b":        "",
	} {
		got, ok := BaseName(name)
		if got != want || ok != (want != "") {
			t.Errorf("BaseName(%q) = %q, %v", name, got, ok)
		}
	}
}
