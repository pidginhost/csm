//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A home directory's incarnation survives changes its owner can make and
// changes when the directory is replaced, even while the old one still
// exists under another name.
func TestAccountDirIncarnation(t *testing.T) {
	home := filepath.Join(t.TempDir(), "carol")
	if err := os.Mkdir(home, 0o750); err != nil {
		t.Fatal(err)
	}
	first, err := accountDirIncarnation(home)
	if err != nil || !strings.HasPrefix(first, "fs:") || len(first) != 35 {
		t.Fatalf("incarnation = %q, %v", first, err)
	}
	if err = os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(home, "index.html"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if again, againErr := accountDirIncarnation(home); againErr != nil || again != first {
		t.Fatalf("the owner's changes moved the incarnation: %q, %v", again, againErr)
	}
	if err = os.Rename(home, home+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(home, 0o750); err != nil {
		t.Fatal(err)
	}
	if replaced, replacedErr := accountDirIncarnation(home); replacedErr != nil || replaced == first {
		t.Fatalf("a replaced home kept its incarnation: %q, %v", replaced, replacedErr)
	}
	if _, err = accountDirIncarnation(filepath.Join(filepath.Dir(home), "missing")); err == nil {
		t.Fatal("a missing home has an incarnation")
	}
}

// The token covers the device, the inode and a valid birth time, and
// nothing an owner can change: mode, ownership and change times. Nor the
// mount instance the home was reached through: the service's own mount
// namespace renews its ID at each start.
func TestStatxIncarnationFields(t *testing.T) {
	base := unix.Statx_t{Mask: unix.STATX_INO | unix.STATX_BTIME, Dev_major: 253, Dev_minor: 1, Ino: 42,
		Btime: unix.StatxTimestamp{Sec: 1_700_000_000, Nsec: 5}, Mode: 0o750, Ctime: unix.StatxTimestamp{Sec: 1}}
	token := statxIncarnation(base)
	owned := base
	owned.Mode, owned.Uid, owned.Ctime, owned.Mtime = 0o700, 1000, unix.StatxTimestamp{Sec: 2}, unix.StatxTimestamp{Sec: 3}
	if statxIncarnation(owned) != token {
		t.Fatal("an owner's change moved the token")
	}
	mounted := base
	mounted.Mask |= unix.STATX_MNT_ID
	mounted.Mnt_id = 461
	if statxIncarnation(mounted) != token {
		t.Fatal("a mount instance moved the token")
	}
	for name, mutate := range map[string]func(*unix.Statx_t){
		"inode":         func(s *unix.Statx_t) { s.Ino++ },
		"device":        func(s *unix.Statx_t) { s.Dev_minor++ },
		"birth time":    func(s *unix.Statx_t) { s.Btime.Nsec++ },
		"no birth time": func(s *unix.Statx_t) { s.Mask &^= unix.STATX_BTIME },
	} {
		other := base
		mutate(&other)
		if statxIncarnation(other) == token {
			t.Errorf("%s does not change the token", name)
		}
	}
	unborn := base
	unborn.Mask &^= unix.STATX_BTIME
	later := unborn
	later.Btime.Sec++
	if statxIncarnation(unborn) != statxIncarnation(later) {
		t.Error("a birth time the filesystem did not report changed the token")
	}
}

// A directory listing may race a replacement: no symlink or regular file
// may become an account incarnation.
func TestAccountDirIncarnationRejectsNonDirectories(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, link} {
		if _, err := accountDirIncarnation(path); err == nil {
			t.Fatal("accepted a non-directory")
		}
	}
}

// Without birth time, inode reuse can hide a replacement between polls.
func TestAccountDirIncarnationRequiresBirthTime(t *testing.T) {
	st := unix.Statx_t{Mask: unix.STATX_TYPE | unix.STATX_INO, Mode: unix.S_IFDIR | 0o750, Ino: 1}
	if _, err := accountStatxIncarnation(st); err == nil {
		t.Fatal("an inode without birth time proved an incarnation")
	}
	st.Mask |= unix.STATX_BTIME
	if _, err := accountStatxIncarnation(st); err != nil {
		t.Fatal(err)
	}
}
