//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func statusChanged(t *testing.T, path string, follow bool) time.Time {
	t.Helper()
	stat := os.Lstat
	if follow {
		stat = os.Stat
	}
	fi, err := stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return time.Unix(st.Ctim.Sec, st.Ctim.Nsec)
}

// pure-ftpd reads its configuration only at start. A source copied or moved
// into place keeps an older modification time, so the change that counts is
// the latest status change of the path and, for a link, of its target.
func TestPureFTPDConfigChanged(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "pure-ftpd.conf")
	target := filepath.Join(dir, "DontResolve.real")
	link := filepath.Join(dir, "DontResolve")
	for _, p := range []string{conf, target} {
		if err := os.WriteFile(p, []byte("yes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, p := range []string{conf, target} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	changed, ok := PureFTPDConfigChanged([]string{conf, link})
	want := slices.MaxFunc([]time.Time{
		statusChanged(t, conf, false), statusChanged(t, link, false), statusChanged(t, link, true),
	}, time.Time.Compare)
	if !ok || !changed.Equal(want) {
		t.Fatalf("PureFTPDConfigChanged = %v, %v; want %v", changed, ok, want)
	}
	if !changed.After(old) {
		t.Fatalf("a back-dated source counted as changed at %v", changed)
	}

	if _, ok := PureFTPDConfigChanged([]string{conf, filepath.Join(dir, "gone")}); ok {
		t.Fatal("a source that cannot be read had a known change time")
	}
	if _, ok := PureFTPDConfigChanged(nil); ok {
		t.Fatal("no sources had a known change time")
	}
}

func TestPureFTPDBinariesMatchInstalledNames(t *testing.T) {
	names := PureFTPDBinaries()
	for _, want := range []string{"pure-ftpd", "pure-ftpd-mysql", "pure-ftpd-postgresql", "pure-ftpd-ldap"} {
		if !slices.Contains(names, want) {
			t.Fatalf("PureFTPDBinaries() = %v, missing %s", names, want)
		}
	}
}
