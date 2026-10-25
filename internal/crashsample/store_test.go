package crashsample

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func file(name, data string) File {
	return File{Name: name, Src: strings.NewReader(data), Size: int64(len(data))}
}

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "parse-crashes")
	s := New(dir)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { now = now.Add(time.Second); return now }
	return s, dir
}

func samples(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestStoreSaveWritesPrivateCopies(t *testing.T) {
	s, dir := newTestStore(t)
	if err := s.Save("1abcDE-000001-AB", []File{file("body", "body bytes"), file("header", "header bytes")}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"body": "body bytes", "header": "header bytes"} {
		path := filepath.Join(dir, "1abcDE-000001-AB", name)
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("%s = %q, %v; want %q", name, data, err, want)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, want 0600", name, info.Mode().Perm())
		}
	}
	for _, d := range []string{dir, filepath.Join(dir, "1abcDE-000001-AB")} {
		if info, _ := os.Stat(d); info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode %v, want 0700", d, info.Mode().Perm())
		}
	}
}

func TestStoreEvictsOldestOverCount(t *testing.T) {
	s, dir := newTestStore(t)
	for i := range MaxSamples + 1 {
		if err := s.Save(fmt.Sprintf("m%02d", i), []File{file("body", "x")}); err != nil {
			t.Fatal(err)
		}
	}
	got := samples(t, dir)
	if len(got) != MaxSamples || got[0] != "m01" {
		t.Fatalf("samples = %v, want the newest %d", got, MaxSamples)
	}
}

func TestStoreEvictsOverBytes(t *testing.T) {
	s, dir := newTestStore(t)
	s.maxBytes = 10
	for _, name := range []string{"a", "b", "c"} {
		if err := s.Save(name, []File{file("body", "1234")}); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(samples(t, dir), ","); got != "b,c" {
		t.Fatalf("samples = %s, want the oldest evicted to fit the byte cap", got)
	}
	if err := s.Save("big", []File{file("body", "12345678901")}); err == nil {
		t.Fatal("a sample over the byte cap was accepted")
	}
	if got := strings.Join(samples(t, dir), ","); got != "b,c" {
		t.Fatalf("samples = %s after a refused save, want them untouched", got)
	}
}

func TestStoreRefusesBadNames(t *testing.T) {
	s, dir := newTestStore(t)
	for _, name := range []string{"", "../x", "a/b", ".hidden", strings.Repeat("a", 129)} {
		if err := s.Save(name, []File{file("body", "x")}); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if err := s.Save("ok", []File{file("../body", "x")}); err == nil {
		t.Error("file name ../body accepted")
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
		t.Fatalf("refused saves wrote %v", entries)
	}
}

func TestStoreRefusesSymlinkedDir(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "parse-crashes")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	s := New(dir)
	if err := s.Save("m", []File{file("body", "x")}); err == nil {
		t.Fatal("Save wrote through a symlinked directory")
	}
	if _, err := s.Sweep(); err == nil {
		t.Fatal("Sweep worked through a symlinked directory")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("symlink target got %v", entries)
	}
}

func TestStoreSweepRemovesOld(t *testing.T) {
	s, dir := newTestStore(t)
	for _, name := range []string{"old", "new"} {
		if err := s.Save(name, []File{file("body", "x")}); err != nil {
			t.Fatal(err)
		}
	}
	base := s.now()
	old := base.Add(-MaxAge - time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "old"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".tmp-stale"), 0o700); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base }
	n, err := s.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(samples(t, dir), ","); n != 1 || got != "new" {
		t.Fatalf("swept %d, left %s; want old and the stale temp removed", n, got)
	}
	if n, err := New(filepath.Join(t.TempDir(), "missing")).Sweep(); n != 0 || err != nil {
		t.Fatalf("sweep of a missing directory = %d, %v", n, err)
	}
}
