package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// getCurrentGID returns the current process's primary group, used by tests
// to simulate "the file's group is the web server group" without root.
func getCurrentGID(t *testing.T) uint32 {
	t.Helper()
	return uint32(os.Getgid())
}

func TestScanGroupWritablePHPRespectsMaxDepthZero(t *testing.T) {
	tmp := t.TempDir()
	php := filepath.Join(tmp, "x.php")
	if err := os.WriteFile(php, []byte("<?php"), 0664); err != nil {
		t.Fatal(err)
	}
	// umask may strip the group-write bit on creation; force it back.
	if err := os.Chmod(php, 0664); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanGroupWritablePHP(tmp, 0, map[uint32]bool{getCurrentGID(t): true}, &findings)
	if len(findings) != 0 {
		t.Errorf("maxDepth=0 should produce no findings, got %d", len(findings))
	}
}

func TestScanGroupWritablePHPMissingDirIsSilent(t *testing.T) {
	var findings []alert.Finding
	scanGroupWritablePHP("/nonexistent-dir-12345", 4, map[uint32]bool{1: true}, &findings)
	if len(findings) != 0 {
		t.Errorf("missing dir should produce no findings, got %d", len(findings))
	}
}

func TestScanGroupWritablePHPSkipsNonPHP(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "readme.txt"), []byte("x"), 0664); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "script.js"), []byte("x"), 0664); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanGroupWritablePHP(tmp, 4, map[uint32]bool{getCurrentGID(t): true}, &findings)
	if len(findings) != 0 {
		t.Errorf("non-PHP files should not produce findings, got %+v", findings)
	}
}

func TestScanGroupWritablePHPSkipsNonGroupWritable(t *testing.T) {
	tmp := t.TempDir()
	php := filepath.Join(tmp, "secure.php")
	if err := os.WriteFile(php, []byte("<?php"), 0644); err != nil { // no group-write
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanGroupWritablePHP(tmp, 4, map[uint32]bool{getCurrentGID(t): true}, &findings)
	if len(findings) != 0 {
		t.Errorf("non-group-writable PHP should be ignored, got %+v", findings)
	}
}

func TestScanGroupWritablePHPSkipsPHPWhenGroupNotInWebGIDs(t *testing.T) {
	tmp := t.TempDir()
	php := filepath.Join(tmp, "writable.php")
	if err := os.WriteFile(php, []byte("<?php"), 0664); err != nil {
		t.Fatal(err)
	}
	// umask may strip the group-write bit on creation; force it back.
	if err := os.Chmod(php, 0664); err != nil {
		t.Fatal(err)
	}
	// Use a GID we definitely don't own.
	var findings []alert.Finding
	scanGroupWritablePHP(tmp, 4, map[uint32]bool{99999: true}, &findings)
	if len(findings) != 0 {
		t.Errorf("file's GID not in webGIDs → no finding, got %+v", findings)
	}
}

func TestScanGroupWritablePHPFlagsWebOwnedFile(t *testing.T) {
	tmp := t.TempDir()
	php := filepath.Join(tmp, "evil.php")
	if err := os.WriteFile(php, []byte("<?php"), 0664); err != nil {
		t.Fatal(err)
	}
	// umask may strip the group-write bit on creation; force it back.
	if err := os.Chmod(php, 0664); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanGroupWritablePHP(tmp, 4, map[uint32]bool{getCurrentGID(t): true}, &findings)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Check != "group_writable_php" {
		t.Errorf("wrong check name: %s", findings[0].Check)
	}
	if findings[0].Severity != alert.High {
		t.Errorf("expected High severity, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "evil.php") {
		t.Errorf("message should reference path: %s", findings[0].Message)
	}
}

func TestScanGroupWritablePHPSkipsCacheAndVendorDirs(t *testing.T) {
	tmp := t.TempDir()
	for _, sub := range []string{"cache", "node_modules", "vendor"} {
		dir := filepath.Join(tmp, sub)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "x.php"), []byte("<?php"), 0664); err != nil {
			t.Fatal(err)
		}
	}
	var findings []alert.Finding
	scanGroupWritablePHP(tmp, 4, map[uint32]bool{getCurrentGID(t): true}, &findings)
	if len(findings) != 0 {
		t.Errorf("skip-listed dirs should not be scanned, got %+v", findings)
	}
}

func TestScanGroupWritablePHPRecursesIntoSubdirs(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "real_dir")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(sub, "deep.php")
	if err := os.WriteFile(deep, []byte("<?php"), 0664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(deep, 0664); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanGroupWritablePHP(tmp, 4, map[uint32]bool{getCurrentGID(t): true}, &findings)
	if len(findings) != 1 {
		t.Fatalf("expected 1 deep finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "real_dir/deep.php") {
		t.Errorf("expected nested path in message, got %s", findings[0].Message)
	}
}

// --- getWebServerGIDs ---------------------------------------------------

func TestGetWebServerGIDsParsesGroupFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/group" {
				return []byte("root:x:0:\nnobody:x:99:\nwww-data:x:33:\nfoo:x:1000:user\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	gids := getWebServerGIDs()
	if !gids[99] || !gids[33] {
		t.Errorf("expected GIDs 99 (nobody) and 33 (www-data) recognized, got %v", gids)
	}
	if gids[1000] {
		t.Errorf("non-web group GID 1000 should not appear, got %v", gids)
	}
}

func TestGetWebServerGIDsMissingFileReturnsEmpty(t *testing.T) {
	withMockOS(t, &mockOS{}) // ReadFile defaults to ErrNotExist
	gids := getWebServerGIDs()
	if len(gids) != 0 {
		t.Errorf("missing /etc/group should return empty map, got %v", gids)
	}
}

// --- CheckGroupWritablePHP integration ---------------------------------

func TestCheckGroupWritablePHPNoWebGIDsReturnsNil(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/group" {
				return []byte("root:x:0:\n"), nil // no web groups
			}
			return nil, os.ErrNotExist
		},
	})
	got := CheckGroupWritablePHP(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("no web GIDs should yield nil findings, got %d: %+v", len(got), got)
	}
}

// realDirEntry adapts a real os.FileInfo to os.DirEntry, used so the mock
// can return an entry whose Info() yields a real syscall.Stat_t.
type realDirEntry struct {
	name string
	info os.FileInfo
}

func (r realDirEntry) Name() string               { return r.name }
func (r realDirEntry) IsDir() bool                { return r.info.IsDir() }
func (r realDirEntry) Type() os.FileMode          { return r.info.Mode().Type() }
func (r realDirEntry) Info() (os.FileInfo, error) { return r.info, nil }

func TestCheckGroupWritablePHPFlagsRealFile(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "public_html")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	php := filepath.Join(docRoot, "shell.php")
	if err := os.WriteFile(php, []byte("<?php"), 0664); err != nil {
		t.Fatal(err)
	}
	// umask may strip the group-write bit on creation; force it back.
	if err := os.Chmod(php, 0664); err != nil {
		t.Fatal(err)
	}

	// Determine current GID and group name from /etc/group entries we know
	// about — we can't add a synthetic group, so we craft a /etc/group that
	// names the current GID under "nobody" and rewire osFS to:
	//   - return that synthetic /etc/group via ReadFile
	//   - return our docRoot's contents via ReadDir(/home/<name>/public_html)
	//   - return our tmp dir as a single entry under /home
	curGID := getCurrentGID(t)
	groupContent := "root:x:0:\nnobody:x:" +
		strconvUint(curGID) + ":\n"

	docInfo, err := os.Stat(docRoot)
	if err != nil {
		t.Fatal(err)
	}
	// Build real DirEntry for the php file (so Info().Sys() is real Stat_t).
	phpInfo, err := os.Stat(php)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := phpInfo.Sys().(*syscall.Stat_t); !ok {
		t.Skip("syscall.Stat_t unavailable on this platform")
	}

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/group" {
				return []byte(groupContent), nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{realDirEntry{name: "alice", info: docInfo}}, nil
			}
			if name == "/home/alice/public_html" {
				return []os.DirEntry{realDirEntry{name: "shell.php", info: phpInfo}}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	got := CheckGroupWritablePHP(context.Background(), &config.Config{}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Check != "group_writable_php" || !strings.Contains(got[0].Message, "shell.php") {
		t.Errorf("unexpected finding: %+v", got[0])
	}
}

// strconvUint is a tiny local helper to format uint32 without dragging
// strconv into the test (keeps the diff minimal).
func strconvUint(u uint32) string {
	if u == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}
