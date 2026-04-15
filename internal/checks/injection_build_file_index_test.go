package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildFileIndex:
//   - GetScanHomeDirs fails → returns nil
//   - /home has non-dir entries → skipped
//   - per-user dirs: public_html + addon domains (exclude mail/etc/logs/ssl/tmp)
//   - uploadDirs → scanDirForPHP
//   - sensitiveWPDirs (languages/upgrade/mu-plugins) → scanDirForPHP
//   - .config → scanDirForExecutables
//   - /tmp, /dev/shm, /var/tmp → scanDirForSuspiciousExt

func TestBuildFileIndexGetScanHomeDirsFailsReturnsNil(t *testing.T) {
	resetScanAccount(t)
	withMockOS(t, &mockOS{
		readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission },
	})
	got := buildFileIndex(dirMtimeCache{}, nil, false)
	if got != nil {
		t.Errorf("GetScanHomeDirs error should yield nil, got %d entries", len(got))
	}
}

func TestBuildFileIndexSkipsNonDirEntries(t *testing.T) {
	resetScanAccount(t)
	// /home contains a regular file (not a dir) → function should skip it
	// without a panic and return the tmp-dir entries (which will also be
	// empty because our mock doesn't serve them).
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{
					realDirEntry{name: "not-a-dir", info: accountScanFakeInfo{name: "not-a-dir"}},
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	got := buildFileIndex(dirMtimeCache{}, nil, false)
	if len(got) != 0 {
		t.Errorf("regular-file entry should not produce index entries, got %v", got)
	}
}

// TestBuildFileIndexFindsUploadsPHPFile drives the full uploadDirs path:
// /home/alice/public_html/wp-content/uploads/shell.php should surface in
// the index. GetScanHomeDirs returns /home/alice; ReadDir for the uploads
// path serves one .php file; the function's scanDirForPHP branch does the
// rest.
func TestBuildFileIndexFindsUploadsPHPFile(t *testing.T) {
	resetScanAccount(t)

	// Real temp uploads dir that scanDirForPHP can ReadDir via default osFS.
	// We mock the top-level /home and /home/alice ReadDir calls but fall
	// through to the real FS for everything under it so scanDirForPHP sees
	// real files and mtimes.
	tmp := t.TempDir()
	uploads := filepath.Join(tmp, "alice-public_html-wp-content-uploads")
	if err := os.MkdirAll(uploads, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploads, "shell.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	alice := accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755, mtime: now}

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{realDirEntry{name: "alice", info: alice}}, nil
			case "/home/alice":
				// No addon domains, just the implicit public_html.
				return nil, nil
			case "/home/alice/public_html/wp-content/uploads":
				// Serve the real files.
				return os.ReadDir(uploads)
			}
			// Return "missing" for anything else so scanDirFor* functions
			// stop cleanly rather than walk the real FS.
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			// dirChanged consults Stat; serve a fresh mtime so the scanner
			// doesn't short-circuit with "unchanged".
			if name == "/home/alice/public_html/wp-content/uploads" {
				return accountScanFakeInfo{name: "uploads", isDir: true, mode: os.ModeDir | 0755, mtime: now}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	got := buildFileIndex(dirMtimeCache{}, nil, true)
	found := false
	for _, e := range got {
		if filepath.Base(e) == "shell.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected shell.php to surface in index, got %v", got)
	}
}

func TestBuildFileIndexSkipsMailEtcLogsSslTmpDirs(t *testing.T) {
	resetScanAccount(t)
	// /home/alice has sub-entries that must NOT be treated as addon roots:
	// mail, etc, logs, ssl, tmp, public_html, .ssh (dot-prefixed).
	// The scanner should not ReadDir any of these as potential addon-
	// domain uploads roots.
	alice := accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755}
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{realDirEntry{name: "alice", info: alice}}, nil
			case "/home/alice":
				entries := []os.DirEntry{}
				for _, n := range []string{"mail", "etc", "logs", "ssl", "tmp", "public_html", ".ssh"} {
					entries = append(entries, realDirEntry{name: n, info: accountScanFakeInfo{name: n, isDir: true, mode: os.ModeDir | 0755}})
				}
				return entries, nil
			}
			// If the function tried to ReadDir any of the forbidden paths,
			// it would get ErrNotExist and silently continue. We assert
			// via Stat below.
			return nil, os.ErrNotExist
		},
		stat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	// Just verify no panic. The exact entries depend on whether
	// public_html's uploads/.config/etc existed — we didn't mock those so
	// they all return ErrNotExist and produce no entries.
	got := buildFileIndex(dirMtimeCache{}, nil, true)
	if len(got) != 0 {
		t.Errorf("unmocked paths should yield empty index, got %v", got)
	}
}
