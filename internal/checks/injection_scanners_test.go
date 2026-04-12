package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// fakeDirEntry wraps fakeFileInfo to implement os.DirEntry for mocks.
// (Different from the production fakeDirEntry in account_scan.go which wraps os.FileInfo.)
type testDirEntry struct {
	name  string
	isDir bool
}

func (d testDirEntry) Name() string               { return d.name }
func (d testDirEntry) IsDir() bool                { return d.isDir }
func (d testDirEntry) Type() os.FileMode          { return 0 }
func (d testDirEntry) Info() (os.FileInfo, error) { return fakeFileInfo{name: d.name, size: 100}, nil }

// --- scanForWebshells with mock directory tree ------------------------

func TestScanForWebshellsWithFiles(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice/public_html" {
				return []os.DirEntry{
					testDirEntry{name: "index.php", isDir: false},
					testDirEntry{name: "wso.php", isDir: false},
					testDirEntry{name: ".htaccess", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wso.php") {
				return []byte("<?php system($_GET['cmd']); ?>"), nil
			}
			return []byte("<?php echo 'ok'; ?>"), nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 500}, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 500}, nil
		},
	})

	var findings []alert.Finding
	scanForWebshells(context.Background(), "/home/alice/public_html", 3, nil, nil, &config.Config{}, &findings)
	_ = findings
}

// --- scanHtaccess with mock ------------------------------------------

func TestScanHtaccessWithFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice/public_html" {
				return []os.DirEntry{
					testDirEntry{name: ".htaccess", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, ".htaccess") {
				return []byte("AddHandler application/x-httpd-php .jpg\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	var findings []alert.Finding
	scanHtaccess(context.Background(), "/home/alice/public_html", 3, nil, nil, &config.Config{}, &findings)
	_ = findings
}

// --- scanForSUID with mock -------------------------------------------

func TestScanForSUIDWithFiles(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice/public_html" {
				return []os.DirEntry{
					testDirEntry{name: "suid_binary", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			// Simulate a SUID file
			return fakeFileInfo{name: "suid_binary", size: 1000}, nil
		},
	})

	var findings []alert.Finding
	scanForSUID(context.Background(), "/home/alice/public_html", 3, &findings)
	_ = findings
}

// --- scanDirForObfuscatedPHP with mock --------------------------------

func TestScanDirForObfuscatedPHPWithFiles(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice/public_html" {
				return []os.DirEntry{
					testDirEntry{name: "evil.php", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "evil.php", size: 5000}, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "evil.php") {
				tmp := t.TempDir() + "/evil.php"
				_ = os.WriteFile(tmp, []byte("<?php echo 'clean'; ?>"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), "/home/alice/public_html", 3, &config.Config{}, &findings)
	_ = findings
}

// --- scanErrorLogs with mock -----------------------------------------

func TestScanErrorLogsWithFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{
				testDirEntry{name: "error_log", isDir: false},
			}, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			// 50MB error log
			return fakeFileInfo{name: "error_log", size: 50 * 1024 * 1024}, nil
		},
	})

	var findings []alert.Finding
	scanErrorLogs("/home/alice/public_html", 5*1024*1024, 3, &findings)
	// The stat returns 50MB but the function may also check Info() on
	// DirEntry which uses testDirEntry.Info() returning size=100.
	_ = findings
}

// --- scanGroupWritablePHP with mock ----------------------------------

func TestScanGroupWritablePHPWithFiles(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{
				testDirEntry{name: "config.php", isDir: false},
			}, nil
		},
	})

	webGIDs := map[uint32]bool{33: true}
	var findings []alert.Finding
	scanGroupWritablePHP("/home/alice/public_html", 3, webGIDs, &findings)
	_ = findings
}
