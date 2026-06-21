package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// TestCheckFileIndexStampsContentFingerprint verifies that CheckFileIndex
// stamps ContentSHA256 and DetectLogic on content findings (obfuscated_php /
// suspicious_php_content). Without the stamp, Re-check and the stale-content
// sweep cannot auto-clear findings produced by this path.
//
// Harness: real PHP file in a temp uploads dir; mockOS intercepts /home,
// /home/alice, and the uploads ReadDir/Stat calls while falling through to
// real os.Open/os.Stat for temp-dir paths so analyzePHPContent can read the
// file content and FileContentSHA256 can hash it.
func TestCheckFileIndexStampsContentFingerprint(t *testing.T) {
	resetScanAccount(t)

	// -----------------------------------------------------------------------
	// State dir: real temp dir so writeIndex / saveDirCache can create files.
	// We write an empty fileindex.previous so CheckFileIndex sees a prior run
	// and proceeds to diff (rather than returning nil on first-run baseline).
	// -----------------------------------------------------------------------
	stateDir := t.TempDir()
	previousPath := filepath.Join(stateDir, "fileindex.previous")
	if err := os.WriteFile(previousPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	// -----------------------------------------------------------------------
	// Uploads dir: real temp directory that mirrors the layout CheckFileIndex
	// expects.  scanDirForPHPContext reads it via osFS.ReadDir; the file
	// itself is real so analyzePHPContent (osFS.Open) and FileContentSHA256
	// (osFS.Open + osFS.Stat) can work on it.
	// -----------------------------------------------------------------------
	uploadsDir := t.TempDir()
	phpContent := []byte("<?php eval(base64_decode($_POST['x'])); system($_GET['c']);")
	// Use a name that is NOT in isWebshellName so the content-based classifier
	// (classifyUploadPHP -> obfuscated_php / suspicious_php_content) is not
	// overwritten by the name-based "new_webshell_file" check.
	phpFile := filepath.Join(uploadsDir, "cache-loader.php")
	if err := os.WriteFile(phpFile, phpContent, 0644); err != nil {
		t.Fatal(err)
	}

	// The path that CheckFileIndex constructs for this user+uploads combo:
	// /home/alice/public_html/wp-content/uploads/cache-loader.php.
	// We tell the mock to serve our real temp dir when ReadDir is called for
	// that logical path, and to return a real stat for it so dirChanged marks
	// it changed.  All reads of actual file content (Open/Stat on phpFile and
	// stateDir files) fall through to the real FS.
	logicalUploads := "/home/alice/public_html/wp-content/uploads"
	logicalPHPFile := logicalUploads + "/cache-loader.php"

	now := time.Now()
	alice := accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755, mtime: now}

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{realDirEntry{name: "alice", info: alice}}, nil
			case "/home/alice":
				// No addon domains.
				return nil, nil
			case logicalUploads:
				// Serve the real temp dir's entries, but rewrite each entry's
				// path so it appears under the logical uploads path.
				entries, err := os.ReadDir(uploadsDir)
				return entries, err
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			switch name {
			case logicalUploads:
				return accountScanFakeInfo{
					name: "uploads", isDir: true, mode: os.ModeDir | 0755, mtime: now,
				}, nil
			case logicalPHPFile:
				// FileContentSHA256 and the details-stat both call osFS.Stat on
				// the logical path; proxy to the real temp file.
				return os.Stat(phpFile)
			case previousPath:
				// Stat returns a valid (empty) file so CheckFileIndex doesn't
				// treat this as first-run and return nil.
				return os.Stat(previousPath)
			}
			// Fall through to real FS for other state dir files.
			if strings.HasPrefix(name, stateDir) {
				return os.Stat(name)
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			// loadIndex(previousPath) and analyzePHPContent(logicalPHPFile)
			// both call osFS.Open.  State-dir files are real; map the logical
			// PHP path to the real temp file.
			if strings.HasPrefix(name, stateDir) {
				return os.Open(name)
			}
			if name == logicalPHPFile {
				return os.Open(phpFile)
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			// loadDirCache calls osFS.ReadFile; fall through for state dir.
			// copyFile (end-of-scan) calls osFS.ReadFile(currentPath); allow it.
			if strings.HasPrefix(name, stateDir) {
				return os.ReadFile(name)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.StatePath = stateDir

	findings := CheckFileIndex(context.Background(), cfg, nil)

	// -----------------------------------------------------------------------
	// Find the content finding that should have been stamped.
	// -----------------------------------------------------------------------
	var contentFinding *struct {
		check         string
		contentSHA256 string
		detectLogic   string
	}
	for _, f := range findings {
		if f.Check == "obfuscated_php" || f.Check == "suspicious_php_content" {
			contentFinding = &struct {
				check         string
				contentSHA256 string
				detectLogic   string
			}{
				check:         f.Check,
				contentSHA256: f.ContentSHA256,
				detectLogic:   f.DetectLogic,
			}
			break
		}
	}

	if contentFinding == nil {
		// Dump all findings for diagnostics.
		var checks []string
		for _, f := range findings {
			checks = append(checks, f.Check)
		}
		t.Fatalf("expected a content finding (obfuscated_php or suspicious_php_content), got: %v", checks)
	}

	if contentFinding.contentSHA256 == "" {
		t.Errorf("content finding %q: ContentSHA256 is empty, want non-empty SHA256", contentFinding.check)
	}
	if contentFinding.detectLogic == "" {
		t.Errorf("content finding %q: DetectLogic is empty, want non-empty version token", contentFinding.check)
	}
}

func TestCheckFileIndexFingerprintUsesClassifiedContent(t *testing.T) {
	resetScanAccount(t)

	stateDir := t.TempDir()
	previousPath := filepath.Join(stateDir, "fileindex.previous")
	if err := os.WriteFile(previousPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	uploadsDir := t.TempDir()
	maliciousContent := []byte("<?php eval(base64_decode($_POST['x'])); system($_GET['c']);")
	cleanContent := []byte("<?php echo 'clean';")
	phpFile := filepath.Join(uploadsDir, "cache-loader.php")
	if err := os.WriteFile(phpFile, maliciousContent, 0644); err != nil {
		t.Fatal(err)
	}

	logicalUploads := "/home/alice/public_html/wp-content/uploads"
	logicalPHPFile := logicalUploads + "/cache-loader.php"

	now := time.Now()
	alice := accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755, mtime: now}
	swappedAfterClassification := false

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{realDirEntry{name: "alice", info: alice}}, nil
			case "/home/alice":
				return nil, nil
			case logicalUploads:
				return os.ReadDir(uploadsDir)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			switch name {
			case logicalUploads:
				return accountScanFakeInfo{name: "uploads", isDir: true, mode: os.ModeDir | 0755, mtime: now}, nil
			case logicalPHPFile:
				if !swappedAfterClassification {
					if err := os.WriteFile(phpFile, cleanContent, 0644); err != nil {
						return nil, err
					}
					swappedAfterClassification = true
				}
				return os.Stat(phpFile)
			case previousPath:
				return os.Stat(previousPath)
			}
			if strings.HasPrefix(name, stateDir) {
				return os.Stat(name)
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.HasPrefix(name, stateDir) {
				return os.Open(name)
			}
			if name == logicalPHPFile {
				return os.Open(phpFile)
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasPrefix(name, stateDir) {
				return os.ReadFile(name)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.StatePath = stateDir

	findings := CheckFileIndex(context.Background(), cfg, nil)

	var got string
	for _, f := range findings {
		if f.Check == "obfuscated_php" || f.Check == "suspicious_php_content" {
			got = f.ContentSHA256
			break
		}
	}
	want := fmt.Sprintf("%x", sha256.Sum256(maliciousContent))
	if got != want {
		t.Fatalf("ContentSHA256 = %q, want classified content hash %q", got, want)
	}
}
