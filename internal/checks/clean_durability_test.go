package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func withHtaccessBackupRoot(t *testing.T) {
	t.Helper()
	old := htaccessBackupDirRoot
	htaccessBackupDirRoot = t.TempDir()
	t.Cleanup(func() { htaccessBackupDirRoot = old })
}

func TestCleanBackupFailurePreservesOriginal(t *testing.T) {
	oldStore := storeQuarantineBackup
	t.Cleanup(func() { storeQuarantineBackup = oldStore })
	for _, kind := range []string{"php", "htaccess", "legacy-htaccess", "crontab"} {
		t.Run(kind, func(t *testing.T) {
			root := mustEvalSymlinks(t, t.TempDir())
			name, content := "infected.php", "<?php\n@include('/tmp/evil.php');\necho 'safe';\n"
			switch kind {
			case "htaccess", "legacy-htaccess":
				name, content = ".htaccess", "# keep\nAddHandler cgi-script .alfa\n# end\n"
				oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
				fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{root}, t.TempDir()
				t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
			case "crontab":
				name, content = "account", "* * * * * /tmp/evil\n"
				withCrontabAllowedRoots(t, root)
			}
			withQuarantineDirCF(t, t.TempDir())
			path := filepath.Join(root, name)
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			storeQuarantineBackup = func(_ string, data []byte, _ any, _ os.FileMode) error {
				called = true
				if string(data) != content {
					t.Fatalf("backup does not contain complete original: %q", data)
				}
				return syscall.EIO
			}
			var success bool
			var resultErr string
			switch kind {
			case "php":
				result := CleanInfectedFile(path)
				success, resultErr = result.Cleaned, result.Error
			case "htaccess":
				result := CleanHtaccessFile(path)
				success, resultErr = result.Success, result.Error
			case "legacy-htaccess":
				result := fixHtaccess(path, "injected directive")
				success, resultErr = result.Success, result.Error
			case "crontab":
				result := fixSuspiciousCrontab(path)
				success, resultErr = result.Success, result.Error
			}
			if !called || success || !strings.Contains(resultErr, syscall.EIO.Error()) {
				t.Fatalf("backup failure not reported: called=%v success=%v error=%q", called, success, resultErr)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != content {
				t.Fatalf("original changed after backup failure: %q, error=%v", data, err)
			}
		})
	}
}

func TestCleanReplacementDurabilityFailureRetainsBackup(t *testing.T) {
	oldClose, oldSync := closeCleanTemp, syncCleanParent
	t.Cleanup(func() { closeCleanTemp, syncCleanParent = oldClose, oldSync })
	for _, phase := range []string{"close", "directory-sync"} {
		t.Run(phase, func(t *testing.T) {
			closeCleanTemp, syncCleanParent = oldClose, oldSync
			withQuarantineDirCF(t, t.TempDir())
			path := filepath.Join(t.TempDir(), "infected.php")
			const original = "<?php\n@include('/tmp/evil.php');\necho 'safe';\n"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			if phase == "close" {
				closeCleanTemp = func(f *os.File) error {
					called = true
					if err := oldClose(f); err != nil {
						t.Fatal(err)
					}
					return syscall.EIO
				}
			} else {
				syncCleanParent = func(int) error { called = true; return syscall.EIO }
			}
			result := CleanInfectedFile(path)
			if !called || result.Cleaned || !strings.Contains(result.Error, syscall.EIO.Error()) {
				t.Fatalf("storage failure not reported: called=%v result=%+v", called, result)
			}
			data, err := os.ReadFile(result.BackupPath)
			if err != nil || string(data) != original {
				t.Fatalf("recovery content changed: %q, error=%v", data, err)
			}
			data, err = os.ReadFile(result.BackupPath + ".meta")
			var meta QuarantineMeta
			if err != nil || json.Unmarshal(data, &meta) != nil || meta.OriginalPath != path || meta.Size != int64(len(original)) {
				t.Fatalf("recovery metadata invalid: %q, error=%v", data, err)
			}
			want := original
			if phase == "directory-sync" {
				want = "<?php\necho 'safe';\n"
				if !strings.Contains(result.Error, "installed") || !strings.Contains(result.Error, "backup retained") {
					t.Fatalf("partial completion omitted: %+v", result)
				}
			}
			data, err = os.ReadFile(path)
			if err != nil || string(data) != want {
				t.Fatalf("unexpected live content: %q, error=%v; want %q", data, err, want)
			}
		})
	}
}

func TestVirtualPatchDirectorySyncFailureRetainsBackup(t *testing.T) {
	root := mustEvalSymlinks(t, t.TempDir())
	oldRoots, oldBackup, oldSync := fixHtaccessAllowedRoots, htaccessBackupDirRoot, syncVirtualPatchDirectory
	fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{root}, t.TempDir()
	t.Cleanup(func() {
		fixHtaccessAllowedRoots, htaccessBackupDirRoot, syncVirtualPatchDirectory = oldRoots, oldBackup, oldSync
	})
	path := filepath.Join(root, ".htaccess")
	const original = "# original directives\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	syncVirtualPatchDirectory = func(string) error { called = true; return syscall.EIO }
	block := buildDenyBlock(".env", false)
	_, err := applyHtaccessDeny(root, block)
	if !called || err == nil || !strings.Contains(err.Error(), "backup retained") {
		t.Fatalf("directory sync failure not reported: called=%v, error=%v", called, err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != original+string(block) {
		t.Fatalf("test did not exercise an installed patch: %q, error=%v", data, readErr)
	}
	entries, readErr := os.ReadDir(htaccessBackupDirRoot)
	if readErr != nil || len(entries) != 2 {
		t.Fatalf("backup content and metadata not retained: %v, error=%v", entries, readErr)
	}
	for _, entry := range entries {
		data, readErr := os.ReadFile(filepath.Join(htaccessBackupDirRoot, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.HasSuffix(entry.Name(), ".meta") {
			var meta QuarantineMeta
			if json.Unmarshal(data, &meta) != nil || meta.OriginalPath != path || meta.ExpectedCurrentSHA256 != virtualPatchSHA256([]byte(original+string(block))) {
				t.Fatalf("invalid recovery metadata: %s", data)
			}
		} else if string(data) != original {
			t.Fatalf("backup changed: %q", data)
		}
	}
}
