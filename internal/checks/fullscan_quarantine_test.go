package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// redirectQuarantineForFullScan sets fixQuarantineAllowedRoots and quarantineDir
// to temp dirs for the duration of t, following the same pattern as other
// remediate tests in this package. Never touches real /home or /opt/csm.
//
// On macOS, t.TempDir() may return a path under /var/folders which EvalSymlinks
// resolves to /private/var/folders; we resolve both dirs so the allowed-roots
// check and the quarantine destination are consistent with how resolveExistingFixPath
// sees the path after EvalSymlinks.
func redirectQuarantineForFullScan(t *testing.T) (root, qdir string) {
	t.Helper()
	raw := t.TempDir()
	rawQ := t.TempDir()

	// Resolve symlinks so the allowed-roots check matches the resolved path.
	var err error
	root, err = filepath.EvalSymlinks(raw)
	if err != nil {
		root = raw
	}
	qdir, err = filepath.EvalSymlinks(rawQ)
	if err != nil {
		qdir = rawQ
	}

	oldRoots := fixQuarantineAllowedRoots
	oldQDir := quarantineDir
	fixQuarantineAllowedRoots = []string{root}
	quarantineDir = qdir
	t.Cleanup(func() {
		fixQuarantineAllowedRoots = oldRoots
		quarantineDir = oldQDir
	})
	return root, qdir
}

// TestQuarantineFindingFile_WebshellEligible: webshell finding with real file
// → eligible=true, file moved to quarantine, Success=true.
func TestQuarantineFindingFile_WebshellEligible(t *testing.T) {
	root, qdir := redirectQuarantineForFullScan(t)

	// Create a real file under the redirected root.
	src := filepath.Join(root, "c99.php")
	if err := os.WriteFile(src, []byte("<?php eval($_POST['x']); ?>"), 0644); err != nil {
		t.Fatal(err)
	}

	f := alert.Finding{
		Check:    "webshell",
		FilePath: src,
	}

	result, eligible := QuarantineFindingFile(f)
	if !eligible {
		t.Fatal("webshell finding must be eligible")
	}
	if !result.Success {
		t.Fatalf("expected Success=true, got error: %s", result.Error)
	}
	if result.Action == "" {
		t.Fatal("Action must be non-empty on success")
	}

	// Source file must be gone (moved).
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("source file must be removed after quarantine")
	}

	// Quarantine dir must contain the moved file.
	entries, err := os.ReadDir(qdir)
	if err != nil {
		t.Fatalf("ReadDir quarantine: %v", err)
	}
	var movedFiles []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) != ".meta" {
			movedFiles = append(movedFiles, e.Name())
		}
	}
	if len(movedFiles) == 0 {
		t.Fatal("no quarantined file found in quarantine dir")
	}
}

// TestQuarantineFindingFile_BackdoorBinaryExcluded: backdoor_binary must
// return eligible=false and NEVER kill or quarantine (safety gate).
func TestQuarantineFindingFile_BackdoorBinaryExcluded(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)

	src := filepath.Join(root, "backdoor")
	if err := os.WriteFile(src, []byte("ELF"), 0755); err != nil {
		t.Fatal(err)
	}

	f := alert.Finding{
		Check:    "backdoor_binary",
		FilePath: src,
	}

	_, eligible := QuarantineFindingFile(f)
	if eligible {
		t.Fatal("backdoor_binary must NOT be eligible (kill path excluded)")
	}

	// File must be untouched.
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("backdoor_binary source file must not be touched: %v", err)
	}
}

// TestQuarantineFindingFile_EmptyFilePath: finding with no FilePath → ineligible.
func TestQuarantineFindingFile_EmptyFilePath(t *testing.T) {
	redirectQuarantineForFullScan(t)

	f := alert.Finding{
		Check:    "webshell",
		FilePath: "",
	}

	_, eligible := QuarantineFindingFile(f)
	if eligible {
		t.Fatal("empty FilePath must be ineligible")
	}
}

// TestQuarantineFindingFile_NonMalwareCheck: a non-malware check → ineligible.
func TestQuarantineFindingFile_NonMalwareCheck(t *testing.T) {
	redirectQuarantineForFullScan(t)

	f := alert.Finding{
		Check:    "account_scan_truncated",
		FilePath: "/home/192-0-2-1/some_file.php",
	}

	_, eligible := QuarantineFindingFile(f)
	if eligible {
		t.Fatal("account_scan_truncated must be ineligible")
	}
}
