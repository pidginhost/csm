package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupHtaccessCleanRoots(t *testing.T) string {
	t.Helper()
	prevRoots := fixHtaccessAllowedRoots
	prevBackup := htaccessBackupDirRoot
	t.Cleanup(func() {
		fixHtaccessAllowedRoots = prevRoots
		htaccessBackupDirRoot = prevBackup
	})
	// macOS /var/folders is a symlink to /private/var/folders; the
	// remediation guard resolves to the real path before checking
	// allowed roots, so the test seam needs to mirror that.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	fixHtaccessAllowedRoots = []string{dir}
	htaccessBackupDirRoot = filepath.Join(t.TempDir(), "pre_clean")
	return dir
}

// The cleaner runs as root inside a directory the account owner controls. A
// staging file with a guessable name is an invitation: the attacker plants a
// symlink under that name and the "cleaned" bytes land wherever it points.
func TestCleanHtaccessFileDoesNotFollowPlantedStagingSymlink(t *testing.T) {
	dir := setupHtaccessCleanRoots(t)

	victim := filepath.Join(t.TempDir(), "authorized_keys")
	const victimBody = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOperatorKey operator\n"
	if err := os.WriteFile(victim, []byte(victimBody), 0600); err != nil {
		t.Fatal(err)
	}

	body := "# legit comment\n" +
		"ErrorDocument 404 https://phish.example.tk/oops.html\n" +
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAttackerKey attacker\n"
	path := writeHtaccess(t, dir, "site", body)
	if err := os.Symlink(victim, path+".csm-clean.tmp"); err != nil {
		t.Fatal(err)
	}

	res := CleanHtaccessFile(path)

	after, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != victimBody {
		t.Fatalf("file outside the site was rewritten through the planted symlink:\n%s", after)
	}
	if !res.Success {
		t.Fatalf("Clean: %v", res.Error)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf(".htaccess after clean is not a regular file (mode=%v)", info.Mode())
	}
	cleaned, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cleaned), "phish.example.tk") {
		t.Errorf("phishing ErrorDocument still present after clean")
	}
}

// Replacing the file must not hand the customer a root-owned 0644 file in
// place of the one they had; the replacement keeps the original permission
// bits (ownership is preserved the same way but needs root to observe).
func TestCleanHtaccessFilePreservesOriginalMode(t *testing.T) {
	dir := setupHtaccessCleanRoots(t)
	path := writeHtaccess(t, dir, "site", "ErrorDocument 404 https://phish.example.tk/oops.html\nOptions -Indexes\n")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	if res := CleanHtaccessFile(path); !res.Success {
		t.Fatalf("Clean: %v", res.Error)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("mode after clean = %o, want 0600 preserved", got)
	}
}
