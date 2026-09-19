//go:build linux

package daemon

import (
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/wpcheck"
)

// A core update that WordPress refuses to install (for example because the
// new release needs a newer PHP) is unpacked, checked and deleted. The
// installed version.php still names the old release, so it cannot identify
// the staged files: comparing them against the old manifest reported every
// file of a clean new release as modified, hundreds per failed update.
func TestStagedCorePackageRemovedWithoutInstallIsReportedOnce(t *testing.T) {
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	staging := filepath.Join(wpRoot, "wp-content", "upgrade", "wp_6aadda1fd74e7")
	root := filepath.Join(staging, "wordpress")

	oldBody, newBody := cleanStagedPHP+"// 6.9\n", cleanStagedPHP+"// 7.1\n"
	rels := []string{"wp-admin/about.php", "wp-content/themes/twentytwentyfive/functions.php"}
	cache := wpcheck.NewCache(t.TempDir())
	manifest := map[string]string{}
	for _, rel := range rels {
		sum := md5.Sum([]byte(oldBody)) // #nosec G401 -- official core digest
		manifest[rel] = hex.EncodeToString(sum[:])
		writeStagedFile(t, filepath.Join(wpRoot, rel), oldBody)
	}
	if err := cache.PersistChecksums("6.9", "en_US", nil, manifest); err != nil {
		t.Fatal(err)
	}
	installedHeader := filepath.Join(wpRoot, "wp-includes", "version.php")
	writeStagedFile(t, installedHeader, "<?php $wp_version = '6.9';")
	fm, ch := newStagedPackageMonitor(t, cache)
	// The update runs well after version.php was last written. The inode
	// change time cannot be set back, so move the queue clock forward.
	later := time.Now().Add(time.Hour)
	fm.stagedPackages().now = func() time.Time { return later }
	// Files arrive before the staged version.php, then WordPress deletes the
	// tree without installing it.
	for _, rel := range rels {
		path := filepath.Join(root, rel)
		fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, newBody)})
	}
	if err := os.RemoveAll(staging); err != nil {
		t.Fatal(err)
	}
	fm.drainStagedPackages(later)
	if got := drainFindings(ch); len(got) != 0 {
		t.Fatalf("got %d findings while a late event could still identify the tree, want none: %+v", len(got), got)
	}
	fm.drainStagedPackages(later.Add(stagedPackageTimeout + time.Second))

	got := drainFindings(ch)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want one package warning: %+v", len(got), got)
	}
	if got[0].FilePath != staging || strings.Contains(got[0].Message, "does not match") {
		t.Fatalf("finding = %+v, want the package warning on %s", got[0], staging)
	}
	if !strings.Contains(got[0].Details, "removed before") {
		t.Errorf("Details = %q, want the reason the package could not be identified", got[0].Details)
	}
	if n := fm.stagedPackages().pendingCount(); n != 0 {
		t.Errorf("pending queue holds %d files, want 0", n)
	}
}
