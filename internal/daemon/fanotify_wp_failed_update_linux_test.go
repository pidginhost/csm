//go:build linux

package daemon

import (
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"encoding/hex"
	"fmt"
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

// Neither a recent installed inode nor an owner-controlled metadata change
// links an installed release to the deleted staging tree.
func TestStagedPackageCannotBorrowInstalledIdentity(t *testing.T) {
	for _, kind := range []wpcheck.PackageKind{wpcheck.KindCore, wpcheck.KindPlugin} {
		for _, change := range []string{"recent", "chmod", "copy", "symlink"} {
			t.Run(fmt.Sprintf("kind=%d/%s", kind, change), func(t *testing.T) {
				wpRoot, staging := stagedPluginFixture(t)
				slug, rel := "gtm-kit", "file.php"
				installedRoot := filepath.Join(wpRoot, "wp-content/plugins", slug)
				header := filepath.Join(installedRoot, "gtm-kit.php")
				if kind == wpcheck.KindCore {
					slug, installedRoot = "wordpress", wpRoot
					header = filepath.Join(wpRoot, "wp-includes/version.php")
				}
				writeStagedFile(t, header, "<?php // installed header\n")
				root := filepath.Join(staging, slug)
				path := filepath.Join(root, rel)
				writeStagedFile(t, path, cleanStagedPHP)
				v := wpcheck.Verification{Kind: kind, Root: root, Slug: slug, Rel: rel, Digest: strings.Repeat("a", 32), Verdict: wpcheck.VerdictNoVersion, Staged: true}
				if kind == wpcheck.KindPlugin {
					v.Digest = strings.Repeat("a", 64)
				}
				v.RootInfo, _ = os.Lstat(root)
				fake := &fakeWPVerifier{
					describe: func(path string) wpcheck.Verification {
						if strings.HasPrefix(path, staging+"/") {
							return wpcheck.Verification{Verdict: wpcheck.VerdictUnknown}
						}
						return wpcheck.Verification{Kind: kind, Root: installedRoot, Slug: slug, Version: "1.0", Verdict: wpcheck.VerdictReady}
					},
					verify: func(wpcheck.Verification) wpcheck.Verdict {
						t.Error("deleted tree borrowed an unrelated installed identity")
						return wpcheck.VerdictVerified
					},
				}
				fm, ch := newStagedPackageMonitor(t, fake)
				now := time.Now()
				fm.stagedPackages().now = func() time.Time { return now }
				fm.handleStagedPackageFile(path, v, "")
				switch change {
				case "chmod":
					marker := header
					if kind == wpcheck.KindPlugin {
						marker = installedRoot
					}
					if err := os.Chmod(marker, 0o700); err != nil {
						t.Fatal(err)
					}
				case "copy":
					// Core and plugin copy fallbacks create new inodes; even
					// a real copy cannot prove the origin of a missing header.
					writeStagedFile(t, filepath.Join(installedRoot, rel), cleanStagedPHP)
					writeStagedFile(t, header, "<?php // new installed header\n")
				case "symlink":
					marker := header
					if kind == wpcheck.KindPlugin {
						marker = installedRoot
					}
					if err := os.Rename(marker, marker+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(marker+".old", marker); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.RemoveAll(staging); err != nil {
					t.Fatal(err)
				}
				fm.drainStagedPackages(now.Add(stagedPackageTimeout + time.Second))
				got := drainFindings(ch)
				if len(got) != 1 || got[0].FilePath != staging || !strings.Contains(got[0].Details, "removed before") {
					t.Fatalf("unidentified removal must produce a package warning: %+v", got)
				}
			})
		}
	}
}

func TestStagedRemovedPackageReusedUnknownGenerationIsReported(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	root := filepath.Join(staging, "gtm-kit")
	fake := &fakeWPVerifier{describe: func(string) wpcheck.Verification {
		return wpcheck.Verification{Verdict: wpcheck.VerdictUnknown}
	}}
	fm, ch := newStagedPackageMonitor(t, fake)
	now := time.Now()
	fm.stagedPackages().now = func() time.Time { return now }
	for attempt := 0; attempt < 2; attempt++ {
		// A delayed event may arrive after the directory has been removed,
		// leaving no inode with which to distinguish a reused upload path.
		for _, rel := range []string{"one.php", "two.php"} {
			v := wpcheck.Verification{Root: root, Kind: wpcheck.KindPlugin, Slug: "gtm-kit", Rel: rel, Verdict: wpcheck.VerdictNoVersion, Staged: true}
			fm.handleStagedPackageFile(filepath.Join(root, rel), v, "")
		}
		fm.drainStagedPackages(now.Add(stagedPackageTimeout + time.Second))
		if got := drainFindings(ch); len(got) != 1 {
			t.Fatalf("attempt %d: got %d findings, want one", attempt, len(got))
		}
		now = now.Add(2 * stagedPackageTimeout)
		fm.alertDedup.Clear() // model the expired normal alert cooldown
	}
}

func TestStagedPluginInstalledIdentityMustRemainLinked(t *testing.T) {
	for _, scenario := range []string{"missing-identity", "replaced-during-read"} {
		t.Run(scenario, func(t *testing.T) {
			wpRoot, staging := stagedPluginFixture(t)
			root := filepath.Join(staging, "gtm-kit")
			path := filepath.Join(root, "file.php")
			installed := filepath.Join(wpRoot, "wp-content/plugins/gtm-kit")
			writeStagedFile(t, path, cleanStagedPHP)
			v := wpcheck.Verification{Root: root, Kind: wpcheck.KindPlugin, Slug: "gtm-kit", Rel: "file.php", Verdict: wpcheck.VerdictNoVersion, Staged: true}
			if scenario != "missing-identity" {
				v.RootInfo, _ = os.Lstat(root)
			}
			fake := &fakeWPVerifier{
				describe: func(path string) wpcheck.Verification {
					if strings.HasPrefix(path, staging+"/") {
						return wpcheck.Verification{Verdict: wpcheck.VerdictUnknown}
					}
					if scenario == "replaced-during-read" {
						if err := os.Rename(installed, installed+".moved"); err != nil {
							t.Fatal(err)
						}
						writeStagedFile(t, filepath.Join(installed, "gtm-kit.php"), "<?php // replacement\n")
					}
					return wpcheck.Verification{Kind: wpcheck.KindPlugin, Root: installed, Slug: "gtm-kit", Version: "1.0", Verdict: wpcheck.VerdictReady}
				},
				verify: func(wpcheck.Verification) wpcheck.Verdict {
					t.Error("verified without a stable link to the original directory")
					return wpcheck.VerdictVerified
				},
			}
			fm, ch := newStagedPackageMonitor(t, fake)
			fm.handleStagedPackageFile(path, v, "")
			if err := os.Rename(installed, installed+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(root, installed); err != nil {
				t.Fatal(err)
			}
			fm.drainStagedPackages(time.Now().Add(stagedPackageTimeout + time.Second))
			got := drainFindings(ch)
			// The outer staging directory still exists after a rename.
			if len(got) != 1 || got[0].FilePath != staging || !strings.Contains(got[0].Details, "removed before") || fm.stagedPackages().pendingCount() != 0 {
				t.Fatalf("unidentified moved tree must produce a package warning: %+v", got)
			}
		})
	}
}
