//go:build linux

package daemon

import (
	"crypto/md5" // #nosec G501 -- official WordPress core checksum format
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/wpcheck"
)

// A staged wordpress.org package is judged by hash, not by where it sits.
// Files whose checksums are still being fetched wait in a queue and are
// compared once they land; only files that fail the comparison get their own
// finding. Packages with no checksum source collapse to one finding per
// staging directory. These tests drive that contract through a fake verifier
// so the queue and its fallbacks are exercised without wordpress.org.

type fakeWPVerifier struct {
	mu       sync.Mutex
	describe func(path string) wpcheck.Verification
	verify   func(v wpcheck.Verification) wpcheck.Verdict
}

func (f *fakeWPVerifier) Describe(path string) wpcheck.Verification {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.describe(path)
	if v.RootInfo == nil {
		v.RootInfo, _ = os.Lstat(v.Root)
	}
	v.Staged = parseWPStagedPackage(path).dir != ""
	return v
}

func (f *fakeWPVerifier) Verify(v wpcheck.Verification) wpcheck.Verdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verify(v)
}

func (f *fakeWPVerifier) VerifyFile(_ int, path string) wpcheck.Verification {
	v := f.Describe(path)
	switch v.Verdict {
	case wpcheck.VerdictNoVersion, wpcheck.VerdictPending, wpcheck.VerdictReady:
		if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- test fixture path
			sum := sha256.Sum256(data)
			v.Digest = hex.EncodeToString(sum[:])
		}
	}
	if v.Verdict == wpcheck.VerdictReady {
		v.Verdict = f.Verify(v)
	}
	return v
}

// describeStagedPlugin classifies any file below staging/<slug>/ as that
// plugin at the given version with the given verdict.
func describeStagedPlugin(staging, slug, version string, verdict wpcheck.Verdict) func(string) wpcheck.Verification {
	root := filepath.Join(staging, slug)
	return func(path string) wpcheck.Verification {
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return wpcheck.Verification{Verdict: wpcheck.VerdictUnknown}
		}
		return wpcheck.Verification{Verdict: verdict, Kind: wpcheck.KindPlugin, Root: root, Slug: slug, Version: version, Rel: rel}
	}
}

func newStagedPackageMonitor(t *testing.T, v wpVerifier) (*FileMonitor, chan alert.Finding) {
	t.Helper()
	wpPathStatCache.Clear()
	ch := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch, wpCache: v}
	return fm, ch
}

func stagedPluginFixture(t *testing.T) (wpRoot, staging string) {
	t.Helper()
	wpRoot = filepath.Join(t.TempDir(), "public_html")
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins", "gtm-kit"), 0o755); err != nil {
		t.Fatal(err)
	}
	return wpRoot, filepath.Join(wpRoot, "wp-content", "upgrade", "gtm-kit.2.18.1")
}

func analyzeStaged(t *testing.T, fm *FileMonitor, path string) {
	t.Helper()
	fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, cleanStagedPHP)})
}

func TestStagedPackagePendingThenVerifiedIsSilent(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	landed := false
	fake := &fakeWPVerifier{
		describe: describeStagedPlugin(staging, "gtm-kit", "2.18.1", wpcheck.VerdictPending),
		verify: func(wpcheck.Verification) wpcheck.Verdict {
			if landed {
				return wpcheck.VerdictVerified
			}
			return wpcheck.VerdictPending
		},
	}
	fm, ch := newStagedPackageMonitor(t, fake)

	for _, rel := range []string{"inc/frontend-functions.php", "gtm-kit.php", "src/Admin/Analytics.php"} {
		analyzeStaged(t, fm, filepath.Join(staging, "gtm-kit", rel))
	}
	if got := drainFindings(ch); len(got) != 0 {
		t.Fatalf("got %d findings while checksums are pending, want none: %+v", len(got), got)
	}
	if n := fm.stagedPackages().pendingCount(); n != 3 {
		t.Fatalf("pending queue holds %d files, want 3", n)
	}

	fake.mu.Lock()
	landed = true
	fake.mu.Unlock()
	fm.drainStagedPackages(time.Now())

	if got := drainFindings(ch); len(got) != 0 {
		t.Fatalf("got %d findings for a stock package, want none: %+v", len(got), got)
	}
	if n := fm.stagedPackages().pendingCount(); n != 0 {
		t.Errorf("pending queue holds %d files after verification, want 0", n)
	}
}

func TestStagedPackageMismatchAlertsOnlyTheDifferingFile(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	fake := &fakeWPVerifier{
		describe: describeStagedPlugin(staging, "gtm-kit", "2.18.1", wpcheck.VerdictPending),
		verify: func(v wpcheck.Verification) wpcheck.Verdict {
			if v.Rel == filepath.Join("inc", "evil.php") {
				return wpcheck.VerdictMismatch
			}
			return wpcheck.VerdictVerified
		},
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	evil := filepath.Join(staging, "gtm-kit", "inc", "evil.php")
	for _, path := range []string{
		filepath.Join(staging, "gtm-kit", "gtm-kit.php"),
		evil,
		filepath.Join(staging, "gtm-kit", "src", "Admin", "Analytics.php"),
	} {
		analyzeStaged(t, fm, path)
	}
	fm.drainStagedPackages(time.Now())

	got := drainFindings(ch)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want exactly the mismatched file: %+v", len(got), got)
	}
	f := got[0]
	if f.Check != "php_in_sensitive_dir_realtime" || f.Severity != alert.Warning || f.FilePath != evil {
		t.Errorf("finding = %+v, want a Warning on %s", f, evil)
	}
	if !strings.Contains(f.Message, "does not match wordpress.org gtm-kit 2.18.1") {
		t.Errorf("Message = %q, want the package it fails against", f.Message)
	}
}

func TestStagedPackageMismatchKnownAtEventTimeAlertsImmediately(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	fake := &fakeWPVerifier{
		describe: describeStagedPlugin(staging, "gtm-kit", "2.18.1", wpcheck.VerdictReady),
		verify: func(v wpcheck.Verification) wpcheck.Verdict {
			if v.Rel == "gtm-kit.php" {
				return wpcheck.VerdictVerified
			}
			return wpcheck.VerdictMismatch
		},
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	analyzeStaged(t, fm, filepath.Join(staging, "gtm-kit", "gtm-kit.php"))
	extra := filepath.Join(staging, "gtm-kit", "inc", "extra.php")
	analyzeStaged(t, fm, extra)

	got := drainFindings(ch)
	if len(got) != 1 || got[0].FilePath != extra {
		t.Fatalf("got %+v, want one immediate Warning on %s", got, extra)
	}
	if n := fm.stagedPackages().pendingCount(); n != 0 {
		t.Errorf("pending queue holds %d files, want 0: nothing was pending", n)
	}
}

func TestStagedPackageNotOnWordPressOrgCollapsesToOnePackageWarning(t *testing.T) {
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins", "js_composer"), 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(wpRoot, "wp-content", "upgrade", "js_composer-jhi6eq")
	fake := &fakeWPVerifier{
		describe: describeStagedPlugin(staging, "js_composer", "8.0", wpcheck.VerdictUnavailable),
		verify:   func(wpcheck.Verification) wpcheck.Verdict { return wpcheck.VerdictUnavailable },
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	for _, rel := range []string{"js_composer.php", "include/classes/core.php", "include/classes/editors.php"} {
		analyzeStaged(t, fm, filepath.Join(staging, "js_composer", rel))
	}

	got := drainFindings(ch)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want one for the package: %+v", len(got), got)
	}
	f := got[0]
	if f.FilePath != staging || f.Severity != alert.Warning {
		t.Errorf("finding = %+v, want a Warning on the staging directory %s", f, staging)
	}
	if !strings.Contains(f.Details, "not published on wordpress.org") || !strings.Contains(f.Details, "updates installed plugin js_composer") {
		t.Errorf("Details = %q, want the reason and that it updates an installed plugin", f.Details)
	}
	if n := fm.stagedPackages().pendingCount(); n != 0 {
		t.Errorf("pending queue holds %d files, want 0", n)
	}
}

// The plugin header can sit late in the ZIP, and WordPress renames the whole
// staged tree into place a few hundred milliseconds after unpacking it. A file
// queued before its package could be identified must still be verified from
// the installed location.
func TestStagedPackageIdentifiedLateVerifiesFromInstalledPath(t *testing.T) {
	wpRoot, staging := stagedPluginFixture(t)
	installedRoot := filepath.Join(wpRoot, "wp-content", "plugins", "gtm-kit")
	fake := &fakeWPVerifier{
		describe: func(path string) wpcheck.Verification {
			if rel, err := filepath.Rel(installedRoot, path); err == nil && !strings.HasPrefix(rel, "..") {
				return wpcheck.Verification{Verdict: wpcheck.VerdictReady, Kind: wpcheck.KindPlugin, Root: installedRoot, Slug: "gtm-kit", Version: "2.18.1", Rel: rel}
			}
			v := describeStagedPlugin(staging, "gtm-kit", "", wpcheck.VerdictNoVersion)(path)
			return v
		},
		verify: func(wpcheck.Verification) wpcheck.Verdict { return wpcheck.VerdictVerified },
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	staged := filepath.Join(staging, "gtm-kit", "inc", "frontend-functions.php")
	analyzeStaged(t, fm, staged)
	if got := drainFindings(ch); len(got) != 0 {
		t.Fatalf("got %d findings before the package was identified, want none: %+v", len(got), got)
	}

	// WordPress parks the old tree under upgrade-temp-backup/ and renames
	// the new one into place.
	backup := filepath.Join(wpRoot, "wp-content", "upgrade-temp-backup", "plugins", "gtm-kit")
	if err := os.MkdirAll(filepath.Dir(backup), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(installedRoot, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(staging, "gtm-kit"), installedRoot); err != nil {
		t.Fatal(err)
	}
	fm.drainStagedPackages(time.Now())

	if got := drainFindings(ch); len(got) != 0 {
		t.Fatalf("got %d findings for a stock file verified after the move, want none: %+v", len(got), got)
	}
	if n := fm.stagedPackages().pendingCount(); n != 0 {
		t.Errorf("pending queue holds %d files, want 0", n)
	}
}

func TestStagedPackageMismatchReportsInstalledPathAfterMove(t *testing.T) {
	wpRoot, staging := stagedPluginFixture(t)
	fake := &fakeWPVerifier{
		describe: describeStagedPlugin(staging, "gtm-kit", "2.18.1", wpcheck.VerdictPending),
		verify:   func(wpcheck.Verification) wpcheck.Verdict { return wpcheck.VerdictMismatch },
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	staged := filepath.Join(staging, "gtm-kit", "inc", "evil.php")
	analyzeStaged(t, fm, staged)

	installed := filepath.Join(wpRoot, "wp-content", "plugins", "gtm-kit", "inc", "evil.php")
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, installed); err != nil {
		t.Fatal(err)
	}
	fm.drainStagedPackages(time.Now())

	got := drainFindings(ch)
	if len(got) != 1 || got[0].FilePath != installed {
		t.Fatalf("got %+v, want one Warning on the installed path %s", got, installed)
	}
	if !strings.Contains(got[0].Details, staged) {
		t.Errorf("Details = %q, want the staged origin", got[0].Details)
	}
}

func TestStagedPackagePendingTimesOutToPackageWarning(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	fake := &fakeWPVerifier{
		describe: describeStagedPlugin(staging, "gtm-kit", "2.18.1", wpcheck.VerdictPending),
		verify:   func(wpcheck.Verification) wpcheck.Verdict { return wpcheck.VerdictPending },
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	for _, rel := range []string{"gtm-kit.php", "inc/a.php"} {
		analyzeStaged(t, fm, filepath.Join(staging, "gtm-kit", rel))
	}
	fm.drainStagedPackages(time.Now().Add(stagedPackageTimeout / 2))
	if got := drainFindings(ch); len(got) != 0 {
		t.Fatalf("got %d findings before the timeout, want none: %+v", len(got), got)
	}

	fm.drainStagedPackages(time.Now().Add(stagedPackageTimeout + time.Second))
	got := drainFindings(ch)
	if len(got) != 1 || got[0].FilePath != staging {
		t.Fatalf("got %+v, want one package Warning on %s", got, staging)
	}
	if !strings.Contains(got[0].Details, "checksums not fetched") {
		t.Errorf("Details = %q, want the timeout reason", got[0].Details)
	}
	if n := fm.stagedPackages().pendingCount(); n != 0 {
		t.Errorf("pending queue holds %d files after timeout, want 0", n)
	}
}

func TestStagedPackageQueueFullFallsBackToPackageWarning(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	fake := &fakeWPVerifier{
		describe: describeStagedPlugin(staging, "gtm-kit", "2.18.1", wpcheck.VerdictPending),
		verify:   func(wpcheck.Verification) wpcheck.Verdict { return wpcheck.VerdictPending },
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	fm.wpPending = newStagedPackageQueue(1)
	analyzeStaged(t, fm, filepath.Join(staging, "gtm-kit", "gtm-kit.php"))
	analyzeStaged(t, fm, filepath.Join(staging, "gtm-kit", "inc", "a.php"))

	got := drainFindings(ch)
	if len(got) != 1 || got[0].FilePath != staging {
		t.Fatalf("got %+v, want one package Warning once the queue is full", got)
	}
	if !strings.Contains(got[0].Details, "queue full") {
		t.Errorf("Details = %q, want the queue-full reason", got[0].Details)
	}
}

func TestStagedPackageWithoutVerifierCollapsesToOnePackageWarning(t *testing.T) {
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(wpRoot, "wp-content", "upgrade", "not-installed.1.0")
	fm, ch := newStagedPackageMonitor(t, nil)
	for _, rel := range []string{"one.php", "two.php"} {
		analyzeStaged(t, fm, filepath.Join(staging, "not-installed", rel))
	}

	got := drainFindings(ch)
	if len(got) != 1 || got[0].FilePath != staging {
		t.Fatalf("got %+v, want one package Warning on %s", got, staging)
	}
	if !strings.Contains(got[0].Details, "new install") {
		t.Errorf("Details = %q, want it marked as a new install", got[0].Details)
	}
}

func TestParseWPStagedPackageShapes(t *testing.T) {
	upgrade := "/home/u/public_html/wp-content/upgrade"
	tests := []struct {
		name         string
		path         string
		wantDir      string
		wantUnpacked string
	}{
		{"plugin package", upgrade + "/cookie-law-info.3.5.5/cookie-law-info/legacy/loader.php", upgrade + "/cookie-law-info.3.5.5", "cookie-law-info"},
		{"core uniqid package", upgrade + "/wp_6a9e080f774ec/wordpress/wp-login.php", upgrade + "/wp_6a9e080f774ec", "wordpress"},
		{"unknown package still parses", upgrade + "/totally-not-a-plugin.1.0/totally-not-a-plugin/shell.php", upgrade + "/totally-not-a-plugin.1.0", "totally-not-a-plugin"},
		{"file directly in upgrade", upgrade + "/version-current.php", "", ""},
		{"package directory with no unpacked tree", upgrade + "/cookie-law-info.3.5.5/loose.php", "", ""},
		{"rollback backup is not staging", "/home/u/public_html/wp-content/upgrade-temp-backup/plugins/x/loader.php", "", ""},
		{"installed plugin", "/home/u/public_html/wp-content/plugins/x/loader.php", "", ""},
		{"installed plugin upgrade fixture", "/home/u/public_html/wp-content/plugins/x/fixtures/wp-content/upgrade/package/inner/loader.php", "", ""},
		{"staged core bundled plugin", upgrade + "/core/wordpress/wp-content/plugins/x/loader.php", upgrade + "/core", "wordpress"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkg := parseWPStagedPackage(tc.path)
			if pkg.dir != tc.wantDir || pkg.unpacked != tc.wantUnpacked {
				t.Errorf("parseWPStagedPackage(%q) = %+v, want dir %q unpacked %q", tc.path, pkg, tc.wantDir, tc.wantUnpacked)
			}
			if tc.wantDir != "" && pkg.wpRoot != "/home/u/public_html" {
				t.Errorf("wpRoot = %q, want /home/u/public_html", pkg.wpRoot)
			}
		})
	}
}

// WordPress moves the old plugin to upgrade-temp-backup/ before it renames
// the new tree in, so during that window the installed directory is absent.
// The rollback copy proves the update just as well.
func TestWPPackageInstalledAcceptsRollbackBackup(t *testing.T) {
	wpPathStatCache.Clear()
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "upgrade-temp-backup", "plugins", "gtm-kit"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !wpPackageInstalled(wpRoot, "gtm-kit") {
		t.Error("wpPackageInstalled = false with the rollback copy present, want true")
	}
	if wpPackageInstalled(wpRoot, "other-plugin") {
		t.Error("wpPackageInstalled = true for a slug installed nowhere, want false")
	}
	if wpPackageInstalled(wpRoot, "wordpress") {
		t.Error("wpPackageInstalled = true for core without wp-includes/version.php, want false")
	}
}

// A negative stat during an update is transient by definition: the old
// directory is gone for a few hundred milliseconds. It must not be cached for
// the same five minutes a positive answer is.
func TestCachedPathExistsRetriesNegativeSoon(t *testing.T) {
	wpPathStatCache.Clear()
	path := filepath.Join(t.TempDir(), "plugins", "gtm-kit")
	if cachedPathExists(path) {
		t.Fatal("path exists before creation")
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if cachedPathExists(path) {
		t.Fatal("a fresh negative answer must be served from cache")
	}
	wpPathStatCache.Store(path, wpPathCacheEntry{exists: false, ts: time.Now().Add(-wpPathNegativeTTL - time.Millisecond)})
	if !cachedPathExists(path) {
		t.Error("an expired negative answer must be re-checked")
	}
	wpPathStatCache.Store(path, wpPathCacheEntry{exists: true, ts: time.Now().Add(-wpPathNegativeTTL - time.Second)})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !cachedPathExists(path) {
		t.Error("a positive answer keeps the long TTL")
	}
}

func TestStagedPackageLateIdentityKeepsDeletedFileDigest(t *testing.T) {
	for _, kind := range []wpcheck.PackageKind{wpcheck.KindPlugin, wpcheck.KindCore} {
		for _, source := range []string{"installed-header", "staged-event", "installed-event"} {
			t.Run(fmt.Sprintf("kind=%d/source=%s", kind, source), func(t *testing.T) {
				usePackageIdentity := source != "installed-header"
				wpRoot, staging := stagedPluginFixture(t)
				slug, rel := "gtm-kit", "inc/deleted.php"
				installed := filepath.Join(wpRoot, "wp-content", "plugins", slug, rel)
				if kind == wpcheck.KindCore {
					slug, rel = "wordpress", "wp-admin/deleted.php"
					installed = filepath.Join(wpRoot, "wp-includes", "version.php")
				}
				staged := filepath.Join(staging, slug, rel)
				initial := wpcheck.Verification{Verdict: wpcheck.VerdictNoVersion, Kind: kind, Root: filepath.Join(staging, slug), Slug: slug, Rel: rel, Digest: strings.Repeat("a", 64), Staged: true}
				if kind == wpcheck.KindCore {
					initial.Digest = strings.Repeat("a", 32)
				}
				resolved := initial
				resolved.Verdict, resolved.Version, resolved.Locale = wpcheck.VerdictReady, "7.1", "ro_RO"
				if source != "staged-event" {
					resolved.Root = strings.TrimSuffix(installed, "/"+rel)
					if kind == wpcheck.KindCore {
						resolved.Root, resolved.Rel = wpRoot, "wp-includes/version.php"
					}
				}
				ready, compared := false, false
				fake := &fakeWPVerifier{
					describe: func(path string) wpcheck.Verification {
						if ready && path == installed {
							v := resolved
							if usePackageIdentity {
								v.Version = "6.9" // the installed copy may still be the old release
							}
							return v
						}
						return wpcheck.Verification{Verdict: wpcheck.VerdictUnknown}
					},
					verify: func(v wpcheck.Verification) wpcheck.Verdict {
						compared = true
						if v.Digest != initial.Digest || v.Rel != rel || v.Kind != kind || v.Locale != resolved.Locale || v.Version != resolved.Version || !v.Staged {
							t.Errorf("verification lost event identity: %+v", v)
						}
						return wpcheck.VerdictMismatch
					},
				}
				fm, ch := newStagedPackageMonitor(t, fake)
				if err := os.MkdirAll(initial.Root, 0o755); err != nil {
					t.Fatal(err)
				}
				initial.RootInfo, _ = os.Lstat(initial.Root)
				resolved.RootInfo = initial.RootInfo
				fm.handleStagedPackageFile(staged, initial, "")
				fm.drainStagedPackages(time.Now())
				if fm.stagedPackages().pendingCount() != 1 || compared {
					t.Fatal("unresolved entry was not kept waiting")
				}
				ready = true
				if !usePackageIdentity {
					// Only an installed tree can name the release: WordPress
					// writes version.php, or renames the plugin into place.
					if kind == wpcheck.KindCore {
						writeStagedFile(t, installed, "<?php $wp_version = '7.1';")
					} else {
						pluginDir := filepath.Join(wpRoot, "wp-content", "plugins", slug)
						if err := os.Rename(pluginDir, pluginDir+".old"); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(pluginDir, 0o755); err != nil {
							t.Fatal(err)
						}
					}
				}
				if usePackageIdentity {
					// Another file carried the header before the package disappeared.
					resolved.Verdict = wpcheck.VerdictVerified
					pkg := parseWPStagedPackage(staged)
					key, _ := fm.stagedPackages().note(pkg, initial, time.Now())
					fm.stagedPackages().record(pkg, key, resolved, time.Now())
				}
				if err := os.RemoveAll(initial.Root); err != nil {
					t.Fatal(err)
				}
				fm.drainStagedPackages(time.Now())
				got := drainFindings(ch)
				if !compared || len(got) != 1 || got[0].FilePath != staged || fm.stagedPackages().pendingCount() != 0 {
					t.Fatalf("deleted mismatch: compared=%v findings=%+v pending=%d", compared, got, fm.stagedPackages().pendingCount())
				}
			})
		}
	}
}

func TestStagedPackageQueueCountsDrainingFiles(t *testing.T) {
	q := newStagedPackageQueue(2)
	if !q.push(stagedPackageFile{path: "first"}) {
		t.Fatal("first push rejected")
	}
	files := q.take(time.Now())
	var workers sync.WaitGroup
	accepted := make(chan string, 16)
	for i := range 16 {
		workers.Go(func() {
			path := fmt.Sprintf("worker-%d", i)
			if q.push(stagedPackageFile{path: path}) {
				accepted <- path
			}
		})
	}
	workers.Wait()
	close(accepted)
	want := map[string]bool{"first": true}
	for path := range accepted {
		want[path] = true
	}
	if len(want) != 2 {
		t.Errorf("accepted %d total entries with limit 2 while draining", len(want))
	}
	q.requeue(files, time.Now())
	got := q.take(time.Now())
	if len(got) != len(want) || got[0].path != "first" {
		t.Fatalf("requeue lost entries or order: %+v, want %v", got, want)
	}
	for _, f := range got {
		if !want[f.path] {
			t.Errorf("duplicate or unexpected entry %s", f.path)
		}
		delete(want, f.path)
	}
	if len(want) != 0 {
		t.Errorf("lost entries: %v", want)
	}
	q.requeue(nil, time.Now())
	if !q.push(stagedPackageFile{path: "after-drain"}) {
		t.Error("completed drain did not release capacity")
	}
}

func TestStagedPackageIdentityCannotComeFromSiblingTree(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	path := filepath.Join(staging, "gtm-kit", "extra.php")
	fake := &fakeWPVerifier{
		describe: func(string) wpcheck.Verification { return wpcheck.Verification{Verdict: wpcheck.VerdictUnknown} },
		verify: func(wpcheck.Verification) wpcheck.Verdict {
			t.Error("unidentified file borrowed a sibling's package identity")
			return wpcheck.VerdictVerified
		},
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	v := wpcheck.Verification{Verdict: wpcheck.VerdictNoVersion, Kind: wpcheck.KindPlugin, Root: filepath.Join(staging, "gtm-kit"), Slug: "gtm-kit", Rel: "extra.php", Digest: strings.Repeat("a", 64)}
	fm.handleStagedPackageFile(path, v, "")
	sibling := parseWPStagedPackage(filepath.Join(staging, "other", "other.php"))
	v.Root, v.Slug, v.Version, v.Verdict = filepath.Join(staging, "other"), "other", "1.0", wpcheck.VerdictVerified
	fm.stagedPackages().note(sibling, v, time.Now())
	fm.drainStagedPackages(time.Now())
	if fm.stagedPackages().pendingCount() != 1 || len(drainFindings(ch)) != 0 {
		t.Fatal("unidentified file did not remain queued")
	}
}

func TestStagedPackageMismatchDoesNotDiscardInertContent(t *testing.T) {
	for _, body := range []string{"<?php // placeholder\n", "<?php return array('a' => 'b');"} {
		_, staging := stagedPluginFixture(t)
		fake := &fakeWPVerifier{
			describe: describeStagedPlugin(staging, "gtm-kit", "2.18.1", wpcheck.VerdictReady),
			verify:   func(wpcheck.Verification) wpcheck.Verdict { return wpcheck.VerdictMismatch },
		}
		fm, ch := newStagedPackageMonitor(t, fake)
		path := filepath.Join(staging, "gtm-kit", "extra.php")
		fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, body)})
		if got := drainFindings(ch); len(got) != 1 || got[0].FilePath != path {
			t.Errorf("mismatching inert content findings = %+v, want per-file warning", got)
		}
	}
}

func TestStagedPackageCoreResolvesAfterMoveWithoutStagedHeader(t *testing.T) {
	for _, rel := range []string{"index.php", "extra.php", "wp-content/plugins/akismet/extra.php"} {
		t.Run(rel, func(t *testing.T) {
			wpRoot := filepath.Join(t.TempDir(), "public_html")
			staging := filepath.Join(wpRoot, "wp-content", "upgrade", "wp_random", "wordpress")
			path := filepath.Join(staging, rel)
			cache := wpcheck.NewCache(t.TempDir())
			stock := cleanStagedPHP
			sum := md5.Sum([]byte(stock)) // #nosec G401 -- official core digest
			manifest := map[string]string{rel: hex.EncodeToString(sum[:])}
			if err := cache.PersistChecksums("7.1", "en_US", nil, manifest); err != nil {
				t.Fatal(err)
			}
			fm, ch := newStagedPackageMonitor(t, cache)
			// Hash the modified event before either the header or installed copy exists.
			fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, stock+"// changed\n")})
			if fm.stagedPackages().pendingCount() != 1 {
				t.Fatal("staged file was not retained before version.php existed")
			}
			installed := filepath.Join(wpRoot, rel)
			if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, installed); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(staging); err != nil {
				t.Fatal(err)
			}
			// A replacement at the installed path cannot erase the original mismatch.
			writeStagedFile(t, installed, stock)
			writeStagedFile(t, filepath.Join(wpRoot, "wp-includes", "version.php"), "<?php $wp_version = '7.1';")
			fm.drainStagedPackages(time.Now())
			got := drainFindings(ch)
			if len(got) != 1 || got[0].FilePath != installed || !strings.Contains(got[0].Message, "does not match") {
				t.Fatalf("findings = %+v, want retained core mismatch on %s", got, installed)
			}
			if fm.stagedPackages().pendingCount() != 0 {
				t.Fatal("resolved core mismatch remains queued")
			}
		})
	}
}

func TestStagedPackageWarningsDoNotInventScanResults(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	fm, ch := newStagedPackageMonitor(t, nil)
	path := filepath.Join(staging, "gtm-kit", "file.php")
	v := wpcheck.Verification{Verdict: wpcheck.VerdictUnavailable, Kind: wpcheck.KindPlugin, Slug: "gtm-kit", Version: "2.18.1", Rel: "file.php"}
	fm.handleStagedPackageFile(path, v, "")
	v.Verdict = wpcheck.VerdictUnverifiable
	fm.handleStagedPackageFile(path, v, "")
	got := drainFindings(ch)
	if len(got) != 2 {
		t.Fatalf("findings = %+v, want package and file warnings", got)
	}
	if strings.Contains(got[0].Details, "none was flagged") {
		t.Error("one content-clean event cannot declare every file in a package clean")
	}
	if strings.Contains(got[1].Details, "larger than") {
		t.Error("an absent digest does not prove the file exceeds the size cap")
	}
}

func TestStagedPackageWaitsForItsOwnRelease(t *testing.T) {
	for _, oldContent := range []bool{false, true} {
		t.Run(fmt.Sprint(oldContent), func(t *testing.T) {
			wpRoot, staging := stagedPluginFixture(t)
			root := filepath.Join(staging, "wordpress")
			rel := "wp-admin/file.php"
			oldBody, newBody := cleanStagedPHP+"// old\n", cleanStagedPHP+"// new\n"
			cache := wpcheck.NewCache(t.TempDir())
			for version, body := range map[string]string{"6.9": oldBody, "7.1": newBody} {
				sum := md5.Sum([]byte(body)) // #nosec G401 -- official core digest
				if err := cache.PersistChecksums(version, "en_US", nil, map[string]string{rel: hex.EncodeToString(sum[:])}); err != nil {
					t.Fatal(err)
				}
			}
			writeStagedFile(t, filepath.Join(wpRoot, "wp-includes/version.php"), "<?php $wp_version = '6.9';")
			fm, ch := newStagedPackageMonitor(t, cache)
			body := newBody
			if oldContent {
				body = oldBody
			}
			path := filepath.Join(root, rel)
			fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, body)})
			fm.drainStagedPackages(time.Now())
			if fm.stagedPackages().pendingCount() != 1 || len(drainFindings(ch)) != 0 {
				t.Fatal("unfinished staged package was compared against the old installed release")
			}
			writeStagedFile(t, filepath.Join(root, "wp-includes/version.php"), "<?php $wp_version = '7.1';")
			fm.drainStagedPackages(time.Now())
			got := drainFindings(ch)
			if oldContent {
				if len(got) != 1 || got[0].FilePath != path {
					t.Fatalf("old release content must mismatch the staged release: %+v", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("stock new release content must verify: %+v", got)
			}
			if fm.stagedPackages().pendingCount() != 0 {
				t.Fatal("identified package remains queued")
			}
		})
	}
}

func TestStagedPackageRecreatedTreeCannotReuseIdentity(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	root := filepath.Join(staging, "gtm-kit")
	path := filepath.Join(root, "file.php")
	writeStagedFile(t, path, cleanStagedPHP)
	initial := wpcheck.Verification{Verdict: wpcheck.VerdictNoVersion, Kind: wpcheck.KindPlugin, Root: root, Slug: "gtm-kit", Rel: "file.php", Digest: strings.Repeat("a", 64)}
	old := initial
	old.RootInfo, _ = os.Lstat(root)
	old.Verdict, old.Version = wpcheck.VerdictReady, "1.0"
	fake := &fakeWPVerifier{
		describe: func(string) wpcheck.Verification { return initial },
		verify: func(wpcheck.Verification) wpcheck.Verdict {
			t.Error("replacement tree reused an old package identity")
			return wpcheck.VerdictVerified
		},
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	fm.stagedPackages().note(parseWPStagedPackage(path), old, time.Now())
	if err := os.Rename(root, root+"-old"); err != nil {
		t.Fatal(err)
	}
	writeStagedFile(t, path, cleanStagedPHP)
	initial.RootInfo, _ = os.Lstat(root)
	fm.handleStagedPackageFile(path, initial, "")
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	fm.drainStagedPackages(time.Now())
	if fm.stagedPackages().pendingCount() != 1 || len(drainFindings(ch)) != 0 {
		t.Fatal("replacement tree did not keep waiting for its own identity")
	}
}

func TestStagedPackageRetainsEachUnpackedIdentity(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	compared := 0
	fake := &fakeWPVerifier{
		describe: func(string) wpcheck.Verification { return wpcheck.Verification{Verdict: wpcheck.VerdictUnknown} },
		verify: func(v wpcheck.Verification) wpcheck.Verdict {
			compared++
			if v.Version != "1.0" || v.Digest != strings.Repeat("a", 64) {
				t.Errorf("lost file evidence: %+v", v)
			}
			return wpcheck.VerdictMismatch
		},
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	for _, slug := range []string{"one", "two"} {
		path := filepath.Join(staging, slug, "file.php")
		writeStagedFile(t, path, cleanStagedPHP)
		v := wpcheck.Verification{Verdict: wpcheck.VerdictNoVersion, Kind: wpcheck.KindPlugin, Root: filepath.Join(staging, slug), Slug: slug, Rel: "file.php", Digest: strings.Repeat("a", 64)}
		v.RootInfo, _ = os.Lstat(v.Root)
		fm.handleStagedPackageFile(path, v, "")
		v.Version, v.Verdict = "1.0", wpcheck.VerdictReady
		fm.stagedPackages().note(parseWPStagedPackage(path), v, time.Now())
	}
	if err := os.RemoveAll(staging); err != nil {
		t.Fatal(err)
	}
	fm.drainStagedPackages(time.Now())
	got := drainFindings(ch)
	if compared != 2 || len(got) != 2 || got[0].FilePath == got[1].FilePath || fm.stagedPackages().pendingCount() != 0 {
		t.Fatalf("sibling identities overwritten: compared=%d findings=%+v", compared, got)
	}
}

func TestStagedPackageMissingGenerationCannotUseRecreatedTree(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	root := filepath.Join(staging, "gtm-kit")
	path := filepath.Join(root, "file.php")
	v := wpcheck.Verification{Verdict: wpcheck.VerdictNoVersion, Kind: wpcheck.KindPlugin, Root: root, Slug: "gtm-kit", Rel: "file.php", Digest: strings.Repeat("a", 64)}
	fake := &fakeWPVerifier{
		describe: func(string) wpcheck.Verification {
			fresh := v
			fresh.Verdict, fresh.Version = wpcheck.VerdictReady, "2.0"
			return fresh
		},
		verify: func(wpcheck.Verification) wpcheck.Verdict {
			t.Error("unidentified old event was verified against a recreated tree")
			return wpcheck.VerdictVerified
		},
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	fm.handleStagedPackageFile(path, v, "")
	writeStagedFile(t, path, cleanStagedPHP)
	fm.drainStagedPackages(time.Now())
	if fm.stagedPackages().pendingCount() != 1 || len(drainFindings(ch)) != 0 {
		t.Fatal("unknown-generation event did not remain pending")
	}
}

func TestStagedPackageDescriptionKeepsItsOriginalTree(t *testing.T) {
	_, staging := stagedPluginFixture(t)
	root := filepath.Join(staging, "wordpress")
	path := filepath.Join(root, "file.php")
	writeStagedFile(t, filepath.Join(root, "wp-includes/version.php"), "<?php $wp_version = '7.1';")
	cache := wpcheck.NewCache(t.TempDir())
	if err := cache.PersistChecksums("7.1", "en_US", nil, map[string]string{"file.php": strings.Repeat("a", 32)}); err != nil {
		t.Fatal(err)
	}
	old := cache.Describe(path)
	old.Verdict = wpcheck.VerdictVerified
	// Another worker can see a replacement while the old event is still
	// scanning content, before it reaches the staged-package handler.
	if err := os.Rename(root, root+"-old"); err != nil {
		t.Fatal(err)
	}
	writeStagedFile(t, path, cleanStagedPHP)
	fresh := cache.Describe(path)
	fresh.Digest = strings.Repeat("a", 32)
	fake := &fakeWPVerifier{
		describe: func(string) wpcheck.Verification { return wpcheck.Verification{Verdict: wpcheck.VerdictUnknown} },
		verify: func(wpcheck.Verification) wpcheck.Verdict {
			t.Error("old description was attributed to the replacement tree")
			return wpcheck.VerdictVerified
		},
	}
	fm, ch := newStagedPackageMonitor(t, fake)
	fm.handleStagedPackageFile(path, old, "")
	fm.handleStagedPackageFile(path, fresh, "")
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	fm.drainStagedPackages(time.Now())
	if fm.stagedPackages().pendingCount() != 1 || len(drainFindings(ch)) != 0 {
		t.Fatal("replacement event did not keep waiting for its own header")
	}
}
