//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
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
	return f.describe(path)
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
