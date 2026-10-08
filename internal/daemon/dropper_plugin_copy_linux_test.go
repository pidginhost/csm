//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/wpcheck"
)

// Synthetic stand-ins for the Elementor files involved in Safe Mode. The
// detector compares bytes, so the fixture needs the layout, not the real code.
const (
	testElementorMain       = "<?php\n/*\nPlugin Name: Elementor\nVersion: 3.30.0\n*/\n"
	testElementorLoader     = "<?php\n/**\n * Plugin Name: Elementor Safe Mode\n * Version: 1.0.0\n */\nclass Safe_Mode_Example {\n\tpublic function __construct() {\n\t\tadd_filter( 'option_active_plugins', [ $this, 'filter_plugins' ] );\n\t}\n}\nnew Safe_Mode_Example();\n"
	testElementorLoaderRel  = "modules/safe-mode/mu-plugin/elementor-safe-mode.php"
	testForgedLoaderPayload = "<?php\n/**\n * Plugin Name: Elementor Safe Mode\n * Version: 1.0.0\n */\nif (isset($_GET['k'])) { system($_POST['c']); }\n"
)

// pluginManifests answers checksum lookups for the listed plugin releases
// ("slug:version") the way the wordpress.org manifests would, and defers
// everything else to a real cache that never reaches the network. Describe
// stays the real implementation, so the test also proves the probe names the
// file the manifest keys.
type pluginManifests struct {
	*wpcheck.Cache
	releases map[string]map[string]string
}

func (m pluginManifests) Verify(v wpcheck.Verification) wpcheck.Verdict {
	files, ok := m.releases[v.Slug+":"+v.Version]
	if v.Kind != wpcheck.KindPlugin || !ok {
		return m.Cache.Verify(v)
	}
	body, ok := files[v.Rel]
	if !ok {
		return wpcheck.VerdictMismatch
	}
	sum := sha256.Sum256([]byte(body))
	if v.Digest == hex.EncodeToString(sum[:]) {
		return wpcheck.VerdictVerified
	}
	return wpcheck.VerdictMismatch
}

// offlinePluginCache has no plugin manifest cached and cannot fetch one:
// every plugin lookup stays pending, as after a daemon restart.
func offlinePluginCache(t *testing.T) *wpcheck.Cache {
	t.Helper()
	cache := wpcheck.NewCache(t.TempDir())
	stop := make(chan struct{})
	close(stop)
	cache.SetStopCh(stop)
	return cache
}

type safeModeSite struct {
	docroot, plugin, muPlugin, loader string
}

func newSafeModeSite(t *testing.T) safeModeSite {
	t.Helper()
	docroot := t.TempDir()
	plugin := filepath.Join(docroot, "wp-content", "plugins", "elementor")
	s := safeModeSite{
		docroot:  docroot,
		plugin:   plugin,
		muPlugin: filepath.Join(docroot, "wp-content", "mu-plugins", "elementor-safe-mode.php"),
		loader:   filepath.Join(plugin, filepath.FromSlash(testElementorLoaderRel)),
	}
	writeWPInstallFile(t, filepath.Join(plugin, "elementor.php"), testElementorMain)
	writeWPInstallFile(t, s.loader, testElementorLoader)
	return s
}

// testChecksums is the checksum source the deletion probe consults.
type testChecksums interface {
	Describe(path string) wpcheck.Verification
	Verify(wpcheck.Verification) wpcheck.Verdict
}

// newSafeModeRun starts a run whose analyzer reads plugin headers from disk
// but, like a daemon just restarted, has no plugin manifest cached.
func newSafeModeRun(t *testing.T, s safeModeSite) *wpInstallRun {
	t.Helper()
	r := newWPInstallRun(t, s.docroot)
	r.fm.wpCache = offlinePluginCache(t)
	return r
}

func (r *wpInstallRun) probeAndFlushWith(checksums testChecksums) {
	prober := &dropperFSProbe{quarantines: r.fm.dropperQuarantines, coreChecksums: checksums}
	probeAt := time.Now().Add(r.ttl + time.Second)
	r.fm.dropper.probeStep(probeAt, prober, probeAt)
	flushAt := probeAt.Add(dropperGraceWindow + time.Second)
	r.fm.dropper.probeStep(flushAt, prober, flushAt)
}

func officialElementor(t *testing.T, loader string) pluginManifests {
	return pluginManifests{Cache: offlinePluginCache(t), releases: map[string]map[string]string{
		"elementor:3.30.0": {testElementorLoaderRel: loader},
	}}
}

// Switching Safe Mode on copies Elementor's shipped loader into mu-plugins;
// switching it off deletes the copy and, when Elementor created mu-plugins,
// the directory. Bytes equal to the official release file of the Elementor
// installed beside it carry nothing an attacker chose.
func TestDropperElementorSafeModeOfficialLoaderNotReported(t *testing.T) {
	for _, removeDir := range []bool{false, true} {
		s := newSafeModeSite(t)
		writeWPInstallFile(t, s.muPlugin, testElementorLoader)
		r := newSafeModeRun(t, s)
		r.observe(t, s.muPlugin, nil)
		remove := os.Remove
		target := s.muPlugin
		if removeDir {
			remove, target = os.RemoveAll, filepath.Dir(s.muPlugin)
		}
		if err := remove(target); err != nil {
			t.Fatal(err)
		}
		r.probeAndFlushWith(officialElementor(t, testElementorLoader))
		if len(*r.alerts) != 0 {
			t.Fatalf("removeDir=%v: official Safe Mode loader reported: %+v", removeDir, *r.alerts)
		}
	}
}

// Without a manifest to consult, bytes identical to the installed plugin's own
// file still survive on disk and are scanned there, so the removal destroyed
// no evidence. The plugin file itself is not proven stock, so the removal is
// still reported, at the lower severity, naming the file that holds the bytes.
func TestDropperElementorSafeModeLoaderMatchingPluginFileDemoted(t *testing.T) {
	for _, withCache := range []bool{true, false} {
		s := newSafeModeSite(t)
		writeWPInstallFile(t, s.muPlugin, testElementorLoader)
		r := newWPInstallRun(t, s.docroot)
		var checksums testChecksums
		if withCache {
			r.fm.wpCache = offlinePluginCache(t)
			checksums = r.fm.wpCache
		}
		r.observe(t, s.muPlugin, nil)
		if err := os.Remove(s.muPlugin); err != nil {
			t.Fatal(err)
		}
		r.probeAndFlushWith(checksums)
		got := *r.alerts
		if len(got) != 1 || got[0].sev != alert.Warning || got[0].path != s.muPlugin || got[0].check != dropperCheckName {
			t.Fatalf("cache=%v: want one Warning for %s, got %+v", withCache, s.muPlugin, got)
		}
		if !strings.Contains(got[0].details, s.loader) {
			t.Fatalf("cache=%v: details do not name the surviving plugin file %s: %q", withCache, s.loader, got[0].details)
		}
	}
}

// The copy is compared with the release the installed plugin declared when
// the copy was written. An update inside the tracking window replaces both
// the version header and the plugin file, and must not turn the official
// loader of the earlier release into a finding.
func TestDropperElementorSafeModeLoaderOfReleaseUpdatedMeanwhile(t *testing.T) {
	const newer = testElementorLoader + "// 3.31.0\n"
	s := newSafeModeSite(t)
	writeWPInstallFile(t, s.muPlugin, testElementorLoader)
	r := newSafeModeRun(t, s)
	r.observe(t, s.muPlugin, nil)
	writeWPInstallFile(t, filepath.Join(s.plugin, "elementor.php"), strings.Replace(testElementorMain, "3.30.0", "3.31.0", 1))
	writeWPInstallFile(t, s.loader, newer)
	if err := os.Remove(s.muPlugin); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlushWith(pluginManifests{Cache: offlinePluginCache(t), releases: map[string]map[string]string{
		"elementor:3.30.0": {testElementorLoaderRel: testElementorLoader},
		"elementor:3.31.0": {testElementorLoaderRel: newer},
	}})
	if len(*r.alerts) != 0 {
		t.Fatalf("official loader of the release installed at write time reported: %+v", *r.alerts)
	}
}

func TestDropperElementorSafeModeLoaderWithoutProofStillCritical(t *testing.T) {
	type setup struct {
		name string
		// writes are the successive contents of the mu-plugin, each observed.
		writes []string
		// prepare changes the site after the loader was written and observed.
		prepare    func(t *testing.T, s safeModeSite)
		checksums  func(t *testing.T) testChecksums
		executable bool
		createOnly bool
	}
	official := func(t *testing.T) testChecksums {
		return officialElementor(t, testElementorLoader)
	}
	offline := func(t *testing.T) testChecksums {
		return offlinePluginCache(t)
	}
	for _, tc := range []setup{
		{name: "forged header, official manifest", writes: []string{testForgedLoaderPayload}, checksums: official},
		{name: "forged header, no manifest", writes: []string{testForgedLoaderPayload}, checksums: offline},
		{name: "plugin file tampered to match, manifest disagrees", writes: []string{testForgedLoaderPayload}, checksums: official,
			prepare: func(t *testing.T, s safeModeSite) { writeWPInstallFile(t, s.loader, testForgedLoaderPayload) }},
		{name: "payload rewritten to official loader", writes: []string{testForgedLoaderPayload, testElementorLoader}, checksums: official},
		{name: "payload rewritten to plugin file copy", writes: []string{testForgedLoaderPayload, testElementorLoader}, checksums: offline},
		{name: "payload emptied then official loader", writes: []string{testForgedLoaderPayload, "", testElementorLoader}, checksums: official},
		{name: "executable mode", writes: []string{testElementorLoader}, checksums: official, executable: true},
		{name: "create before the close supplied bytes", writes: []string{testElementorLoader}, checksums: official, createOnly: true},
		{name: "Elementor not installed", writes: []string{testElementorLoader}, checksums: offline,
			prepare: func(t *testing.T, s safeModeSite) {
				if err := os.RemoveAll(s.plugin); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "plugin file reached through a symlink", writes: []string{testElementorLoader}, checksums: offline,
			prepare: func(t *testing.T, s safeModeSite) {
				elsewhere := filepath.Join(t.TempDir(), "elementor")
				if err := os.Rename(s.plugin, elsewhere); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(elsewhere, s.plugin); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "plugin file differs, no manifest", writes: []string{testElementorLoader}, checksums: offline,
			prepare: func(t *testing.T, s safeModeSite) {
				writeWPInstallFile(t, s.loader, testElementorLoader+"// changed\n")
			}},
		{name: "plugin file same size, other bytes, no manifest", writes: []string{testElementorLoader}, checksums: offline,
			prepare: func(t *testing.T, s safeModeSite) {
				writeWPInstallFile(t, s.loader, strings.Replace(testElementorLoader, "filter_plugins", "filter_payload", 1))
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSafeModeSite(t)
			r := newSafeModeRun(t, s)
			for _, body := range tc.writes {
				writeWPInstallFile(t, s.muPlugin, body)
				if tc.executable {
					if err := os.Chmod(s.muPlugin, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				f, err := os.Open(s.muPlugin)
				if err != nil {
					t.Fatal(err)
				}
				mask := uint64(FAN_CREATE | FAN_CLOSE_WRITE)
				if tc.createOnly {
					mask = FAN_CREATE
				}
				c := r.fm.observeDropperCandidate(fileEvent{path: s.muPlugin, fd: int(f.Fd()), pid: 4242, mask: mask}, "pid=4242 cmd=lsphp uid=1000")
				_ = f.Close()
				if c == nil {
					t.Fatal("mu-plugin write was not admitted")
				}
			}
			if tc.prepare != nil {
				tc.prepare(t, s)
			}
			if err := os.Remove(s.muPlugin); err != nil {
				t.Fatal(err)
			}
			r.probeAndFlushWith(tc.checksums(t))
			assertSingleCriticalDropper(t, *r.alerts, s.muPlugin)
		})
	}
}

// A site nested inside another plugin's directory resolves its Elementor
// files to that outer plugin as well. Official releases of the outer plugin,
// whoever published it, must not vouch for the copy.
func TestDropperPluginCopyOtherPluginReleaseStillCritical(t *testing.T) {
	outer := t.TempDir()
	host := filepath.Join(outer, "wp-content", "plugins", "host")
	site := filepath.Join(host, "site")
	muPlugin := filepath.Join(site, "wp-content", "mu-plugins", "elementor-safe-mode.php")
	writeWPInstallFile(t, filepath.Join(host, "host.php"), "<?php\n/*\nPlugin Name: Host\nVersion: 1.0\n*/\n")
	writeWPInstallFile(t, muPlugin, testForgedLoaderPayload)
	r := newWPInstallRun(t, outer)
	r.fm.wpCache = offlinePluginCache(t)
	r.observe(t, muPlugin, nil)
	if err := os.Remove(muPlugin); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlushWith(pluginManifests{Cache: offlinePluginCache(t), releases: map[string]map[string]string{
		"host:1.0": {filepath.Join("site", "wp-content", "plugins", "elementor", filepath.FromSlash(testElementorLoaderRel)): testForgedLoaderPayload},
	}})
	assertSingleCriticalDropper(t, *r.alerts, muPlugin)
}

func TestDropperPluginCopyPayloadThenOfficialWithDirectoryRemoved(t *testing.T) {
	s := newSafeModeSite(t)
	r := newSafeModeRun(t, s)
	for _, body := range []string{testForgedLoaderPayload, "", testElementorLoader} {
		writeWPInstallFile(t, s.muPlugin, body)
		r.observe(t, s.muPlugin, nil)
	}
	if err := os.RemoveAll(filepath.Dir(s.muPlugin)); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlushWith(officialElementor(t, testElementorLoader))
	assertSingleCriticalDropper(t, *r.alerts, s.muPlugin)
}

func TestDropperPluginCopyEmptyAndReplayedSnapshotsAreNotRewrites(t *testing.T) {
	s := newSafeModeSite(t)
	r := newSafeModeRun(t, s)
	writeWPInstallFile(t, s.muPlugin, testElementorLoader)
	first := r.observe(t, s.muPlugin, nil)
	writeWPInstallFile(t, s.muPlugin, "")
	r.observe(t, s.muPlugin, nil)
	r.fm.dropper.tr.Refresh(*first)
	writeWPInstallFile(t, s.muPlugin, testElementorLoader)
	r.observe(t, s.muPlugin, nil)
	if err := os.Remove(s.muPlugin); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlushWith(officialElementor(t, testElementorLoader))
	if len(*r.alerts) != 0 {
		t.Fatalf("empty writes and a replay prevented official proof: %+v", *r.alerts)
	}
}

func TestDropperPluginCopyHeaderLookupDoesNotBlockOnFIFO(t *testing.T) {
	for _, target := range []string{"elementor.php", ".", "style.css"} {
		t.Run(target, func(t *testing.T) {
			s := newSafeModeSite(t)
			writeWPInstallFile(t, s.muPlugin, testElementorLoader)
			r := newSafeModeRun(t, s)
			path := filepath.Join(s.plugin, target)
			if target == "." {
				if err := os.RemoveAll(s.plugin); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(filepath.Join(s.plugin, "elementor.php")); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0o644); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(s.muPlugin)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			done := make(chan *dropperCandidate, 1)
			go func() {
				done <- r.fm.observeDropperCandidate(fileEvent{
					path: s.muPlugin, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE | FAN_CLOSE_WRITE,
				}, "")
			}()
			select {
			case c := <-done:
				if c == nil || c.PluginRelease != nil {
					t.Fatalf("non-regular package header supplied release proof: %+v", c)
				}
			case <-time.After(2 * time.Second):
				// Release the blocked lookup before reporting the regression.
				writer, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				_ = writer.Close()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("header lookup did not stop after FIFO release")
				}
				t.Fatal("account-writable FIFO blocked analyzer header lookup")
			}
		})
	}
}

func TestDropperPluginCopyInstalledDigestRejectsConcurrentChanges(t *testing.T) {
	for _, change := range []string{"same-size rewrite", "restored bytes and mtime", "unlink"} {
		t.Run(change, func(t *testing.T) {
			s := newSafeModeSite(t)
			before, err := os.Stat(s.loader)
			if err != nil {
				t.Fatal(err)
			}
			state, err := statDropperFileNoSymlinksWithDigest(s.loader, func(fd int, size int64) ([32]byte, bool) {
				sum, known := digestFromFD(fd, size)
				if !known {
					t.Fatal("initial plugin snapshot was not readable")
				}
				if change == "unlink" {
					if removeErr := os.Remove(s.loader); removeErr != nil {
						t.Fatal(removeErr)
					}
				} else {
					writeWPInstallFile(t, s.loader, strings.Replace(testElementorLoader, "filter_plugins", "filter_payload", 1))
					if change == "restored bytes and mtime" {
						writeWPInstallFile(t, s.loader, testElementorLoader)
					}
					if timeErr := os.Chtimes(s.loader, before.ModTime(), before.ModTime()); timeErr != nil {
						t.Fatal(timeErr)
					}
				}
				return sum, true
			})
			if err != nil {
				t.Fatal(err)
			}
			if state.DigestKnown {
				t.Fatal("changed plugin file supplied surviving-content proof")
			}
		})
	}
}

func TestDropperPluginCopyReplacementStillUsesPackageProof(t *testing.T) {
	for _, tc := range []struct {
		name, body  string
		checksums   func(*testing.T) testChecksums
		want        alert.Severity
		wantFinding bool
	}{
		{name: "official copy", body: testElementorLoader,
			checksums: func(t *testing.T) testChecksums { return officialElementor(t, testElementorLoader) }},
		{name: "installed copy", body: testElementorLoader, want: alert.Warning, wantFinding: true,
			checksums: func(t *testing.T) testChecksums { return offlinePluginCache(t) }},
		{name: "forged copy", body: testForgedLoaderPayload, want: alert.Critical, wantFinding: true,
			checksums: func(t *testing.T) testChecksums { return officialElementor(t, testElementorLoader) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSafeModeSite(t)
			r := newSafeModeRun(t, s)
			writeWPInstallFile(t, s.muPlugin, tc.body)
			r.observe(t, s.muPlugin, nil)
			replaceAtomically(t, s.muPlugin, testElementorLoader, time.Time{})
			r.probeAndFlushWith(tc.checksums(t))
			got := *r.alerts
			if !tc.wantFinding {
				if len(got) != 0 {
					t.Fatalf("official replaced copy reported: %+v", got)
				}
			} else if len(got) != 1 || got[0].sev != tc.want || got[0].path != s.muPlugin {
				t.Fatalf("findings = %+v, want one %v", got, tc.want)
			}
		})
	}
}
