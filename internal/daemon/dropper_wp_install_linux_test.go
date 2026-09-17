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

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/wpcheck"
)

const testL10nCache = "<?php\nreturn ['x-generator'=>'GlotPress/4.1.0','translation-revision-date'=>'2026-01-01 00:00:00+0000','plural-forms'=>'nplurals=3; plural=(n==1 ? 0 : 2);','messages'=>['Settings'=>'Setari','Save'=>'Salveaza']];\n"

const testVersionPHP = "<?php\n/**\n * WordPress Version\n */\n$wp_version = '7.1';\n$wp_db_version = 60000;\n$tinymce_version = '49110-20250317';\n$required_php_version = '7.4';\n$required_mysql_version = '5.5.5';\n$wp_local_package = 'ro_RO';\n"

const testDropperPHP = "<?php if (isset($_GET['k'])) { system($_POST['c']); }\n"

type wpInstallRun struct {
	fm     *FileMonitor
	alerts *[]capturedAlert
	ttl    time.Duration
}

func newWPInstallRun(t *testing.T, docroot string) *wpInstallRun {
	t.Helper()
	const ttl = time.Minute
	fm := newDropperWiringTestMonitor(docroot, ttl)
	var got []capturedAlert
	fm.dropper.emit = func(sev alert.Severity, check, msg, details, path string) {
		got = append(got, capturedAlert{sev: sev, check: check, msg: msg, details: details, path: path})
	}
	return &wpInstallRun{fm: fm, alerts: &got, ttl: ttl}
}

func writeWPInstallFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// observe admits path as the analyzer would, running beforeObserve while
// the event fd is still open. That reproduces the production race in which the
// updater has already removed the staged file, and possibly its directory,
// by the time a worker reaches the event.
func (r *wpInstallRun) observe(t *testing.T, path string, beforeObserve func()) *dropperCandidate {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if beforeObserve != nil {
		beforeObserve()
	}
	c := r.fm.observeDropperCandidate(fileEvent{
		path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE | FAN_CLOSE_WRITE,
	}, "pid=4242 cmd=lsphp uid=1000")
	if c == nil {
		t.Fatalf("staged PHP %s was not admitted", path)
	}
	return c
}

func (r *wpInstallRun) probeAndFlush() {
	probeAt := time.Now().Add(r.ttl + time.Second)
	prober := r.fm.newDropperFSProbe()
	r.fm.dropper.probeStep(probeAt, prober, probeAt)
	flushAt := probeAt.Add(dropperGraceWindow + time.Second)
	r.fm.dropper.probeStep(flushAt, prober, flushAt)
}

func TestDropperLanguagePackCopiedAfterStagingDirRemoved(t *testing.T) {
	docroot := t.TempDir()
	stageDir := filepath.Join(docroot, "wp-content", "upgrade", "wordpress-seo-28.5-ro_ro")
	staged := filepath.Join(stageDir, "wordpress-seo-ro_RO.l10n.php")
	installed := filepath.Join(docroot, "wp-content", "languages", "plugins", "wordpress-seo-ro_RO.l10n.php")
	writeWPInstallFile(t, staged, testL10nCache)

	r := newWPInstallRun(t, docroot)
	r.observe(t, staged, func() {
		writeWPInstallFile(t, installed, testL10nCache)
		if err := os.RemoveAll(stageDir); err != nil {
			t.Fatal(err)
		}
	})
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("language pack installed by copy raised %+v, want no finding", *r.alerts)
	}
}

func TestDropperCoreLanguagePackCopiedWithStagingDirKept(t *testing.T) {
	docroot := t.TempDir()
	staged := filepath.Join(docroot, "wp-content", "upgrade", "wordpress-7.1-ro_ro", "admin-ro_RO.l10n.php")
	installed := filepath.Join(docroot, "wp-content", "languages", "admin-ro_RO.l10n.php")
	writeWPInstallFile(t, staged, testL10nCache)

	r := newWPInstallRun(t, docroot)
	r.observe(t, staged, nil)
	writeWPInstallFile(t, installed, testL10nCache)
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("core language pack installed by copy raised %+v, want no finding", *r.alerts)
	}
}

func TestDropperCoreVersionProbeMatchesInstalledVersionFile(t *testing.T) {
	docroot := t.TempDir()
	probe := filepath.Join(docroot, "wp-content", "upgrade", "version-current.php")
	installed := filepath.Join(docroot, "wp-includes", "version.php")
	writeWPInstallFile(t, installed, "<?php\n$wp_version = '6.9.7';\n")
	writeWPInstallFile(t, probe, testVersionPHP)

	r := newWPInstallRun(t, docroot)
	r.observe(t, probe, nil)
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	// The core update rewrites version.php from the same staged tree.
	if err := os.Remove(installed); err != nil {
		t.Fatal(err)
	}
	writeWPInstallFile(t, installed, testVersionPHP)
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("core update version probe raised %+v, want no finding", *r.alerts)
	}
}

func TestDropperInLanguagePackStagingStillCritical(t *testing.T) {
	docroot := t.TempDir()
	stageDir := filepath.Join(docroot, "wp-content", "upgrade", "wordpress-seo-28.5-ro_ro")
	legit := filepath.Join(stageDir, "wordpress-seo-ro_RO.l10n.php")
	dropper := filepath.Join(stageDir, "wordpress-seo-en_GB.l10n.php")
	writeWPInstallFile(t, legit, testL10nCache)
	writeWPInstallFile(t, dropper, testDropperPHP)
	// An installed file of the same name with other bytes is not the
	// dropper's content living on.
	writeWPInstallFile(t, filepath.Join(docroot, "wp-content", "languages", "plugins", "wordpress-seo-en_GB.l10n.php"), testL10nCache)

	r := newWPInstallRun(t, docroot)
	r.observe(t, dropper, nil)
	if err := os.Remove(dropper); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	assertSingleCriticalDropper(t, *r.alerts, dropper)
}

func TestDropperNamedLikeVersionProbeStillCritical(t *testing.T) {
	docroot := t.TempDir()
	probe := filepath.Join(docroot, "wp-content", "upgrade", "version-current.php")
	writeWPInstallFile(t, filepath.Join(docroot, "wp-includes", "version.php"), testVersionPHP)
	writeWPInstallFile(t, probe, testDropperPHP)

	r := newWPInstallRun(t, docroot)
	r.observe(t, probe, nil)
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	assertSingleCriticalDropper(t, *r.alerts, probe)
}

func assertSingleCriticalDropper(t *testing.T, got []capturedAlert, path string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("emitted %d findings (%+v), want 1", len(got), got)
	}
	if a := got[0]; a.sev != alert.Critical || a.check != dropperCheckName || a.path != path {
		t.Fatalf("finding = %+v, want Critical %s for %s", a, dropperCheckName, path)
	}
}

// A destination the staged file cannot live at must not turn the probe
// inconclusive: retries end in a dropped candidate, which would let a dropper
// in staging evade the finding by breaking one install path.
func TestDropperUnreachableInstallDestinationStillCritical(t *testing.T) {
	cases := map[string]func(t *testing.T, languages string){
		"component is a file": func(t *testing.T, languages string) {
			writeWPInstallFile(t, filepath.Join(languages, "themes"), "not a directory")
		},
		"component is a symlink loop": func(t *testing.T, languages string) {
			if err := os.MkdirAll(languages, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("themes", filepath.Join(languages, "themes")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, breakDestination := range cases {
		t.Run(name, func(t *testing.T) {
			docroot := t.TempDir()
			dropper := filepath.Join(docroot, "wp-content", "upgrade", "wordpress-seo-28.5-ro_ro", "wordpress-seo-ro_RO.l10n.php")
			writeWPInstallFile(t, dropper, testDropperPHP)
			breakDestination(t, filepath.Join(docroot, "wp-content", "languages"))

			r := newWPInstallRun(t, docroot)
			r.observe(t, dropper, nil)
			if err := os.Remove(dropper); err != nil {
				t.Fatal(err)
			}
			r.probeAndFlush()
			assertSingleCriticalDropper(t, *r.alerts, dropper)
		})
	}
}

func TestDropperWPPreplantedCopyStillCritical(t *testing.T) {
	for _, tc := range []struct {
		name, staged, installed, body string
		executable, suspicious        bool
	}{
		{"arbitrary PHP", "stage/shell.php", "wp-content/languages/shell.php", testDropperPHP, false, false},
		{"translation extension", "stage/example-ro_RO.l10n.php", "wp-content/languages/plugins/example-ro_RO.l10n.php", testDropperPHP, false, false},
		{"translation trailing code", "stage/example-ro_RO.l10n.php", "wp-content/languages/themes/example-ro_RO.l10n.php", testL10nCache + strings.Repeat(" ", dropperTrackedHeadMax) + "system($_POST['c']);", false, false},
		{"version probe", "version-current.php", "wp-includes/version.php", testDropperPHP, false, false},
		{"version trailing code", "version-current.php", "wp-includes/version.php", testVersionPHP + "system($_POST['c']);", false, false},
		{"translation attribute", "stage/example-ro_RO.l10n.php", "wp-content/languages/example-ro_RO.l10n.php", "<?php #[Example] function example() {} system($_POST['c']);\nreturn [];", false, false},
		{"version attribute", "version-current.php", "wp-includes/version.php", testVersionPHP + "#[Example] function example() {} system($_POST['c']);", false, false},
		{"executable translation", "stage/example-ro_RO.l10n.php", "wp-content/languages/example-ro_RO.l10n.php", testL10nCache, true, false},
		{"content verdict", "stage/example-ro_RO.l10n.php", "wp-content/languages/example-ro_RO.l10n.php", testL10nCache, false, true},
		{"oversize snapshot", "stage/example-ro_RO.l10n.php", "wp-content/languages/example-ro_RO.l10n.php", testL10nCache + strings.Repeat(" ", dropperDigestMax), false, false},
	} {
		for _, hardlink := range []bool{false, true} {
			name := "copy"
			if hardlink {
				name = "hardlink"
			}
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				docroot := t.TempDir()
				staged := filepath.Join(docroot, "wp-content", "upgrade", tc.staged)
				installed := filepath.Join(docroot, tc.installed)
				writeWPInstallFile(t, installed, tc.body)
				if hardlink {
					if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.Link(installed, staged); err != nil {
						t.Fatal(err)
					}
				} else {
					writeWPInstallFile(t, staged, tc.body)
				}
				if tc.executable {
					if err := os.Chmod(staged, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				r := newWPInstallRun(t, docroot)
				c := r.observe(t, staged, nil)
				if tc.suspicious {
					// Model the content pass flagging this exact admitted snapshot.
					c.ContentSuspicious = true
					if !r.fm.dropper.tr.Refresh(*c) {
						t.Fatal("content verdict did not reach the tracked candidate")
					}
				}
				if err := os.Remove(staged); err != nil {
					t.Fatal(err)
				}
				r.probeAndFlush()
				assertSingleCriticalDropper(t, *r.alerts, staged)
			})
		}
	}
}

func TestDropperLargeLanguagePackCopy(t *testing.T) {
	docroot := t.TempDir()
	staged := filepath.Join(docroot, "wp-content", "upgrade", "stage", "example-ro_RO.l10n.php")
	installed := filepath.Join(docroot, "wp-content", "languages", "themes", "example-ro_RO.l10n.php")
	body := string(wpTranslationCacheOfSize(256 << 10))
	writeWPInstallFile(t, staged, body)
	r := newWPInstallRun(t, docroot)
	r.observe(t, staged, nil)
	writeWPInstallFile(t, installed, body)
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("complete large translation raised %+v", *r.alerts)
	}
}

func TestDropperWPDataRename(t *testing.T) {
	for _, tc := range []struct{ staged, installed, body string }{
		{"stage/example-ro_RO.l10n.php", "wp-content/languages/example-ro_RO.l10n.php", testL10nCache},
		{"version-current.php", "wp-includes/version.php", testVersionPHP},
	} {
		t.Run(tc.staged, func(t *testing.T) {
			docroot := t.TempDir()
			staged := filepath.Join(docroot, "wp-content", "upgrade", tc.staged)
			installed := filepath.Join(docroot, tc.installed)
			writeWPInstallFile(t, staged, tc.body)
			if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
				t.Fatal(err)
			}
			r := newWPInstallRun(t, docroot)
			r.observe(t, staged, nil)
			if err := os.Rename(staged, installed); err != nil {
				t.Fatal(err)
			}
			r.probeAndFlush()
			if len(*r.alerts) != 0 {
				t.Fatalf("data installed by rename raised %+v", *r.alerts)
			}
		})
	}
}

func TestDropperWPRewriteCannotErasePayload(t *testing.T) {
	docroot := t.TempDir()
	staged := filepath.Join(docroot, "wp-content", "upgrade", "stage", "example-ro_RO.l10n.php")
	installed := filepath.Join(docroot, "wp-content", "languages", "example-ro_RO.l10n.php")
	writeWPInstallFile(t, staged, testDropperPHP)
	writeWPInstallFile(t, installed, testL10nCache)
	r := newWPInstallRun(t, docroot)
	r.observe(t, staged, nil)
	writeWPInstallFile(t, staged, testL10nCache)
	r.observe(t, staged, nil)
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	assertSingleCriticalDropper(t, *r.alerts, staged)
}

func TestDropperWPCreateThenCloseKeepsDataProof(t *testing.T) {
	docroot := t.TempDir()
	staged := filepath.Join(docroot, "wp-content", "upgrade", "stage", "example-ro_RO.l10n.php")
	installed := filepath.Join(docroot, "wp-content", "languages", "example-ro_RO.l10n.php")
	writeWPInstallFile(t, staged, "")
	r := newWPInstallRun(t, docroot)
	f, err := os.Open(staged)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE}, ""); c == nil {
		t.Fatal("create was not admitted")
	}
	// Some writers close the empty file before reopening it for the data.
	if c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: FAN_CLOSE_WRITE}, ""); c == nil {
		t.Fatal("empty close was not admitted")
	}
	writeWPInstallFile(t, staged, testL10nCache)
	if c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: FAN_CLOSE_WRITE}, ""); c == nil {
		t.Fatal("close was not admitted")
	}
	writeWPInstallFile(t, installed, testL10nCache)
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("create/close translation raised %+v", *r.alerts)
	}
}

func TestDropperWPCreatePayloadCannotBeClearedByClose(t *testing.T) {
	docroot := t.TempDir()
	staged := filepath.Join(docroot, "wp-content", "upgrade", "stage", "example-ro_RO.l10n.php")
	installed := filepath.Join(docroot, "wp-content", "languages", "example-ro_RO.l10n.php")
	writeWPInstallFile(t, staged, testDropperPHP)
	r := newWPInstallRun(t, docroot)
	f, err := os.Open(staged)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE}, ""); c == nil {
		t.Fatal("create was not admitted")
	}
	writeWPInstallFile(t, staged, testL10nCache)
	if c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: FAN_CLOSE_WRITE}, ""); c == nil {
		t.Fatal("close was not admitted")
	}
	writeWPInstallFile(t, installed, testL10nCache)
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	assertSingleCriticalDropper(t, *r.alerts, staged)
}

func TestDropperWPLateCreateKeepsDataProof(t *testing.T) {
	docroot := t.TempDir()
	staged := filepath.Join(docroot, "wp-content", "upgrade", "stage", "example-ro_RO.l10n.php")
	installed := filepath.Join(docroot, "wp-content", "languages", "example-ro_RO.l10n.php")
	writeWPInstallFile(t, staged, testL10nCache)
	r := newWPInstallRun(t, docroot)
	f, err := os.Open(staged)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, mask := range []uint64{FAN_CLOSE_WRITE, FAN_CREATE} {
		if c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: mask}, ""); c == nil {
			t.Fatal("update was not admitted")
		}
	}
	writeWPInstallFile(t, installed, testL10nCache)
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("late CREATE turned an installed data file into %+v", *r.alerts)
	}
}

func TestDropperInstallDestinationDisappearsDuringDigest(t *testing.T) {
	for _, errno := range []error{unix.ENOENT, unix.ENOTDIR, unix.ELOOP, unix.EACCES, unix.EIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			c := freshDropperCandidate(time.Now())
			c.Path = filepath.Join(c.Docroot, "wp-content/upgrade/version-current.php")
			c.WPInstallData = true
			calls := 0
			target, _, found, err := dropperFindRenameTargetWithStat(c, func(path string, digest bool) (dropperPathState, error) {
				calls++
				if digest {
					return dropperPathState{}, errno
				}
				return dropperPathState{mode: unix.S_IFREG, file: dropperFileState{
					Path: path, Device: c.Device, Inode: c.Inode + 1, Size: c.Size,
				}}, nil
			})
			if calls != 2 || found || target != "" {
				t.Fatalf("calls=%d, found=%v, target=%q", calls, found, target)
			}
			wantErr := errno == unix.EACCES || errno == unix.EIO
			if (err != nil) != wantErr {
				t.Fatalf("err=%v, want inconclusive=%v", err, wantErr)
			}
		})
	}
}

func TestDropperUploadExecutionProbeCopy(t *testing.T) {
	for _, body := range rssslProbeBodies {
		docroot := t.TempDir()
		probe := filepath.Join(docroot, "wp-content", "uploads", "code-execution.php")
		writeWPInstallFile(t, probe, body)
		r := newWPInstallRun(t, docroot)
		r.observeCloseWrite(t, probe)
		if err := os.Remove(probe); err != nil {
			t.Fatal(err)
		}
		r.probeAndFlush()
		if len(*r.alerts) != 0 {
			t.Fatalf("upload execution test script raised %+v, want no finding", *r.alerts)
		}
	}
}

func TestDropperUploadExecutionProbeNameStillCritical(t *testing.T) {
	for name, writes := range map[string][]string{
		"payload":                {testDropperPHP},
		"probe with payload":     {rssslProbeBodies[1] + testDropperPHP},
		"payload rewritten away": {testDropperPHP, rssslProbeBodies[1]},
	} {
		t.Run(name, func(t *testing.T) {
			docroot := t.TempDir()
			probe := filepath.Join(docroot, "wp-content", "uploads", "code-execution.php")
			r := newWPInstallRun(t, docroot)
			for _, body := range writes {
				writeWPInstallFile(t, probe, body)
				r.observeCloseWrite(t, probe)
			}
			if err := os.Remove(probe); err != nil {
				t.Fatal(err)
			}
			r.probeAndFlush()
			assertSingleCriticalDropper(t, *r.alerts, probe)
		})
	}
}

// officialCoreChecksums returns a checksum cache that holds the given
// wordpress.org manifests and never reaches the network.
func officialCoreChecksums(t *testing.T, manifests map[[2]string]string) *wpcheck.Cache {
	t.Helper()
	cache := wpcheck.NewCache(t.TempDir())
	stop := make(chan struct{})
	close(stop)
	cache.SetStopCh(stop)
	for release, versionFile := range manifests {
		// #nosec G401 -- mirrors the MD5 digests wordpress.org publishes
		sum := md5.Sum([]byte(versionFile))
		checksums := map[string]string{
			"wp-includes/version.php": hex.EncodeToString(sum[:]),
			"wp-load.php":             "0123456789abcdef0123456789abcdef",
		}
		if err := cache.PersistChecksums(release[0], release[1], []byte(`{"checksums":{}}`), checksums); err != nil {
			t.Fatal(err)
		}
	}
	return cache
}

// A core update that stops after reading the new version file, for example
// because the host fails its PHP or database requirement, leaves the old
// release installed. The deleted probe is still the official file of the
// release it names.
func TestDropperCoreVersionProbeOfAbortedUpdate(t *testing.T) {
	docroot := t.TempDir()
	probe := filepath.Join(docroot, "wp-content", "upgrade", "version-current.php")
	writeWPInstallFile(t, filepath.Join(docroot, "wp-includes", "version.php"), "<?php\n$wp_version = '6.9.7';\n")
	writeWPInstallFile(t, probe, testVersionPHP)

	r := newWPInstallRun(t, docroot)
	r.fm.wpCache = officialCoreChecksums(t, map[[2]string]string{{"7.1", "ro_RO"}: testVersionPHP})
	r.observe(t, probe, nil)
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("official version file of an aborted update raised %+v, want no finding", *r.alerts)
	}
}

func TestDropperCoreVersionProbeWithoutOfficialMatchStillCritical(t *testing.T) {
	const official = "<?php\n$wp_version = '7.1';\n$wp_local_package = 'ro_RO';\n"
	for _, tc := range []struct {
		name       string
		writes     []string
		manifests  map[[2]string]string
		executable bool
		noCache    bool
	}{
		{name: "checksums not available", writes: []string{testVersionPHP}},
		{name: "no checksum source", writes: []string{testVersionPHP}, noCache: true},
		{name: "differs from official file", writes: []string{testVersionPHP},
			manifests: map[[2]string]string{{"7.1", "ro_RO"}: official}},
		{name: "official file of another locale", writes: []string{testVersionPHP},
			manifests: map[[2]string]string{{"7.1", "en_US"}: testVersionPHP}},
		{name: "code after version data", writes: []string{testVersionPHP + "system($_POST['c']);"},
			manifests: map[[2]string]string{{"7.1", "ro_RO"}: testVersionPHP + "system($_POST['c']);"}},
		{name: "executable mode", writes: []string{testVersionPHP}, executable: true,
			manifests: map[[2]string]string{{"7.1", "ro_RO"}: testVersionPHP}},
		{name: "payload rewritten to official file", writes: []string{testDropperPHP, testVersionPHP},
			manifests: map[[2]string]string{{"7.1", "ro_RO"}: testVersionPHP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docroot := t.TempDir()
			probe := filepath.Join(docroot, "wp-content", "upgrade", "version-current.php")
			writeWPInstallFile(t, filepath.Join(docroot, "wp-includes", "version.php"), "<?php\n$wp_version = '6.9.7';\n")
			r := newWPInstallRun(t, docroot)
			if !tc.noCache {
				r.fm.wpCache = officialCoreChecksums(t, tc.manifests)
			}
			for _, body := range tc.writes {
				writeWPInstallFile(t, probe, body)
				if tc.executable {
					if err := os.Chmod(probe, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				r.observe(t, probe, nil)
			}
			if err := os.Remove(probe); err != nil {
				t.Fatal(err)
			}
			r.probeAndFlush()
			assertSingleCriticalDropper(t, *r.alerts, probe)
		})
	}
}
