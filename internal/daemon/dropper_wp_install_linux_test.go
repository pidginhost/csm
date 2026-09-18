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

func TestDropperUploadExecutionProbeEventOrdering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		masks []uint64
	}{
		{"create then close", []uint64{FAN_CREATE, FAN_CLOSE_WRITE}},
		{"close then late create", []uint64{FAN_CLOSE_WRITE, FAN_CREATE}},
		{"create then combined close", []uint64{FAN_CREATE, FAN_CREATE | FAN_CLOSE_WRITE}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, body := range rssslProbeBodies {
				docroot := t.TempDir()
				path := filepath.Join(docroot, "wp-content", "uploads", "code-execution.php")
				writeWPInstallFile(t, path, body)
				f, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()
				r := newWPInstallRun(t, docroot)
				for _, mask := range tc.masks {
					if c := r.fm.observeDropperCandidate(fileEvent{
						path: path, fd: int(f.Fd()), pid: 4242, mask: mask,
					}, ""); c == nil {
						t.Fatal("probe event was not observed")
					}
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				r.probeAndFlush()
				if len(*r.alerts) != 0 {
					t.Fatalf("completed upload execution probe raised %+v", *r.alerts)
				}
			}
		})
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

func TestDropperCoreVersionProbeRejectsOversizedRelease(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "wp-content", "upgrade", "version-current.php")
	body := "<?php $wp_version = '" + strings.Repeat("9", 1<<20) + "';"
	writeWPInstallFile(t, path, body)
	r := newWPInstallRun(t, docroot)
	lookups := 0
	r.fm.wpCache = &fakeWPVerifier{verify: func(wpcheck.Verification) wpcheck.Verdict {
		lookups++
		return wpcheck.VerdictPending
	}}
	c := r.observe(t, path, nil)
	if !c.WPInstallData {
		t.Fatal("fixture must reach release parsing as complete version data")
	}
	if c.WPCoreRelease != nil || lookups != 0 {
		t.Fatal("oversized release retained or sent to the checksum cache")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	assertSingleCriticalDropper(t, *r.alerts, path)
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

const testCoreThemeFile = "<?php\nfunction twentytwentysix_setup() {\n\tadd_theme_support( 'wp-block-styles' );\n}\n"

// coreReleaseChecksums returns a checksum cache holding one wordpress.org
// core manifest with the given files, never reaching the network.
func coreReleaseChecksums(t *testing.T, version, locale string, files map[string]string) *wpcheck.Cache {
	t.Helper()
	cache := wpcheck.NewCache(t.TempDir())
	stop := make(chan struct{})
	close(stop)
	cache.SetStopCh(stop)
	checksums := make(map[string]string, len(files))
	for rel, body := range files {
		// #nosec G401 -- mirrors the MD5 digests wordpress.org publishes
		sum := md5.Sum([]byte(body))
		checksums[rel] = hex.EncodeToString(sum[:])
	}
	if err := cache.PersistChecksums(version, locale, []byte(`{"checksums":{}}`), checksums); err != nil {
		t.Fatal(err)
	}
	return cache
}

// A core update unpacks the whole release under upgrade/, copies only the
// files that changed into place, never copies the bundled themes and plugins
// under wp-content/ over installed ones, and then deletes the working tree.
// Those staged files vanish without an install destination that matches, but
// they are byte for byte the official files of the release now installed.
func TestDropperCorePackageFileNotCopiedByUpdate(t *testing.T) {
	docroot := t.TempDir()
	workDir := filepath.Join(docroot, "wp-content", "upgrade", "wordpress-7.1-ro_ro-new")
	staged := filepath.Join(workDir, "wordpress", "wp-content", "themes", "twentytwentysix", "functions.php")
	writeWPInstallFile(t, filepath.Join(docroot, "wp-includes", "version.php"), testVersionPHP)
	writeWPInstallFile(t, filepath.Join(docroot, "wp-content", "themes", "twentytwentysix", "functions.php"), "<?php\n// customised copy\n")
	writeWPInstallFile(t, staged, testCoreThemeFile)

	r := newWPInstallRun(t, docroot)
	r.fm.wpCache = coreReleaseChecksums(t, "7.1", "ro_RO", map[string]string{
		"wp-includes/version.php":                         testVersionPHP,
		"wp-content/themes/twentytwentysix/functions.php": testCoreThemeFile,
	})
	r.observe(t, staged, nil)
	if err := os.RemoveAll(workDir); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("official core package file removed with the working tree raised %+v, want no finding", *r.alerts)
	}
}

func TestDropperCorePackageFileWithoutOfficialMatchStillReported(t *testing.T) {
	const rel = "wp-content/themes/twentytwentysix/functions.php"
	for _, tc := range []struct {
		name       string
		pkg        string
		writes     []string
		manifest   map[string]string
		executable bool
		noCache    bool
	}{
		{name: "differs from official file", writes: []string{testCoreThemeFile},
			manifest: map[string]string{rel: testCoreThemeFile + "// changed\n"}},
		{name: "not in the official package", writes: []string{testCoreThemeFile},
			manifest: map[string]string{"wp-load.php": testCoreThemeFile}},
		{name: "checksums not available", writes: []string{testCoreThemeFile}},
		{name: "no checksum source", writes: []string{testCoreThemeFile}, noCache: true},
		{name: "executable mode", writes: []string{testCoreThemeFile}, executable: true,
			manifest: map[string]string{rel: testCoreThemeFile}},
		{name: "payload rewritten to official file", writes: []string{testDropperPHP, testCoreThemeFile},
			manifest: map[string]string{rel: testCoreThemeFile}},
		{name: "outside a core package", pkg: "twentytwentysix-theme", writes: []string{testCoreThemeFile},
			manifest: map[string]string{rel: testCoreThemeFile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docroot := t.TempDir()
			pkg := tc.pkg
			if pkg == "" {
				pkg = "wordpress"
			}
			workDir := filepath.Join(docroot, "wp-content", "upgrade", "wordpress-7.1-ro_ro-new")
			staged := filepath.Join(workDir, pkg, filepath.FromSlash(rel))
			writeWPInstallFile(t, filepath.Join(docroot, "wp-includes", "version.php"), testVersionPHP)
			r := newWPInstallRun(t, docroot)
			if !tc.noCache {
				if tc.manifest == nil {
					cache := wpcheck.NewCache(t.TempDir())
					stop := make(chan struct{})
					close(stop)
					cache.SetStopCh(stop)
					r.fm.wpCache = cache
				} else {
					r.fm.wpCache = coreReleaseChecksums(t, "7.1", "ro_RO", tc.manifest)
				}
			}
			for _, body := range tc.writes {
				writeWPInstallFile(t, staged, body)
				if tc.executable {
					if err := os.Chmod(staged, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				r.observe(t, staged, nil)
			}
			if err := os.RemoveAll(workDir); err != nil {
				t.Fatal(err)
			}
			r.probeAndFlush()
			got := *r.alerts
			if len(got) != 1 || got[0].path != staged || got[0].check != "self_deleting_dropper_realtime" {
				t.Fatalf("want one self-deleting finding for %s, got %+v", staged, got)
			}
		})
	}
}

// A site nested below another tree's wp-includes/ resolves its version header
// to the outer root. That header does not describe the nested install, so it
// cannot vouch for the nested site's staged files.
func TestDropperCorePackageFileVersionFromOtherRootStillReported(t *testing.T) {
	outer := t.TempDir()
	docroot := filepath.Join(outer, "wp-includes", "site")
	workDir := filepath.Join(docroot, "wp-content", "upgrade", "wordpress-7.1-ro_ro-new")
	staged := filepath.Join(workDir, "wordpress", "wp-content", "themes", "twentytwentysix", "functions.php")
	writeWPInstallFile(t, filepath.Join(outer, "wp-includes", "version.php"), testVersionPHP)
	writeWPInstallFile(t, filepath.Join(docroot, "wp-includes", "version.php"), testVersionPHP)
	writeWPInstallFile(t, staged, testCoreThemeFile)

	r := newWPInstallRun(t, docroot)
	r.fm.wpCache = coreReleaseChecksums(t, "7.1", "ro_RO", map[string]string{
		"wp-includes/version.php":                         testVersionPHP,
		"wp-content/themes/twentytwentysix/functions.php": testCoreThemeFile,
	})
	r.observe(t, staged, nil)
	if err := os.RemoveAll(workDir); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	got := *r.alerts
	if len(got) != 1 || got[0].path != staged {
		t.Fatalf("want one finding for %s, got %+v", staged, got)
	}
}

func TestDropperCorePackageSnapshotHistory(t *testing.T) {
	const rel = "wp-content/themes/twentytwentysix/functions.php"
	type observation struct {
		body string
		mask uint64
	}
	for _, tc := range []struct {
		name         string
		writes       []observation
		resendCreate bool
		installed    bool
		wantAlert    bool
	}{
		{name: "rewritten file has an installed copy", writes: []observation{{testDropperPHP, FAN_CREATE | FAN_CLOSE_WRITE}, {testCoreThemeFile, FAN_CLOSE_WRITE}}, installed: true, wantAlert: true},
		{name: "create payload then official close", writes: []observation{{testDropperPHP, FAN_CREATE}, {testCoreThemeFile, FAN_CLOSE_WRITE}}, wantAlert: true},
		{name: "payload empty official", writes: []observation{{testDropperPHP, FAN_CREATE | FAN_CLOSE_WRITE}, {"", FAN_CLOSE_WRITE}, {testCoreThemeFile, FAN_CLOSE_WRITE}}, wantAlert: true},
		{name: "empty create then official close", writes: []observation{{"", FAN_CREATE}, {testCoreThemeFile, FAN_CLOSE_WRITE}}},
		{name: "official create then close", writes: []observation{{testCoreThemeFile, FAN_CREATE}, {testCoreThemeFile, FAN_CLOSE_WRITE}}},
		{name: "resend create then close", writes: []observation{{testCoreThemeFile, FAN_CREATE}, {testCoreThemeFile, FAN_CLOSE_WRITE}}, resendCreate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			staged := filepath.Join(root, "wp-content/upgrade/update/wordpress", rel)
			writeWPInstallFile(t, filepath.Join(root, "wp-includes/version.php"), testVersionPHP)
			r := newWPInstallRun(t, root)
			r.fm.wpCache = coreReleaseChecksums(t, "7.1", "ro_RO", map[string]string{rel: testCoreThemeFile})
			if tc.installed {
				writeWPInstallFile(t, filepath.Join(root, rel), testCoreThemeFile)
			}
			var snapshots []*dropperCandidate
			for _, write := range tc.writes {
				writeWPInstallFile(t, staged, write.body)
				f, err := os.Open(staged)
				if err != nil {
					t.Fatal(err)
				}
				c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: write.mask}, "")
				_ = f.Close()
				if c == nil {
					t.Fatal("missing candidate")
				}
				snapshots = append(snapshots, c)
			}
			if tc.resendCreate {
				// Analyzer verdicts resend the original snapshot; they must not invent
				// a content rewrite or discard history accumulated by another worker.
				snapshots[0].ContentSuspicious = true
				if !r.fm.dropper.tr.Refresh(*snapshots[0]) || !r.fm.dropper.tr.Refresh(*snapshots[1]) {
					t.Fatal("refresh lost candidate")
				}
				due := r.fm.dropper.tr.Due(time.Now().Add(2 * r.ttl))
				if len(due) != 1 || due[0].ContentRewritten || !due[0].ContentSuspicious {
					t.Fatalf("resend changed content history: %+v", due)
				}
				return
			}
			if err := os.Remove(staged); err != nil {
				t.Fatal(err)
			}
			r.probeAndFlush()
			if tc.wantAlert {
				if len(*r.alerts) != 1 || (*r.alerts)[0].path != staged {
					t.Fatalf("payload deletion lost: %+v", *r.alerts)
				}
			} else if len(*r.alerts) != 0 {
				t.Fatalf("official bytes reported: %+v", *r.alerts)
			}
		})
	}
}

func TestDropperCorePackageCreateSnapshotIsComplete(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "wp-content/upgrade/update/wordpress/wp-content/themes/example/functions.php")
	body := testCoreThemeFile + strings.Repeat("// official content\n", 100)
	writeWPInstallFile(t, staged, body)
	r := newWPInstallRun(t, root)
	f, err := os.Open(staged)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE}, "")
	// #nosec G401 -- mirrors the official checksum format
	want := md5.Sum([]byte(body))
	if c == nil || !c.CoreMD5Known || c.CoreMD5 != want || string(c.Head) != body[:dropperTrackedHeadMax] {
		t.Fatalf("create snapshot lacks a complete, bound digest: %+v", c)
	}
}

const testPluginFile = "<?php\n/*\nPlugin Name: Example\nVersion: 2.0\n*/\nfunction example_boot() {}\n"

// Plugin and theme updates stage packages the same way a core update does, and
// the same history rule applies: an installed copy or a rename into place can
// only account for a staged file whose written content never changed.
func TestDropperStagedPackageSnapshotHistory(t *testing.T) {
	type observation struct {
		body string
		mask uint64
	}
	const (
		copyInstall = iota
		renameInstall
	)
	for _, tc := range []struct {
		name      string
		kind      string // plugins or themes
		writes    []observation
		install   int
		wantAlert bool
	}{
		{name: "payload overwritten with installed bytes", kind: "plugins", install: copyInstall, wantAlert: true,
			writes: []observation{{testDropperPHP, FAN_CREATE | FAN_CLOSE_WRITE}, {testPluginFile, FAN_CLOSE_WRITE}}},
		{name: "payload overwritten then renamed into place", kind: "plugins", install: renameInstall, wantAlert: true,
			writes: []observation{{testDropperPHP, FAN_CREATE | FAN_CLOSE_WRITE}, {testPluginFile, FAN_CLOSE_WRITE}}},
		{name: "create payload then close", kind: "plugins", install: copyInstall, wantAlert: true,
			writes: []observation{{testDropperPHP, FAN_CREATE}, {testPluginFile, FAN_CLOSE_WRITE}}},
		{name: "payload emptied then rewritten", kind: "plugins", install: renameInstall, wantAlert: true,
			writes: []observation{{testDropperPHP, FAN_CREATE | FAN_CLOSE_WRITE}, {"", FAN_CLOSE_WRITE}, {testPluginFile, FAN_CLOSE_WRITE}}},
		{name: "theme payload overwritten with installed bytes", kind: "themes", install: copyInstall, wantAlert: true,
			writes: []observation{{testDropperPHP, FAN_CREATE | FAN_CLOSE_WRITE}, {testPluginFile, FAN_CLOSE_WRITE}}},
		{name: "single write copied into place", kind: "plugins", install: copyInstall,
			writes: []observation{{testPluginFile, FAN_CREATE | FAN_CLOSE_WRITE}}},
		{name: "single write renamed into place", kind: "plugins", install: renameInstall,
			writes: []observation{{testPluginFile, FAN_CREATE | FAN_CLOSE_WRITE}}},
		{name: "empty create then close", kind: "plugins", install: renameInstall,
			writes: []observation{{"", FAN_CREATE}, {testPluginFile, FAN_CLOSE_WRITE}}},
		{name: "create and close of the same bytes", kind: "themes", install: copyInstall,
			writes: []observation{{testPluginFile, FAN_CREATE}, {testPluginFile, FAN_CLOSE_WRITE}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			staged := filepath.Join(root, "wp-content", "upgrade", "example-2.0", "example", "example.php")
			installed := filepath.Join(root, "wp-content", tc.kind, "example", "example.php")
			r := newWPInstallRun(t, root)
			for _, write := range tc.writes {
				writeWPInstallFile(t, staged, write.body)
				f, err := os.Open(staged)
				if err != nil {
					t.Fatal(err)
				}
				c := r.fm.observeDropperCandidate(fileEvent{path: staged, fd: int(f.Fd()), pid: 4242, mask: write.mask}, "")
				_ = f.Close()
				if c == nil {
					t.Fatal("missing candidate")
				}
			}
			switch tc.install {
			case copyInstall:
				writeWPInstallFile(t, installed, testPluginFile)
				if err := os.Remove(staged); err != nil {
					t.Fatal(err)
				}
			case renameInstall:
				if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(staged, installed); err != nil {
					t.Fatal(err)
				}
			}
			r.probeAndFlush()
			if tc.wantAlert {
				if len(*r.alerts) != 1 || (*r.alerts)[0].path != staged {
					t.Fatalf("payload deletion lost: %+v", *r.alerts)
				}
			} else if len(*r.alerts) != 0 {
				t.Fatalf("clean package install reported: %+v", *r.alerts)
			}
		})
	}
}
