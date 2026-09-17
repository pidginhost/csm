//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
func (r *wpInstallRun) observe(t *testing.T, path string, beforeObserve func()) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if beforeObserve != nil {
		beforeObserve()
	}
	if c := r.fm.observeDropperCandidate(fileEvent{
		path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE | FAN_CLOSE_WRITE,
	}, "pid=4242 cmd=lsphp uid=1000"); c == nil {
		t.Fatalf("staged PHP %s was not admitted", path)
	}
}

func (r *wpInstallRun) probeAndFlush() {
	probeAt := time.Now().Add(r.ttl + time.Second)
	prober := &dropperFSProbe{quarantines: r.fm.dropperQuarantines}
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
