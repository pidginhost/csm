//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Configuration basenames must not hide an executable from the temp check,
// including names recovered from an editor's atomic-save staging file.
func TestTmpExecutableConfigNames(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned executable; run through scripts/go-linux.sh")
	}
	oldWindow, oldAncestry, oldRoots := tmpExecPkgWindow, tmpExecAncestry, panelToolRoots
	t.Cleanup(func() {
		tmpExecPkgWindow, tmpExecAncestry, panelToolRoots = oldWindow, oldAncestry, oldRoots
	})
	panelToolRoots = func() []string { return nil }
	tmpExecAncestry = func(int32) ancestryEvidence { return ancestryEvidence{packageManager: true} }
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		t.Run(root, func(t *testing.T) {
			t.Setenv("TMPDIR", root)
			dir := t.TempDir()
			for _, name := range []string{".htaccess", ".user.ini", "php.ini", ".temp.123..htaccess", ".temp.123..user.ini", ".temp.123.php.ini"} {
				for _, maintenance := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/maintenance=%v", name, maintenance), func(t *testing.T) {
						tmpExecPkgWindow = func(time.Time) bool { return maintenance }
						path := filepath.Join(dir, name)
						if err := os.WriteFile(path, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
							t.Fatal(err)
						}
						fd := openRawFd(t, path)
						ch := make(chan alert.Finding, 4)
						fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
						event, admitted := fm.classifyEvent(path, fd)
						if !admitted {
							t.Fatal("executable was not admitted")
						}
						event.pid = 4242
						fm.analyzeFile(event)
						findings := drainFindings(ch)
						if len(findings) != 1 {
							t.Fatalf("findings = %+v, want exactly one", findings)
						}
						want := alert.Critical
						if maintenance {
							want = alert.Warning
						}
						got := findings[0]
						if got.Check != "executable_in_tmp_realtime" || got.FilePath != path || got.Severity != want {
							t.Fatalf("finding = %+v, want temp executable at %s with severity %v", got, path, want)
						}
						if strings.Contains(got.Details, "[demoted:") != maintenance {
							t.Errorf("incorrect provenance annotation: %s", got.Details)
						}
						if err := os.Chmod(path, 0o644); err != nil {
							t.Fatal(err)
						}
						fm = &FileMonitor{cfg: &config.Config{}, alertCh: ch}
						fm.analyzeFile(event)
						if got := drainFindings(ch); len(got) != 0 {
							t.Fatalf("non-executable configuration raised findings: %+v", got)
						}
						if err := os.Chmod(path, 0o755); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		})
	}
}

// An initramfs-sized burst uses per-file dedup and the shared bounded ingest
// queue. This pins loss accounting without hiding maintenance executables.
func TestTmpExecutableBurstAccounting(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	dir := filepath.Join(t.TempDir(), "dracut.work")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 500)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	for i := 0; i < 600; i++ {
		path := filepath.Join(dir, fmt.Sprintf("tool%d", i))
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(ch) != 500 || atomic.LoadInt64(&fm.droppedAlerts) != 100 {
		t.Fatalf("queued = %d, dropped = %d; want 500 and 100", len(ch), atomic.LoadInt64(&fm.droppedAlerts))
	}
	entries := 0
	fm.alertDedup.Range(func(_, _ any) bool { entries++; return true })
	if entries != 600 {
		t.Fatalf("dedup entries = %d, want 600 including dropped findings", entries)
	}
	for _, got := range drainFindings(ch) {
		if got.Check != "executable_in_tmp_realtime" || got.Severity != alert.Critical {
			t.Fatalf("unexpected burst finding: %+v", got)
		}
	}
}

func TestTmpExecutableConfigContentAndSuppression(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	for _, tc := range []struct {
		name, body string
		checks     []string
	}{
		{".htaccess", "php_value auto_prepend_file /tmp/payload.php\n", []string{"executable_in_tmp_realtime", "htaccess_injection_realtime", "htaccess_auto_prepend"}},
		{".user.ini", "allow_url_include = On\n", []string{"executable_in_tmp_realtime", "php_config_realtime"}},
		{"php.ini", "allow_url_include = On\n", []string{"executable_in_tmp_realtime", "php_config_realtime"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(path, []byte(tc.body), 0o755); err != nil {
				t.Fatal(err)
			}
			fd := openRawFd(t, path)
			ch := make(chan alert.Finding, 4)
			cfg := &config.Config{}
			fm := &FileMonitor{cfg: cfg, alertCh: ch}
			fm.analyzeFile(fileEvent{path: path, fd: fd})
			findings := drainFindings(ch)
			var gotChecks []string
			for _, finding := range findings {
				gotChecks = append(gotChecks, finding.Check)
			}
			if !reflect.DeepEqual(gotChecks, tc.checks) {
				t.Fatalf("checks = %v, want %v", gotChecks, tc.checks)
			}
			cfg.Suppressions.IgnorePaths = []string{path}
			fm = &FileMonitor{cfg: cfg, alertCh: ch}
			fm.analyzeFile(fileEvent{path: path, fd: fd})
			if got := drainFindings(ch); len(got) != 0 {
				t.Fatalf("operator suppression ignored: %+v", got)
			}
		})
	}
}

// writeTmpExec creates an executable and runs it through the analyzer.
func writeTmpExec(t *testing.T, fm *FileMonitor, path string) {
	t.Helper()
	writeTmpExecAs(t, fm, path, 4242)
}

// writeTmpExecAs is writeTmpExec for a chosen writer PID.
func writeTmpExecAs(t *testing.T, fm *FileMonitor, path string, pid int32) {
	t.Helper()
	makeTmpExec(t, path)
	analyzeTmpExec(t, fm, path, pid)
}

func tmpWorkDirForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "csm-workdir-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func overrideTmpExecDemote(t *testing.T, demote func(path string) bool) *string {
	t.Helper()
	current := new(string)
	old, oldAncestry := tmpExecDemote, tmpExecAncestry
	// A live writer that proves nothing: the stubbed decision is the only
	// thing that can demote.
	tmpExecAncestry = func(int32) ancestryEvidence { return ancestryEvidence{} }
	tmpExecDemote = func(uint32, ancestryEvidence, time.Time) (bool, string) {
		return demote(*current), "test maintenance"
	}
	t.Cleanup(func() { tmpExecDemote, tmpExecAncestry = old, oldAncestry })
	return current
}

// Maintenance writes hundreds of executables into one work directory. Demoted
// findings are grouped by that directory so they cannot fill the queue, while
// an executable that was not demoted in the same directory is still reported.
func TestTmpExecutableDemotedBurstGroupsByWorkDir(t *testing.T) {
	work := tmpWorkDirForTest(t)
	nested := filepath.Join(work, "initramfs", "usr", "bin")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	other := tmpWorkDirForTest(t)
	demoted := true
	overrideTmpExecDemote(t, func(string) bool { return demoted })

	ch := make(chan alert.Finding, 500)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	for i := 0; i < 600; i++ {
		dir := work
		if i%2 == 1 {
			dir = nested
		}
		writeTmpExec(t, fm, filepath.Join(dir, fmt.Sprintf("tool%d", i)))
	}
	got := drainFindings(ch)
	if len(got) != 1 || atomic.LoadInt64(&fm.droppedAlerts) != 0 {
		t.Fatalf("burst queued %d findings and dropped %d; want 1 and 0", len(got), atomic.LoadInt64(&fm.droppedAlerts))
	}
	if got[0].Severity != alert.Warning || got[0].FilePath != filepath.Join(work, "tool0") {
		t.Fatalf("grouped finding = %+v, want a Warning naming the first file", got[0])
	}
	if !strings.Contains(got[0].Details, "work directory") {
		t.Fatalf("Details = %q, want a note that the finding stands for its work directory", got[0].Details)
	}

	writeTmpExec(t, fm, filepath.Join(other, "tool"))
	got = drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("a second work directory must get its own finding, got %+v", got)
	}

	demoted = false
	planted := filepath.Join(nested, "planted")
	writeTmpExec(t, fm, planted)
	got = drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Critical || got[0].FilePath != planted {
		t.Fatalf("an executable that is not demoted must be reported on its own, got %+v", got)
	}
}

// A file directly in a temp root has no work directory to stand for, so each
// one keeps its own finding.
func TestTmpExecutableDemotedTopLevelFilesStaySeparate(t *testing.T) {
	overrideTmpExecDemote(t, func(string) bool { return true })
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	for i := 0; i < 2; i++ {
		f, err := os.CreateTemp("/tmp", "csm-toplevel-*")
		if err != nil {
			t.Fatal(err)
		}
		path := f.Name()
		_ = f.Close()
		t.Cleanup(func() { _ = os.Remove(path) })
		writeTmpExec(t, fm, path)
	}
	if got := drainFindings(ch); len(got) != 2 {
		t.Fatalf("top-level temp executables queued %d findings, want 2", len(got))
	}
}

func TestTmpWorkDir(t *testing.T) {
	cases := map[string]string{
		"/tmp/tool":                     "/tmp/tool",
		"/var/tmp/tool":                 "/var/tmp/tool",
		"/dev/shm/tool":                 "/dev/shm/tool",
		"/tmp/work/tool":                "/tmp/work/",
		"/tmp/work/a/b/tool":            "/tmp/work/",
		"/var/tmp/build.x/usr/bin/tool": "/var/tmp/build.x/",
		"/dev/shm/x/y":                  "/dev/shm/x/",
		"/home/user/tmp/x/y":            "/home/user/tmp/x/y",
	}
	for path, want := range cases {
		if got := tmpWorkDir(path); got != want {
			t.Errorf("tmpWorkDir(%q) = %q, want %q", path, got, want)
		}
	}
}

// A maintenance warning must not consume a later Critical file cooldown.
func TestTmpExecutableTopLevelSeverityEscalation(t *testing.T) {
	demoted := true
	overrideTmpExecDemote(t, func(string) bool { return demoted })
	f, err := os.CreateTemp("/tmp", "csm-escalation-*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(path) })
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	writeTmpExec(t, fm, path)
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("maintenance: %+v", got)
	}
	demoted = false
	writeTmpExec(t, fm, path)
	got = drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("severity escalation: %+v", got)
	}
}

const (
	tmpProvenPID int32 = 5001 // descends from an initramfs build
	tmpGonePID   int32 = 5002 // exited before its ancestry was read
	tmpLivePID   int32 = 5003 // still running, proves nothing
)

// stubTmpExecWriters replaces the process table with three fixed writers and
// leaves the real demotion decision in place.
func stubTmpExecWriters(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the files under test must be root-owned")
	}
	oldW, oldA, oldR := tmpExecPkgWindow, tmpExecAncestry, panelToolRoots
	tmpExecPkgWindow = func(time.Time) bool { return false }
	panelToolRoots = func() []string { return nil }
	tmpExecAncestry = func(pid int32) ancestryEvidence {
		switch pid {
		case tmpProvenPID:
			return ancestryEvidence{initramfsBuilder: true}
		case tmpGonePID:
			return ancestryEvidence{vanished: true}
		}
		return ancestryEvidence{}
	}
	t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry, panelToolRoots = oldW, oldA, oldR })
}

// endAlertCooldown lets the next finding through as if the cooldown had run out.
func endAlertCooldown(fm *FileMonitor) {
	fm.alertDedup.Range(func(k, _ any) bool {
		fm.alertDedup.Delete(k)
		return true
	})
}

// A build copies most of its files with tools that exit as soon as the file is
// closed, so their ancestry can no longer be read. Such a file is judged by a
// writer that was proven in the same work directory; a writer that is still
// running and proves nothing is not.
func TestTmpExecutableVanishedWriterFollowsWorkDir(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	nested := filepath.Join(work, "initramfs", "usr", "bin")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	early := filepath.Join(nested, "early")
	writeTmpExecAs(t, fm, early, tmpGonePID)
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Critical || got[0].FilePath != early {
		t.Fatalf("exited writer before any proof: %+v, want its own Critical", got)
	}
	if !strings.Contains(got[0].Details, "writer exited") {
		t.Fatalf("Details = %q, want a note that the writer had exited", got[0].Details)
	}

	writeTmpExecAs(t, fm, filepath.Join(nested, "bash"), tmpProvenPID)
	got = drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("proven writer: %+v, want one Warning", got)
	}

	for i := 0; i < 50; i++ {
		writeTmpExecAs(t, fm, filepath.Join(nested, fmt.Sprintf("lib%d.so", i)), tmpGonePID)
	}
	if got = drainFindings(ch); len(got) != 0 {
		t.Fatalf("exited writers in a proven work directory queued %+v, want them grouped with its Warning", got)
	}

	endAlertCooldown(fm)
	late := filepath.Join(work, "late")
	writeTmpExecAs(t, fm, late, tmpGonePID)
	got = drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Warning || got[0].FilePath != late {
		t.Fatalf("exited writer after the cooldown: %+v, want the next grouped Warning", got)
	}
	for _, want := range []string{"initramfs build ancestry", "writer exited", "work directory"} {
		if !strings.Contains(got[0].Details, want) {
			t.Fatalf("Details = %q, want %q", got[0].Details, want)
		}
	}

	planted := filepath.Join(nested, "planted")
	writeTmpExecAs(t, fm, planted, tmpLivePID)
	got = drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Critical || got[0].FilePath != planted {
		t.Fatalf("running writer that proves nothing: %+v, want its own Critical", got)
	}
}

// Only a directory nobody but root can write to carries a proven writer's
// verdict, and only for root-owned files.
func TestTmpExecutableVouchNeedsRootPrivateWorkDir(t *testing.T) {
	for _, tt := range []struct {
		name    string
		prepare func(t *testing.T, work string)
		file    func(t *testing.T, path string)
	}{
		{name: "world-writable directory", prepare: func(t *testing.T, work string) { chmodForTest(t, work, 0o777) }},
		{name: "sticky world-writable directory", prepare: func(t *testing.T, work string) { chmodForTest(t, work, 0o1777) }},
		{name: "group-writable directory", prepare: func(t *testing.T, work string) { chmodForTest(t, work, 0o770) }},
		{name: "directory owned by another user", prepare: func(t *testing.T, work string) { chownForTest(t, work) }},
		{name: "file owned by another user", file: chownForTest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stubTmpExecWriters(t)
			work := tmpWorkDirForTest(t)
			if tt.prepare != nil {
				tt.prepare(t, work)
			}
			ch := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			writeTmpExecAs(t, fm, filepath.Join(work, "bash"), tmpProvenPID)
			if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
				t.Fatalf("proven writer: %+v, want one Warning", got)
			}

			path := filepath.Join(work, "tool")
			makeTmpExec(t, path)
			if tt.file != nil {
				tt.file(t, path)
			}
			// As captured at admission, so the file's owner at analysis time
			// is what decides.
			gone := ancestryEvidence{vanished: true}
			fm.analyzeFile(fileEvent{path: path, fd: openRawFd(t, path), pid: tmpGonePID, tmpAncestry: &gone})
			got := drainFindings(ch)
			if len(got) != 1 || got[0].Severity != alert.Critical || got[0].FilePath != path {
				t.Fatalf("exited writer: %+v, want its own Critical", got)
			}
		})
	}
}

// A file placed directly in a temp root has no work directory, so nothing can
// vouch for it.
func TestTmpExecutableTopLevelFileIsNeverVouched(t *testing.T) {
	stubTmpExecWriters(t)
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	var paths []string
	for i := 0; i < 2; i++ {
		f, err := os.CreateTemp("/tmp", "csm-toplevel-*")
		if err != nil {
			t.Fatal(err)
		}
		path := f.Name()
		_ = f.Close()
		t.Cleanup(func() { _ = os.Remove(path) })
		paths = append(paths, path)
	}
	writeTmpExecAs(t, fm, paths[0], tmpProvenPID)
	writeTmpExecAs(t, fm, paths[1], tmpGonePID)
	got := drainFindings(ch)
	if len(got) != 2 || got[0].Severity != alert.Warning || got[1].Severity != alert.Critical {
		t.Fatalf("top-level files: %+v, want a Warning then a Critical", got)
	}
}

// A vouch binds the directory inode and placement, lasts a short time after
// the last proof, and the table stays small.
func TestTmpVouchesIdentityExpiryAndBound(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: a vouched directory must be root-owned")
	}
	now := time.Unix(1_700_000_000, 0)
	work := tmpWorkDirForTest(t)
	var v tmpVouches
	t.Cleanup(v.close)
	eventFor := func(dir string) fileEvent {
		path := filepath.Join(dir, "tool")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			makeTmpExec(t, path)
		}
		return fileEvent{path: path, fd: openRawFd(t, path)}
	}

	if _, ok := v.covers(eventFor(work), now); ok {
		t.Fatal("covered a directory nobody vouched for")
	}
	v.grant(eventFor(work), "initramfs build ancestry", now)
	if reason, ok := v.covers(eventFor(work), now.Add(tmpVouchTTL-time.Second)); !ok || reason != "initramfs build ancestry" {
		t.Fatalf("covers = (%q, %v), want the granted reason", reason, ok)
	}
	if _, ok := v.covers(eventFor(work), now.Add(tmpVouchTTL+time.Second)); ok {
		t.Fatal("vouch outlived its time limit")
	}

	v.grant(eventFor(work), "initramfs build ancestry", now)

	// Neither a replacement nor a renamed directory inherits the old placement proof.
	moved := work + ".moved"
	if err := os.Rename(work, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.covers(eventFor(work), now); ok {
		t.Fatal("a new directory under a vouched name was covered")
	}
	if _, ok := v.covers(eventFor(moved), now); ok {
		t.Fatal("a renamed directory inherited a vouch for another placement")
	}

	for i := 0; i < tmpVouchCap+8; i++ {
		v.grant(eventFor(tmpWorkDirForTest(t)), "x", now.Add(time.Duration(i)*time.Millisecond))
	}
	if len(v.entries) > tmpVouchCap {
		t.Fatalf("vouch table holds %d entries, cap is %d", len(v.entries), tmpVouchCap)
	}
	newest := tmpWorkDirForTest(t) + "/"
	v.grant(eventFor(newest), "newest", now.Add(time.Second))
	if _, ok := v.covers(eventFor(newest), now.Add(time.Second)); !ok {
		t.Fatal("a full table refused the newest vouch")
	}
}

// Copy tools exit within moments of closing the file, long before an analyzer
// worker reaches the event, so the writer's ancestry is read on admission.
func TestTmpExecAncestryCapturedAtAdmission(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	path := filepath.Join(work, "tool")
	makeTmpExec(t, path)

	walks := 0
	tmpExecAncestry = func(pid int32) ancestryEvidence {
		walks++
		return ancestryEvidence{initramfsBuilder: pid == tmpProvenPID}
	}
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch, analyzerCh: make(chan fileEvent, 1)}
	fm.handleEvent(openRawFd(t, path), tmpProvenPID, FAN_CLOSE_WRITE)
	event := <-fm.analyzerCh
	if walks != 1 || event.tmpAncestry == nil || !event.tmpAncestry.initramfsBuilder {
		t.Fatalf("ancestry not captured at admission: walks=%d captured=%+v", walks, event.tmpAncestry)
	}

	// The writer has exited while the event waited in the analyzer queue.
	tmpExecAncestry = func(int32) ancestryEvidence {
		t.Error("walked the writer after admission")
		return ancestryEvidence{vanished: true}
	}
	fm.analyzeFile(event)
	if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("findings = %+v, want one Warning from the captured ancestry", got)
	}
}

// The capture is paid only for root-owned files under a temp root.
func TestTmpExecAncestryCaptureIsScoped(t *testing.T) {
	stubTmpExecWriters(t)
	tmpExecAncestry = func(int32) ancestryEvidence {
		t.Error("walked a writer whose file can never be demoted")
		return ancestryEvidence{}
	}
	foreign := filepath.Join(tmpWorkDirForTest(t), "tool")
	makeTmpExec(t, foreign)
	chownForTest(t, foreign)
	// t.TempDir can itself sit under /tmp.
	outsideDir, err := os.MkdirTemp("/var/cache", "csm-outside-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outsideDir) })
	outside := filepath.Join(outsideDir, "tool")
	makeTmpExec(t, outside)
	for _, path := range []string{foreign, outside} {
		event := fileEvent{path: path, fd: openRawFd(t, path), pid: tmpProvenPID}
		captureTmpExecAncestry(&event)
		if event.tmpAncestry != nil {
			t.Fatalf("captured ancestry for %s", path)
		}
	}
}

func makeTmpExec(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	chmodForTest(t, path, 0o755)
}

func analyzeTmpExec(t *testing.T, fm *FileMonitor, path string, pid int32) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd()), pid: pid})
}

func chmodForTest(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// chownForTest hands path to the nobody user.
func chownForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
}
