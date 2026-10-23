package checks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// docrootExecBackend reports a critical match for content carrying the
// marker and counts scans, so tests can tell a cached verdict from a rescan.
type docrootExecBackend struct {
	scans atomic.Int32
	err   error
}

func (b *docrootExecBackend) ScanFile(string, int) []yara.Match { return nil }
func (b *docrootExecBackend) ScanBytes(data []byte) []yara.Match {
	matches, _ := b.ScanBytesChecked(data)
	return matches
}
func (b *docrootExecBackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	b.scans.Add(1)
	if b.err != nil {
		return nil, b.err
	}
	if strings.Contains(string(data), "payload-fetcher") {
		return []yara.Match{{RuleName: "elf_web_payload_dropper", Meta: map[string]string{"severity": "critical"}}}, nil
	}
	return nil, nil
}
func (b *docrootExecBackend) RuleCount() int { return 1 }
func (b *docrootExecBackend) Reload() error  { return nil }

const testELFHeader = "\x7fELF\x02\x01\x01"

// docrootExecFixture is one account docroot with a process table. procs maps
// a PID to the target /proc/<pid>/exe resolves to; a PID missing from it has
// exited.
type docrootExecFixture struct {
	docroot string
	roots   *DocrootIndex
	procs   map[int]string
	opens   []string
	backend *docrootExecBackend
}

func newDocrootExecFixture(t *testing.T) *docrootExecFixture {
	t.Helper()
	resetDocrootBinaryCache()
	t.Cleanup(resetDocrootBinaryCache)
	docroot := filepath.Join(t.TempDir(), "home", "alice", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &docrootExecFixture{
		docroot: docroot,
		roots:   NewDocrootIndex([]string{docroot}),
		procs:   map[int]string{},
		backend: &docrootExecBackend{},
	}
	withMockOS(t, &mockOS{
		readlink: func(name string) (string, error) {
			for pid, target := range f.procs {
				if name == procExePath(pid) {
					return target, nil
				}
			}
			return "", os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			f.opens = append(f.opens, name)
			for pid, target := range f.procs {
				if name == procExePath(pid) {
					return os.Open(strings.TrimSuffix(target, " (deleted)"))
				}
			}
			return os.Open(name)
		},
	})
	old := activeYARABackend
	activeYARABackend = func() yara.Backend { return f.backend }
	t.Cleanup(func() { activeYARABackend = old })
	return f
}

func (f *docrootExecFixture) write(t *testing.T, rel, content string) string {
	t.Helper()
	path := filepath.Join(f.docroot, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInspectDocrootExecReportsMalwareProgram(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "wp-content/themes/t/node_modules/lib/a1b2", testELFHeader+"payload-fetcher")
	f.procs[4242] = path

	got := InspectDocrootExec(nil, 4242, 1001, "./a1b2", "lsphp", f.roots)
	if got == nil {
		t.Fatal("no finding for a malware program started from a document root")
	}
	if got.Severity != alert.Critical || got.Check != "docroot_binary_exec" {
		t.Fatalf("finding = %s/%s, want critical docroot_binary_exec", got.Severity, got.Check)
	}
	if got.FilePath != path || got.PID != 4242 {
		t.Fatalf("finding path/pid = %q/%d, want %q/4242", got.FilePath, got.PID, path)
	}
	if !strings.Contains(got.Message, "elf_web_payload_dropper") || !strings.Contains(got.Details, "lsphp") {
		t.Fatalf("finding must name the rule and the parent: %q / %q", got.Message, got.Details)
	}
	if len(got.ContentSHA256) != 64 {
		t.Fatalf("content digest = %q, want the scanned file's sha256", got.ContentSHA256)
	}
}

// Any launcher counts for a malware match: cron or a login shell can start a
// dropper as well as PHP.
func TestInspectDocrootExecMalwareMatchIgnoresParent(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "bin/agent", testELFHeader+"payload-fetcher")
	f.procs[77] = path

	got := InspectDocrootExec(nil, 77, 1001, path, "crond", f.roots)
	if got == nil || got.Severity != alert.Critical {
		t.Fatalf("finding = %+v, want critical", got)
	}
}

func TestInspectDocrootExecWarnsWhenPHPStartsCleanProgram(t *testing.T) {
	for _, parent := range []string{"lsphp", "php-fpm", "php-cgi", "php", "php8.2", "php-fpm8.1"} {
		t.Run(parent, func(t *testing.T) {
			f := newDocrootExecFixture(t)
			path := f.write(t, "wp-content/plugins/img/bin/cwebp-linux", testELFHeader+"image encoder")
			f.procs[300] = path

			got := InspectDocrootExec(nil, 300, 1001, path, parent, f.roots)
			if got == nil || got.Severity != alert.Warning || got.Check != "docroot_binary_exec" {
				t.Fatalf("finding = %+v, want warning docroot_binary_exec", got)
			}
			if got.FilePath != path {
				t.Fatalf("finding path = %q, want %q", got.FilePath, path)
			}
		})
	}
}

// Web servers run CGI programs from document roots, and build tools such as
// esbuild run from node_modules. Neither is reported without a malware match.
func TestInspectDocrootExecQuietForCleanProgramFromOtherLaunchers(t *testing.T) {
	for _, parent := range []string{"lscgid", "httpd", "suexec", "node", "bash", "crond", "phpstorm"} {
		t.Run(parent, func(t *testing.T) {
			f := newDocrootExecFixture(t)
			path := f.write(t, "cgi-bin/cgiecho", testELFHeader+"cgi program")
			f.procs[301] = path
			if got := InspectDocrootExec(nil, 301, 1001, path, parent, f.roots); got != nil {
				t.Fatalf("finding = %+v, want none", got)
			}
			if n := f.backend.scans.Load(); n != 1 {
				t.Fatalf("scans = %d, want the program judged by content before staying quiet", n)
			}
		})
	}
}

// A CGI script started from a document root runs an interpreter installed
// elsewhere; /proc names the interpreter, so the script is not a program.
func TestInspectDocrootExecSkipsScriptsRunByInterpreter(t *testing.T) {
	f := newDocrootExecFixture(t)
	script := f.write(t, "cgi-bin/form.pl", "#!/usr/bin/perl\nprint 1;\n")
	f.procs[302] = "/usr/bin/perl"

	if got := InspectDocrootExec(nil, 302, 1001, script, "lsphp", f.roots); got != nil {
		t.Fatalf("finding = %+v, want none", got)
	}
	if len(f.opens) != 0 {
		t.Fatalf("opened %v for a program outside every document root", f.opens)
	}
}

func TestInspectDocrootExecSkipsRootWithoutIO(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "x", testELFHeader+"payload-fetcher")
	f.procs[1] = path
	if got := InspectDocrootExec(nil, 1, 0, path, "lsphp", f.roots); got != nil {
		t.Fatalf("finding = %+v, want none for root", got)
	}
	if len(f.opens) != 0 {
		t.Fatalf("opened %v for a root process", f.opens)
	}
}

func TestInspectDocrootExecResolvesRelativeName(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "wp-content/uploads/x", testELFHeader+"payload-fetcher")
	f.procs[303] = path
	got := InspectDocrootExec(nil, 303, 1001, "./x", "sh", f.roots)
	if got == nil || got.FilePath != path {
		t.Fatalf("finding = %+v, want one for %s", got, path)
	}
}

// A dropper commonly deletes itself after it starts. The kernel keeps the
// running file, so it is still read and named by its original path.
func TestInspectDocrootExecReadsDeletedRunningProgram(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "a", testELFHeader+"payload-fetcher")
	f.procs[304] = path + " (deleted)"
	got := InspectDocrootExec(nil, 304, 1001, path, "lsphp", f.roots)
	if got == nil || got.Severity != alert.Critical || got.FilePath != path {
		t.Fatalf("finding = %+v, want critical for %s", got, path)
	}
}

// A short-lived program may exit before it is inspected. Its file is then
// read by the started name; a script there is still not a program.
func TestInspectDocrootExecFallsBackToStartedPathAfterExit(t *testing.T) {
	f := newDocrootExecFixture(t)
	program := f.write(t, "p", testELFHeader+"payload-fetcher")
	if got := InspectDocrootExec(nil, 305, 1001, program, "lsphp", f.roots); got == nil || got.Severity != alert.Critical {
		t.Fatalf("finding = %+v, want critical for an exited program", got)
	}
	script := f.write(t, "s.cgi", "#!/bin/sh\necho ok\n")
	if got := InspectDocrootExec(nil, 306, 1001, script, "lsphp", f.roots); got != nil {
		t.Fatalf("finding = %+v, want none for an exited script", got)
	}
	if got := InspectDocrootExec(nil, 307, 1001, "./gone", "lsphp", f.roots); got != nil {
		t.Fatalf("finding = %+v, want none when neither /proc nor the name resolves", got)
	}
}

func TestInspectDocrootExecIgnoresProgramsOutsideDocroots(t *testing.T) {
	f := newDocrootExecFixture(t)
	home := filepath.Dir(f.docroot)
	path := filepath.Join(home, "bin", "tool")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(testELFHeader+"payload-fetcher"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.procs[308] = path
	if got := InspectDocrootExec(nil, 308, 1001, path, "bash", f.roots); got != nil {
		t.Fatalf("finding = %+v, want none for ~/bin", got)
	}
	if f.backend.scans.Load() != 0 {
		t.Fatal("scanned a program outside every document root")
	}
}

// A hot program is read once; a changed file is read again.
func TestInspectDocrootExecCachesVerdictByFileVersion(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "bin/encoder", testELFHeader+"image encoder")
	f.procs[309] = path
	for i := 0; i < 3; i++ {
		if got := InspectDocrootExec(nil, 309, 1001, path, "lsphp", f.roots); got == nil || got.Severity != alert.Warning {
			t.Fatalf("run %d: finding = %+v, want warning", i, got)
		}
	}
	if n := f.backend.scans.Load(); n != 1 {
		t.Fatalf("scans = %d, want 1 for an unchanged program", n)
	}

	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte(testELFHeader+"payload-fetcher"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := InspectDocrootExec(nil, 309, 1001, path, "lsphp", f.roots)
	if got == nil || got.Severity != alert.Critical {
		t.Fatalf("finding after rewrite = %+v, want critical", got)
	}
	if n := f.backend.scans.Load(); n != 2 {
		t.Fatalf("scans = %d, want a rescan after the file changed", n)
	}
}

// A scan that failed is not a verdict: the next start scans again.
func TestInspectDocrootExecDoesNotCacheFailedScan(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "bin/tool", testELFHeader+"payload-fetcher")
	f.procs[310] = path
	f.backend.err = errors.New("worker down")

	got := InspectDocrootExec(nil, 310, 1001, path, "lsphp", f.roots)
	if got == nil || got.Severity != alert.Warning || !strings.Contains(got.Details, "worker down") {
		t.Fatalf("finding = %+v, want a warning naming the scan failure", got)
	}
	f.backend.err = nil
	if got := InspectDocrootExec(nil, 310, 1001, path, "lsphp", f.roots); got == nil || got.Severity != alert.Critical {
		t.Fatalf("finding after recovery = %+v, want critical", got)
	}
}

func TestInspectDocrootExecReportsOversizeProgramUnscanned(t *testing.T) {
	f := newDocrootExecFixture(t)
	cfg := &config.Config{}
	cfg.Thresholds.FullScanMaxFileMB = 1
	path := f.write(t, "big", testELFHeader+strings.Repeat("A", 1<<20)+"payload-fetcher")
	f.procs[311] = path

	got := InspectDocrootExec(cfg, 311, 1001, path, "lsphp", f.roots)
	if got == nil || got.Severity != alert.Warning || !strings.Contains(got.Details, "scan limit") {
		t.Fatalf("finding = %+v, want a warning that the program was not scanned", got)
	}
	if f.backend.scans.Load() != 0 {
		t.Fatal("scanned a program past the size limit")
	}
	if got := InspectDocrootExec(cfg, 311, 1001, path, "lscgid", f.roots); got != nil {
		t.Fatalf("finding = %+v, want none for an unscanned program from a CGI launcher", got)
	}
}

// The periodic process walk runs where the live exec monitor is unavailable,
// and catches programs that were already running when CSM started.
func TestCheckSuspiciousProcessesReportsDocrootProgram(t *testing.T) {
	resetDocrootBinaryCache()
	t.Cleanup(resetDocrootBinaryCache)
	docroot := filepath.Join(t.TempDir(), "home", "alice", "public_html")
	program := filepath.Join(docroot, "wp-content", "uploads", "x")
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte(testELFHeader+"payload-fetcher"), 0o755); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/proc/[0-9]*/exe":
				return []string{"/proc/500/exe", "/proc/501/exe"}, nil
			case docroot:
				return []string{docroot}, nil
			}
			return nil, nil
		},
		stat: os.Stat,
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/500/status":
				return []byte("Name:\tx\nPPid:\t400\nUid:\t1001\t1001\t1001\t1001\n"), nil
			case "/proc/501/status":
				return []byte("Name:\tx\nPPid:\t400\nUid:\t0\t0\t0\t0\n"), nil
			case "/proc/400/comm":
				return []byte("lsphp\n"), nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) {
			if name == "/proc/500/exe" || name == "/proc/501/exe" {
				return program, nil
			}
			return "", os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/proc/500/exe" || name == "/proc/501/exe" {
				return os.Open(program)
			}
			return nil, os.ErrNotExist
		},
	})
	backend := &docrootExecBackend{}
	old := activeYARABackend
	activeYARABackend = func() yara.Backend { return backend }
	t.Cleanup(func() { activeYARABackend = old })

	findings := CheckSuspiciousProcesses(context.Background(), &config.Config{AccountRoots: []string{docroot}}, nil)
	var got []alert.Finding
	for _, f := range findings {
		if f.Check == "docroot_binary_exec" {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		t.Fatalf("docroot findings = %+v, want exactly one for the non-root process", got)
	}
	if got[0].Severity != alert.Critical || got[0].PID != 500 || got[0].FilePath != program {
		t.Fatalf("finding = %+v, want critical for pid 500 at %s", got[0], program)
	}
	if !strings.Contains(got[0].Details, "Parent process: lsphp") {
		t.Fatalf("details = %q, want the parent process name", got[0].Details)
	}
}

func TestDocrootExecFindingAttributesByPath(t *testing.T) {
	f := newDocrootExecFixture(t)
	withAccountHomeRoots(t, filepath.Dir(filepath.Dir(f.docroot)))
	path := f.write(t, "wp-content/uploads/x", testELFHeader+"payload-fetcher")
	f.procs[600] = path
	got := InspectDocrootExec(nil, 600, 1001, path, "lsphp", f.roots)
	if got == nil {
		t.Fatal("no finding")
	}
	requireChecks(t, expectAttributed(t, []alert.Finding{*got}, "alice"), "docroot_binary_exec")
}

func TestIsPHPInterpreterComm(t *testing.T) {
	for comm, want := range map[string]bool{
		"lsphp": true, "lsphp8": true, "php": true, "php74": true, "php8.2": true,
		"php-fpm": true, "php-fpm8.1": true, "php-cgi": true, "ea-php81": true,
		"phpstorm": false, "php-worker": false, "lscgid": false, "httpd": false, "": false, "sh": false,
	} {
		if got := isPHPInterpreterComm(comm); got != want {
			t.Errorf("isPHPInterpreterComm(%q) = %v, want %v", comm, got, want)
		}
	}
}

func TestInspectDocrootExecRechecksRaisedScanLimit(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "big", testELFHeader+strings.Repeat("A", 1<<20)+"payload-fetcher")
	f.procs[700] = path
	cfg := &config.Config{}
	cfg.Thresholds.FullScanMaxFileMB = 1
	if got := InspectDocrootExec(cfg, 700, 1001, path, "bash", f.roots); got != nil {
		t.Fatalf("oversize program: %+v", got)
	}
	cfg.Thresholds.FullScanMaxFileMB = 2
	if got := InspectDocrootExec(cfg, 700, 1001, path, "bash", f.roots); got == nil || got.Severity != alert.Critical {
		t.Fatalf("raised limit retained an unscanned verdict: %+v", got)
	}
}

func TestInspectDocrootExecSameSizeRewriteInvalidatesCache(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "tool", testELFHeader+strings.Repeat("x", len("payload-fetcher")))
	f.procs[701] = path
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := InspectDocrootExec(nil, 701, 1001, path, "bash", f.roots); got != nil {
		t.Fatalf("clean program: %+v", got)
	}
	time.Sleep(10 * time.Millisecond)
	f.write(t, "tool", testELFHeader+"payload-fetcher")
	if err = os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("fixture did not retain inode, size and mtime: %v", err)
	}
	if got := InspectDocrootExec(nil, 701, 1001, path, "bash", f.roots); got == nil || got.Severity != alert.Critical {
		t.Fatalf("same-size rewrite retained a clean verdict: %+v", got)
	}
	if got := f.backend.scans.Load(); got != 2 {
		t.Fatalf("scans = %d, want 2", got)
	}
}

func TestInspectDocrootExecRejectsPermissionFallback(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "tool", testELFHeader+"payload-fetcher")
	osFS.(*mockOS).readlink = func(string) (string, error) { return "", os.ErrPermission }
	if got := InspectDocrootExec(nil, 702, 1001, path, "lsphp", f.roots); got != nil {
		t.Fatalf("permission failure treated as an exited process: %+v", got)
	}
	if len(f.opens) != 0 {
		t.Fatalf("opened fallback on permission failure: %v", f.opens)
	}
}

// The worker fallback must read the pinned inode even when the start name
// has been replaced after the inline scan was rejected.
type docrootPathRetryBackend struct {
	docrootExecBackend
	beforeRetry func()
	retryPath   string
}

func (b *docrootPathRetryBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	b.beforeRetry()
	return nil, yaraipc.ErrPayloadTooLarge
}

func (b *docrootPathRetryBackend) ScanFileChecked(path string, _ int) (yara.FileScanResult, error) {
	b.retryPath = path
	data, err := os.ReadFile(path)
	if err != nil {
		return yara.FileScanResult{}, err
	}
	matches, err := b.docrootExecBackend.ScanBytesChecked(data)
	sum := sha256.Sum256(data)
	return yara.FileScanResult{Matches: matches, ContentSHA256: fmt.Sprintf("%x", sum)}, err
}

func TestInspectDocrootExecCacheBound(t *testing.T) {
	f := newDocrootExecFixture(t)
	for i := 0; i < docrootBinaryCacheMax+2; i++ {
		path := f.write(t, fmt.Sprintf("tool-%d", i), testELFHeader+"payload-fetcher")
		f.procs[703] = path
		if got := InspectDocrootExec(nil, 703, 1001, path, "bash", f.roots); got == nil || got.Severity != alert.Critical {
			t.Fatalf("program %d: %+v", i, got)
		}
		docrootBinaryCache.Lock()
		n := len(docrootBinaryCache.verdicts)
		docrootBinaryCache.Unlock()
		if n > docrootBinaryCacheMax {
			t.Fatalf("cache retained %d entries", n)
		}
	}
	if n := f.backend.scans.Load(); n != docrootBinaryCacheMax+2 {
		t.Fatalf("scans = %d, want one per distinct inode", n)
	}
}

func TestInspectDocrootBinaryReadsOnlyHeaderForRejectedContent(t *testing.T) {
	for _, program := range []bool{false, true} {
		t.Run(fmt.Sprintf("program=%t", program), func(t *testing.T) {
			f := newDocrootExecFixture(t)
			prefix := "#!/bin/sh\n"
			if program {
				prefix = testELFHeader
			}
			path := f.write(t, "large", prefix)
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err = file.Truncate(2 << 20); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Thresholds.FullScanMaxFileMB = 1
			v, ok := inspectDocrootBinary(cfg, file)
			if !ok || v.program != program || (program && v.gap == "") {
				t.Fatalf("verdict = %+v, ok = %v", v, ok)
			}
			// Header inspection uses ReadAt. A body read would advance the
			// shared descriptor offset and reveal work past admission.
			if pos, err := file.Seek(0, io.SeekCurrent); err != nil || pos != 0 {
				t.Fatalf("body consumed: offset=%d, err=%v", pos, err)
			}
			if f.backend.scans.Load() != 0 {
				t.Fatal("scanned rejected content")
			}
		})
	}
}

func TestCheckSuspiciousProcessesHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var reads int
	withMockOS(t, &mockOS{glob: func(string) ([]string, error) {
		reads++
		return nil, nil
	}})
	if got := CheckSuspiciousProcesses(ctx, &config.Config{}, nil); len(got) != 0 {
		t.Fatalf("cancelled process check returned findings: %+v", got)
	}
	if reads != 0 {
		t.Fatalf("cancelled process check performed %d filesystem searches", reads)
	}
}

func TestInspectDocrootExecDoesNotRewriteExitedStartPath(t *testing.T) {
	f := newDocrootExecFixture(t)
	f.write(t, "tool", testELFHeader+"payload-fetcher")
	// Lexical cleaning would silently replace a nonexistent start path
	// with a different file. A symlink before '..' is ambiguous as well.
	filename := f.docroot + "/missing/../tool"
	if got := InspectDocrootExec(nil, 706, 1001, filename, "lsphp", f.roots); got != nil {
		t.Fatalf("rewrote the exited program's start path: %+v", got)
	}
	if len(f.opens) != 0 {
		t.Fatalf("opened an ambiguous fallback: %v", f.opens)
	}
}
