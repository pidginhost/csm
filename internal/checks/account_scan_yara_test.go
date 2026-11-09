package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/yara"
)

// countingYARABackend matches "dormant malware" like deepYARATestBackend and
// records every payload it is asked to scan.
type countingYARABackend struct {
	deepYARATestBackend
	mu      sync.Mutex
	scanned []string
	onScan  func()
}

func (b *countingYARABackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	b.mu.Lock()
	b.scanned = append(b.scanned, string(data))
	b.mu.Unlock()
	if b.onScan != nil {
		b.onScan()
	}
	return b.deepYARATestBackend.ScanBytesChecked(data)
}

func (b *countingYARABackend) scans() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.scanned...)
}

func useCountingYARABackend(t *testing.T) *countingYARABackend {
	t.Helper()
	backend := &countingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	return backend
}

func yaraMatchPaths(findings []alert.Finding) []string {
	var paths []string
	for _, f := range findings {
		if f.Check == "yara_match_scheduled" {
			paths = append(paths, f.FilePath)
		}
	}
	sort.Strings(paths)
	return paths
}

func fullAccountYARAContext(account string, opts AccountScanOptions) context.Context {
	return ContextWithScanOptions(ContextWithAccountScope(context.Background(), account), opts)
}

// The full account scan is the operator's answer to "is this account
// clean". Without a YARA content pass it reported clean on files only the
// YARA rules recognise, including ones in addon-domain document roots.
func TestFullAccountScanRunsYARAOverAccountDocRoots(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	main := writeYARADeepFile(t, root, "alice/public_html/wp-content/uploads/image.dat", "dormant malware")
	addon := writeYARADeepFile(t, root, "alice/addon.example/assets/kit.dat", "dormant malware")
	writeYARADeepFile(t, root, "alice/public_html/index.php", "clean")
	writeYARADeepFile(t, root, "bob/public_html/image.dat", "dormant malware")
	useCountingYARABackend(t)
	cfg := &config.Config{StatePath: t.TempDir()}

	findings := RunAccountScanWithOptions(context.Background(), cfg, nil, "alice", FullScanOptions(cfg, false))

	want := []string{addon, main}
	sort.Strings(want)
	if got := yaraMatchPaths(findings); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("YARA matches = %v, want exactly %v", got, want)
	}
	for _, f := range findings {
		if f.Check != "yara_match_scheduled" {
			continue
		}
		if f.TenantID != "alice" || f.ContentSHA256 == "" || f.Severity != alert.Critical {
			t.Fatalf("match = %+v, want a Critical alice finding with a content hash", f)
		}
	}
}

// The non-full account scan keeps its existing check set: no YARA pass.
func TestDefaultAccountScanRunsNoYARAPass(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	writeYARADeepFile(t, root, "alice/public_html/image.dat", "dormant malware")
	backend := useCountingYARABackend(t)
	cfg := &config.Config{StatePath: t.TempDir()}

	findings := RunAccountScanWithOptions(context.Background(), cfg, nil, "alice", DefaultAccountScanOptions(cfg))

	if got := yaraMatchPaths(findings); len(got) != 0 {
		t.Fatalf("default scan produced YARA matches %v", got)
	}
	if scans := backend.scans(); len(scans) != 0 {
		t.Fatalf("default scan sent %d payloads to YARA", len(scans))
	}
}

// An account on another home partition is resolved through the registry,
// so its document roots get the YARA pass too.
func TestFullAccountScanRunsYARAOnAnotherPartition(t *testing.T) {
	base := withPartitionedAccounts(t, "alice:x:1001:1001::BASE/home2/alice:/bin/bash\n", "alice")
	path := writeYARADeepFile(t, filepath.Join(base, "home2"), "alice/public_html/image.dat", "dormant malware")
	useCountingYARABackend(t)
	cfg := &config.Config{StatePath: t.TempDir()}

	findings := RunAccountScanWithOptions(context.Background(), cfg, nil, "alice", FullScanOptions(cfg, false))

	if got := yaraMatchPaths(findings); len(got) != 1 || got[0] != path {
		t.Fatalf("YARA matches = %v, want %s; findings %+v", got, path, findings)
	}
}

// A file over the full-scan size limit is never read or sent to the worker,
// and the report says which file was skipped and why.
func TestAccountYARAPassReportsOversizeFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	big := writeYARADeepFile(t, root, "alice/public_html/video.dat", strings.Repeat("x", 64))
	writeYARADeepFile(t, root, "alice/public_html/small.dat", "clean")
	backend := useCountingYARABackend(t)

	ctx := fullAccountYARAContext("alice", AccountScanOptions{ForceContent: true, MaxFileBytes: 16})
	findings := checkAccountYARA(ctx, &config.Config{}, nil)

	if scans := backend.scans(); len(scans) != 1 || scans[0] != "clean" {
		t.Fatalf("payloads scanned = %q, want only the small file", scans)
	}
	gap := findingByCheck(findings, "yara_scan_incomplete")
	if !strings.Contains(gap.Details, "oversize=1") || !strings.Contains(gap.Details, big) {
		t.Fatalf("gap = %+v, want the oversize file named", gap)
	}
}

// Symbolic links are not followed: a link planted in a document root must not
// pull a file or a tree from elsewhere into the account's report.
func TestAccountYARAPassDoesNotFollowSymlinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "home")
	withAccountHomeRoots(t, root)
	outside := writeYARADeepFile(t, base, "outside/evil.dat", "dormant malware")
	docroot := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(docroot, "link.dat")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(docroot, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(docroot, filepath.Join(filepath.Dir(docroot), "www")); err != nil {
		t.Fatal(err)
	}
	backend := useCountingYARABackend(t)

	findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(&config.Config{}, false)), &config.Config{}, nil)

	if len(findings) != 0 || len(backend.scans()) != 0 {
		t.Fatalf("followed a symlink: findings %+v, scans %q", findings, backend.scans())
	}
}

// --respect-ignores keeps ignore_paths out of the YARA pass; the default
// full scan covers them.
func TestAccountYARAPassHonorsRespectIgnores(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	path := writeYARADeepFile(t, root, "alice/public_html/cache/blob.dat", "dormant malware")
	useCountingYARABackend(t)
	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{"*/cache/*"}

	respected := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(cfg, true)), cfg, nil)
	if got := yaraMatchPaths(respected); len(got) != 0 {
		t.Fatalf("--respect-ignores still scanned %v", got)
	}
	bypassed := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(cfg, false)), cfg, nil)
	if got := yaraMatchPaths(bypassed); len(got) != 1 || got[0] != path {
		t.Fatalf("full scan matches = %v, want %s", got, path)
	}
}

// With no compiled rules the pass cannot run; the report must say so
// instead of reading as clean.
func TestAccountYARAPassReportsMissingBackend(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	writeYARADeepFile(t, root, "alice/public_html/image.dat", "dormant malware")
	prevBackend, prevAvailable := activeYARABackend, yaraAvailable
	activeYARABackend = func() yara.Backend { return nil }
	yaraAvailable = func() bool { return true }
	t.Cleanup(func() { activeYARABackend, yaraAvailable = prevBackend, prevAvailable })

	findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(&config.Config{}, false)), &config.Config{}, nil)

	if len(findings) != 1 || findings[0].Check != "yara_scan_incomplete" {
		t.Fatalf("findings = %+v, want one yara_scan_incomplete", findings)
	}
}

// The pass stops before its check budget runs out and returns what it found,
// marked incomplete: a check that overruns its budget loses every finding.
func TestAccountYARAPassStopsBeforeDeadlineWithPartialResults(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	first := writeYARADeepFile(t, root, "alice/public_html/a.dat", "dormant malware")
	writeYARADeepFile(t, root, "alice/public_html/b.dat", "dormant malware")
	deadline := time.Now().Add(time.Hour)
	clock := deadline.Add(-2 * yaraDeepDeadlineMargin)
	useYARADeepClock(t, &clock)
	backend := useCountingYARABackend(t)
	backend.onScan = func() { clock = deadline }
	ctx, cancel := context.WithDeadline(fullAccountYARAContext("alice", FullScanOptions(&config.Config{}, false)), deadline)
	defer cancel()

	findings := checkAccountYARA(ctx, &config.Config{}, nil)

	if got := yaraMatchPaths(findings); len(got) != 1 || got[0] != first {
		t.Fatalf("YARA matches = %v, want only %s", got, first)
	}
	if len(backend.scans()) != 1 {
		t.Fatalf("scanned %d files after the soft deadline passed", len(backend.scans()))
	}
	gap := findingByCheck(findings, "yara_scan_incomplete")
	if !strings.Contains(gap.Details, "time budget") {
		t.Fatalf("gap = %+v, want the early stop reported", gap)
	}
}

func TestAccountYARAPassRejectsDirectoryReplacement(t *testing.T) {
	for _, replacement := range []string{"symlink", "missing"} {
		t.Run(replacement, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "home")
			withAccountHomeRoots(t, root)
			first := writeYARADeepFile(t, root, "alice/public_html/a.dat", "dormant malware")
			dir := filepath.Dir(writeYARADeepFile(t, root, "alice/public_html/z/b.dat", "clean"))
			outside := filepath.Dir(writeYARADeepFile(t, base, "outside/b.dat", "outside account"))
			backend := useCountingYARABackend(t)
			backend.onScan = func() {
				backend.onScan = nil
				if err := os.Rename(dir, dir+"-moved"); err != nil {
					t.Fatal(err)
				}
				if replacement == "symlink" {
					if err := os.Symlink(outside, dir); err != nil {
						t.Fatal(err)
					}
				}
			}
			findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(nil, false)), &config.Config{}, nil)
			if scans := backend.scans(); len(scans) != 1 || scans[0] != "dormant malware" {
				t.Fatalf("read a replaced directory: %q", scans)
			}
			if got := yaraMatchPaths(findings); len(got) != 1 || got[0] != first {
				t.Fatalf("lost confirmed match: %v", got)
			}
			if gap := findingByCheck(findings, "yara_scan_incomplete"); !strings.Contains(gap.Details, dir) {
				t.Fatalf("missing coverage gap for replaced directory: %+v", findings)
			}
		})
	}
}

// accountYARASnapshotBackend records the bytes it is handed; a backend has
// no way to reopen the tenant path.
type accountYARASnapshotBackend struct {
	countingYARABackend
	onInline func()
	data     []byte
	scanErr  error
}

func (b *accountYARASnapshotBackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	if b.onInline != nil {
		b.onInline()
	}
	b.data = append([]byte(nil), data...)
	if b.scanErr != nil {
		return nil, b.scanErr
	}
	return b.deepYARATestBackend.ScanBytesChecked(data)
}

func assertNoStateCopies(t *testing.T, statePath string) {
	t.Helper()
	entries, err := os.ReadDir(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("scan left %d files in daemon state, first %q", len(entries), entries[0].Name())
	}
}

func TestAccountYARAScansTheOriginalSnapshot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "home")
	withAccountHomeRoots(t, root)
	path := writeYARADeepFile(t, root, "alice/public_html/a.dat", "dormant malware")
	outside := writeYARADeepFile(t, base, "outside/b.dat", "outside account")
	backend := &accountYARASnapshotBackend{onInline: func() {
		if err := os.Rename(path, path+"-moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
	}}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(nil, false)), cfg, nil)
	if string(backend.data) != "dormant malware" {
		t.Fatalf("scan reopened tenant path: scanned %q", backend.data)
	}
	if got := yaraMatchPaths(findings); len(got) != 1 || got[0] != path {
		t.Fatalf("snapshot match lost: %+v", findings)
	}
	assertNoStateCopies(t, cfg.StatePath)
}

// A failed byte scan is a coverage gap. It never leaves a copy of tenant
// bytes in daemon state.
func TestAccountYARAByteScanErrorIsGapWithoutPathRetry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	path := writeYARADeepFile(t, root, "alice/public_html/a.dat", "dormant malware")
	backend := &accountYARASnapshotBackend{scanErr: errors.New("worker connection closed")}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(nil, false)), cfg, nil)
	if got := yaraMatchPaths(findings); len(got) != 0 {
		t.Fatalf("failed scan produced matches: %v", got)
	}
	if gap := findingByCheck(findings, "yara_scan_incomplete"); !strings.Contains(gap.Details, "scan_error=1") || !strings.Contains(gap.Details, path) {
		t.Fatalf("failed scan not reported: %+v", findings)
	}
	assertNoStateCopies(t, cfg.StatePath)
}

func TestAccountYARAPassKeepsFindingsWhenBackendExceedsDeadline(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	first := writeYARADeepFile(t, root, "alice/public_html/a.dat", "dormant malware")
	writeYARADeepFile(t, root, "alice/public_html/b.dat", "clean")
	backend := useCountingYARABackend(t)
	blocked, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	backend.onScan = func() {
		if len(backend.scans()) == 2 {
			close(blocked)
			<-release
		}
	}
	// Keep the soft clock before the margin while the real runner expires.
	clock := time.Now().Add(-time.Hour)
	useYARADeepClock(t, &clock)
	ctx := fullAccountYARAContext("alice", FullScanOptions(nil, false))
	check := namedCheck{"yara_deep", func(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
		defer close(finished)
		return checkAccountYARA(ctx, cfg, nil)
	}}
	result := make(chan []alert.Finding, 1)
	go func() { result <- runAccountScanCheck(ctx, check, &config.Config{}, nil, time.Second) }()
	defer func() { close(release); <-finished }()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("second scan did not start")
	}
	select {
	case findings := <-result:
		if got := yaraMatchPaths(findings); len(got) != 1 || got[0] != first {
			t.Fatalf("deadline discarded confirmed match: %+v", findings)
		}
		if f := findingByCheck(findings, "check_timeout"); f.Check == "" {
			t.Fatalf("deadline was not reported: %+v", findings)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not honor deadline")
	}
}

func TestAccountYARAPassRespectsIgnoredDocroot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	path := writeYARADeepFile(t, root, "alice/public_html/a.dat", "dormant malware")
	backend := useCountingYARABackend(t)
	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{filepath.Dir(path)}
	findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(cfg, true)), cfg, nil)
	if len(backend.scans()) != 0 || len(findings) != 0 {
		t.Fatalf("scanned ignored document root: %+v", findings)
	}
}

// A shop's product images can sort before its code folders and fill the
// time budget. Images go last, so a scan that runs out of time has read
// the code.
func TestAccountYARAPassScansImagesLast(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	writeYARADeepFile(t, root, "alice/public_html/img/p/1.jpg", "dormant malware")
	code := writeYARADeepFile(t, root, "alice/public_html/modules/x/x.php", "dormant malware")
	deadline := time.Now().Add(time.Hour)
	clock := deadline.Add(-2 * yaraDeepDeadlineMargin)
	useYARADeepClock(t, &clock)
	backend := useCountingYARABackend(t)
	backend.onScan = func() { clock = deadline }
	ctx, cancel := context.WithDeadline(fullAccountYARAContext("alice", FullScanOptions(&config.Config{}, false)), deadline)
	defer cancel()

	findings := checkAccountYARA(ctx, &config.Config{}, nil)

	if got := yaraMatchPaths(findings); len(got) != 1 || got[0] != code {
		t.Fatalf("YARA matches = %v, want only the code file %s", got, code)
	}
	gap := findingByCheck(findings, "yara_scan_incomplete")
	if !strings.Contains(gap.Details, "only image files were left") {
		t.Fatalf("gap = %+v, want it to say only images were left", gap)
	}
}

func TestAccountYARAPassStillScansImages(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	image := writeYARADeepFile(t, root, "alice/public_html/img/p/1.jpg", "dormant malware")
	code := writeYARADeepFile(t, root, "alice/public_html/modules/x/x.php", "dormant malware")
	missing := filepath.Join(root, "alice/public_html/gone")
	if err := os.Symlink(missing, filepath.Join(root, "alice/public_html/link")); err != nil {
		t.Fatal(err)
	}
	backend := useCountingYARABackend(t)

	findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(&config.Config{}, false)), &config.Config{}, nil)

	want := []string{image, code}
	sort.Strings(want)
	if got := yaraMatchPaths(findings); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("YARA matches = %v, want %v", got, want)
	}
	if n := len(backend.scans()); n != 2 {
		t.Fatalf("scanned %d files, want each file once", n)
	}
	if gap := findingByCheck(findings, "yara_scan_incomplete"); gap.Check != "" {
		t.Fatalf("unexpected gap %+v", gap)
	}
}

func TestAccountYARAPassDoesNotReportEmptyImagePass(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	code := writeYARADeepFile(t, root, "alice/public_html/index.php", "dormant malware")
	deadline := time.Now().Add(time.Hour)
	clock := deadline.Add(-2 * yaraDeepDeadlineMargin)
	useYARADeepClock(t, &clock)
	backend := useCountingYARABackend(t)
	backend.onScan = func() { clock = deadline }
	ctx, cancel := context.WithDeadline(fullAccountYARAContext("alice", FullScanOptions(nil, false)), deadline)
	defer cancel()
	findings := checkAccountYARA(ctx, &config.Config{}, nil)
	if paths := yaraMatchPaths(findings); len(paths) != 1 || paths[0] != code {
		t.Fatalf("matches = %v, want %s", paths, code)
	}
	if gap := findingByCheck(findings, "yara_scan_incomplete"); gap.Check != "" {
		t.Fatalf("reported unscanned images when there are none: %+v", gap)
	}
}

func TestAccountYARAImagePassStopsWithEarlierGaps(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	writeYARADeepFile(t, root, "alice/public_html/a.php", strings.Repeat("x", 32))
	writeYARADeepFile(t, root, "alice/public_html/b.jpg", "image one")
	writeYARADeepFile(t, root, "alice/public_html/c.PNG", "image two")
	deadline := time.Now().Add(time.Hour)
	clock := deadline.Add(-2 * yaraDeepDeadlineMargin)
	useYARADeepClock(t, &clock)
	backend := useCountingYARABackend(t)
	backend.onScan = func() { clock = deadline }
	ctx, cancel := context.WithDeadline(fullAccountYARAContext("alice", AccountScanOptions{ForceContent: true, MaxFileBytes: 16}), deadline)
	defer cancel()
	findings := checkAccountYARA(ctx, &config.Config{}, nil)
	if scans := backend.scans(); len(scans) != 1 || scans[0] != "image one" {
		t.Fatalf("image pass exceeded its budget: %q", scans)
	}
	gap := findingByCheck(findings, "yara_scan_incomplete")
	if !strings.Contains(gap.Details, "oversize=1") || !strings.Contains(gap.Details, "time budget") {
		t.Fatalf("missing coverage gaps: %+v", gap)
	}
	if strings.Contains(gap.Details, "only image files were left") {
		t.Fatalf("claimed code coverage despite skipped code: %+v", gap)
	}
}

func TestAccountYARAImagePassRepinsHome(t *testing.T) {
	for _, replacePath := range []string{"alice", "alice/public_html", "alice/public_html/images", "alice/a.example"} {
		for _, replacement := range []string{"symlink", "file"} {
			t.Run(replacePath+"/"+replacement, func(t *testing.T) {
				base := t.TempDir()
				root := filepath.Join(base, "home")
				withAccountHomeRoots(t, root)
				imageRoot := "alice/public_html"
				if replacePath == "alice/a.example" {
					imageRoot = replacePath
				}
				writeYARADeepFile(t, root, imageRoot+"/images/a.jpg", "original image")
				writeYARADeepFile(t, root, "alice/public_html/z.php", "original code")
				outside := filepath.Join(base, "outside")
				writeYARADeepFile(t, outside, "public_html/a.jpg", "outside image")
				backend := useCountingYARABackend(t)
				backend.onScan = func() {
					backend.onScan = nil
					home := filepath.Join(root, replacePath)
					if err := os.Rename(home, home+"-moved"); err != nil {
						t.Fatal(err)
					}
					if replacement == "symlink" {
						if err := os.Symlink(outside, home); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(home, []byte("replacement"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(nil, false)), &config.Config{}, nil)
				if scans := backend.scans(); len(scans) != 1 || scans[0] != "original code" {
					t.Fatalf("followed a replacement home in the image pass: %q", scans)
				}
				if gap := findingByCheck(findings, "yara_scan_incomplete"); !strings.Contains(gap.Details, filepath.Join(root, replacePath)) {
					t.Fatalf("missing gap for replaced home: %+v", gap)
				}
			})
		}
	}
}

func TestAccountYARAImagePassDoesNotStopOnScannedCode(t *testing.T) {
	for _, codePath := range []string{
		"alice/public_html/z.php",
		"alice/public_html/z/code.php",
		"alice/z.example/code.php",
	} {
		t.Run(codePath, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "home")
			withAccountHomeRoots(t, root)
			writeYARADeepFile(t, root, "alice/public_html/a.jpg", "image")
			writeYARADeepFile(t, root, codePath, "code")
			deadline := time.Now().Add(time.Hour)
			clock := deadline.Add(-2 * yaraDeepDeadlineMargin)
			useYARADeepClock(t, &clock)
			backend := useCountingYARABackend(t)
			backend.onScan = func() {
				if len(backend.scans()) == 2 {
					clock = deadline
				}
			}
			ctx, cancel := context.WithDeadline(fullAccountYARAContext("alice", FullScanOptions(nil, false)), deadline)
			defer cancel()
			findings := checkAccountYARA(ctx, &config.Config{}, nil)
			if scans := backend.scans(); strings.Join(scans, ",") != "code,image" {
				t.Fatalf("scans = %q, want code then image exactly once", scans)
			}
			if gap := findingByCheck(findings, "yara_scan_incomplete"); gap.Check != "" {
				t.Fatalf("reported a gap for code scanned in the first pass: %+v", gap)
			}
		})
	}
}

func TestAccountYARAImagePassDoesNotStopOnIgnoredImage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	writeYARADeepFile(t, root, "alice/public_html/a.jpg", "image")
	writeYARADeepFile(t, root, "alice/public_html/code.php", "code")
	ignored := writeYARADeepFile(t, root, "alice/public_html/z.jpg", "ignored image")
	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{ignored}
	deadline := time.Now().Add(time.Hour)
	clock := deadline.Add(-2 * yaraDeepDeadlineMargin)
	useYARADeepClock(t, &clock)
	backend := useCountingYARABackend(t)
	backend.onScan = func() {
		if len(backend.scans()) == 2 {
			clock = deadline
		}
	}
	ctx, cancel := context.WithDeadline(fullAccountYARAContext("alice", FullScanOptions(cfg, true)), deadline)
	defer cancel()
	findings := checkAccountYARA(ctx, cfg, nil)
	if scans := backend.scans(); strings.Join(scans, ",") != "code,image" {
		t.Fatalf("scans = %q, want only the in-scope files", scans)
	}
	if gap := findingByCheck(findings, "yara_scan_incomplete"); gap.Check != "" {
		t.Fatalf("reported a gap outside the requested scope: %+v", gap)
	}
}

// Entries deferred in the code pass must not silently disappear when the
// tenant changes the tree before the image pass starts.
func TestAccountYARAImagePassReportsLostEntries(t *testing.T) {
	for _, target := range []string{"image", "directory", "docroot"} {
		for _, replacement := range []string{"missing", "symlink", "directory"} {
			t.Run(target+"/"+replacement, func(t *testing.T) {
				base := t.TempDir()
				root := filepath.Join(base, "home")
				withAccountHomeRoots(t, root)
				image := writeYARADeepFile(t, root, "alice/a.example/images/a.jpg", "deferred image")
				writeYARADeepFile(t, root, "alice/public_html/z.php", "code")
				outside := writeYARADeepFile(t, base, "outside/a.jpg", "outside account")
				path := image
				if target != "image" {
					path = filepath.Dir(path)
				}
				if target == "docroot" {
					path = filepath.Dir(path)
				}
				backend := useCountingYARABackend(t)
				backend.onScan = func() {
					backend.onScan = nil
					if err := os.Rename(path, filepath.Join(base, "moved")); err != nil {
						t.Fatal(err)
					}
					switch replacement {
					case "symlink":
						if err := os.Symlink(outside, path); err != nil {
							t.Fatal(err)
						}
					case "directory":
						if err := os.Mkdir(path, 0o700); err != nil {
							t.Fatal(err)
						}
					}
				}
				findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(nil, false)), &config.Config{}, nil)
				if scans := backend.scans(); len(scans) != 1 || scans[0] != "code" {
					t.Fatalf("scanned replacement contents: %q", scans)
				}
				gap := findingByCheck(findings, "yara_scan_incomplete")
				if !strings.Contains(gap.Details, path) {
					t.Fatalf("lost deferred entry without a coverage gap: %+v", findings)
				}
			})
		}
	}
}
