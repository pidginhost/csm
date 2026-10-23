package checks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
	"github.com/pidginhost/csm/internal/yaraipc"
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

type accountYARAFallbackBackend struct {
	countingYARABackend
	onInline  func()
	path      string
	data      []byte
	mode      os.FileMode
	fileErr   error
	wrongHash bool
}

func (b *accountYARAFallbackBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	if b.onInline != nil {
		b.onInline()
	}
	return nil, yaraipc.ErrPayloadTooLarge
}

func (b *accountYARAFallbackBackend) ScanFileChecked(path string, limit int) (yara.FileScanResult, error) {
	b.path = path
	info, err := os.Stat(path)
	if err != nil {
		return yara.FileScanResult{}, err
	}
	b.mode = info.Mode()
	if info.Size() > int64(limit) {
		return yara.FileScanResult{}, errors.New("snapshot exceeds worker limit")
	}
	if b.fileErr != nil {
		return yara.FileScanResult{}, b.fileErr
	}
	data, err := os.ReadFile(path)
	b.data = data
	if err != nil {
		return yara.FileScanResult{}, err
	}
	matches, err := b.deepYARATestBackend.ScanBytesChecked(data)
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if b.wrongHash {
		digest = strings.Repeat("0", 64)
	}
	return yara.FileScanResult{Matches: matches, ContentSHA256: digest}, err
}

func TestAccountYARAFallbackScansTheOriginalSnapshot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "home")
	withAccountHomeRoots(t, root)
	path := writeYARADeepFile(t, root, "alice/public_html/a.dat", "dormant malware")
	outside := writeYARADeepFile(t, base, "outside/b.dat", "outside account")
	backend := &accountYARAFallbackBackend{onInline: func() {
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
		t.Fatalf("fallback reopened tenant path: scanned %q", backend.data)
	}
	if got := yaraMatchPaths(findings); len(got) != 1 || got[0] != path {
		t.Fatalf("snapshot match lost: %+v", findings)
	}
	if filepath.Dir(backend.path) != cfg.StatePath || backend.mode.Perm() != 0o600 {
		t.Fatalf("snapshot is not private daemon state: %q (%v)", backend.path, backend.mode)
	}
	if _, err := os.Stat(backend.path); !os.IsNotExist(err) {
		t.Fatalf("temporary snapshot remains: %v", err)
	}
}

func TestAccountYARAFallbackFailuresReportGapsAndRemoveSnapshots(t *testing.T) {
	for _, failure := range []string{"worker", "digest", "storage"} {
		t.Run(failure, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "home")
			withAccountHomeRoots(t, root)
			path := writeYARADeepFile(t, root, "alice/public_html/a.dat", "dormant malware")
			backend := &accountYARAFallbackBackend{}
			cfg := &config.Config{StatePath: t.TempDir()}
			switch failure {
			case "worker":
				backend.fileErr = errors.New("worker unavailable")
			case "digest":
				backend.wrongHash = true
			case "storage":
				cfg.StatePath = filepath.Join(cfg.StatePath, "missing")
			}
			yara.SetActive(backend)
			t.Cleanup(func() { yara.SetActive(nil) })
			findings := checkAccountYARA(fullAccountYARAContext("alice", FullScanOptions(nil, false)), cfg, nil)
			if got := yaraMatchPaths(findings); len(got) != 0 {
				t.Fatalf("failed scan produced matches: %v", got)
			}
			if gap := findingByCheck(findings, "yara_scan_incomplete"); !strings.Contains(gap.Details, "scan_error=1") || !strings.Contains(gap.Details, path) {
				t.Fatalf("failed scan not reported: %+v", findings)
			}
			if backend.path != "" {
				if _, err := os.Stat(backend.path); !os.IsNotExist(err) {
					t.Fatalf("failed scan left snapshot: %v", err)
				}
			}
		})
	}
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
