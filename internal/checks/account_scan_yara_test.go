package checks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
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
