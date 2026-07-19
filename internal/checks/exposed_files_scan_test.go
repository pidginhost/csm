package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// fakeProbe returns canned reachability results keyed by URL path, and records
// which paths were probed so a test can assert the classifier gate ran first.
type fakeProbe struct {
	byPath map[string]probeResult
	seen   map[string]bool
}

func (f *fakeProbe) probe(_ context.Context, _ string, urlPath string) probeResult {
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	f.seen[urlPath] = true
	return f.byPath[urlPath]
}

func withFakeProbe(t *testing.T, f webProbe) {
	t.Helper()
	prev := webProber
	webProber = f
	t.Cleanup(func() { webProber = prev })
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestScanVhostsForExposure reproduces the production reality: a docroot serves
// a raw SQL dump (leak) and a source-config backup (leak), while the .env is
// present on disk but blocked by the server (403), and wp-config-sample.php is
// benign. Only the two real, confirmed leaks must be reported.
func TestScanVhostsForExposure(t *testing.T) {
	root := t.TempDir()
	site1 := filepath.Join(root, "alice", "public_html")
	site2 := filepath.Join(root, "bob", "shop.example.net")

	mustWrite(t, filepath.Join(site1, "softsql.sql"), "-- dump\n")
	mustWrite(t, filepath.Join(site1, "wp-config-sample.php"), "<?php // sample")
	mustWrite(t, filepath.Join(site1, ".env"), "SECRET=redacted")
	mustWrite(t, filepath.Join(site2, "inc", "config.php.old"), "<?php $db='x';")

	vhosts := []vhost{
		{domain: "alice.example.com", user: "alice", typ: "main", docroot: site1},
		{domain: "shop.example.net", user: "bob", typ: "addon", docroot: site2},
	}

	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{
		"/softsql.sql":        {status: 200, contentType: "text/x-sql", reachable: true},
		"/.env":               {status: 403, contentType: "text/html", reachable: true}, // server blocks it
		"/inc/config.php.old": {status: 200, contentType: "text/plain", reachable: true},
	}})

	findings := scanVhostsForExposure(context.Background(), vhosts, nil)

	if len(findings) != 2 {
		t.Fatalf("expected 2 confirmed findings, got %d: %+v", len(findings), findings)
	}

	byCheck := map[string]int{}
	for _, f := range findings {
		byCheck[f.Check]++
		if f.Domain == "" || f.FilePath == "" {
			t.Errorf("finding missing domain/filepath: %+v", f)
		}
	}
	if byCheck["web_exposed_db_dump"] != 1 {
		t.Errorf("expected 1 db_dump finding, got %d", byCheck["web_exposed_db_dump"])
	}
	if byCheck["web_exposed_config_leak"] != 1 {
		t.Errorf("expected 1 config_leak finding, got %d", byCheck["web_exposed_config_leak"])
	}
	// The blocked .env and benign sample must not produce findings.
	if byCheck["web_exposed_config_leak"] > 1 {
		t.Errorf(".env (403) or sample must not be reported")
	}
}

// TestScanVhostsRespectsContextCancellation ensures a cancelled deep scan bails
// out instead of walking every account on a busy host.
func TestScanVhostsRespectsContextCancellation(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "alice", "public_html")
	mustWrite(t, filepath.Join(site, "softsql.sql"), "-- dump\n")

	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{
		"/softsql.sql": {status: 200, contentType: "text/x-sql", reachable: true},
	}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := scanVhostsForExposure(ctx, []vhost{
		{domain: "alice.example.com", user: "alice", docroot: site},
	}, nil)
	if len(findings) != 0 {
		t.Errorf("cancelled scan should emit nothing, got %d", len(findings))
	}
}

func TestWalkExposureCandidatesPrioritizesShallowFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "aaa-cache", "one.txt"), "one")
	mustWrite(t, filepath.Join(root, "aaa-cache", "two.txt"), "two")
	rootLeak := filepath.Join(root, "z-backup.sql")
	mustWrite(t, rootLeak, "-- dump\n")

	paths, complete := walkExposureCandidatesLimit(context.Background(), root, 2, 2)
	if complete {
		t.Fatal("capped walk must report incomplete so prior findings are preserved")
	}
	if len(paths) != 2 {
		t.Fatalf("walked paths = %v, want two", paths)
	}
	if paths[0] != rootLeak {
		t.Fatalf("first path = %q, want shallow leak %q", paths[0], rootLeak)
	}
}

func TestWalkExposureCandidatesRejectsNonPositiveLimit(t *testing.T) {
	paths, complete := walkExposureCandidatesLimit(context.Background(), t.TempDir(), 2, 0)
	if complete || len(paths) != 0 {
		t.Fatalf("zero-limit walk = (%v, %v), want empty incomplete result", paths, complete)
	}
}

func TestExposureScanDepthClampsUnsafeConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.ExposedFileScanDepth = config.MaxExposedFileScanDepth + 100
	if got := exposureScanDepth(cfg); got != config.MaxExposedFileScanDepth {
		t.Fatalf("exposureScanDepth() = %d, want maximum %d", got, config.MaxExposedFileScanDepth)
	}
}

func TestCheckExposedFilesPreservesFindingsWhenVhostMapUnreadable(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}})
	ctx, collector := withIncompleteCheckCollector(context.Background())

	if findings := CheckExposedFiles(ctx, nil, nil); len(findings) != 0 {
		t.Fatalf("unreadable vhost map findings = %+v, want none", findings)
	}
	if !collector.contains("exposed_files") {
		t.Fatal("unreadable vhost map must preserve findings from the prior completed scan")
	}
}

func TestCheckExposedFilesTreatsMissingVhostMapAsNonCPanel(t *testing.T) {
	withMockOS(t, &mockOS{})
	ctx, collector := withIncompleteCheckCollector(context.Background())

	if findings := CheckExposedFiles(ctx, nil, nil); len(findings) != 0 {
		t.Fatalf("missing vhost map findings = %+v, want none", findings)
	}
	if collector.contains("exposed_files") {
		t.Fatal("missing vhost map on a non-cPanel host must be a completed no-op")
	}
}

func TestCheckExposedFilesPreservesFindingsWhenCPanelVhostMapIsMissing(t *testing.T) {
	installInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{stat: func(path string) (os.FileInfo, error) {
		if path == cpanelInstallPath {
			return installInfo, nil
		}
		return nil, os.ErrNotExist
	}})
	ctx, collector := withIncompleteCheckCollector(context.Background())

	if findings := CheckExposedFiles(ctx, nil, nil); len(findings) != 0 {
		t.Fatalf("missing cPanel vhost map findings = %+v, want none", findings)
	}
	if !collector.contains("exposed_files") {
		t.Fatal("missing vhost map on a cPanel host must preserve prior findings")
	}
}

func TestScanVhostsPreservesFindingsWhenProbeIsUnreachable(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "backup.sql"), "-- dump\n")
	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{}})
	ctx, collector := withIncompleteCheckCollector(context.Background())

	findings := scanVhostsForExposure(ctx, []vhost{{
		domain: "example.com", user: "alice", typ: "main", docroot: root,
	}}, nil)

	if len(findings) != 0 {
		t.Fatalf("unreachable probe findings = %+v, want none", findings)
	}
	if !collector.contains("exposed_files") {
		t.Fatal("unreachable probe must preserve findings from the prior completed scan")
	}
}

func TestScanVhostsPreservesFindingsWhenProbeIsPartial(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "backup.sql"), "-- dump\n")
	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{
		"/backup.sql": {
			scheme: "https", status: 403, contentType: "text/html",
			reachable: true, partial: true,
		},
	}})
	ctx, collector := withIncompleteCheckCollector(context.Background())

	findings := scanVhostsForExposure(ctx, []vhost{{
		domain: "example.com", user: "alice", typ: "main", docroot: root,
	}}, nil)

	if len(findings) != 0 {
		t.Fatalf("partial blocked probe findings = %+v, want none", findings)
	}
	if !collector.contains("exposed_files") {
		t.Fatal("partial probe must preserve findings from the prior completed scan")
	}
}

func TestScanVhostsPreservesFindingsWhenDocrootIsUnreadable(t *testing.T) {
	ctx, collector := withIncompleteCheckCollector(context.Background())
	missing := filepath.Join(t.TempDir(), "missing-docroot")

	findings := scanVhostsForExposure(ctx, []vhost{{
		domain: "example.com", user: "alice", typ: "main", docroot: missing,
	}}, nil)

	if len(findings) != 0 {
		t.Fatalf("unreadable docroot findings = %+v, want none", findings)
	}
	if !collector.contains("exposed_files") {
		t.Fatal("unreadable docroot must preserve findings from the prior completed scan")
	}
}

func TestBuildExposedFindingUsesActualProbeScheme(t *testing.T) {
	finding := buildExposedFinding(
		vhost{domain: "example.com", user: "alice"},
		"/missing/db backup.sql",
		"/db backup.sql",
		classDBDump,
		probeResult{scheme: "http", status: 200, reachable: true},
	)
	if !strings.Contains(finding.Message, "http://example.com/db%20backup.sql") {
		t.Fatalf("finding message = %q, want escaped HTTP probe URL", finding.Message)
	}
}
