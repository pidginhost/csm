package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/workerproc"
)

type fakeZipLister struct {
	err   error
	calls int
}

func (f *fakeZipLister) ListZip(context.Context, *os.File, int64, uint64, func(string, bool) error) error {
	f.calls++
	return f.err
}

// useZipLister installs l for one test and resets the strike record.
func useZipLister(t *testing.T, l ZipLister) {
	t.Helper()
	SetZipLister(l)
	zipStrikes = workerproc.NewStrikes()
	t.Cleanup(func() {
		SetZipLister(inProcessZipLister{})
		zipStrikes = workerproc.NewStrikes()
	})
}

func kitZip(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "office365.zip")
	kitZipWithFiller(t, path, 0)
	return path
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestKitZipWithoutListerIsIncomplete(t *testing.T) {
	useZipLister(t, nil)
	ctx, c := withIncompleteCheckCollector(context.Background())
	if zipLooksLikeKit(ctx, kitZip(t)) {
		t.Fatal("kit reported without a worker to list it")
	}
	if !c.contains("phishing") {
		t.Fatal("check not marked incomplete without a lister")
	}
}

func TestKitZipWorkerFailureStrikesThenSkips(t *testing.T) {
	fake := &fakeZipLister{err: fmt.Errorf("parse worker: %w", workerproc.ErrWorkerFailed)}
	useZipLister(t, fake)
	path := kitZip(t)
	for run := 1; run <= 2; run++ {
		ctx, c := withIncompleteCheckCollector(context.Background())
		if v, _ := classifyKitZip(ctx, path); v != zipNotKit || !c.contains("phishing") {
			t.Fatalf("run %d: verdict %v incomplete %v", run, v, c.contains("phishing"))
		}
	}
	ctx, c := withIncompleteCheckCollector(context.Background())
	v, sum := classifyKitZip(ctx, path)
	if v != zipSkipped || sum != fileSHA256(t, path) {
		t.Fatalf("run 3: verdict %v sum %q", v, sum)
	}
	if fake.calls != 2 || c.contains("phishing") {
		t.Fatalf("run 3: worker calls %d incomplete %v", fake.calls, c.contains("phishing"))
	}
}

func TestKitZipIncompleteListingDoesNotStrike(t *testing.T) {
	useZipLister(t, &fakeZipLister{err: errors.New("zip listing incomplete")})
	ctx, c := withIncompleteCheckCollector(context.Background())
	if zipLooksLikeKit(ctx, kitZip(t)) || !c.contains("phishing") {
		t.Fatal("incomplete listing: want not a kit and incomplete")
	}
	if got := zipStrikes.Len(); got != 0 {
		t.Fatalf("incomplete listing struck the zip: %d", got)
	}
}

func TestScanForPhishingWarnsOnSkippedZip(t *testing.T) {
	useZipLister(t, &fakeZipLister{})
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	docroot := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(docroot, "office365.zip")
	kitZipWithFiller(t, path, 0)
	sum := fileSHA256(t, path)
	zipStrikes.Record(sum)
	zipStrikes.Record(sum)

	var findings []alert.Finding
	scanForPhishing(context.Background(), docroot, phishingScanMaxDepth, "alice", &config.Config{}, &findings)
	var got []alert.Finding
	for _, f := range findings {
		if f.Check == "phishing_kit_archive_unscannable" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Severity != alert.Warning || got[0].FilePath != path ||
		!strings.Contains(got[0].Details, path) || !strings.Contains(got[0].Details, sum) {
		t.Fatalf("skipped zip findings = %+v", got)
	}
	expectAttributed(t, got, "alice")
}
