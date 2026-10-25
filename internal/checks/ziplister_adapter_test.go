package checks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/crashsample"
	"github.com/pidginhost/csm/internal/workerproc"
)

type fakeZipLister struct {
	err   error
	calls int
}

type zipListerFunc func(context.Context, *os.File, int64, uint64, func(string, bool) error) error

func (fn zipListerFunc) ListZip(ctx context.Context, f *os.File, size int64, max uint64, visit func(string, bool) error) error {
	return fn(ctx, f, size, max, visit)
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

func TestKitZipBlockedWithoutListerIsIncomplete(t *testing.T) {
	useZipLister(t, nil)
	path := kitZip(t)
	sum := fileSHA256(t, path)
	zipStrikes.Record(sum)
	zipStrikes.Record(sum)
	ctx, c := withIncompleteCheckCollector(context.Background())
	if v, _ := classifyKitZip(ctx, path); v != zipNotKit || !c.contains("phishing") {
		t.Fatalf("missing lister: verdict %v incomplete %v", v, c.contains("phishing"))
	}
}

func TestKitZipBlockedCancellationIsIncomplete(t *testing.T) {
	fake := &fakeZipLister{}
	useZipLister(t, fake)
	path := kitZip(t)
	sum := fileSHA256(t, path)
	zipStrikes.Record(sum)
	zipStrikes.Record(sum)
	ctx, c := withIncompleteCheckCollector(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if v, _ := classifyKitZip(ctx, path); v != zipNotKit || !c.contains("phishing") || fake.calls != 0 {
		t.Fatalf("cancellation: verdict %v incomplete %v calls %d", v, c.contains("phishing"), fake.calls)
	}
}

func TestKitZipChangedDuringWorkerFailureDoesNotStrike(t *testing.T) {
	path := kitZip(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	useZipLister(t, zipListerFunc(func(context.Context, *os.File, int64, uint64, func(string, bool) error) error {
		// Change the same inode to a different, same-size archive while the
		// worker is running. Its failure cannot identify these new bytes.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		data[100] ^= 1
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		mtime := before.ModTime().Add(time.Second)
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return workerproc.ErrWorkerFailed
	}))
	ctx, c := withIncompleteCheckCollector(context.Background())
	if v, _ := classifyKitZip(ctx, path); v != zipNotKit || !c.contains("phishing") {
		t.Fatalf("changed archive: verdict %v incomplete %v", v, c.contains("phishing"))
	}
	if got := zipStrikes.Len(); got != 0 {
		t.Fatalf("charged worker failure to replacement contents: %d strikes", got)
	}
}

func TestZipSHA256RejectsShortRead(t *testing.T) {
	path := kitZip(t)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-1); err != nil {
		t.Fatal(err)
	}
	if sum, err := zipSHA256(f, info); !errors.Is(err, io.EOF) || sum != "" {
		t.Fatalf("short read: sum %q error %v", sum, err)
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
	for _, err := range []error{
		errors.New("zip listing incomplete"), context.Canceled, context.DeadlineExceeded,
		workerproc.ErrBreakerOpen, workerproc.ErrSpawn, workerproc.ErrStopped,
	} {
		t.Run(err.Error(), func(t *testing.T) {
			fake := &fakeZipLister{err: err}
			useZipLister(t, fake)
			path := kitZip(t)
			for range 3 {
				ctx, c := withIncompleteCheckCollector(context.Background())
				if v, _ := classifyKitZip(ctx, path); v != zipNotKit || !c.contains("phishing") {
					t.Fatalf("verdict %v incomplete %v", v, c.contains("phishing"))
				}
			}
			if got := zipStrikes.Len(); got != 0 || fake.calls != 3 {
				t.Fatalf("non-worker failure: strikes %d calls %d", got, fake.calls)
			}
		})
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

func TestPhishingZipCrashSampleSaved(t *testing.T) {
	useZipLister(t, &fakeZipLister{err: fmt.Errorf("parse worker: %w", workerproc.ErrWorkerFailed)})
	dir := filepath.Join(t.TempDir(), "parse-crashes")
	SetCrashSamples(crashsample.New(dir))
	t.Cleanup(func() { SetCrashSamples(nil) })
	path := kitZip(t)
	sum := fileSHA256(t, path)
	ctx, _ := withIncompleteCheckCollector(context.Background())
	classifyKitZip(ctx, path)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "zip-"+sum, "archive.zip"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("crash sample = %d bytes, %v; want a copy of the zip", len(got), err)
	}
}

func TestPhishingZipNonWorkerFailuresDoNotSaveSamples(t *testing.T) {
	for _, cause := range []error{workerproc.ErrSpawn, workerproc.ErrBreakerOpen, workerproc.ErrStopped, context.Canceled, context.DeadlineExceeded, syscall.EMFILE, syscall.ENFILE} {
		t.Run(cause.Error(), func(t *testing.T) {
			fake := &fakeZipLister{err: fmt.Errorf("operation: %w", cause)}
			useZipLister(t, fake)
			dir := filepath.Join(t.TempDir(), "parse-crashes")
			SetCrashSamples(crashsample.New(dir))
			t.Cleanup(func() { SetCrashSamples(nil) })
			path := kitZip(t)
			for range workerproc.StrikeLimit + 1 {
				ctx, c := withIncompleteCheckCollector(context.Background())
				if verdict, _ := classifyKitZip(ctx, path); verdict != zipNotKit || !c.contains("phishing") {
					t.Fatal("non-worker failure changed the coverage result")
				}
			}
			if zipStrikes.Len() != 0 || fake.calls != workerproc.StrikeLimit+1 {
				t.Fatal("non-worker failure charged to archive")
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("non-worker failure saved a sample: %v", err)
			}
		})
	}
}
