package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/parseworker"
	"github.com/pidginhost/csm/internal/workerproc"
)

type scanZipFunc func(context.Context, *os.File, int64, uint64, func(string, bool) error) error

func (f scanZipFunc) ListZip(ctx context.Context, zip *os.File, size int64, max uint64, visit func(string, bool) error) error {
	return f(ctx, zip, size, max, visit)
}

func TestLegacyScanReportsLazyWorkerFailure(t *testing.T) {
	lister, err := parseworker.NewLister(parseworker.ListerConfig{
		Launch: func(context.Context) (workerproc.Process, error) {
			return nil, errors.New("systemd unavailable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lister.Stop() })
	coverage := &scanZipCoverage{ZipLister: lister}
	zip, err := os.CreateTemp(t.TempDir(), "kit.zip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = zip.Close() })
	if err := coverage.ListZip(context.Background(), zip, 0, 0, nil); !errors.Is(err, workerproc.ErrSpawn) {
		t.Fatalf("listing error = %v, want launch failure", err)
	}
	var out bytes.Buffer
	printLegacyScanFindings(&out, nil, coverage.Err())
	if strings.Contains(out.String(), "Account is clean") || !strings.Contains(out.String(), "were not checked") {
		t.Fatalf("incomplete scan output = %q", out.String())
	}
}

func TestLegacyScanKeepsZipCoverageFailureAfterRecovery(t *testing.T) {
	for _, failure := range []error{workerproc.ErrWorkerFailed, errors.New("zip listing incomplete"), context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			calls := 0
			coverage := &scanZipCoverage{ZipLister: scanZipFunc(func(context.Context, *os.File, int64, uint64, func(string, bool) error) error {
				calls++
				if calls == 1 {
					return failure
				}
				return nil
			})}
			if err := coverage.ListZip(context.Background(), nil, 0, 0, nil); !errors.Is(err, failure) {
				t.Fatalf("first listing error = %v", err)
			}
			if err := coverage.ListZip(context.Background(), nil, 0, 0, nil); err != nil {
				t.Fatalf("second listing error = %v", err)
			}
			if !errors.Is(coverage.Err(), failure) {
				t.Fatalf("coverage error = %v, want %v", coverage.Err(), failure)
			}
			var out bytes.Buffer
			findings := []alert.Finding{{Severity: alert.High, Check: "phishing_kit_archive", Message: "kit found"}}
			printLegacyScanFindings(&out, findings, coverage.Err())
			if !strings.Contains(out.String(), "kit found") || !strings.Contains(out.String(), "were not checked") {
				t.Fatalf("partial scan lost finding or coverage warning: %q", out.String())
			}
		})
	}
}

func TestLegacyScanZipVisitorStopIsNotCoverageFailure(t *testing.T) {
	coverage := &scanZipCoverage{ZipLister: scanZipFunc(func(_ context.Context, _ *os.File, _ int64, _ uint64, visit func(string, bool) error) error {
		return visit("login.php", false)
	})}
	// The kit classifier stops visiting once it has enough evidence.
	stop := errors.New("kit evidence complete")
	for _, visitErr := range []error{nil, stop} {
		if err := coverage.ListZip(context.Background(), nil, 0, 0, func(string, bool) error { return visitErr }); err != visitErr {
			t.Fatalf("visitor result = %v, want %v", err, visitErr)
		}
		if err := coverage.Err(); err != nil {
			t.Fatalf("successful listing marked incomplete: %v", err)
		}
	}
	var out bytes.Buffer
	printLegacyScanFindings(&out, nil, coverage.Err())
	if got := out.String(); got != "No findings. Account is clean.\n" {
		t.Fatalf("complete scan output = %q", got)
	}
}
