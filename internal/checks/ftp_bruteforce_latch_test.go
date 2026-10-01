package checks

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func appendFTPFailures(t *testing.T, log, ip string, n int) {
	t.Helper()
	f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for i := 0; i < n; i++ {
		if _, err := f.WriteString(ftpFailLine(time.Now(), ip) + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func ftpLatchFixture(t *testing.T) (string, *state.Store) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "messages")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(log) }})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return log, store
}

// A burst is reported when its failures are read, not again on every scan
// while they stay in the window. A repeat with no new failure would re-block
// an address the operator just unblocked and count the same burst again in
// the attack database.
func TestCheckFTPLoginsReportsBurstOnce(t *testing.T) {
	log, store := ftpLatchFixture(t)
	cfg := &config.Config{}

	appendFTPFailures(t, log, "198.51.100.20", ftpFailThreshold)
	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store)); len(got) != 1 || got[0].SourceIP != "198.51.100.20" {
		t.Fatalf("first scan = %+v, want one finding for the burst", got)
	}
	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store)); len(got) != 0 {
		t.Fatalf("scan without new failures re-reported the burst: %+v", got)
	}

	// The attack goes on: each new failure reports the address again with
	// the whole window's count.
	appendFTPFailures(t, log, "198.51.100.20", 1)
	got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store))
	if len(got) != 1 || got[0].SourceIP != "198.51.100.20" {
		t.Fatalf("new failure not reported: %+v", got)
	}
}

// Only the addresses with new failures are reported; another address still
// over the threshold from an earlier burst stays quiet.
func TestCheckFTPLoginsReportsOnlyAddressesWithNewFailures(t *testing.T) {
	log, store := ftpLatchFixture(t)
	cfg := &config.Config{}

	appendFTPFailures(t, log, "198.51.100.21", ftpFailThreshold)
	appendFTPFailures(t, log, "198.51.100.22", ftpFailThreshold)
	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store)); len(got) != 2 {
		t.Fatalf("first scan = %+v, want both bursts", got)
	}

	appendFTPFailures(t, log, "198.51.100.22", 1)
	got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store))
	if len(got) != 1 || got[0].SourceIP != "198.51.100.22" {
		t.Fatalf("second scan = %+v, want only the address with a new failure", got)
	}
}

// Failures spread over scans still add up: the scan whose new failure
// crosses the threshold reports the address.
func TestCheckFTPLoginsReportsWhenNewFailureCrossesThreshold(t *testing.T) {
	log, store := ftpLatchFixture(t)
	cfg := &config.Config{}

	appendFTPFailures(t, log, "198.51.100.23", ftpFailThreshold-1)
	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store)); len(got) != 0 {
		t.Fatalf("below threshold reported: %+v", got)
	}
	appendFTPFailures(t, log, "198.51.100.23", 1)
	got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store))
	if len(got) != 1 || got[0].SourceIP != "198.51.100.23" {
		t.Fatalf("crossing failure not reported: %+v", got)
	}
}

// A diagnostic scan does not run auto-response. Its observation must still be
// available to the next live scan, including when it crosses the threshold.
func TestCheckFTPLoginsDryRunPreservesLiveDetection(t *testing.T) {
	log, store := ftpLatchFixture(t)
	cfg := &config.Config{}
	checks := []namedCheck{{"ftp_logins", CheckFTPLogins}}

	appendFTPFailures(t, log, "198.51.100.24", ftpFailThreshold-1)
	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store)); len(got) != 0 {
		t.Fatalf("below threshold reported: %+v", got)
	}
	appendFTPFailures(t, log, "198.51.100.24", 1)
	preview, _ := runParallel(cfg, store, checks, "test", true)
	if got := ftpBruteFindings(preview); len(got) != 1 || got[0].SourceIP != "198.51.100.24" {
		t.Fatalf("diagnostic scan = %+v, want the new offender", got)
	}
	findings, _ := runParallel(cfg, store, checks, "test", false)
	if got := ftpBruteFindings(findings); len(got) != 1 || got[0].SourceIP != "198.51.100.24" {
		t.Fatalf("diagnostic scan consumed live detection: %+v", got)
	}
}

// The runner discards a cancelled check's output. Advancing its cursor would
// prevent a later scan from reporting the failures that were never delivered.
func TestCheckFTPLoginsCancelledScanPreservesLiveDetection(t *testing.T) {
	log, store := ftpLatchFixture(t)
	cfg := &config.Config{}
	checks := []namedCheck{{"ftp_logins", CheckFTPLogins}}
	appendFTPFailures(t, log, "198.51.100.25", ftpFailThreshold)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) {
		f, err := os.Open(log)
		cancel()
		return f, err
	}})
	interrupted, _ := runParallelWithContext(ctx, cfg, store, checks, "test", false)
	if got := ftpBruteFindings(interrupted); len(got) != 0 {
		t.Fatalf("cancelled scan delivered findings: %+v", got)
	}
	findings, _ := runParallel(cfg, store, checks, "test", false)
	if got := ftpBruteFindings(findings); len(got) != 1 || got[0].SourceIP != "198.51.100.25" {
		t.Fatalf("cancelled scan consumed live detection: %+v", got)
	}
}

// FTP can finish before another check causes the whole tier to be cancelled.
// The tier's discarded result must not consume FTP's reporting opportunity.
func TestCheckFTPLoginsCancelledTierPreservesLiveDetection(t *testing.T) {
	log, store := ftpLatchFixture(t)
	cfg := &config.Config{}
	appendFTPFailures(t, log, "198.51.100.26", ftpFailThreshold)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ftpDone := make(chan struct{})
	checks := []namedCheck{
		{"ftp_logins", func(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
			findings := CheckFTPLogins(ctx, cfg, store)
			close(ftpDone)
			return findings
		}},
		{"cancel_scan", func(context.Context, *config.Config, *state.Store) []alert.Finding {
			<-ftpDone
			cancel()
			return nil
		}},
	}
	interrupted, _ := runParallelWithContext(withScanBudget(ctx, 2), cfg, store, checks, "test", false)
	if len(interrupted) != 0 {
		t.Fatalf("cancelled tier delivered findings: %+v", interrupted)
	}
	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store)); len(got) != 1 || got[0].SourceIP != "198.51.100.26" {
		t.Fatalf("cancelled tier consumed live detection: %+v", got)
	}
}

// A competing live scan may consume the failures while this tier is still
// running. Completing the tier must not publish the same burst a second time.
func TestCheckFTPLoginsConcurrentScanReportsBurstOnce(t *testing.T) {
	log, store := ftpLatchFixture(t)
	cfg := &config.Config{}
	appendFTPFailures(t, log, "198.51.100.27", ftpFailThreshold)
	ftpDone, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() { unblock(); <-finished }()
	checks := []namedCheck{
		{"ftp_logins", func(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
			findings := CheckFTPLogins(ctx, cfg, store)
			close(ftpDone)
			return findings
		}},
		{"wait", func(context.Context, *config.Config, *state.Store) []alert.Finding {
			<-release
			return nil
		}},
	}
	var findings []alert.Finding
	go func() {
		defer close(finished)
		findings, _ = runParallelWithContext(withScanBudget(context.Background(), 2), cfg, store, checks, "test", false)
	}()
	select {
	case <-ftpDone:
	case <-time.After(5 * time.Second):
		t.Fatal("FTP check did not finish")
	}
	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store)); len(got) != 1 || got[0].SourceIP != "198.51.100.27" {
		t.Fatalf("unfinished tier consumed live detection: %+v", got)
	}
	unblock()
	<-finished
	if got := ftpBruteFindings(findings); len(got) != 0 {
		t.Fatalf("competing scan re-reported the burst: %+v", got)
	}
}
