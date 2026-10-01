package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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
