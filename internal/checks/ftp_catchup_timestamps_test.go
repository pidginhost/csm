package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func ftpFailLine(at time.Time, ip string) string {
	return fmt.Sprintf("%s host pure-ftpd[4242]: (?@%s) [WARNING] Authentication failed for user [admin]",
		at.Format("Jan _2 15:04:05"), ip)
}

func ftpBruteFindings(findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == "ftp_bruteforce" {
			out = append(out, f)
		}
	}
	return out
}

// A first run (empty follow state) catches up on up to 8 MiB of history.
// Stamping those lines with the current time turns days of scattered
// failures into one burst and auto-blocks the address, so failures must be
// counted at the time the log recorded them.
func TestCheckFTPLoginsCatchUpUsesLineTimestamps(t *testing.T) {
	log := filepath.Join(t.TempDir(), "messages")
	old := time.Now().Add(-72 * time.Hour)
	var body string
	for i := 0; i < 2*ftpFailThreshold; i++ {
		body += ftpFailLine(old.Add(time.Duration(i)*time.Minute), "198.51.100.7") + "\n"
	}
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(log) }})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := &config.Config{}

	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store)); len(got) != 0 {
		t.Fatalf("three-day-old catch-up lines reported as a burst: %+v", got)
	}

	// Failures the log records now still trip the detector.
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < ftpFailThreshold; i++ {
		if _, err := f.WriteString(ftpFailLine(time.Now(), "198.51.100.7") + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()
	got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store))
	if len(got) != 1 || got[0].SourceIP != "198.51.100.7" {
		t.Fatalf("fresh failures not reported: %+v", got)
	}
}
