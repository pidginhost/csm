package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Where FTP logins come from pure-ftpd's journal entries, the scheduled scan
// of the system log file reports nothing and leaves its position alone.
func TestFTPLoginScanYieldsToTheJournal(t *testing.T) {
	log, store := ftpLatchFixture(t)
	t.Cleanup(func() { SetFTPLoginsFromJournal(false) })
	appendFTPFailures(t, log, "198.51.100.21", ftpFailThreshold)
	SetFTPLoginsFromJournal(true)
	if got := CheckFTPLogins(context.Background(), &config.Config{}, store); len(got) != 0 {
		t.Fatalf("scan with journal FTP reported %+v", got)
	}
	SetFTPLoginsFromJournal(false)
	if got := ftpBruteFindings(CheckFTPLogins(context.Background(), &config.Config{}, store)); len(got) != 1 {
		t.Fatalf("scan without journal FTP = %+v, want the burst", got)
	}
}
