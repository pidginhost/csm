package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Where SSH logins come from sshd's journal entries, the scheduled scan of
// the auth log file reports nothing: a file line any local user wrote could
// otherwise share a login's record and stand in for the real one.
func TestSSHLoginScanYieldsToTheJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secure")
	if err := os.WriteFile(path, []byte("Nov 21 12:00:00 host sshd[4242]: Accepted publickey for root from 198.51.100.9 port 22 ssh2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prevPath := authLogPath
	t.Cleanup(func() { authLogPath = prevPath; SetSSHLoginsFromJournal(false) })
	authLogPath = func() string { return path }
	for _, journal := range []bool{false, true} {
		SetSSHLoginsFromJournal(journal)
		got := CheckSSHLogins(context.Background(), nil, nil)
		if (len(got) != 0) == journal {
			t.Errorf("journal=%v: scan reported %d logins", journal, len(got))
		}
	}
}
