package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// The forward reader keeps each complete line's start offset, skips blank
// lines and leaves a partial last line for the next read.
func TestReadNewSyslogRecordsKeepLineOffsets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	if err := os.WriteFile(path, []byte("first\n\nsecond\npartial"), 0o600); err != nil {
		t.Fatal(err)
	}
	records, next, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0] != (syslogRecord{text: "first", offset: 0}) || records[1] != (syslogRecord{text: "second", offset: 7}) || next.Offset != 14 {
		t.Fatalf("records %+v next %+v, want first at 0 and second at 7", records, next)
	}
}

// A login found by the scheduled scan names its line in the auth log.
func TestSSHLoginScanStampsObservation(t *testing.T) {
	path := useAuthLog(t)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now()
	failed := sshFailedLine(now.Add(-time.Minute), "203.0.113.77")
	accepted := sshAcceptedLine(now.Add(-time.Minute), "198.51.100.20")
	appendLines(t, path, failed, accepted)
	got := sshLoginFindings(CheckSSHLogins(context.Background(), &config.Config{}, store))
	if len(got) != 1 {
		t.Fatalf("findings %+v, want one login", got)
	}
	o := got[0].Observation
	at, _ := syslogLineTime(accepted, now)
	if o.Producer != "ssh_login_scan" || !strings.HasPrefix(o.Stream, "s:") || len(o.Stream) <= 2 ||
		o.Cursor != strconv.Itoa(len(failed)+1) || !o.ObservedAt.Equal(at) {
		t.Fatalf("observation %+v, want ssh_login_scan at offset %d logged at %v", o, len(failed)+1, at)
	}
}

// An FTP brute-force finding names the newest new failure of its address.
func TestFTPBruteforceNamesItsNewestFailure(t *testing.T) {
	log, store := ftpLatchFixture(t)
	cfg := &config.Config{}
	appendFTPFailures(t, log, "198.51.100.30", ftpFailThreshold)
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	appendFTPFailures(t, log, "198.51.100.31", 1)
	got := ftpBruteFindings(CheckFTPLogins(context.Background(), cfg, store))
	if len(got) != 1 {
		t.Fatalf("findings %+v, want one", got)
	}
	lines := strings.SplitAfter(string(data), "\n")
	newest := len(data) - len(lines[len(lines)-2])
	o := got[0].Observation
	if o.Producer != "ftp_scan" || !strings.HasPrefix(o.Stream, "s:") || o.Cursor != strconv.Itoa(newest) || o.ObservedAt.IsZero() {
		t.Fatalf("observation %+v, want ftp_scan at the last failure's offset %d", o, newest)
	}
}

// Rewrites with an unchanged prefix must never reuse a prior line position.
// An append, repeat of the same input and persisted restart keep the reference.
func TestReadNewSyslogRecordsSeparateGenerations(t *testing.T) {
	followReal(t)
	for _, mode := range []string{"append", "copytruncate", "empty truncate", "rewrite", "rotate", "marker reset"} {
		t.Run(mode, func(t *testing.T) {
			head := strings.Repeat("H", fingerprintBytes) + "\n"
			original := head + "first\nsecond\n"
			path := writeFollowFile(t, original)
			_, old, _, err := readNewSyslogRecords(path, followState{})
			if err != nil {
				t.Fatal(err)
			}
			content := original + "third\n"
			switch mode {
			case "empty truncate":
				content = ""
			case "copytruncate":
				content = head + "new\n"
			case "rewrite":
				content = head + "other\nchanged\nthird\n"
			case "rotate":
				if renameErr := os.Rename(path, path+".old"); renameErr != nil {
					t.Fatal(renameErr)
				}
			case "marker reset":
				old.AnchorFP = ""
			}
			if writeErr := os.WriteFile(path, []byte(content), 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			a, next, _, err := readNewSyslogRecords(path, old)
			if err != nil || (len(a) == 0 && mode != "empty truncate") {
				t.Fatalf("records %+v, error %v", a, err)
			}
			same := syslogStream(old) == syslogStream(next)
			if same != (mode == "append") || next.Stream == "" || len(next.Stream) > 128 {
				t.Fatalf("%s: stream %+v became %+v", mode, old, next)
			}
			if mode == "empty truncate" {
				if writeErr := os.WriteFile(path, []byte(original), 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
				_, regrown, _, regrowErr := readNewSyslogRecords(path, next)
				if regrowErr != nil || regrown.Stream != next.Stream || regrown.Stream == old.Stream {
					t.Fatalf("empty rewind reused %+v as %+v, error %v", old, regrown, regrowErr)
				}
				// Continue the repeat/persistence checks on the regrown input.
				old, next = next, regrown
			}
			for i := range next.Stream {
				if next.Stream[i] < 0x21 || next.Stream[i] > 0x7e {
					t.Fatalf("stream %q is not printable", next.Stream)
				}
			}
			_, repeated, _, err := readNewSyslogRecords(path, old)
			if err != nil || repeated.Stream != next.Stream {
				t.Fatalf("repeat changed %+v to %+v, error %v", next, repeated, err)
			}
			raw, err := json.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			var restored followState
			if decodeErr := json.Unmarshal(raw, &restored); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			before := scanObservationEpoch
			scanObservationEpoch = alert.NewObservationEpoch()
			_, restarted, _, err := readNewSyslogRecords(path, restored)
			scanObservationEpoch = before
			if err != nil || restarted.Stream != next.Stream || restarted.Offset != next.Offset {
				t.Fatalf("restart changed %+v to %+v, error %v", next, restarted, err)
			}
		})
	}
}

// Diagnostic re-reports over unchanged evidence keep the full reference.
func TestFTPBruteforceNamesUnchangedInputConsistently(t *testing.T) {
	log, store := ftpLatchFixture(t)
	appendFTPFailures(t, log, "198.51.100.32", ftpFailThreshold)
	ctx := context.WithValue(context.Background(), scanDryRunKey{}, true)
	a := ftpBruteFindings(CheckFTPLogins(ctx, &config.Config{}, store))
	b := ftpBruteFindings(CheckFTPLogins(ctx, &config.Config{}, store))
	if len(a) != 1 || len(b) != 1 || a[0].Observation == (alert.Observation{}) || a[0].Observation != b[0].Observation {
		t.Fatalf("unchanged input produced %+v then %+v", a, b)
	}
}

func TestReadNewSyslogRecordsSeparatesUncommittedRewrites(t *testing.T) {
	followReal(t)
	head := strings.Repeat("H", fingerprintBytes) + "\n"
	path := writeFollowFile(t, head+"first\n"+head)
	var previous followState
	for _, line := range []string{"first", "other", "third"} {
		if err := os.WriteFile(path, []byte(head+line+"\n"+head), 0o600); err != nil {
			t.Fatal(err)
		}
		records, next, _, err := readNewSyslogRecords(path, followState{})
		if err != nil || len(records) != 3 || records[1].offset != int64(len(head)) {
			t.Fatalf("records %+v, error %v", records, err)
		}
		if next.Stream == "" || next.Stream == previous.Stream {
			t.Fatalf("uncommitted rewrite reused stream %q", next.Stream)
		}
		_, repeat, _, err := readNewSyslogRecords(path, followState{})
		if err != nil || repeat.Stream != next.Stream {
			t.Fatalf("unchanged repeat changed %+v to %+v: %v", next, repeat, err)
		}
		previous = next
	}
}

func TestReadNewSyslogRecordsCappedRewindChangesStream(t *testing.T) {
	followReal(t)
	path := writeFollowFile(t, "first\n")
	_, old, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat(strings.Repeat("o", 1023)+"\n", maxCatchUpBytes/1024+2)
	if writeErr := os.WriteFile(path, []byte(content), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	// A restart has only the persisted state, so the rewind must be
	// recognized even without the previous reader's captured bytes.
	before := scanObservationEpoch
	scanObservationEpoch = alert.NewObservationEpoch()
	t.Cleanup(func() { scanObservationEpoch = before })
	_, next, skipped, err := readNewSyslogRecords(path, old)
	if err != nil || skipped <= old.Offset || next.Stream == old.Stream || next.Generation <= old.Generation {
		t.Fatalf("capped rewind reused %+v as %+v (skipped %d): %v", old, next, skipped, err)
	}
}

func TestReadNewSyslogRecordsUncommittedEmptyTruncate(t *testing.T) {
	followReal(t)
	path := writeFollowFile(t, "first\n")
	_, old, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	if truncateErr := os.Truncate(path, 0); truncateErr != nil {
		t.Fatal(truncateErr)
	}
	_, empty, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(path, []byte("first\n"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	_, regrown, _, err := readNewSyslogRecords(path, followState{})
	if err != nil || empty.Stream == "" || empty.Stream == old.Stream || regrown.Stream != empty.Stream {
		t.Fatalf("empty truncate reused %+v as %+v then %+v: %v", old, empty, regrown, err)
	}
}

func TestSyslogObservationUsesReadSnapshot(t *testing.T) {
	followReal(t)
	path := writeFollowFile(t, "first\n")
	_, old, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	// A writer can restore the old disk bytes after ReadAt captured a new
	// line. Provenance must describe the captured bytes being processed.
	next := old
	setSyslogObservationStream(&next, followState{}, path, f, info, false, 0, []byte("other\n"))
	if next.Stream == old.Stream {
		t.Fatalf("different read snapshot reused stream %q", old.Stream)
	}
}
