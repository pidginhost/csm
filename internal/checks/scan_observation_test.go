package checks

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
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
	stream := syslogTestRef(t, path, 0, "").Stream
	if len(records) != 2 || records[0] != (syslogRecord{text: "first", offset: 0, stream: stream}) ||
		records[1] != (syslogRecord{text: "second", offset: 7, stream: stream}) || next.Offset != 14 {
		t.Fatalf("records %+v next %+v, want first at 0 and second at 7", records, next)
	}
}

// Catch-up can reach EOF without finding a newline. The next read still
// delivers the suffix, but only the following complete record has an identity.
func TestReadNewSyslogRecordsDoesNotNameACatchUpFragment(t *testing.T) {
	followReal(t)
	prefix := strings.Repeat("x", maxCatchUpBytes+1)
	path := writeFollowFile(t, prefix)
	records, state, skipped, err := readNewSyslogRecords(path, followState{})
	if err != nil || len(records) != 0 || state.Offset != int64(len(prefix)) || skipped != state.Offset {
		t.Fatalf("initial catch-up: %d records, state %+v, skipped %d, error %v", len(records), state, skipped, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, writeErr := f.WriteString("hit suf"); writeErr != nil {
		t.Fatal(writeErr)
	}
	records, partial, _, err := readNewSyslogRecords(path, state)
	if err != nil || len(records) != 0 || partial.Offset != state.Offset {
		t.Fatalf("partial read: %+v, state %+v, error %v", records, partial, err)
	}
	if _, writeErr := f.WriteString("fix\nhit next\n"); writeErr != nil {
		t.Fatal(writeErr)
	}
	records, next, _, err := readNewSyslogRecords(path, partial)
	if err != nil || len(records) != 2 || records[0].text != "hit suffix" || records[1].text != "hit next" {
		t.Fatalf("completed read: %+v, error %v", records, err)
	}
	if o := records[0].observation(ProducerFTPScan, time.Unix(1, 0)); o != (alert.Observation{}) {
		t.Errorf("catch-up fragment named %+v, want no observation", o)
	}
	offset := int64(len(prefix) + len("hit suffix\n"))
	o, want := records[1].observation(ProducerFTPScan, time.Unix(1, 0)), syslogTestRef(t, path, offset, "hit next")
	if o.Stream != want.Stream || o.Cursor != want.Cursor || next.Offset != offset+int64(len("hit next\n")) {
		t.Errorf("next record named %+v, state %+v, want %+v and all bytes consumed", o, next, want)
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
	if got[0].Attribution != admission.AttributionPeer {
		t.Errorf("scheduled SSH login attribution %s, want peer", got[0].Attribution)
	}
	o := got[0].Observation
	at, _ := syslogLineTime(accepted, now)
	want := syslogTestRef(t, path, int64(len(failed)+1), accepted)
	if o.Producer != "ssh_login_scan" || o.Stream != want.Stream || o.Cursor != want.Cursor || !o.ObservedAt.Equal(at) {
		t.Fatalf("observation %+v, want ssh_login_scan %+v logged at %v", o, want, at)
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
	if got[0].Attribution != admission.AttributionPeer {
		t.Errorf("attribution %s, want the pure-ftpd peer", got[0].Attribution)
	}
	want := syslogTestRef(t, log, int64(newest), lines[len(lines)-2])
	if o.Producer != "ftp_scan" || o.Stream != want.Stream || o.Cursor != want.Cursor || o.ObservedAt.IsZero() {
		t.Fatalf("observation %+v, want ftp_scan at the last failure %+v", o, want)
	}
}

// syslogTestRef is the reference every reader gives a record of path: the
// file by device and inode, the record by offset and bytes.
func syslogTestRef(t *testing.T, path string, offset int64, text string) alert.Observation {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := selfWriteIdentityFromFileInfo(info)
	if !ok {
		t.Fatal("no file identity")
	}
	return alert.Observation{Stream: alert.FileStream(id.Device, id.Inode), Cursor: alert.RecordCursor(offset, text)}
}

type syslogRef struct{ stream, cursor string }

func refsOf(records []syslogRecord) map[syslogRef]syslogRecord {
	out := make(map[syslogRef]syslogRecord, len(records))
	for _, r := range records {
		o := r.observation(ProducerFTPScan, time.Unix(1, 0))
		out[syslogRef{o.Stream, o.Cursor}] = r
	}
	return out
}

// checkRecordRefs asserts that every record names its file, offset and bytes,
// and that a ref an earlier read used names the same bytes at the same
// offset: a reused offset with other bytes is never an earlier record.
func checkRecordRefs(t *testing.T, path string, earlier map[syslogRef]syslogRecord, records []syslogRecord) {
	t.Helper()
	for _, r := range records {
		o := r.observation(ProducerFTPScan, time.Unix(1, 0))
		if want := syslogTestRef(t, path, r.offset, r.text); o.Stream != want.Stream || o.Cursor != want.Cursor {
			t.Fatalf("record %+v named %+v, want %+v", r, o, want)
		}
		if prior, ok := earlier[syslogRef{o.Stream, o.Cursor}]; ok && (prior.text != r.text || prior.offset != r.offset) {
			t.Fatalf("record %+v reuses the ref of %+v", r, prior)
		}
	}
}

// Every rewrite of a followed file names the records it changed anew and
// keeps the refs of unchanged bytes, whether the reader follows the stored
// state, repeats a read or starts after a restart with no state (design A7).
func TestReadNewSyslogRecordsNameRecordsByFileOffsetAndBytes(t *testing.T) {
	followReal(t)
	for _, mode := range []string{"append", "copytruncate", "empty truncate", "rewrite", "rotate", "marker reset"} {
		t.Run(mode, func(t *testing.T) {
			head := strings.Repeat("H", fingerprintBytes) + "\n"
			original := head + "first\nsecond\n"
			path := writeFollowFile(t, original)
			before, old, _, err := readNewSyslogRecords(path, followState{})
			if err != nil || len(before) != 3 {
				t.Fatalf("records %+v, error %v", before, err)
			}
			earlier := refsOf(before)
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
			after, next, _, err := readNewSyslogRecords(path, old)
			if err != nil || (len(after) == 0 && mode != "empty truncate") {
				t.Fatalf("records %+v, error %v", after, err)
			}
			checkRecordRefs(t, path, earlier, after)
			if mode == "rotate" {
				for ref := range refsOf(after) {
					if _, reused := earlier[ref]; reused {
						t.Fatalf("a rotated file reused ref %+v", ref)
					}
				}
			}
			if mode == "empty truncate" {
				if writeErr := os.WriteFile(path, []byte(head+"other\n"), 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
				regrown, _, _, regrowErr := readNewSyslogRecords(path, next)
				if regrowErr != nil || len(regrown) != 2 {
					t.Fatalf("regrown records %+v, error %v", regrown, regrowErr)
				}
				checkRecordRefs(t, path, earlier, regrown)
				after = regrown
			}
			repeated, _, _, err := readNewSyslogRecords(path, followState{})
			if err != nil {
				t.Fatal(err)
			}
			again := refsOf(repeated)
			for ref, r := range refsOf(after) {
				if prior, ok := again[ref]; !ok || prior != r {
					t.Fatalf("a read with no state named %+v otherwise", r)
				}
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

// An uncommitted rewrite of one line names that line anew; the unchanged
// lines around it, read again, keep their refs.
func TestReadNewSyslogRecordsNameUncommittedRewritesAnew(t *testing.T) {
	followReal(t)
	head := strings.Repeat("H", fingerprintBytes) + "\n"
	path := writeFollowFile(t, head+"first\n"+head)
	earlier := map[syslogRef]syslogRecord{}
	for _, line := range []string{"first", "other", "third"} {
		if err := os.WriteFile(path, []byte(head+line+"\n"+head), 0o600); err != nil {
			t.Fatal(err)
		}
		records, _, _, err := readNewSyslogRecords(path, followState{})
		if err != nil || len(records) != 3 || records[1].offset != int64(len(head)) {
			t.Fatalf("records %+v, error %v", records, err)
		}
		checkRecordRefs(t, path, earlier, records)
		repeat, _, _, err := readNewSyslogRecords(path, followState{})
		if err != nil || !maps.Equal(refsOf(repeat), refsOf(records)) {
			t.Fatalf("unchanged repeat named %+v as %+v: %v", records, repeat, err)
		}
		maps.Copy(earlier, refsOf(records))
	}
}

// A capped rewind after the file was replaced names the bytes it reads now,
// never the records the stored state remembered.
func TestReadNewSyslogRecordsCappedRewindNamesNewBytes(t *testing.T) {
	followReal(t)
	path := writeFollowFile(t, "first\n")
	before, old, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat(strings.Repeat("o", 1023)+"\n", maxCatchUpBytes/1024+2)
	if writeErr := os.WriteFile(path, []byte(content), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	after, _, skipped, err := readNewSyslogRecords(path, old)
	if err != nil || skipped <= old.Offset || len(after) == 0 {
		t.Fatalf("capped rewind read %+v (skipped %d): %v", after, skipped, err)
	}
	checkRecordRefs(t, path, refsOf(before), after)
}

// Emptied and regrown with other bytes, a file names its new first line
// anew; regrown with the same bytes, the line is the record it was.
func TestReadNewSyslogRecordsEmptyTruncateNamesBytes(t *testing.T) {
	followReal(t)
	path := writeFollowFile(t, "first\n")
	before, _, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"other\n", "first\n"} {
		if truncateErr := os.Truncate(path, 0); truncateErr != nil {
			t.Fatal(truncateErr)
		}
		if _, _, _, emptyErr := readNewSyslogRecords(path, followState{}); emptyErr != nil {
			t.Fatal(emptyErr)
		}
		if writeErr := os.WriteFile(path, []byte(content), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		regrown, _, _, regrowErr := readNewSyslogRecords(path, followState{})
		if regrowErr != nil || len(regrown) != 1 {
			t.Fatalf("regrown %+v: %v", regrown, regrowErr)
		}
		checkRecordRefs(t, path, refsOf(before), regrown)
		if same := maps.Equal(refsOf(regrown), refsOf(before)); same != (content == "first\n") {
			t.Fatalf("regrown %q named %+v, earlier %+v", content, regrown, before)
		}
	}
}

// A writer can restore the old disk bytes after ReadAt captured a new line.
// The ref describes the captured bytes being processed.
func TestSyslogObservationNamesTheCapturedBytes(t *testing.T) {
	followReal(t)
	path := writeFollowFile(t, "first\n")
	records, _, _, err := readNewSyslogRecords(path, followState{})
	if err != nil || len(records) != 1 {
		t.Fatalf("records %+v: %v", records, err)
	}
	captured := records[0]
	captured.text = "other"
	if a, b := records[0].observation(ProducerFTPScan, time.Unix(1, 0)), captured.observation(ProducerFTPScan, time.Unix(1, 0)); a.Cursor == b.Cursor {
		t.Fatalf("different captured bytes shared cursor %q", a.Cursor)
	}
}

// A record without a known file names no observation.
func TestSyslogRecordWithoutAFileNamesNothing(t *testing.T) {
	if o := (syslogRecord{text: "first", offset: 0}).observation(ProducerFTPScan, time.Unix(1, 0)); o != (alert.Observation{}) {
		t.Fatalf("observation %+v, want none", o)
	}
}

// A log line may carry a UTC offset the JSON encoder refuses. The scans keep
// the instant and name it in UTC, so the observation stays encodable.
func TestScanObservationsNameTheirTimeInUTC(t *testing.T) {
	zone := time.FixedZone("", 24*60*60)
	t.Run("ftp", func(t *testing.T) {
		log, store := ftpLatchFixture(t)
		var lines []string
		for i := 0; i < ftpFailThreshold; i++ {
			lines = append(lines, time.Now().In(zone).Format(time.RFC3339Nano)+" host pure-ftpd[4242]: (?@192.0.2.81) [WARNING] Authentication failed for user [admin]")
		}
		if err := os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := ftpBruteFindings(CheckFTPLogins(context.Background(), &config.Config{}, store))
		if len(got) != 1 || got[0].Observation.ObservedAt.Location() != time.UTC {
			t.Fatalf("findings %+v, want one with a UTC observed time", got)
		}
		if _, err := got[0].Observation.ObservedAt.MarshalJSON(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ssh", func(t *testing.T) {
		path := useAuthLog(t)
		store, err := state.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		appendLines(t, path, time.Now().In(zone).Format(time.RFC3339Nano)+" host sshd[1201]: Accepted publickey for root from 198.51.100.82 port 51234 ssh2")
		got := sshLoginFindings(CheckSSHLogins(context.Background(), &config.Config{}, store))
		if len(got) != 1 || got[0].Observation.ObservedAt.Location() != time.UTC {
			t.Fatalf("findings %+v, want one with a UTC observed time", got)
		}
		if _, err := got[0].Observation.ObservedAt.MarshalJSON(); err != nil {
			t.Fatal(err)
		}
	})
}

// A followed record is named as the shared helper names the raw record: one
// LF, CRLF or repeated CR before LF ends it, and leading and trailing spaces
// are content. A read with no state names unchanged bytes the same way.
func TestReadNewSyslogRecordsLineEndingsMatchTheSharedRef(t *testing.T) {
	raw := []string{"hit x\n", "hit x\r\n", "hit x\r\r\n", " hit x \n", "hit x  \r\n", "hit y\n"}
	path := filepath.Join(t.TempDir(), "messages")
	if err := os.WriteFile(path, []byte(strings.Join(raw, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	again, _, _, err := readNewSyslogRecords(path, followState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(raw) || len(again) != len(raw) {
		t.Fatalf("records %+v then %+v, want %d each", first, again, len(raw))
	}
	seen := map[string]int{}
	var offset int64
	for i, record := range raw {
		o := first[i].observation(ProducerFTPScan, time.Unix(1, 0))
		if want := syslogTestRef(t, path, offset, record); o.Stream != want.Stream || o.Cursor != want.Cursor {
			t.Errorf("record %d %q named %+v, want %+v", i, record, o, want)
		}
		if a := again[i].observation(ProducerFTPScan, time.Unix(1, 0)); a.Stream != o.Stream || a.Cursor != o.Cursor {
			t.Errorf("record %d %q named %+v on a second read, first %+v", i, record, a, o)
		}
		if j, dup := seen[o.Cursor]; dup {
			t.Errorf("records %d and %d share cursor %q", j, i, o.Cursor)
		}
		seen[o.Cursor] = i
		offset += int64(len(record))
	}
}
