package checks

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/state"
)

func TestFTPAccumulatorSlowBruteCrossesThresholdOverWindow(t *testing.T) {
	tr := newFTPFailTracker()
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	// 5 failures in minute 0, 5 in minute 1 = 10 within a 30m window.
	for i := 0; i < 5; i++ {
		tr.record("203.0.113.5", base)
	}
	for i := 0; i < 5; i++ {
		tr.record("203.0.113.5", base.Add(time.Minute))
	}
	tr.evict(base.Add(time.Minute), 30)
	offs := tr.offenders(10)
	if len(offs) != 1 || offs[0].IP != "203.0.113.5" || offs[0].Count != 10 {
		t.Fatalf("want one offender 203.0.113.5 count 10, got %+v", offs)
	}
}

func TestFTPAccumulatorEvictionDropsOldBuckets(t *testing.T) {
	tr := newFTPFailTracker()
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		tr.record("198.51.100.7", base)
	}
	// 31 minutes later the bucket is outside a 30m window.
	tr.evict(base.Add(31*time.Minute), 30)
	if offs := tr.offenders(10); len(offs) != 0 {
		t.Fatalf("expected no offenders after eviction, got %+v", offs)
	}
}

func TestFTPAccumulatorKeepsBoundaryBucket(t *testing.T) {
	tr := newFTPFailTracker()
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		tr.record("198.51.100.8", base)
	}
	// Exactly 30 minutes old is still inside a 30m window; only older buckets
	// are evicted.
	tr.evict(base.Add(30*time.Minute), 30)
	offs := tr.offenders(10)
	if len(offs) != 1 || offs[0].IP != "198.51.100.8" || offs[0].Count != 10 {
		t.Fatalf("boundary bucket should remain inside the window, got %+v", offs)
	}
}

func TestFTPAccumulatorCapIPsEvictsOldestActivity(t *testing.T) {
	tr := newFTPFailTracker()
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	// IP "a" active earliest, "c" latest.
	tr.record("203.0.113.1", base)
	tr.record("203.0.113.2", base.Add(time.Minute))
	tr.record("203.0.113.3", base.Add(2*time.Minute))
	tr.capIPs(2)
	if _, ok := tr.Buckets["203.0.113.1"]; ok {
		t.Fatalf("oldest-activity IP should have been evicted; buckets=%v", tr.Buckets)
	}
	if len(tr.Buckets) != 2 {
		t.Fatalf("want 2 tracked IPs after cap, got %d", len(tr.Buckets))
	}
}

// writeFollowFile writes content to a temp file and returns its path.
func writeFollowFile(t *testing.T, content string) string {
	t.Helper()
	p := t.TempDir() + "/messages"
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// followReal points osFS.Open at the real filesystem for these tests.
func followReal(t *testing.T) {
	t.Helper()
	withMockOS(t, &mockOS{open: os.Open})
}

func TestReadNewSyslogLinesAppendReturnsOnlyNew(t *testing.T) {
	followReal(t)
	p := writeFollowFile(t, "line one\nline two\n")
	lines1, st1, _, err := readNewSyslogLines(p, followState{})
	if err != nil {
		t.Fatalf("cycle1: %v", err)
	}
	// First run over a small file reads the whole file (below the cap).
	if len(lines1) != 2 {
		t.Fatalf("cycle1 want 2 lines, got %v", lines1)
	}
	if err = os.WriteFile(p, []byte("line one\nline two\nline three\n"), 0644); err != nil {
		t.Fatal(err)
	}
	lines2, _, _, err := readNewSyslogLines(p, st1)
	if err != nil {
		t.Fatalf("cycle2: %v", err)
	}
	if len(lines2) != 1 || lines2[0] != "line three" {
		t.Fatalf("cycle2 want [line three], got %v", lines2)
	}
}

func TestReadNewSyslogLinesPartialLineHeldUntilComplete(t *testing.T) {
	followReal(t)
	p := writeFollowFile(t, "complete one\npartial")
	lines1, st1, _, err := readNewSyslogLines(p, followState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines1) != 1 || lines1[0] != "complete one" {
		t.Fatalf("cycle1 want [complete one], got %v", lines1)
	}
	if err = os.WriteFile(p, []byte("complete one\npartial now done\n"), 0644); err != nil {
		t.Fatal(err)
	}
	lines2, _, _, err := readNewSyslogLines(p, st1)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines2) != 1 || lines2[0] != "partial now done" {
		t.Fatalf("cycle2 want [partial now done] once, got %v", lines2)
	}
}

func TestReadNewSyslogLinesCopytruncateRestartsAtZero(t *testing.T) {
	followReal(t)
	p := writeFollowFile(t, "aaaa\nbbbb\ncccc\n")
	_, st1, _, _ := readNewSyslogLines(p, followState{})
	// copytruncate: file replaced with smaller content.
	if err := os.WriteFile(p, []byte("xxxx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	lines, _, _, err := readNewSyslogLines(p, st1)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "xxxx" {
		t.Fatalf("want restart-at-0 [xxxx], got %v", lines)
	}
}

func TestReadNewSyslogLinesDifferentHeadRotateRestarts(t *testing.T) {
	followReal(t)
	p := writeFollowFile(t, "HEADER-A\nrow1\nrow2\n")
	_, st1, _, _ := readNewSyslogLines(p, followState{})
	// Rotated file with a different head but larger than the old offset.
	if err := os.WriteFile(p, []byte("HEADER-B\nrow1\nrow2\nrow3\nrow4\n"), 0644); err != nil {
		t.Fatal(err)
	}
	lines, _, _, err := readNewSyslogLines(p, st1)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 5 {
		t.Fatalf("different-head rotate should reread from 0 (5 lines), got %v", lines)
	}
}

func TestReadNewSyslogLinesSameHeadReplacementAnchorMismatchRestarts(t *testing.T) {
	followReal(t)
	head := strings.Repeat("H", fingerprintBytes)
	p := writeFollowFile(t, head+"\nAAA\nBBB\n")
	_, st1, _, _ := readNewSyslogLines(p, followState{})
	// Same first 512 bytes, but the bytes around the old offset differ.
	if err := os.WriteFile(p, []byte(head+"\nZZZ\nYYY\nXXX\n"), 0644); err != nil {
		t.Fatal(err)
	}
	lines, _, _, err := readNewSyslogLines(p, st1)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 4 {
		t.Fatalf("same-head replacement with anchor mismatch should reread from 0 (4 lines), got %v", lines)
	}
}

func TestReadNewSyslogLinesFirstRunCatchUpCapSkips(t *testing.T) {
	followReal(t)
	// Build a file larger than maxCatchUpBytes: each line is "x...\n".
	var b strings.Builder
	line := strings.Repeat("x", 99) + "\n" // 100 bytes/line
	for b.Len() < maxCatchUpBytes+200_000 {
		b.WriteString(line)
	}
	p := writeFollowFile(t, b.String())
	lines, _, skipped, err := readNewSyslogLines(p, followState{})
	if err != nil {
		t.Fatal(err)
	}
	if skipped <= 0 {
		t.Fatalf("expected skipped > 0 on first-run over a >cap file, got %d", skipped)
	}
	// Read content must be within the cap (allowing one line slack for newline alignment).
	if got := int64(len(lines)) * 100; got > maxCatchUpBytes+100 {
		t.Fatalf("read window exceeded cap: %d bytes", got)
	}
}

func TestReadNewSyslogLinesErrorReturnsOriginalState(t *testing.T) {
	st := followState{Offset: 123, HeadLen: 8, HeadFP: "abc", AnchorLen: 8, AnchorFP: "def"}
	withMockOS(t, &mockOS{open: func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}})
	lines, next, skipped, err := readNewSyslogLines("/missing/messages", st)
	if err == nil {
		t.Fatal("expected open error")
	}
	if len(lines) != 0 || skipped != 0 || next != st {
		t.Fatalf("on error want no lines, no skip, original state; lines=%v skipped=%d next=%+v", lines, skipped, next)
	}
}

func TestFTPTrackerPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	tr := newFTPFailTracker()
	tr.Follow = followState{Offset: 123, HeadLen: 8, HeadFP: "abc", AnchorLen: 8, AnchorFP: "def"}
	tr.record("203.0.113.9", time.Unix(60_000, 0))
	tr.save(st)
	if err = st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st2, err := state.Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = st2.Close() }()
	got := loadFTPFailTracker(st2)
	if got.Follow.Offset != 123 || got.Follow.HeadFP != "abc" || got.Follow.AnchorFP != "def" {
		t.Fatalf("follow not restored: %+v", got.Follow)
	}
	if got.Buckets["203.0.113.9"][1000] != 1 { // 60000/60 = 1000
		t.Fatalf("buckets not restored: %+v", got.Buckets)
	}
}

func TestFTPTrackerLoadCorruptJSONYieldsZeroState(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()
	st.SetRaw(ftpTrackerKey, "{not valid json")
	got := loadFTPFailTracker(st)
	if got == nil || got.Buckets == nil || len(got.Buckets) != 0 || got.Follow.Offset != 0 {
		t.Fatalf("corrupt JSON should yield zero state, got %+v", got)
	}
}

func TestFTPTrackerLoadIncompleteFollowYieldsZeroState(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()
	st.SetRaw(ftpTrackerKey, `{"follow":{"offset":123},"buckets":{"203.0.113.9":{"1000":1}}}`)
	got := loadFTPFailTracker(st)
	if got == nil || got.Buckets == nil || len(got.Buckets) != 0 || got.Follow.Offset != 0 {
		t.Fatalf("incomplete follow state should yield zero state, got %+v", got)
	}
}
