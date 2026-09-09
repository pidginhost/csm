//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDropperInertReadRejectsConcurrentGrowth(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "snapshot-*.php")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd())
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		t.Fatal(err)
	}
	head, _, stable := readDropperHead(fd, before, func(fd, maxBytes int) []byte {
		head := readFromFd(fd, maxBytes)
		if _, err := f.WriteString("<?php echo 1;"); err != nil {
			t.Fatal(err)
		}
		return head
	})
	if stable {
		t.Fatalf("prefix of a growing file accepted as a stable snapshot: head=%q", head)
	}
}

func TestDropperInertCreatePreservesFreshness(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.php")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fm := newDropperWiringTestMonitor(dir, time.Minute)
	created := fm.observeDropperCandidate(fileEvent{path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE}, "")
	if created == nil || fm.dropper.tr.trackedCount() != 1 {
		t.Fatal("empty create discarded the freshness evidence for a later write")
	}
	// Emulate a filesystem without STATX_BTIME. Only the create can prove
	// freshness when the following close carries executable content.
	created.BirthKnown = false
	fm.dropper.tr = newDropperTracker(time.Minute)
	fm.dropper.tr.Observe(*created)
	closed := *created
	closed.Created = false
	closed.WritePending = false
	closed.Observed = created.Observed.Add(time.Second)
	closed.Head = []byte("<?php echo 1;")
	closed.Size = int64(len(closed.Head))
	if !fm.dropper.tr.Refresh(closed) {
		t.Fatal("close could not find the prior create")
	}
	due := fm.dropper.tr.Due(closed.Observed.Add(2 * time.Minute))
	if len(due) != 1 || !due[0].Created || assessDropper(due[0], dropperProbe{Conclusive: true}) != dropperSuspect {
		t.Fatalf("completed payload lost: %+v", due)
	}
}

func TestDropperInertContentSignatureOverridesAdmission(t *testing.T) {
	useRealtimeRules(t, strings.Replace(realtimeHighRule, "EVIL_MARKER_A", "    ", 1))
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.php")
	if err := os.WriteFile(path, []byte("    \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fm := newDropperWiringTestMonitor(dir, time.Minute)
	event := fileEvent{path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE | FAN_CLOSE_WRITE}
	cand := fm.observeDropperCandidate(event, "")
	if cand == nil || !dropperCandidateIsInert(*cand) || fm.dropper.tr.trackedCount() != 0 {
		t.Fatal("test must start with a snapshot rejected by the inert gate")
	}
	fm.analyzeFile(event)
	due := fm.dropper.tr.Due(time.Now().Add(2 * time.Minute))
	if len(due) != 1 || !due[0].ContentSuspicious {
		t.Fatalf("signature hit did not override inert admission: %+v", due)
	}
	if got := assessDropper(due[0], dropperProbe{Conclusive: true}); got != dropperSuspect {
		t.Fatalf("signature-flagged deletion = %v, want suspect", got)
	}
}

func TestDropperInertRefreshDoesNotForgetCode(t *testing.T) {
	for _, initiallyActive := range []bool{false, true} {
		c := inertTestCandidate()
		c.WritePending = true
		if initiallyActive {
			c.Head = []byte("<?php echo 1;")
			c.Size = int64(len(c.Head))
		}
		tr := newDropperTracker(time.Minute)
		tr.Observe(c)
		closed := c
		closed.Created = false
		closed.WritePending = false
		closed.Observed = c.Observed.Add(time.Second)
		closed.Head, closed.Size = nil, 0
		if !tr.Refresh(closed) {
			t.Fatal("close did not refresh create")
		}
		due := tr.Due(c.Observed.Add(2 * time.Minute))
		if len(due) != 1 {
			t.Fatalf("got %d candidates, want 1", len(due))
		}
		want := dropperBenign
		if initiallyActive {
			want = dropperSuspect
		}
		if got := assessDropper(due[0], dropperProbe{Conclusive: true}); got != want {
			t.Errorf("initially active=%v: verdict=%v, want %v", initiallyActive, got, want)
		}
	}
}

// The plugin temp-file false positive: WP All Import recreates a zero-byte
// index.php guard in a scratch directory roughly once a second and removes
// the whole directory again. The unlink bumps the inode's ctime, so when it
// lands between the two stats that bracket the head read the snapshot looks
// racy even though no byte was ever written. Marking such a candidate
// "content may execute" is sticky, so the empty-guard gate could never fire
// and every one of those files was reported.
func TestDropperInertHeadSnapshotSurvivesMetadataOnlyChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.php")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd())
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		t.Fatal(err)
	}

	unlinked := false
	head, size, stable := readDropperHead(fd, before, func(fd, maxBytes int) []byte {
		got := readFromFd(fd, maxBytes)
		if !unlinked {
			unlinked = true
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		return got
	})
	if !unlinked {
		t.Fatal("test did not exercise the metadata change")
	}
	if !stable || len(head) != 0 || size != 0 {
		t.Fatalf("metadata-only change poisoned the content snapshot: stable=%v head=%q size=%d", stable, head, size)
	}
}

// A file that keeps being rewritten must stay unstable however many times the
// snapshot is retried.
func TestDropperInertHeadSnapshotStaysUnstableWhileWritten(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "growing-*.php")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd())
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		t.Fatal(err)
	}
	reads := 0
	_, _, stable := readDropperHead(fd, before, func(fd, maxBytes int) []byte {
		got := readFromFd(fd, maxBytes)
		reads++
		if _, err := f.WriteString("<?php echo 1;"); err != nil {
			t.Fatal(err)
		}
		return got
	})
	if stable {
		t.Fatal("a file under active rewrite was accepted as a stable snapshot")
	}
	if reads < 2 {
		t.Fatalf("snapshot was not retried: reads=%d", reads)
	}
}
