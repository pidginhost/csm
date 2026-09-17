//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
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
	for _, content := range []string{"", wordfenceWAFHead} {
		for _, changes := range []int{1, 2} {
			t.Run(fmt.Sprintf("bytes=%d/changes=%d", len(content), changes), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "index.php")
				f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()
				if _, err := f.WriteString(content); err != nil {
					t.Fatal(err)
				}
				fd := int(f.Fd())
				var before unix.Stat_t
				if err := unix.Fstat(fd, &before); err != nil {
					t.Fatal(err)
				}
				reads := 0
				head, size, stable := readDropperHead(fd, before, func(fd, maxBytes int) []byte {
					got := readFromFd(fd, maxBytes)
					reads++
					if reads < changes {
						if err := os.Rename(path, path+".moved"); err != nil {
							t.Fatal(err)
						}
						path += ".moved"
					} else if reads == changes {
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
					}
					return got
				})
				if reads != changes+1 {
					t.Fatalf("metadata changes were not retried: reads=%d", reads)
				}
				if !stable || string(head) != content || size != int64(len(content)) {
					t.Fatalf("metadata change poisoned the snapshot: stable=%v head=%q size=%d", stable, head, size)
				}
			})
		}
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
	if reads != 1 {
		t.Fatalf("content changes must not be retried: reads=%d", reads)
	}
}

func TestDropperInertHeadSnapshotRetainsWriteEvidence(t *testing.T) {
	for _, change := range []string{"truncate", "same-size rewrite", "restored mtime", "chmod"} {
		t.Run(change, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "changing-*.php")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			body := []byte("<?php echo 1;")
			if _, err = f.Write(body); err != nil {
				t.Fatal(err)
			}
			fd := int(f.Fd())
			var before unix.Stat_t
			if err = unix.Fstat(fd, &before); err != nil {
				t.Fatal(err)
			}
			reads := 0
			_, _, stable := readDropperHead(fd, before, func(fd, maxBytes int) []byte {
				head := readFromFd(fd, maxBytes)
				reads++
				if reads == 1 {
					switch change {
					case "truncate":
						err = f.Truncate(0)
					case "same-size rewrite", "restored mtime":
						_, err = f.WriteAt([]byte(strings.Repeat(" ", len(body))), 0)
						if err == nil && change == "restored mtime" {
							err = os.Chtimes(f.Name(), time.Unix(before.Atim.Sec, before.Atim.Nsec), time.Unix(before.Mtim.Sec, before.Mtim.Nsec))
						}
					case "chmod":
						err = f.Chmod(0o755)
					}
					if err != nil {
						t.Fatal(err)
					}
					// A quiet retry is only a pause in this writer's activity.
				}
				return head
			})
			if stable {
				t.Fatal("a quiet retry erased evidence of a concurrent change")
			}
		})
	}
}

func TestDropperInertCloseWriteFamilies(t *testing.T) {
	previous := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(previous) })
	for _, tc := range []struct {
		name  string
		body  string
		inert bool
	}{
		{"empty guard", "", true},
		{"WAF state head", wordfenceWAFHead, true},
		{"WAF state with data tail", wordfenceWAFHead + strings.Repeat("*", 21927), true},
		{"code", "<?php echo 1;", false},
		{"invalid opening tag", "<?php\vexit(); ?><?php echo 1;", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "payload.php")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			fm := newDropperWiringTestMonitor(dir, time.Minute)
			c := fm.observeDropperCandidate(fileEvent{path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CLOSE_WRITE}, "")
			if c == nil || !c.BirthKnown || c.Created || c.WritePending {
				t.Fatalf("test did not exercise birth-time admission on close-write: %+v", c)
			}
			if c.ContentMayExecute || c.Size != int64(len(tc.body)) {
				t.Fatalf("stable close-write snapshot lost: %+v", c)
			}
			due := fm.dropper.tr.Due(time.Now().Add(2 * time.Minute))
			if tc.inert {
				if len(due) != 0 {
					t.Fatal("inert file admitted on close-write")
				}
			} else if len(due) != 1 || assessDropper(due[0], dropperProbe{Conclusive: true}) != dropperSuspect {
				t.Fatalf("code-bearing deletion lost: %+v", due)
			}
		})
	}
}

func TestDropperInertPHPDataFileSignatureWins(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	dir := t.TempDir()
	fm := newDropperWiringTestMonitor(dir, time.Minute)
	path := filepath.Join(dir, "state.php")
	if err := os.WriteFile(path, []byte(wordfenceWAFHead+"EVIL_MARKER_A"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	event := fileEvent{path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CLOSE_WRITE}
	c := fm.observeDropperCandidate(event, "")
	if c == nil || !dropperCandidateIsInert(*c) {
		t.Fatalf("test must start from a snapshot the terminator gate exempts: %+v", c)
	}
	fm.analyzeFile(event)
	due := fm.dropper.tr.Due(time.Now().Add(2 * time.Minute))
	if len(due) != 1 || !due[0].ContentSuspicious || assessDropper(due[0], dropperProbe{Conclusive: true}) != dropperSuspect {
		t.Fatalf("signature did not override the PHP exemption: %+v", due)
	}
}

// wafAttackDataBody is shaped like a WAF attack log: a terminator header, a
// signature and a binary row table the PHP compiler never reaches.
var wafAttackDataBody = "<?php exit('Access denied'); __halt_compiler(); ?>\nwfWAF" +
	strings.Repeat("\x00\x01\x7f\xfe", 512)

// observeDuringConcurrentWrite keeps a second writer resizing path while the
// analyzer snapshots it, the way concurrent requests append rows to a shared
// WAF log while another request closes its handle. It returns once a snapshot
// raced that writer and the writer has stopped.
func observeDuringConcurrentWrite(t *testing.T, r *wpInstallRun, path string, body string) {
	t.Helper()
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		chunk := []byte("\x00\x02\x7f\xfd")
		for {
			select {
			case <-stop:
				done <- w.Truncate(int64(len(body)))
				return
			default:
			}
			if _, err := w.WriteAt(chunk, int64(len(body))); err != nil {
				done <- err
				return
			}
			if err := w.Truncate(int64(len(body))); err != nil {
				done <- err
				return
			}
		}
	}()
	raced := false
	deadline := time.Now().Add(10 * time.Second)
	for !raced && time.Now().Before(deadline) {
		r.observeCloseWrite(t, path)
		raced = r.fm.dropper.tr.trackedCount() == 1
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !raced {
		t.Fatal("no snapshot raced the concurrent writer")
	}
}

func (r *wpInstallRun) observeCloseWrite(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r.fm.observeDropperCandidate(fileEvent{path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CLOSE_WRITE}, "pid=4242 cmd=lsphp uid=1000")
}

func replaceAtomically(t *testing.T, path, body string) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(path), "attack.tmp.example")
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// A snapshot that raced another writer proves nothing about the bytes, but
// that writer's own close delivers a complete snapshot. When that snapshot is
// a data file, the later atomic replacement of the log is not a dropper.
func TestDropperWAFLogSettledAfterConcurrentWrite(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "wp-content", "wflogs", "attack-data.php")
	writeWPInstallFile(t, path, wafAttackDataBody)
	r := newWPInstallRun(t, docroot)
	r.observeCloseWrite(t, path)
	if r.fm.dropper.tr.trackedCount() != 0 {
		t.Fatal("test must start from a data file the inert gate exempts")
	}
	observeDuringConcurrentWrite(t, r, path, wafAttackDataBody)
	r.observeCloseWrite(t, path)
	replaceAtomically(t, path, wafAttackDataBody)
	r.probeAndFlush()
	if len(*r.alerts) != 0 {
		t.Fatalf("settled WAF log replacement raised %+v, want no finding", *r.alerts)
	}
}

// Without a later complete snapshot the raced bytes stay unknown.
func TestDropperWAFLogRacedSnapshotAloneStillReported(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(fmt.Sprintf("replaced=%v", replaced), func(t *testing.T) {
			docroot := t.TempDir()
			path := filepath.Join(docroot, "wp-content", "wflogs", "attack-data.php")
			writeWPInstallFile(t, path, wafAttackDataBody)
			r := newWPInstallRun(t, docroot)
			observeDuringConcurrentWrite(t, r, path, wafAttackDataBody)
			want := alert.Critical
			if replaced {
				replaceAtomically(t, path, wafAttackDataBody)
				want = alert.Warning
			} else if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			r.probeAndFlush()
			if got := *r.alerts; len(got) != 1 || got[0].sev != want || got[0].path != path {
				t.Fatalf("raced snapshot findings = %+v, want one %v", got, want)
			}
		})
	}
}

// Code seen in any snapshot outlives a later complete data snapshot.
func TestDropperWAFLogNameWithCodeStillCritical(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "wp-content", "wflogs", "attack-data.php")
	writeWPInstallFile(t, path, testDropperPHP)
	r := newWPInstallRun(t, docroot)
	r.observeCloseWrite(t, path)
	if err := os.WriteFile(path, []byte(wafAttackDataBody), 0o600); err != nil {
		t.Fatal(err)
	}
	r.observeCloseWrite(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r.probeAndFlush()
	assertSingleCriticalDropper(t, *r.alerts, path)
}
