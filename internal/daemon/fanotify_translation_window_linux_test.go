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
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// wpTranslationCacheOfSize builds a valid WordPress *.l10n.php data literal of
// at least minBytes, padded with extra message pairs rather than whitespace so
// the recognizer has to walk the whole body.
func wpTranslationCacheOfSize(minBytes int) []byte {
	var b strings.Builder
	b.WriteString("<?php\nreturn ['language'=>'ro_RO','messages'=>[")
	for i := 0; b.Len() < minBytes; i++ {
		fmt.Fprintf(&b, "'Message number %d'=>'Mesajul numarul %d',", i, i)
	}
	b.WriteString("]];\n")
	return []byte(b.String())
}

// Nearly half the *.l10n.php files on a busy shared host are larger than the
// old 64 KiB realtime read window, so the recognizer could never see a whole
// file and every one of them opened a Warning.
func TestPHPInLanguagesTranslationCacheAboveOldWindowNoAlert(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages", "plugins")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "woocommerce-ro_RO.l10n.php")
	body := wpTranslationCacheOfSize(256 * 1024)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		t.Errorf("expected no alert for a %d-byte WP translation cache, got %+v", len(body), got)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestReadCompleteFromFdRefusesOversizeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.php")
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	if got := readCompleteFromFd(fd, 4095); got != nil {
		t.Errorf("readCompleteFromFd over cap returned %d bytes, want nil", len(got))
	}
	if got := readCompleteFromFd(fd, checks.MaxInertPHPScanBytes); len(got) != 4096 {
		t.Errorf("readCompleteFromFd = %d bytes, want 4096", len(got))
	}
}

func TestReadExactSizeStopsAtSnapshotWhileSourceGrows(t *testing.T) {
	calls := 0
	got := readExactSize(4, 4, func(p []byte, _ int64) (int, error) {
		calls++
		p[0] = byte('a' + calls - 1)
		return 1, nil // model a writer that always has another byte available
	})
	if string(got) != "abcd" || calls != 4 {
		t.Fatalf("readExactSize = %q in %d calls, want %q in 4 calls", got, calls, "abcd")
	}
}

func TestReadExactSizeRejectsShortAndEndlesslyInterruptedReads(t *testing.T) {
	if got := readExactSize(4, 4, func([]byte, int64) (int, error) {
		return 0, nil
	}); got != nil {
		t.Fatalf("zero-length short read returned %d bytes, want nil", len(got))
	}

	calls := 0
	if got := readExactSize(4, 4, func([]byte, int64) (int, error) {
		calls++
		return 0, unix.EINTR
	}); got != nil {
		t.Fatalf("endlessly interrupted read returned %d bytes, want nil", len(got))
	}
	if calls != readCompleteMaxInterrupts+1 {
		t.Errorf("interrupted read made %d calls, want %d", calls, readCompleteMaxInterrupts+1)
	}
}

func TestSameReadSnapshotRejectsConcurrentMutation(t *testing.T) {
	before := unix.Stat_t{
		Dev: 1, Ino: 2, Size: 4,
		Mtim: unix.Timespec{Sec: 3, Nsec: 4},
		Ctim: unix.Timespec{Sec: 5, Nsec: 6},
	}
	if !sameReadSnapshot(before, before) {
		t.Fatal("identical file snapshots did not match")
	}
	after := before
	after.Size++
	if sameReadSnapshot(before, after) {
		t.Fatal("growing file snapshots matched")
	}
	after = before
	after.Ctim.Nsec++
	if sameReadSnapshot(before, after) {
		t.Fatal("fixed-size concurrent rewrite snapshots matched")
	}
}
