package yaraworker

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// A scanner that cannot load its rules fails identically for every buffer it
// is handed. Logging each failure turned one broken rules directory into
// hundreds of identical journal lines per minute during a full account scan,
// which reached the operator as alert noise and buried everything else.
//
// The first failure must still be logged -- the condition matters -- but a
// repeat of the same message inside the window is counted, not repeated.
func TestScanErrLogIsDeduplicated(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	s := &Supervisor{}
	s.cfg.Logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, format)
	}

	err := errors.New("yara scanner unavailable: rules path has unsafe mode 0664")
	for i := 0; i < 500; i++ {
		s.logScanErr(err)
	}

	mu.Lock()
	got := len(lines)
	mu.Unlock()
	if got != 1 {
		t.Errorf("logged %d lines for 500 identical failures, want 1", got)
	}
}

// A different failure is a different condition and must not be swallowed by
// the previous one's suppression window.
func TestScanErrLogReportsDistinctErrors(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	s := &Supervisor{}
	s.cfg.Logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, format)
	}

	s.logScanErr(errors.New("rules path has unsafe mode 0664"))
	s.logScanErr(errors.New("worker exited unexpectedly"))
	s.logScanErr(errors.New("rules path has unsafe mode 0664"))

	mu.Lock()
	got := len(lines)
	mu.Unlock()
	if got != 2 {
		t.Errorf("logged %d lines for 2 distinct failures, want 2", got)
	}
}

// Once the window closes the condition is reported again, with the count of
// what was suppressed, so a persistent fault stays visible instead of going
// silent forever after one line.
func TestScanErrLogResurfacesAfterWindowWithCount(t *testing.T) {
	var mu sync.Mutex
	var msgs []string
	s := &Supervisor{}
	s.cfg.Logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, format)
	}

	err := errors.New("rules path has unsafe mode 0664")
	s.logScanErr(err)
	for i := 0; i < 9; i++ {
		s.logScanErr(err)
	}

	// Age the window rather than sleeping through it.
	s.scanErrMu.Lock()
	for _, rec := range s.scanErrSeen {
		rec.at = time.Now().Add(-2 * scanErrLogWindow)
	}
	s.scanErrMu.Unlock()

	s.logScanErr(err)

	mu.Lock()
	defer mu.Unlock()
	if len(msgs) != 2 {
		t.Fatalf("logged %d lines, want 2 (first plus one after the window)", len(msgs))
	}
	if !strings.Contains(msgs[1], "suppressed") {
		t.Errorf("second line does not report the suppressed count: %q", msgs[1])
	}
}
