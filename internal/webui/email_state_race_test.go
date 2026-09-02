package webui

import (
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/emailav"
)

// The daemon installs the email quarantine and the AV watcher mode after the
// listener already serves requests, with plain field writes that request
// goroutines read concurrently. Both are held atomically and read through
// accessors; run this test with -race to prove it.
func TestEmailStateSettersAreSafeAfterServeStarts(t *testing.T) {
	s := newTestServer(t, "tok")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = s.emailQuarantineHandle()
			_ = s.emailAVMode()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			s.SetEmailQuarantine(&emailav.Quarantine{})
			s.SetEmailAVWatcherMode("inline")
		}
	}()
	wg.Wait()
	if s.emailAVMode() != "inline" {
		t.Fatalf("watcher mode = %q after set", s.emailAVMode())
	}
	if s.emailQuarantineHandle() == nil {
		t.Fatal("quarantine handle nil after set")
	}
}
