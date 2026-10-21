package webui

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/mailstats"
)

// The daemon installs the email quarantine, the AV watcher mode and the mail
// decision counter after the listener already serves requests, while request
// goroutines read them. All are held atomically and read through accessors;
// run this test with -race to prove it.
func TestEmailStateSettersAreSafeAfterServeStarts(t *testing.T) {
	s := newTestServer(t, "tok")
	if s.mailStatsCounter() != nil {
		t.Fatal("mail stats counter set before SetMailStats")
	}
	counter := mailstats.New(time.Now)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = s.emailQuarantineHandle()
			_ = s.emailAVMode()
			_ = s.mailStatsCounter()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			s.SetEmailQuarantine(&emailav.Quarantine{})
			s.SetEmailAVWatcherMode("inline")
			s.SetMailStats(counter)
		}
	}()
	wg.Wait()
	if s.emailAVMode() != "inline" {
		t.Fatalf("watcher mode = %q after set", s.emailAVMode())
	}
	if s.emailQuarantineHandle() == nil {
		t.Fatal("quarantine handle nil after set")
	}
	if s.mailStatsCounter() != counter {
		t.Fatal("mailStatsCounter did not return the installed counter")
	}
}
