package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The trackers capture time under different locks. A mail failure can reach
// the shared index after SMTP failures with a later timestamp.
func TestStandingDailyCapDelayedProtocolFailure(t *testing.T) {
	mailClock := &staticClock{t: standingBase}
	smtpClock := &staticClock{t: standingBase.Add(time.Second)}
	s := newLoginStanding(smtpClock.Now)
	earnStanding(t, s, standingIP, standingBox)
	mail := newTestMailTracker(t, mailClock)
	mail.SetLoginStanding(s)
	smtp := newTestTracker(t, smtpClock)
	smtp.SetLoginStanding(s)
	captured, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	mail.backendDownFn = func() bool {
		close(captured)
		<-resume
		return false
	}
	go func() {
		defer close(done)
		mail.Record(standingIP, standingBox)
	}()
	<-captured
	for range standingDailyFailureCap {
		smtp.Record("::ffff:"+standingIP, standingBox)
	}
	close(resume)
	<-done
	if !s.OverDailyCap(standingIP, standingBox, smtpClock.Now()) {
		t.Fatal("delayed mail failure reset the SMTP daily count")
	}
}

func TestStandingDailyCapDelayedDecision(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	earnStanding(t, s, standingIP, standingBox)
	for range standingDailyFailureCap + 1 {
		s.NoteFailure(standingIP, standingBox, clock.Now())
	}
	// A tracker that captured its decision time before the other tracker
	// opened this window must still enforce the shared count.
	if !s.OverDailyCap(standingIP, standingBox, clock.Now().Add(-time.Second)) {
		t.Fatal("an older decision timestamp bypassed the daily cap")
	}
}

func TestStandingDailyCapSlowPathsAcrossProtocols(t *testing.T) {
	for _, protocol := range []string{"mail", "smtp"} {
		t.Run(protocol, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			s := newLoginStanding(clock.Now)
			mail, smtp := newTestMailTracker(t, clock), newTestTracker(t, clock)
			mail.SetLoginStanding(s)
			smtp.SetLoginStanding(s)
			boxes := []string{standingBox, otherBox, "third@example.com"}
			earnStanding(t, s, standingIP, boxes...)
			record, other := mail.Record, smtp.Record
			if protocol == "smtp" {
				record, other = other, record
			}
			// Populate only the other protocol's window. The tested tracker
			// must use the shared daily count, not its own fast-window cap.
			for range standingDailyFailureCap {
				other("::ffff:"+standingIP, standingBox)
				clock.advance(30 * time.Second)
			}
			var out []alert.Finding
			for i := range 40 {
				out = append(out, record(standingIP, boxes[i%len(boxes)])...)
				clock.advance(3 * time.Minute)
			}
			f := findCheck(out, protocol+"_bruteforce")
			if f == nil || f.Severity != alert.Critical {
				t.Fatalf("slow path beyond shared daily cap = %+v, want Critical block", out)
			}
			if findCheck(out, "mail_bruteforce_suspected") != nil {
				t.Fatal("slow path excused a mailbox beyond its daily cap")
			}
		})
	}
}

func TestStandingDailyCapRowLifecycle(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for range standingDailyFailureCap + 1 {
		s.NoteFailure(standingIP, standingBox, clock.Now())
	}
	if s.Len() != 0 {
		t.Fatal("failures allocated standing rows")
	}
	earnStanding(t, s, standingIP, standingBox)
	if s.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("a new row inherited failures counted before it existed")
	}
	for range standingDailyFailureCap + 1 {
		s.NoteFailure(standingIP, standingBox, clock.Now())
	}
	saved, _, _ := s.Changes()
	clock.advance(time.Hour)
	s.Note(standingIP, standingBox, clock.Now())
	s.Load(saved)
	s.Purge()
	s.Changes()
	if !s.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("refreshing, saving or reloading a live row lost its daily count")
	}
	restarted := newLoginStanding(clock.Now)
	restarted.Load(saved)
	if !restarted.Has(standingIP, standingBox, clock.Now()) || restarted.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("restart must restore standing but not its memory-only failure count")
	}
	s.Revoke(standingBox)
	s.NoteFailure(standingIP, standingBox, clock.Now())
	if s.Len() != 0 || s.Has(standingIP, standingBox, clock.Now()) || s.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("revocation left standing or a failure counter behind")
	}
	s.Note(standingIP, standingBox, clock.Now())
	if s.Has(standingIP, standingBox, clock.Now()) || s.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("a replacement row inherited standing or the removed row's daily count")
	}
}

func TestStandingDailyCapFixedWindow(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	earnStanding(t, s, standingIP, standingBox)
	s.NoteFailure(standingIP, standingBox, clock.Now())
	clock.advance(23 * time.Hour)
	for range standingDailyFailureCap {
		s.NoteFailure(standingIP, standingBox, clock.Now())
	}
	clock.advance(time.Hour - time.Second)
	if !s.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("the daily window expired early")
	}
	clock.advance(time.Second)
	if s.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("the daily window slid with later failures")
	}
	for range standingDailyFailureCap {
		s.NoteFailure(standingIP, standingBox, clock.Now())
	}
	if s.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("the new window inherited the old count")
	}
	s.NoteFailure(standingIP, standingBox, clock.Now())
	if !s.OverDailyCap(standingIP, standingBox, clock.Now()) {
		t.Fatal("the new window did not count its own failures")
	}
}
