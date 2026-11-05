package blockdigest

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSummaryFailureRetriesOnlyFailedDestinationAfterRestart(t *testing.T) {
	st := &summaryStore{}
	cap := &summaryCapture{}
	c := summaryCollector(Options{SaveSummary: st.save, EmailSink: cap.email,
		WebhookSink: func(WebhookPayload) error { return errors.New("unavailable") }})
	c.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING"}})
	due := summaryDueOf(c)
	c.SendDue(due)
	c.NoteHandled([]Handled{{Check: "mail_bruteforce_suspected", Severity: "HIGH"}})
	c.Flush()
	restarted := summaryCollector(Options{Now: func() time.Time { return due.Add(time.Minute) }, LoadSummary: st.load, SaveSummary: st.save,
		EmailSink: cap.email, WebhookSink: cap.webhook})
	runStopped(t, restarted)
	if len(cap.sent()) != 1 || len(cap.webhooks) != 1 {
		t.Fatalf("email=%d webhook=%d; want only the failed webhook retried", len(cap.sent()), len(cap.webhooks))
	}
	if got := cap.webhooks[0].CSM.Summary.Checks["challenge_route"]["WARNING"]; got != 1 {
		t.Fatalf("retried window lost its finding: %d", got)
	}
	if got := summaryOf(restarted).Checks["mail_bruteforce_suspected"]["HIGH"]; got != 1 {
		t.Fatalf("new-window findings lost: %d", got)
	}
}

func TestSummaryPersistsWholeWindowBeforeCallingSink(t *testing.T) {
	st := &summaryStore{}
	c := summaryCollector(Options{SaveSummary: st.save,
		EmailSink: func(string, string) error { panic("simulated process death") }})
	c.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING"}})
	due := summaryDueOf(c)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("sink did not simulate a crash")
			}
		}()
		c.SendDue(due)
	}()
	cap := &summaryCapture{}
	restarted := summaryCollector(Options{Now: func() time.Time { return due.Add(time.Minute) }, LoadSummary: st.load, SaveSummary: st.save, EmailSink: cap.email})
	runStopped(t, restarted)
	if sent := cap.sent(); len(sent) != 1 || !strings.Contains(sent[0].body, "Challenges: 1") {
		t.Fatalf("crash lost the uncheckpointed window: %+v", sent)
	}
}

func TestSummaryDoesNotDeliverUntilStateIsDurable(t *testing.T) {
	cap := &summaryCapture{}
	fail := true
	c := summaryCollector(Options{EmailSink: cap.email, SaveSummary: func([]byte) error {
		if fail {
			return errors.New("disk unavailable")
		}
		return nil
	}})
	c.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING"}})
	due := summaryDueOf(c)
	c.SendDue(due)
	if len(cap.sent()) != 0 {
		t.Fatal("delivered a window that could not be saved")
	}
	fail = false
	if !c.SendDue(due.Add(time.Minute)) || len(cap.sent()) != 1 || !strings.Contains(cap.sent()[0].body, "Challenges: 1") {
		t.Fatalf("recovered save did not deliver the retained window: %+v", cap.sent())
	}
}

func TestSummaryBackwardClockDoesNotRepeatSameMorning(t *testing.T) {
	st := &summaryStore{}
	cap := &summaryCapture{}
	c := summaryCollector(Options{EmailSink: cap.email, SaveSummary: st.save})
	due := summaryDueOf(c)
	c.SendDue(due)
	restarted := summaryCollector(Options{Now: func() time.Time { return due.Add(-time.Hour) }, LoadSummary: st.load, SaveSummary: st.save, EmailSink: cap.email})
	runStopped(t, restarted)
	if restarted.SendDue(due) || len(cap.sent()) != 1 {
		t.Fatalf("clock correction repeated today's summary: %d emails", len(cap.sent()))
	}
}

func TestSummaryTickDetectsForwardClockStep(t *testing.T) {
	var now atomic.Int64
	now.Store(summaryNow.UnixNano())
	sent := make(chan struct{}, 2)
	c := summaryCollector(Options{Now: func() time.Time { return time.Unix(0, now.Load()) }, EmailSink: func(string, string) error { sent <- struct{}{}; return nil }})
	stop := make(chan struct{})
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); c.Run(stop, tick) }()
	t.Cleanup(func() { close(stop); <-done })
	tick <- summaryNow
	now.Store(summaryDueOf(c).Add(time.Hour).UnixNano())
	tick <- time.Unix(0, now.Load())
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("clock crossed 08:00 but collector still waits for its old timer")
	}
}

func TestSummaryConcurrentDeliveryKeepsNewFindings(t *testing.T) {
	st := &summaryStore{}
	cap := &summaryCapture{}
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c := summaryCollector(Options{SaveSummary: st.save, EmailSink: func(subject, body string) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return cap.email(subject, body)
	}})
	c.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING"}})
	due := summaryDueOf(c)
	done := make(chan bool, 2)
	go func() { done <- c.SendDue(due) }()
	<-entered
	go func() { done <- c.SendDue(due) }()
	noted := make(chan struct{})
	go func() {
		c.NoteHandled([]Handled{{Check: "mail_bruteforce_suspected", Severity: "HIGH"}})
		close(noted)
	}()
	select {
	case <-noted:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("summary hook blocked on notification delivery")
	}
	close(release)
	first, second := <-done, <-done
	if first == second || len(cap.sent()) != 1 {
		t.Fatalf("concurrent send results=%v/%v emails=%d; want one completed window", first, second, len(cap.sent()))
	}
	if got := st.saved(t).Checks["mail_bruteforce_suspected"]["HIGH"]; got != 1 {
		t.Fatalf("checkpoint lost findings arriving during delivery: %d", got)
	}
	c.SendDue(summaryDueOf(c))
	sent := cap.sent()
	if len(sent) != 2 || !strings.Contains(sent[0].body, "Challenges: 1") || !strings.Contains(sent[1].body, "Mail login advisories, observe only: 1") || !strings.Contains(sent[1].body, "Challenges: 0") {
		t.Fatalf("findings crossed summary windows: %+v", sent)
	}
}

func TestSummaryClockPollDoesNotChangeWatchedDedupWindow(t *testing.T) {
	c := summaryCollector(Options{Watch: true})
	c.Observe("192.0.2.1", "fixture block", summaryNow)
	if c.SendDue(summaryNow.Add(time.Minute)) {
		t.Fatal("sent before due")
	}
	c.Observe("192.0.2.1", "fixture block", summaryNow.Add(2*time.Minute))
	c.Flush()
	if got := summaryOf(c).Watched.Total; got != 1 {
		t.Fatalf("clock polling split a watched-country dedup window: %d blocks", got)
	}
}
