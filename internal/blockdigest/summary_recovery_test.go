package blockdigest

import (
	"encoding/json"
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

// A failed save does not hold the summary back: it is sent anyway, since a
// repeat after a crash is accepted, and the save warning backs off like a
// failing destination (first failure, then when the wait reaches an hour).
func TestSummaryDeliversWhenStateCannotBeSaved(t *testing.T) {
	var clock atomic.Int64
	clock.Store(summaryNow.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	cap := &summaryCapture{}
	fail := true
	warnings := 0
	c := summaryCollector(Options{Now: now, EmailSink: cap.email,
		SaveSummary: func([]byte) error {
			if fail {
				return errors.New("disk unavailable")
			}
			return nil
		},
		OnError: func(channel string, err error) {
			if channel != "summary" {
				t.Errorf("unexpected %s error: %v", channel, err)
			}
			warnings++
		},
	})
	c.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING"}})
	due := summaryDueOf(c)
	clock.Store(due.UnixNano())
	if !c.SendDue(due) || len(cap.sent()) != 1 || !strings.Contains(cap.sent()[0].body, "Challenges: 1") {
		t.Fatalf("summary held back by a failed save: %+v", cap.sent())
	}
	// Three hours of one-minute fold ticks with the store still failing.
	for minute := 1; minute <= 180; minute++ {
		clock.Store(due.Add(time.Duration(minute) * time.Minute).UnixNano())
		c.Flush()
		c.SendDue(now())
	}
	if warnings != 2 {
		t.Fatalf("save warnings = %d, want the first failure and the hourly cap", warnings)
	}
	if len(cap.sent()) != 1 {
		t.Fatalf("summary sent %d times, want once", len(cap.sent()))
	}
	fail = false
	c.Flush()
	fail = true
	c.Flush()
	if warnings != 3 {
		t.Fatalf("a failure after a successful save warned %d times in total, want a fresh first warning", warnings)
	}
}

// One failing destination must not stop the daily summary on the others
// (P3-R20): at the next send time the stale pending summary is dropped,
// logged once, and the new window goes out as normal.
func TestSummaryDropsStalePendingAtNextSend(t *testing.T) {
	var subjects []string
	drops, failures := 0, 0
	c := summaryCollector(Options{
		EmailSink:   func(subject, _ string) error { subjects = append(subjects, subject); return nil },
		WebhookSink: func(WebhookPayload) error { return errors.New("fixture hook down") },
		OnError: func(channel string, err error) {
			if channel != "webhook" {
				t.Errorf("unexpected %s error: %v", channel, err)
			}
			if strings.Contains(err.Error(), "dropped") {
				drops++
			} else {
				failures++
			}
		},
	})
	due := summaryDueOf(c)
	for minute := 0; minute < 3*24*60; minute++ {
		c.SendDue(due.Add(time.Duration(minute) * time.Minute))
	}
	want := []string{"2026-06-10", "2026-06-11", "2026-06-12"}
	if len(subjects) != len(want) {
		t.Fatalf("summary emails = %q, want one a day for 3 days", subjects)
	}
	for i, day := range want {
		if !strings.HasSuffix(subjects[i], " "+day) {
			t.Fatalf("summary emails = %q, want windows starting %v", subjects, want)
		}
	}
	if drops != 2 || failures != 6 {
		t.Fatalf("webhook logs: drops=%d failures=%d, want one per dropped summary and first failure plus hourly cap for each of 3", drops, failures)
	}
	rows := digestQueueStatuses(t, c, time.Now())
	if row := rows["webhook"]; row.DroppedTotal != 3 || row.Depth != 1 || row.InFlight != 0 {
		t.Fatalf("webhook row = %+v, want one loss per summary and today's still pending", row)
	}
	if row := rows["email"]; row.DroppedTotal != 0 || row.Depth != 0 || row.InFlight != 0 {
		t.Fatalf("email row = %+v", row)
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

// After downtime across a send time, a saved pending summary is dropped
// before any attempt in this process, so its unfinished destination counts
// its loss there; nothing is dropped without a count.
func TestSummaryDropAfterRestartCountsUntriedLoss(t *testing.T) {
	st := &summaryStore{}
	saved := summaryState{
		Summary: newSummary(summaryNow.Add(-26*time.Hour), summaryNow.Add(-90*time.Minute)),
		Pending: &pendingSummary{Summary: newSummary(summaryNow.Add(-50*time.Hour), summaryNow.Add(-26*time.Hour)), Until: summaryNow.Add(-26 * time.Hour), EmailDone: true},
	}
	b, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	st.data = b
	cap := &summaryCapture{}
	var logs []string
	c := summaryCollector(Options{LoadSummary: st.load, SaveSummary: st.save, EmailSink: cap.email, WebhookSink: cap.webhook,
		OnError: func(channel string, err error) { logs = append(logs, channel+": "+err.Error()) }})
	runStopped(t, c)
	if len(logs) != 1 || !strings.HasPrefix(logs[0], "webhook: ") || !strings.Contains(logs[0], "dropped") {
		t.Fatalf("logs = %q, want one drop line for the webhook", logs)
	}
	if len(cap.sent()) != 1 || len(cap.webhooks) != 1 {
		t.Fatalf("new window email=%d webhook=%d, want 1/1", len(cap.sent()), len(cap.webhooks))
	}
	if row := digestQueueStatuses(t, c, time.Now())["webhook"]; row.DroppedTotal != 1 || row.Depth != 0 || row.InFlight != 0 {
		t.Fatalf("webhook row = %+v, want the dropped summary counted once", row)
	}
}

// A backward clock step after a send must not send that date again while
// the summary is still pending on a failing destination.
func TestSummaryBackwardStepWhilePendingSendsOnce(t *testing.T) {
	var subjects []string
	c := summaryCollector(Options{
		EmailSink:   func(subject, _ string) error { subjects = append(subjects, subject); return nil },
		WebhookSink: func(WebhookPayload) error { return errors.New("fixture hook down") },
		OnError:     func(string, error) {},
	})
	due := summaryDueOf(c)
	c.SendDue(due)
	day2 := due.Add(24 * time.Hour)
	c.SendDue(day2)
	// The clock steps back 30 minutes and runs past 08:00 again.
	for minute := -30; minute <= 10; minute++ {
		c.SendDue(day2.Add(time.Duration(minute) * time.Minute))
	}
	if len(subjects) != 2 || subjects[0] == subjects[1] {
		t.Fatalf("summary emails = %q, want one for each of two windows", subjects)
	}
}

// A destination switched on while the summary is being sent, failing on
// that late attempt, counts one loss for the summary, not again on its
// retry or when the summary is dropped.
func TestSummaryLateEnabledDestinationCountsOneLoss(t *testing.T) {
	var hookOn atomic.Bool
	webhooks := 0
	c := summaryCollector(Options{
		EmailSink:   func(string, string) error { hookOn.Store(true); return nil },
		WebhookSink: func(WebhookPayload) error { webhooks++; return errors.New("fixture hook down") },
		OnError:     func(string, error) {},
		DeliveryEnabled: func(_, channel string) bool {
			return channel == "email" || hookOn.Load()
		},
	})
	due := summaryDueOf(c)
	c.SendDue(due)
	c.SendDue(due.Add(time.Minute))
	c.SendDue(due.Add(24 * time.Hour)) // drops the pending summary
	hookOn.Store(false)
	if webhooks != 3 {
		t.Fatalf("webhook attempts = %d, want the late first one, its retry and the next summary's", webhooks)
	}
	if row := digestQueueStatuses(t, c, time.Now())["webhook"]; row.DroppedTotal != 2 {
		t.Fatalf("webhook row = %+v, want one loss for each of the two summaries", row)
	}
}

// A failing destination the policy switches off is settled at the next
// poll, as an attempt would settle it, instead of waiting out its backoff.
func TestSummarySwitchedOffDestinationSettles(t *testing.T) {
	var hookOn atomic.Bool
	hookOn.Store(true)
	webhooks := 0
	var logs []string
	c := summaryCollector(Options{
		EmailSink:   func(string, string) error { return nil },
		WebhookSink: func(WebhookPayload) error { webhooks++; return errors.New("fixture hook down") },
		OnError:     func(channel string, err error) { logs = append(logs, channel+": "+err.Error()) },
		DeliveryEnabled: func(_, channel string) bool {
			return channel == "email" || hookOn.Load()
		},
	})
	due := summaryDueOf(c)
	for minute := 0; minute <= 70; minute++ {
		c.SendDue(due.Add(time.Duration(minute) * time.Minute))
	}
	attempts := webhooks
	hookOn.Store(false)
	c.SendDue(due.Add(71 * time.Minute))
	if row := digestQueueStatuses(t, c, time.Now())["webhook"]; row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 1 {
		t.Fatalf("webhook row after switch-off = %+v, want settled with its one loss", row)
	}
	c.summaryMu.Lock()
	pending := c.pending
	c.summaryMu.Unlock()
	if pending != nil {
		t.Fatalf("summary still pending after its failing destination was switched off: %+v", pending)
	}
	logged := len(logs)
	c.SendDue(due.Add(24 * time.Hour))
	if webhooks != attempts || len(logs) != logged {
		t.Fatalf("switched-off destination retried or dropped: attempts %d -> %d, logs %q", attempts, webhooks, logs)
	}
}

func TestSummaryMultiDayRollbackKeepsSentDates(t *testing.T) {
	st := &summaryStore{}
	cap := &summaryCapture{}
	c := summaryCollector(Options{EmailSink: cap.email, SaveSummary: st.save})
	first := summaryDueOf(c)
	c.SendDue(first)
	c.SendDue(first.Add(24 * time.Hour))
	restarted := summaryCollector(Options{
		Now:         func() time.Time { return first.Add(-time.Hour) },
		LoadSummary: st.load, SaveSummary: st.save, EmailSink: cap.email,
	})
	runStopped(t, restarted)
	for minute := 0; minute < 48*60; minute++ {
		restarted.SendDue(first.Add(time.Duration(minute) * time.Minute))
	}
	if got := len(cap.sent()); got != 2 {
		t.Fatalf("rollback repeated a sent date: got %d emails, want 2", got)
	}
	if !restarted.SendDue(first.Add(48*time.Hour)) || len(cap.sent()) != 3 {
		t.Fatal("first unsent morning did not deliver")
	}
}
