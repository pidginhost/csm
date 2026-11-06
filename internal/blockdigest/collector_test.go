package blockdigest

import (
	"sync"
	"testing"
	"time"
)

type capture struct {
	mu       sync.Mutex
	emails   []string // subjects
	webhooks []WebhookPayload
}

func (c *capture) email(subject, body string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emails = append(c.emails, subject)
	return nil
}

func (c *capture) webhook(p WebhookPayload) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.webhooks = append(c.webhooks, p)
	return nil
}

func (c *capture) emailCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.emails)
}

func (c *capture) webhookCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.webhooks)
}

func TestSendDueSendsThroughBothSinks(t *testing.T) {
	cap := &capture{}
	c := New(Options{
		Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" },
		EmailSink: cap.email, WebhookSink: cap.webhook,
	})
	c.Observe("203.0.113.5", "rule escalation: x", time.Unix(0, 0))
	if !c.SendDue(summaryDueOf(c)) {
		t.Fatal("due summary not sent")
	}
	if cap.emailCount() != 1 || cap.webhookCount() != 1 {
		t.Fatalf("emails=%d webhooks=%d, want 1/1", cap.emailCount(), cap.webhookCount())
	}
	if p := cap.webhooks[0]; p.CSM.Event != "daily_summary" || p.CSM.Summary == nil || p.CSM.Summary.Watched.Total != 1 {
		t.Errorf("payload = %+v, want daily_summary with the folded watched block", p.CSM)
	}
}

// Ticks only fold watched blocks into the summary; nothing is sent before the
// daily send time, and an empty summary still goes out then.
func TestTickNeverSends(t *testing.T) {
	cap := &capture{}
	c := New(Options{Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" },
		EmailSink: cap.email})
	stop := make(chan struct{})
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { c.Run(stop, tick); close(done) }()
	tick <- time.Unix(0, 0)
	c.Observe("203.0.113.5", "rule escalation: x", time.Unix(0, 0))
	tick <- time.Unix(0, 0)
	close(stop)
	<-done
	if cap.emailCount() != 0 {
		t.Fatalf("ticks sent %d emails", cap.emailCount())
	}
	if c.SendDue(summaryDueOf(c).Add(-time.Second)) || cap.emailCount() != 0 {
		t.Fatal("summary sent before its send time")
	}

	empty := New(Options{SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, EmailSink: cap.email})
	if !empty.SendDue(summaryDueOf(empty)) || cap.emailCount() != 1 {
		t.Fatalf("empty summary emails = %d, want 1", cap.emailCount())
	}
}

func TestRunFoldsAndSavesOnStop(t *testing.T) {
	cap := &capture{}
	st := &summaryStore{}
	c := New(Options{Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" },
		EmailSink: cap.email, SaveSummary: st.save})
	c.Observe("203.0.113.7", "rule escalation: x", time.Unix(0, 0))
	stop := make(chan struct{})
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { c.Run(stop, tick); close(done) }()
	close(stop)
	<-done
	if cap.emailCount() != 0 {
		t.Errorf("shutdown sent %d emails, want 0", cap.emailCount())
	}
	if w := st.saved(t).Watched; w.Total != 1 || w.ByCountry["RO"] != 1 {
		t.Errorf("shutdown saved watched = %+v, want the folded block", w)
	}
}

func TestRunFoldsAndExitsWhenTickChannelCloses(t *testing.T) {
	cap := &capture{}
	st := &summaryStore{}
	c := New(Options{Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" },
		EmailSink: cap.email, SaveSummary: st.save})
	c.Observe("203.0.113.8", "rule escalation: x", time.Unix(0, 0))
	stop := make(chan struct{})
	tick := make(chan time.Time)
	close(tick)
	done := make(chan struct{})
	go func() { c.Run(stop, tick); close(done) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after tick channel closed")
	}
	if cap.emailCount() != 0 {
		t.Errorf("closed tick sent %d emails, want 0", cap.emailCount())
	}
	if w := st.saved(t).Watched; w.Total != 1 {
		t.Errorf("closed tick saved watched = %+v, want the folded block", w)
	}
}

func TestLiveAlertDedupsPerIPWithinWindow(t *testing.T) {
	cap := &capture{}
	now := time.Unix(0, 0)
	c := New(Options{
		Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1, Live: true,
		Now:         func() time.Time { return now },
		CountryOf:   func(string) string { return "RO" },
		WebhookSink: cap.webhook,
	})
	c.Observe("203.0.113.5", "rule escalation: x", now)
	c.Observe("203.0.113.5", "rule escalation: x", now) // same IP, within window -> deduped
	if got := cap.webhookCount(); got != 1 {
		t.Fatalf("live webhooks = %d, want 1", got)
	}
	if cap.webhooks[0].CSM.Event != "block_live" {
		t.Errorf("live event = %q, want block_live", cap.webhooks[0].CSM.Event)
	}
	now = now.Add(2 * time.Hour) // window rolled
	c.Observe("203.0.113.5", "rule escalation: x", now)
	if got := cap.webhookCount(); got != 2 {
		t.Errorf("after window roll live webhooks = %d, want 2", got)
	}
}

func TestLiveAlertPrunesExpiredDedupEntries(t *testing.T) {
	cap := &capture{}
	now := time.Unix(0, 0)
	c := New(Options{
		Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1, Live: true,
		Now:         func() time.Time { return now },
		CountryOf:   func(string) string { return "RO" },
		WebhookSink: cap.webhook,
	})
	c.Observe("203.0.113.5", "rule escalation: x", now)
	now = now.Add(2 * time.Hour)
	c.Observe("203.0.113.6", "rule escalation: y", now)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.lastLive["203.0.113.5"]; ok {
		t.Fatalf("expired live dedup entry was not pruned: %+v", c.lastLive)
	}
	if _, ok := c.lastLive["203.0.113.6"]; !ok {
		t.Fatalf("current live dedup entry missing: %+v", c.lastLive)
	}
}

func TestLivePayloadCountriesCannotMutateCollectorOptions(t *testing.T) {
	calls := 0
	now := time.Unix(0, 0)
	c := New(Options{
		Watch: true, Countries: []string{"RO"}, SendOn: "any", Interval: time.Hour, MinBlock: 1, Live: true,
		Now:       func() time.Time { return now },
		CountryOf: func(string) string { return "RO" },
		WebhookSink: func(p WebhookPayload) error {
			calls++
			p.CSM.Countries[0] = "US"
			return nil
		},
	})
	c.Observe("203.0.113.5", "rule escalation: x", now)
	now = now.Add(time.Minute)
	c.Observe("203.0.113.6", "rule escalation: y", now)

	if calls != 2 {
		t.Fatalf("live webhooks = %d, want 2 after mutating payload Countries", calls)
	}
}

func TestLiveCustomerModeOnlyFiresOnCustomer(t *testing.T) {
	cap := &capture{}
	now := time.Unix(0, 0)
	c := New(Options{
		Watch: true, SendOn: "customer", Interval: time.Hour, MinBlock: 1, Live: true,
		Now:         func() time.Time { return now },
		CountryOf:   func(string) string { return "RO" },
		WebhookSink: cap.webhook,
	})
	c.Observe("203.0.113.5", "rule escalation: x", now) // attacker -> no live
	if cap.webhookCount() != 0 {
		t.Fatalf("attacker fired live in customer mode")
	}
	c.Observe("203.0.113.6", "unrecognized customer block", now) // customer -> live
	if cap.webhookCount() != 1 {
		t.Errorf("customer live webhooks = %d, want 1", cap.webhookCount())
	}
}
