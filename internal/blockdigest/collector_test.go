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

func TestTickSendsThroughBothSinks(t *testing.T) {
	cap := &capture{}
	c := New(Options{
		Countries: nil, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" },
		EmailSink: cap.email, WebhookSink: cap.webhook,
	})
	c.Observe("203.0.113.5", "rule escalation: x", time.Unix(0, 0))
	c.tick()
	if cap.emailCount() != 1 || cap.webhookCount() != 1 {
		t.Fatalf("emails=%d webhooks=%d, want 1/1", cap.emailCount(), cap.webhookCount())
	}
	if cap.webhooks[0].CSM.Event != "block_digest" {
		t.Errorf("event = %q", cap.webhooks[0].CSM.Event)
	}
}

func TestTickSuppressesEmptyDigest(t *testing.T) {
	cap := &capture{}
	c := New(Options{SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" },
		EmailSink: cap.email})
	c.tick()
	if cap.emailCount() != 0 {
		t.Errorf("empty digest sent %d emails", cap.emailCount())
	}
}

func TestLiveAlertDedupsPerIPWithinWindow(t *testing.T) {
	cap := &capture{}
	now := time.Unix(0, 0)
	c := New(Options{
		Countries: nil, SendOn: "any", Interval: time.Hour, MinBlock: 1, Live: true,
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

func TestLiveCustomerModeOnlyFiresOnCustomer(t *testing.T) {
	cap := &capture{}
	now := time.Unix(0, 0)
	c := New(Options{
		SendOn: "customer", Interval: time.Hour, MinBlock: 1, Live: true,
		Now:         func() time.Time { return now },
		CountryOf:   func(string) string { return "RO" },
		WebhookSink: cap.webhook,
	})
	c.Observe("203.0.113.5", "rule escalation: x", now) // attacker -> no live
	if cap.webhookCount() != 0 {
		t.Fatalf("attacker fired live in customer mode")
	}
	c.Observe("203.0.113.6", "ModSecurity escalation: y", now) // customer -> live
	if cap.webhookCount() != 1 {
		t.Errorf("customer live webhooks = %d, want 1", cap.webhookCount())
	}
}

func TestRunDrainsFinalDigestOnStop(t *testing.T) {
	cap := &capture{}
	c := New(Options{SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" },
		EmailSink: cap.email})
	c.Observe("203.0.113.7", "rule escalation: x", time.Unix(0, 0))
	stop := make(chan struct{})
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { c.Run(stop, tick); close(done) }()
	close(stop)
	<-done
	if cap.emailCount() != 1 {
		t.Errorf("shutdown drain emails = %d, want 1", cap.emailCount())
	}
}
