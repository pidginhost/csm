package checks

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

type mailboxBoundaryBlockedContext struct {
	context.Context
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *mailboxBoundaryBlockedContext) Err() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Context.Err()
}

func TestMailboxQueueAbandonDoesNotLockHealthDuringContextRead(t *testing.T) {
	m := newScanBatchMonitor()
	b := m.begin(3, 2)
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	ctx := &mailboxBoundaryBlockedContext{Context: parent, entered: entered, release: release}
	abandoned := make(chan struct{})
	go func() { defer close(abandoned); b.abandon(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("abandon did not reach context evaluation")
	}
	snapshot := make(chan queuehealth.Status, 1)
	go func() { snapshot <- m.snapshot(time.Now()) }()
	blocked := false
	select {
	case q := <-snapshot:
		if q.Depth != 3 || q.InFlight != 0 || q.DroppedTotal != 0 {
			t.Errorf("context evaluation changed ownership: %+v", q)
		}
	case <-time.After(time.Second):
		blocked = true
	}
	finish()
	<-abandoned
	if blocked {
		<-snapshot
		t.Fatal("mailbox health snapshot blocked behind ctx.Err under the monitor lock")
	}
	if q := m.snapshot(time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("withdrawal settlement: %+v", q)
	}
}

type mailboxBoundaryAfterCommitContext struct {
	context.Context
	db      *store.DB
	key     string
	entered chan struct{}
	once    sync.Once
}

func (c *mailboxBoundaryAfterCommitContext) Err() error {
	if c.db.GetMetaString(c.key) != "" {
		c.once.Do(func() { close(c.entered) })
		<-c.Done()
	}
	return c.Context.Err()
}

type mailboxBoundaryImmediateTransport struct{}

func (mailboxBoundaryImmediateTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func TestMailboxQueueCompletedCacheWriteSurvivesLateDeadline(t *testing.T) {
	previous := emailMailboxAudits
	emailMailboxAudits = newScanBatchMonitor()
	defer func() { emailMailboxAudits = previous }()
	db := withTestStore(t)
	withWeakPasswords(t, nil)
	path := t.TempDir() + "/shadow"
	if err := os.WriteFile(path, []byte("mailbox:{PLAIN}mailbox\n"), 0600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{"/home/alice/etc/example.test/shadow"}, nil },
		open: func(string) (*os.File, error) { return os.Open(path) },
	})
	oldClient := hibpClient
	hibpClient = &http.Client{Transport: mailboxBoundaryImmediateTransport{}}
	defer func() { hibpClient = oldClient }()
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan struct{})
	key := "email:pwaudit:alice:mailbox@example.test"
	ctx := &mailboxBoundaryAfterCommitContext{Context: parent, db: db, key: key, entered: entered}
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckEmailPasswords(ctx, &config.Config{}, nil) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	select {
	case <-entered:
	case <-done:
		joined = true
		t.Fatal("audit returned without committing the successful mailbox result")
	case <-time.After(2 * time.Second):
		t.Fatal("audit never reached completed cache write")
	}
	if parent.Err() != nil || db.GetMetaString(key) == "" {
		t.Fatal("probe did not reach the window after a successful commit and before deadline")
	}
	var findings []alert.Finding
	select {
	case findings = <-done:
		joined = true
	case <-time.After(2 * time.Second):
		t.Fatal("audit failed to return after deadline")
	}
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Check]++
	}
	if len(findings) != 2 || counts["email_weak_password"] != 1 || counts["email_password_audit_incomplete"] != 1 || db.GetMetaString(key) == "" {
		t.Fatalf("existing late-check result/cache semantics changed: findings=%v", counts)
	}
	q := mailboxQueue(t, time.Now())
	if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
		t.Fatalf("completed mailbox persistence became failed work only during final cleanup: %+v", q)
	}
}

func TestMailboxQueueConcurrentBatchesKeepOwnSlotsAndDeadlines(t *testing.T) {
	previous := emailMailboxAudits
	emailMailboxAudits = newScanBatchMonitor()
	defer func() { emailMailboxAudits = previous }()
	db := withTestStore(t)
	withWeakPasswords(t, nil)
	path := t.TempDir() + "/shadow"
	if err := os.WriteFile(path, []byte(strings.Repeat("mailbox:{PLAIN}mailbox\n", 8)), 0600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{"/home/alice/etc/example.test/shadow"}, nil },
		open: func(string) (*os.File, error) { return os.Open(path) },
	})
	entered, release := make(chan struct{}, 16), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	oldClient := hibpClient
	hibpClient = &http.Client{Transport: mailboxQueueTransport{entered, release}}
	defer func() { hibpClient = oldClient }()
	a, cancelA := context.WithCancel(context.Background())
	b, cancelB := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelA()
	defer cancelB()
	done := make(chan []alert.Finding, 2)
	for _, ctx := range []context.Context{a, b} {
		go func() { done <- CheckEmailPasswords(ctx, &config.Config{}, nil) }()
	}
	joined := 0
	defer func() {
		cancelA()
		cancelB()
		finish()
		for joined < 2 {
			<-done
			joined++
		}
	}()
	for range 10 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("two batches did not each start five actual audits")
		}
	}
	select {
	case <-entered:
		t.Fatal("more than ten actual audits started across two five-slot batches")
	default:
	}
	q := mailboxQueue(t, time.Now())
	if q.Depth != 6 || q.InFlight != 10 || q.Status != "ok" || !q.CapacityUnavailable || q.DroppedTotal != 0 {
		t.Fatalf("two busy batches: %+v", q)
	}
	q = mailboxQueue(t, time.Now().Add(61*time.Second))
	if q.Depth != 6 || q.InFlight != 10 || q.Reason != "processing_lag" || q.DroppedTotal != 0 {
		t.Fatalf("long batch hid shorter peer deadline: %+v", q)
	}
	cancelA()
	cancelB()
	until := time.Now().Add(time.Second)
	for {
		q = mailboxQueue(t, time.Now())
		if q.Depth == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("waiting demand retained after cancellation: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
	if q.InFlight != 10 || q.DroppedTotal != 0 {
		t.Fatalf("cancellation hid actual work or created loss: %+v", q)
	}
	finish()
	for joined < 2 {
		var findings []alert.Finding
		select {
		case findings = <-done:
			joined++
		case <-time.After(3 * time.Second):
			t.Fatal("released batch did not join")
		}
		counts := make(map[string]int)
		for _, f := range findings {
			counts[f.Check]++
		}
		if len(findings) != 6 || counts["email_weak_password"] != 5 || counts["email_password_audit_incomplete"] != 1 {
			t.Fatalf("batch results changed: %v", counts)
		}
	}
	if q := mailboxQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("joined batches retained ownership: %+v", q)
	}
	if !db.GetEmailPWLastRefresh().IsZero() || db.GetMetaString("email:pwaudit:alice:mailbox@example.test") != "" {
		t.Fatal("canceled batches wrote successful audit metadata")
	}
}
