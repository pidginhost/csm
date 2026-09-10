package checks

import (
	"context"
	"fmt"
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
)

func TestMailboxQueueInputLimitsAreNotWorkerLosses(t *testing.T) {
	previous := emailMailboxAudits
	emailMailboxAudits = newScanBatchMonitor()
	defer func() { emailMailboxAudits = previous }()
	withTestStore(t)
	path := t.TempDir() + "/shadow"
	if err := os.WriteFile(path, []byte("unknown:{UNKNOWN}fixture\nmalformed:{SHA}invalid\nexpensive:$6$rounds=1000001$salt$"+strings.Repeat("a", 86)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{"/home/alice/etc/example.test/shadow"}, nil },
		open: func(string) (*os.File, error) { return os.Open(path) },
	})
	findings := CheckEmailPasswords(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 || findings[0].Check != "email_password_audit_incomplete" {
		t.Fatalf("input limits changed results: %+v", findings)
	}
	if q := mailboxQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
		t.Fatalf("expected input rejection became queue failure: %+v", q)
	}
}

func TestMailboxQueueCacheWriteFailuresRetainFindings(t *testing.T) {
	previous := emailMailboxAudits
	emailMailboxAudits = newScanBatchMonitor()
	defer func() { emailMailboxAudits = previous }()
	db := withTestStore(t)
	withWeakPasswords(t, nil)
	path := t.TempDir() + "/shadow"
	var shadow strings.Builder
	for i := range 3 {
		fmt.Fprintf(&shadow, "mailbox%d:{PLAIN}example\n", i)
	}
	if err := os.WriteFile(path, []byte(shadow.String()), 0600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{"/home/alice/etc/example.test/shadow"}, nil },
		open: func(string) (*os.File, error) { return os.Open(path) },
	})
	entered, release := make(chan struct{}, 3), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	oldClient := hibpClient
	hibpClient = &http.Client{Transport: mailboxQueueTransport{entered, release}}
	defer func() { hibpClient = oldClient }()
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckEmailPasswords(context.Background(), &config.Config{}, nil) }()
	joined := false
	defer func() {
		finish()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("audit did not finish during cleanup")
			}
		}
	}()
	for range 3 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("audit did not reach the held transport")
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	finish()
	select {
	case findings := <-done:
		joined = true
		seen := make(map[string]bool)
		for _, f := range findings {
			if f.Check != "email_weak_password" || seen[f.Mailbox] {
				t.Fatalf("cache failure altered findings: %+v", findings)
			}
			seen[f.Mailbox] = true
		}
		if len(findings) != 3 {
			t.Fatalf("cache failures hid confirmed findings: count=%d", len(findings))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("audit did not finish")
	}
	if q := mailboxQueue(t, time.Now()); q.DroppedTotal != 3 || q.RecentDrops != 3 || q.Reason != "dropped_work" || q.Depth != 0 || q.InFlight != 0 {
		t.Fatalf("failed persistence lost queue evidence: %+v", q)
	}
	if q := mailboxQueue(t, time.Now().Add(time.Minute)); q.Status != "ok" || q.DroppedTotal != 3 || q.RecentDrops != 0 {
		t.Fatalf("persistence recovery lost evidence: %+v", q)
	}
}

type mailboxQueueTransport struct {
	entered chan struct{}
	release <-chan struct{}
}

func (tr mailboxQueueTransport) RoundTrip(*http.Request) (*http.Response, error) {
	tr.entered <- struct{}{}
	<-tr.release
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func mailboxQueue(t *testing.T, now time.Time) queuehealth.Status {
	t.Helper()
	done := make(chan map[string]queuehealth.Status, 1)
	go func() { done <- EmailPasswordQueueStatuses(now) }()
	select {
	case rows := <-done:
		q, ok := rows["mailboxes"]
		if !ok {
			t.Fatal("outer mailbox audit queue is absent")
		}
		return q
	case <-time.After(time.Second):
		t.Fatal("mailbox snapshot waited for an audit")
		return queuehealth.Status{}
	}
}

func TestMailboxQueueRetainsActualAuditsAfterCancellation(t *testing.T) {
	previousMonitor := emailMailboxAudits
	emailMailboxAudits = newScanBatchMonitor()
	defer func() { emailMailboxAudits = previousMonitor }()
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
	entered, release := make(chan struct{}, 8), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	previous := hibpClient
	hibpClient = &http.Client{Transport: mailboxQueueTransport{entered, release}}
	defer func() { hibpClient = previous }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckEmailPasswords(ctx, &config.Config{}, nil) }()
	joined := false
	defer func() {
		cancel()
		finish()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("audit did not finish during cleanup")
			}
		}
	}()
	for range 5 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("five audits did not reach the held transport")
		}
	}
	q := mailboxQueue(t, time.Now().Add(61*time.Second))
	if q.Depth != 3 || q.InFlight != 5 || q.Status != "ok" || !q.CapacityUnavailable || q.DroppedTotal != 0 {
		t.Fatalf("busy audit pool lost work or reported ordinary saturation as a stall: %+v", q)
	}
	cancel()
	until := time.Now().Add(time.Second)
	for {
		q = mailboxQueue(t, time.Now().Add(6*time.Minute))
		if q.Depth == 0 {
			if q.InFlight != 5 || q.DroppedTotal != 0 || q.Reason != "processing_lag" {
				t.Fatalf("cancellation hid live audits: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("canceled waiting demand was not removed: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
	finish()
	select {
	case findings := <-done:
		joined = true
		counts := make(map[string]int)
		for _, f := range findings {
			counts[f.Check]++
		}
		if len(findings) != 6 || counts["email_weak_password"] != 5 || counts["email_password_audit_incomplete"] != 1 {
			t.Fatalf("cancellation changed retained findings: %+v", counts)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("released audit did not return")
	}
	if q := mailboxQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
		t.Fatalf("drained audit queue: %+v", q)
	}
	if !db.GetEmailPWLastRefresh().IsZero() || db.GetMetaString("email:pwaudit:alice:mailbox@example.test") != "" {
		t.Fatal("canceled audits recorded successful completion")
	}
}
