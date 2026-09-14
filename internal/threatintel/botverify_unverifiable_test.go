package threatintel

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// countingResolver answers every PTR query with not-found and counts them.
type countingResolver struct {
	mu      sync.Mutex
	lookups int
}

func (r *countingResolver) LookupAddr(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	return nil, &net.DNSError{IsNotFound: true}
}

func (*countingResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return nil, errors.New("forward lookup without a PTR match")
}

func (r *countingResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups
}

// memoryUnverifiable keeps no-PTR records the way the store does, on the
// caller's clock, so fake time can drive expiry.
type memoryUnverifiable struct {
	until   map[string]time.Time
	failPut bool
}

func (m *memoryUnverifiable) PutBotVerifyUnverifiable(ip net.IP, bot string, expiresAt time.Time) error {
	if m.failPut {
		return errors.New("store unavailable")
	}
	if m.until == nil {
		m.until = make(map[string]time.Time)
	}
	m.until[bot+"|"+ip.String()] = expiresAt
	return nil
}

func (m *memoryUnverifiable) BotVerifyUnverifiable(ip net.IP, bot string) bool {
	until, ok := m.until[bot+"|"+ip.String()]
	return ok && !time.Now().After(until)
}

func TestBotNoPTRRecordSuppressesDNSAfterRestart(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	res := &countingResolver{}
	ip := net.ParseIP("192.0.2.30")

	first := NewAsyncBotVerifier(db.PutBotVerify, db)
	first.v["facebookbot"] = newVerifier(res, []string{"fbsv.net"})
	if !first.Enqueue(ip, "facebookbot") {
		t.Fatal("first claim was not queued")
	}
	first.process(<-first.ch)

	// A deploy restart loses in-memory retry history. Scan cycles after it
	// must not queue DNS again for a source with a live no-PTR record.
	restarted := NewAsyncBotVerifier(db.PutBotVerify, db)
	restarted.v["facebookbot"] = newVerifier(res, []string{"fbsv.net"})
	for cycle := range 6 {
		if restarted.Enqueue(ip, "facebookbot") {
			t.Fatalf("scan cycle %d queued DNS for a recorded no-PTR source", cycle)
		}
		if restarted.Pending(ip, "facebookbot") {
			t.Fatalf("scan cycle %d gave a recorded no-PTR source pending treatment", cycle)
		}
	}
	if n := res.count(); n != 1 {
		t.Errorf("PTR lookups = %d, want 1", n)
	}
	if status := botQueueStatus(t, restarted); status.DroppedTotal != 0 || status.Depth != 0 {
		t.Errorf("suppressed claims counted as queue work: %+v", status)
	}
	if _, valid := db.GetBotVerify(ip, "facebookbot"); valid {
		t.Error("no-PTR result was stored as a verification verdict")
	}
}

func TestBotNoPTRRetriesAfterRecordLapsesWithoutPendingRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		res := &countingResolver{}
		records := &memoryUnverifiable{}
		a := NewAsyncBotVerifier(nil, records)
		a.v["claudebot"] = newVerifier(res, []string{"anthropic.com"})
		ip := net.ParseIP("2001:db8::30")

		if !a.Enqueue(ip, "claudebot") {
			t.Fatal("first claim was not queued")
		}
		a.process(<-a.ch)
		for elapsed := 10 * time.Minute; elapsed <= botVerifyUnverifiableTTL; elapsed += 10 * time.Minute {
			time.Sleep(10 * time.Minute)
			if a.Enqueue(ip, "claudebot") {
				t.Fatalf("queued DNS %s after a no-PTR result", elapsed)
			}
		}

		time.Sleep(10 * time.Minute)
		if !a.Enqueue(ip, "claudebot") {
			t.Fatal("lapsed no-PTR record still blocked a retry")
		}
		if a.Pending(ip, "claudebot") {
			t.Error("retry after a lapsed record renewed pending treatment")
		}
		a.process(<-a.ch)
		if n := res.count(); n != 2 {
			t.Errorf("PTR lookups = %d, want 2", n)
		}
		if status := botQueueStatus(t, a); status.DroppedTotal != 0 {
			t.Errorf("recorded no-PTR results counted as lost work: %+v", status)
		}
	})
}

func TestBotNoPTRRecordWriteFailureIsLostWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		res := &countingResolver{}
		a := NewAsyncBotVerifier(nil, &memoryUnverifiable{failPut: true})
		a.v["gptbot"] = newVerifier(res, []string{"openai.com"})
		ip := net.ParseIP("198.51.100.30")

		if !a.Enqueue(ip, "gptbot") {
			t.Fatal("first claim was not queued")
		}
		a.process(<-a.ch)
		if status := botQueueStatus(t, a); status.DroppedTotal != 1 {
			t.Fatalf("unrecorded no-PTR result dropped %d, want 1", status.DroppedTotal)
		}
		// Nothing was persisted, so the normal retry cooldown governs.
		time.Sleep(botVerifyRetryDelay + time.Second)
		if !a.Enqueue(ip, "gptbot") {
			t.Fatal("unrecorded no-PTR result blocked the next retry")
		}
	})
}
