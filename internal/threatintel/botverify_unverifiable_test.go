package threatintel

import (
	"context"
	"errors"
	"fmt"
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
	mu      sync.Mutex
	until   map[string]time.Time
	failPut bool
}

func (m *memoryUnverifiable) PutBotVerifyUnverifiable(ip net.IP, bot string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut {
		return errors.New("store unavailable")
	}
	if m.until == nil {
		m.until = make(map[string]time.Time)
	}
	m.until[bot+"|"+ip.String()] = expiresAt
	return nil
}

func (m *memoryUnverifiable) BotVerifyUnverifiable(ip net.IP, bot string) (live, recorded bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.until[bot+"|"+ip.String()]
	return ok && !time.Now().After(until), ok
}

func TestBotNoPTRExpiredRecordCannotRenewGraceAfterRestart(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ip := net.ParseIP("192.0.2.31")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	// Neither a new process nor repeated reads of a lapsed record may turn
	// an already attempted source into a first-time pending exemption.
	for range 2 {
		a := NewAsyncBotVerifier(db.PutBotVerify, db)
		if !a.Enqueue(ip, "facebookbot") {
			t.Fatal("expired record prevented a DNS retry")
		}
		if a.Pending(ip, "facebookbot") {
			t.Error("expired no-PTR record granted fresh pending grace after restart")
		}
	}
}

func TestBotNoPTRRecordCannotRenewGraceAfterHistoryEviction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewAsyncBotVerifier(nil, &memoryUnverifiable{})
		a.v["facebookbot"] = newVerifier(&countingResolver{}, []string{"fbsv.net"})
		ip := net.ParseIP("2001:db8::31")
		if !a.Enqueue(ip, "facebookbot") {
			t.Fatal("initial claim not admitted")
		}
		a.process(<-a.ch)
		time.Sleep(botVerifyRetryDelay)
		for i := range cap(a.ch) {
			other := net.ParseIP(fmt.Sprintf("2001:db8:1::%x", i+1))
			if !a.Enqueue(other, "facebookbot") {
				t.Fatal("new source not admitted after cooldown")
			}
			a.process(<-a.ch)
		}
		if _, tracked := a.attempts["facebookbot|"+ip.String()]; tracked {
			t.Fatal("test did not evict the original attempt")
		}
		time.Sleep(botVerifyUnverifiableTTL)
		if !a.Enqueue(ip, "facebookbot") {
			t.Fatal("expired no-PTR record prevented a retry")
		}
		if a.Pending(ip, "facebookbot") {
			t.Fatal("evicted no-PTR source received fresh pending grace")
		}
	})
}

type pausedUnverifiableRead struct {
	memoryUnverifiable
	read, release, written chan struct{}
}

func (m *pausedUnverifiableRead) BotVerifyUnverifiable(ip net.IP, bot string) (live, recorded bool) {
	live, recorded = m.memoryUnverifiable.BotVerifyUnverifiable(ip, bot)
	if m.read != nil {
		close(m.read)
		<-m.release
	}
	return live, recorded
}

func (m *pausedUnverifiableRead) PutBotVerifyUnverifiable(ip net.IP, bot string, expiry time.Time) error {
	err := m.memoryUnverifiable.PutBotVerifyUnverifiable(ip, bot, expiry)
	close(m.written)
	return err
}

func TestBotNoPTRAdmissionReadCannotRaceCompletion(t *testing.T) {
	records := &pausedUnverifiableRead{written: make(chan struct{})}
	a := NewAsyncBotVerifier(nil, records)
	lookup, releaseDNS := make(chan struct{}), make(chan struct{})
	a.v["facebookbot"] = newVerifier(botQueueResolver{lookup: func(context.Context, string) ([]string, error) {
		close(lookup)
		<-releaseDNS
		return nil, &net.DNSError{IsNotFound: true}
	}}, []string{"fbsv.net"})
	ip := net.ParseIP("192.0.2.32")
	if !a.Enqueue(ip, "facebookbot") {
		t.Fatal("initial claim not admitted")
	}
	job, finished := <-a.ch, make(chan struct{})
	go func() { a.process(job); close(finished) }()
	<-lookup
	records.read, records.release = make(chan struct{}), make(chan struct{})
	admitted := make(chan bool, 1)
	go func() { admitted <- a.Enqueue(ip, "facebookbot") }()
	<-records.read
	close(releaseDNS)
	<-records.written
	// Once admission reads the old record, completion must retain the in-flight
	// key until that admission finishes. Otherwise a delayed reader can requeue
	// the source after its cooldown or eviction despite the new live record.
	select {
	case <-finished:
		t.Error("worker released its in-flight key while admission held a stale record read")
	case <-time.After(100 * time.Millisecond):
	}
	close(records.release)
	<-admitted
	<-finished
	if len(a.ch) != 0 || a.Pending(ip, "facebookbot") {
		t.Fatal("stale record read queued a duplicate after no-PTR completion")
	}
	if status := botQueueStatus(t, a); status.Depth != 0 || status.DroppedTotal != 0 {
		t.Fatalf("duplicate claim changed settled queue accounting: %+v", status)
	}
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

func BenchmarkBotNoPTRScan(b *testing.B) {
	db, err := store.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	// Reuse a working set representative of a busy scan, without timing
	// DNS or initial persistence. Both are off the repeated-claim hot path.
	ips := make([]net.IP, 678)
	for i := range ips {
		ips[i] = net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1))
		if err := db.PutBotVerifyUnverifiable(ips[i], "facebookbot", time.Now().Add(time.Hour)); err != nil {
			b.Fatal(err)
		}
	}
	for _, enqueue := range []bool{false, true} {
		b.Run(fmt.Sprintf("enqueue=%t", enqueue), func(b *testing.B) {
			a := NewAsyncBotVerifier(db.PutBotVerify, db)
			i := 0
			b.ReportAllocs()
			for b.Loop() {
				ip := ips[i%len(ips)]
				if _, valid := db.GetBotVerify(ip, "facebookbot"); valid {
					b.Fatal("no-PTR source has a verdict")
				}
				if enqueue && a.Enqueue(ip, "facebookbot") {
					b.Fatal("recorded source was queued again")
				}
				i++
			}
		})
	}
}
