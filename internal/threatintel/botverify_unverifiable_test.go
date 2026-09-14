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

// memoryUnverifiable keeps no-PTR records the way the store does, so fake
// time can drive suppression, history and sweeps.
type memoryUnverifiable struct {
	mu        sync.Mutex
	observed  map[string]time.Time
	failPut   bool
	failSweep bool
	sweeps    int
}

func (m *memoryUnverifiable) PutBotVerifyUnverifiable(ip net.IP, bot string, observedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut {
		return errors.New("store unavailable")
	}
	if m.observed == nil {
		m.observed = make(map[string]time.Time)
	}
	m.observed[bot+"|"+ip.String()] = observedAt
	return nil
}

func (m *memoryUnverifiable) BotVerifyUnverifiable(ip net.IP, bot string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	observed, ok := m.observed[bot+"|"+ip.String()]
	return observed, ok
}

func (m *memoryUnverifiable) SweepBotVerifyUnverifiable(cutoff time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweeps++
	if m.failSweep {
		return 0, errors.New("sweep unavailable")
	}
	n := 0
	for key, observed := range m.observed {
		if observed.Before(cutoff) {
			delete(m.observed, key)
			n++
		}
	}
	return n, nil
}

func (m *memoryUnverifiable) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.observed)
}

func TestBotNoPTRExpiredRecordCannotRenewGraceAfterRestart(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ip := net.ParseIP("192.0.2.31")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now().Add(-botVerifyUnverifiableTTL-time.Second)); err != nil {
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

func (m *pausedUnverifiableRead) BotVerifyUnverifiable(ip net.IP, bot string) (time.Time, bool) {
	observed, ok := m.memoryUnverifiable.BotVerifyUnverifiable(ip, bot)
	if m.read != nil {
		close(m.read)
		<-m.release
	}
	return observed, ok
}

func (m *pausedUnverifiableRead) PutBotVerifyUnverifiable(ip net.IP, bot string, observedAt time.Time) error {
	err := m.memoryUnverifiable.PutBotVerifyUnverifiable(ip, bot, observedAt)
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
		records := &memoryUnverifiable{failPut: true}
		a := NewAsyncBotVerifier(nil, records)
		a.v["gptbot"] = newVerifier(res, []string{"openai.com"})
		ip := net.ParseIP("198.51.100.30")

		if !a.Enqueue(ip, "gptbot") {
			t.Fatal("first claim was not queued")
		}
		a.process(<-a.ch)
		if status := botQueueStatus(t, a); status.DroppedTotal != 1 {
			t.Fatalf("unrecorded no-PTR result dropped %d, want 1", status.DroppedTotal)
		}
		if records.sweeps != 0 {
			t.Fatal("failed record write triggered a sweep")
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
		if err := db.PutBotVerifyUnverifiable(ips[i], "facebookbot", time.Now()); err != nil {
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

func TestBotNoPTRHistoryIsSweptOnceItCannotMatter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		records := &memoryUnverifiable{}
		a := NewAsyncBotVerifier(nil, records)
		a.v["facebookbot"] = newVerifier(&countingResolver{}, []string{"fbsv.net"})
		noPTR := func(ip string) {
			t.Helper()
			if !a.Enqueue(net.ParseIP(ip), "facebookbot") {
				t.Fatalf("claim from %s was not queued", ip)
			}
			a.process(<-a.ch)
		}

		noPTR("192.0.2.50")
		// Sources that never return must not accumulate: once a record is
		// past the retry history window it affects nothing and is removed.
		time.Sleep(botVerifyCacheTTL + time.Second)
		noPTR("192.0.2.51")
		if _, ok := records.BotVerifyUnverifiable(net.ParseIP("192.0.2.50"), "facebookbot"); ok {
			t.Fatal("record past the history window survived a later write")
		}
		if records.len() != 1 {
			t.Fatalf("records = %d, want only the fresh one", records.len())
		}

		// Sweeping scans the bucket, so busy hours sweep once, not per result.
		sweeps := records.sweeps
		for i := range 20 {
			noPTR(fmt.Sprintf("2001:db8:2::%x", i+1))
		}
		if records.sweeps != sweeps {
			t.Errorf("sweeps ran %d more times within one hour", records.sweeps-sweeps)
		}
		time.Sleep(botVerifyUnverifiableTTL)
		noPTR("192.0.2.52")
		if records.sweeps != sweeps+1 {
			t.Errorf("sweeps after an hour = %d, want %d", records.sweeps, sweeps+1)
		}
	})
}

func TestBotNoPTRFailedSweepWaitsBeforeRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		records := &memoryUnverifiable{failSweep: true}
		stale := net.ParseIP("192.0.2.60")
		if err := records.PutBotVerifyUnverifiable(stale, "facebookbot", time.Now().Add(-2*botVerifyCacheTTL)); err != nil {
			t.Fatal(err)
		}
		a := NewAsyncBotVerifier(nil, records)
		a.v["facebookbot"] = newVerifier(&countingResolver{}, []string{"fbsv.net"})
		noPTR := func(ip string) {
			t.Helper()
			addr := net.ParseIP(ip)
			if !a.Enqueue(addr, "facebookbot") {
				t.Fatalf("claim from %s was not queued", ip)
			}
			a.process(<-a.ch)
			if a.Enqueue(addr, "facebookbot") || a.Pending(addr, "facebookbot") {
				t.Fatal("sweep failure discarded successful retry suppression")
			}
			if status := botQueueStatus(t, a); status.DroppedTotal != 0 || status.Depth != 0 || status.InFlight != 0 {
				t.Fatalf("sweep failure unsettled recorded work: %+v", status)
			}
		}
		noPTR("192.0.2.61")
		if records.sweeps != 1 {
			t.Fatalf("initial sweep attempts = %d, want 1", records.sweeps)
		}
		for i := range 20 {
			noPTR(fmt.Sprintf("2001:db8:3::%x", i+1))
		}
		time.Sleep(botVerifyUnverifiableTTL - time.Nanosecond)
		noPTR("192.0.2.62")
		if records.sweeps != 1 {
			t.Fatalf("failed sweep retried within the hour: %d attempts", records.sweeps)
		}
		if _, ok := records.BotVerifyUnverifiable(stale, "facebookbot"); !ok {
			t.Fatal("failed sweep removed history")
		}
		records.failSweep = false
		time.Sleep(time.Nanosecond)
		noPTR("192.0.2.63")
		if records.sweeps != 2 {
			t.Fatalf("sweep attempts after recovery = %d, want 2", records.sweeps)
		}
		if _, ok := records.BotVerifyUnverifiable(stale, "facebookbot"); ok {
			t.Fatal("recovered sweep retained stale history")
		}
		if records.len() != 23 {
			t.Fatalf("recovered sweep retained %d records, want 23 fresh records", records.len())
		}
	})
}

func TestBotNoPTRHistoryBoundaryWithAndWithoutSweep(t *testing.T) {
	for _, age := range []time.Duration{botVerifyCacheTTL - time.Nanosecond, botVerifyCacheTTL, botVerifyCacheTTL + time.Nanosecond} {
		for _, sweep := range []bool{false, true} {
			t.Run(fmt.Sprintf("age=%s/sweep=%t", age, sweep), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					records := &memoryUnverifiable{}
					ip := net.ParseIP("192.0.2.64")
					if err := records.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now().Add(-age)); err != nil {
						t.Fatal(err)
					}
					if sweep {
						if _, err := records.SweepBotVerifyUnverifiable(time.Now().Add(-botVerifyCacheTTL)); err != nil {
							t.Fatal(err)
						}
					}
					a := NewAsyncBotVerifier(nil, records)
					if !a.Enqueue(ip, "facebookbot") {
						t.Fatal("lapsed record prevented DNS retry")
					}
					if want := age >= botVerifyCacheTTL; a.Pending(ip, "facebookbot") != want {
						t.Fatalf("pending = %t, want %t", a.Pending(ip, "facebookbot"), want)
					}
				})
			})
		}
	}
}

func TestBotNoPTRRecordVolumeIsBoundedByAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		records := &memoryUnverifiable{}
		res := &countingResolver{}
		a := NewAsyncBotVerifier(nil, records)
		a.v["facebookbot"] = newVerifier(res, []string{"fbsv.net"})
		// Even instantly completed lookups can add only one full history per
		// cooldown. This limits the volume scanned by hourly retention.
		for round := range 3 {
			for i := range 2 * cap(a.ch) {
				ip := net.ParseIP(fmt.Sprintf("2001:db8:%x::%x", round, i+1))
				admitted := a.Enqueue(ip, "facebookbot")
				if admitted != (i < cap(a.ch)) {
					t.Fatalf("round %d source %d admission = %t", round, i, admitted)
				}
				if admitted {
					a.process(<-a.ch)
				}
			}
			if want := (round + 1) * cap(a.ch); records.len() != want || res.count() != want {
				t.Fatalf("record/lookup counts = %d/%d, want %d", records.len(), res.count(), want)
			}
			if len(a.attempts) != cap(a.ch) {
				t.Fatalf("attempt history size = %d, want %d", len(a.attempts), cap(a.ch))
			}
			time.Sleep(botVerifyRetryDelay)
		}
		if records.sweeps != 1 {
			t.Fatalf("busy cooldowns triggered %d sweeps, want 1", records.sweeps)
		}
	})
}
