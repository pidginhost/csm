package daemon

import (
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func msgIndexQueueStatus(t *testing.T, p *msgIndexPersister) queuehealth.Status {
	t.Helper()
	provider, ok := any(p).(queueSource)
	if !ok {
		t.Fatal("message index persistence has no queue health")
	}
	d := &Daemon{}
	d.registerQueueSource("phprelay.index", provider)
	got, exists := d.QueueStatuses()["phprelay.index.persistence"]
	if !exists {
		t.Fatal("registered persistence queue has no health row")
	}
	return got
}

func TestMsgIndexQueueRetainsWaitingAndRunningWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := openTestDB(t)
		p := newMsgIndexPersister(db, 4, time.Hour)
		p.Enqueue("pending", indexEntry{At: time.Now()})
		time.Sleep(61 * time.Second)
		got := msgIndexQueueStatus(t, p)
		if got.Depth != 1 || got.LagSeconds != 61 || got.Reason != "backlog_lag" {
			t.Fatalf("queued persistence delay disappeared: %+v", got)
		}
		p.Start()
		defer p.Stop()
		synctest.Wait()
		time.Sleep(61 * time.Second)
		got = msgIndexQueueStatus(t, p)
		if got.Depth != 0 || got.InFlight != 1 || got.ProcessingSeconds != 61 || got.Reason != "processing_lag" {
			t.Fatalf("pending batch disappeared after leaving the channel: %+v", got)
		}
		p.Flush()
		got = msgIndexQueueStatus(t, p)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
			t.Fatalf("committed persistence batch stayed pending: %+v", got)
		}
		if _, exists, err := p.Lookup("pending"); err != nil || !exists {
			t.Fatalf("completed persistence claim has no stored row: exists=%v err=%v", exists, err)
		}
	})
}

func TestMsgIndexQueueStopCommitsAcceptedBacklog(t *testing.T) {
	db := openTestDB(t)
	if err := db.PHPRelayPut(msgIndexBucket, "lock-row", []byte("lock")); err != nil {
		t.Fatal(err)
	}
	locked, release, unlocked := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseDB := sync.OnceFunc(func() { close(release) })
	defer releaseDB()
	go func() {
		defer close(unlocked)
		_, err := db.PHPRelaySweep(msgIndexBucket, func(_, _ []byte) bool {
			close(locked)
			<-release
			return false
		})
		if err != nil {
			t.Errorf("hold write transaction: %v", err)
		}
	}()
	<-locked
	const capacity = 64
	p := newMsgIndexPersister(db, capacity, time.Hour)
	p.batchSize = 1
	p.Enqueue("running", indexEntry{At: time.Now()})
	p.Start()
	stopPersister := sync.OnceFunc(p.Stop)
	defer func() { releaseDB(); stopPersister(); <-unlocked }()
	deadline := time.Now().Add(2 * time.Second)
	for len(p.queue) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(p.queue) != 0 {
		t.Fatal("persister did not reach the blocked commit")
	}
	for i := range capacity {
		p.Enqueue(fmt.Sprintf("waiting-%d", i), indexEntry{At: time.Now()})
	}
	if p.DroppedCount() != 0 || len(p.queue) != capacity {
		t.Fatalf("backlog was not accepted: queued=%d dropped=%d", len(p.queue), p.DroppedCount())
	}
	stopped := make(chan struct{})
	go func() { defer close(stopped); stopPersister() }()
	<-p.stopCh
	select {
	case <-stopped:
		t.Fatal("Stop returned before the running write finished")
	default:
	}
	releaseDB()
	<-unlocked
	<-stopped
	rows, err := db.PHPRelayList(msgIndexBucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != capacity+2 || len(p.queue) != 0 || p.DroppedCount() != 0 {
		t.Fatalf("shutdown abandoned accepted persistence: rows=%d queued=%d dropped=%d", len(rows), len(p.queue), p.DroppedCount())
	}
}

func TestMsgIndexQueueStopIsIdempotent(t *testing.T) {
	p := newMsgIndexPersister(openTestDB(t), 1, time.Hour)
	p.Start()
	p.Stop()
	var caught any
	func() { defer func() { caught = recover() }(); p.Stop() }()
	if caught != nil {
		t.Fatalf("repeated Stop panicked: %v", caught)
	}
}

func TestMsgIndexQueueFlushWaitsForShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := openTestDB(t)
		p := newMsgIndexPersister(db, 1, time.Hour)
		p.batchSize = 1
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		releaseReport := sync.OnceFunc(func() { close(release) })
		defer releaseReport()
		p.SetErrorCallback(func(alert.Finding) { close(entered); <-release })
		p.Enqueue("running", indexEntry{At: time.Now()})
		p.Start()
		<-entered
		stopped := make(chan struct{})
		go func() { defer close(stopped); p.Stop() }()
		<-p.stopCh
		flushed := make(chan struct{})
		go func() { defer close(flushed); p.Flush() }()
		synctest.Wait()
		select {
		case <-flushed:
			t.Error("Flush returned while shutdown still owned an unfinished batch")
		default:
		}
		releaseReport()
		<-stopped
		<-flushed
	})
}

func TestMsgIndexQueueFailedBatchSettlesBeforeReporting(t *testing.T) {
	db := openTestDB(t)
	p := newMsgIndexPersister(db, 3, time.Hour)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	releaseReport := sync.OnceFunc(func() { close(release) })
	defer releaseReport()
	p.SetErrorCallback(func(alert.Finding) { close(entered); <-release })
	for i := range 3 {
		p.Enqueue(fmt.Sprint(i), indexEntry{At: time.Now()})
	}
	p.Start()
	defer func() { releaseReport(); p.Stop() }()
	flushed := make(chan struct{})
	go func() { defer close(flushed); p.Flush() }()
	<-entered
	got := msgIndexQueueStatus(t, p)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.Status != "degraded" || p.ErrorCount() != 1 {
		t.Fatalf("failed writes remain hidden behind the reporter: status=%+v errors=%d", got, p.ErrorCount())
	}
	releaseReport()
	<-flushed
	if got = msgIndexQueueStatus(t, p); got.DroppedTotal != 3 || got.InFlight != 0 {
		t.Fatalf("report completion changed failed-write accounting: %+v", got)
	}
}

func TestMsgIndexQueueEncodingFailurePreservesOtherWrites(t *testing.T) {
	p := newMsgIndexPersister(openTestDB(t), 3, time.Hour)
	bad := indexEntry{At: time.Now().In(time.FixedZone("invalid", 32768*60))}
	p.Enqueue("bad", bad)
	p.Enqueue("good-a", indexEntry{At: time.Now()})
	p.Enqueue("good-b", indexEntry{At: time.Now()})
	p.Start()
	defer p.Stop()
	p.Flush()
	rows, err := p.db.PHPRelayList(msgIndexBucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows["good-a"] == nil || rows["good-b"] == nil || rows["bad"] != nil {
		t.Fatalf("encoding failure damaged unrelated writes: keys=%v", rows)
	}
	got := msgIndexQueueStatus(t, p)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || p.ErrorCount() != 1 {
		t.Fatalf("encoding loss miscounted: status=%+v errors=%d", got, p.ErrorCount())
	}
}

func TestMsgIndexQueueConcurrentAdmissionFlushAndStop(t *testing.T) {
	p := newMsgIndexPersister(openTestDB(t), 16, time.Hour)
	p.Start()
	start := make(chan struct{})
	var callers sync.WaitGroup
	const producers, writes = 8, 64
	for producer := range producers {
		callers.Go(func() {
			<-start
			for i := range writes {
				p.Enqueue(fmt.Sprintf("%d-%d", producer, i), indexEntry{At: time.Now()})
			}
		})
	}
	for range 4 {
		callers.Go(func() {
			defer func() {
				if caught := recover(); caught != nil {
					t.Errorf("concurrent public method panicked: %v", caught)
				}
			}()
			<-start
			p.Flush()
			p.Stop()
		})
	}
	close(start)
	callers.Wait()
	rows, err := p.db.PHPRelayList(msgIndexBucket)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(rows))+p.DroppedCount() != producers*writes || len(p.queue) != 0 {
		t.Fatalf("concurrent shutdown lost accepted writes: stored=%d refused=%d queued=%d", len(rows), p.DroppedCount(), len(p.queue))
	}
	got := msgIndexQueueStatus(t, p)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != p.DroppedCount() {
		t.Fatalf("concurrent shutdown left unsettled accounting: %+v", got)
	}
}

func TestMsgIndexQueueFlushBoundsTransactionsAndAdmission(t *testing.T) {
	p := newMsgIndexPersister(openTestDB(t), 6, time.Hour)
	p.batchSize = 2
	p.Enqueue("", indexEntry{At: time.Now()})
	for i := 1; i < 6; i++ {
		p.Enqueue(fmt.Sprintf("good-%d", i), indexEntry{At: time.Now()})
	}
	p.SetErrorCallback(func(alert.Finding) {
		p.Enqueue("later-a", indexEntry{At: time.Now()})
		p.Enqueue("later-b", indexEntry{At: time.Now()})
	})
	p.flushPending(nil)
	rows, err := p.db.PHPRelayList(msgIndexBucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rows["good-1"] != nil || rows["later-a"] != nil || rows["later-b"] != nil {
		t.Fatalf("one rejected transaction affected other batches, or flush consumed later arrivals: stored=%d", len(rows))
	}
	for i := 2; i < 6; i++ {
		if rows[fmt.Sprintf("good-%d", i)] == nil {
			t.Errorf("healthy batch did not persist good-%d", i)
		}
	}
	got := msgIndexQueueStatus(t, p)
	if got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 2 || p.ErrorCount() != 1 || p.DroppedCount() != 0 {
		t.Fatalf("flush did not preserve its bounded admission snapshot: status=%+v errors=%d refused=%d", got, p.ErrorCount(), p.DroppedCount())
	}
	p.flushPending(nil)
	rows, err = p.db.PHPRelayList(msgIndexBucket)
	if err != nil || len(rows) != 6 || rows["later-a"] == nil || rows["later-b"] == nil {
		t.Fatalf("next flush lost later arrivals: stored=%d err=%v", len(rows), err)
	}
	got = msgIndexQueueStatus(t, p)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 2 {
		t.Fatalf("next flush changed earlier loss: %+v", got)
	}
}

func TestMsgIndexQueueReportPanicSettlesOwnedBatch(t *testing.T) {
	for _, failure := range []string{"encode", "commit"} {
		t.Run(failure, func(t *testing.T) {
			p := newMsgIndexPersister(openTestDB(t), 4, time.Hour)
			p.batchSize = 2
			entry := indexEntry{At: time.Now()}
			key := "bad"
			if failure == "encode" {
				entry.At = entry.At.In(time.FixedZone("invalid", 32768*60))
			} else {
				key = ""
			}
			p.Enqueue(key, entry)
			for i := range 3 {
				p.Enqueue(fmt.Sprint(i), indexEntry{At: time.Now()})
			}
			p.SetErrorCallback(func(alert.Finding) { panic("report failure") })
			var caught any
			func() { defer func() { caught = recover() }(); p.flushPending(nil) }()
			if caught != "report failure" {
				t.Fatalf("callback panic was concealed: %v", caught)
			}
			got := msgIndexQueueStatus(t, p)
			if got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 2 || p.ErrorCount() != 1 {
				t.Fatalf("panicking batch was left running or rejected twice: status=%+v errors=%d", got, p.ErrorCount())
			}
		})
	}
}
