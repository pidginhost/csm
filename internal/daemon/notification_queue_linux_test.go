//go:build linux

package daemon

import (
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type notificationTestSource struct {
	pending int
	err     error
	closed  bool
	closes  int
}

func (s *notificationTestSource) Pending() (int, error) {
	if s.closed {
		panic("queried a closed descriptor")
	}
	return s.pending, s.err
}

func (s *notificationTestSource) Read(buf []byte) (int, error) {
	if s.closed {
		panic("read a closed descriptor")
	}
	if s.pending == 0 {
		return 0, unix.EAGAIN
	}
	s.pending--
	clear(buf[:metadataSize])
	return metadataSize, nil
}

func (s *notificationTestSource) Write([]byte) (int, error) {
	if s.closed {
		panic("wrote a closed descriptor")
	}
	return responseSize, nil
}

func (s *notificationTestSource) Close() error {
	s.closes++
	s.closed = true
	return nil
}

func notificationQueueForTest(source *notificationTestSource) *notificationQueue {
	return newNotificationQueue(source, queuehealth.New(0, time.Minute), queuehealth.New(1, time.Minute))
}

func TestNotificationQueueRetainsRunningBatchThroughClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := &notificationTestSource{pending: 3}
		q := notificationQueueForTest(source)
		release, done := make(chan struct{}), make(chan struct{})
		releaseReader := sync.OnceFunc(func() { close(release) })
		defer releaseReader()
		go func() {
			defer close(done)
			n, err := q.read(make([]byte, metadataSize), func(data []byte) {
				if len(data) != metadataSize {
					t.Errorf("reader batch contains %d bytes", len(data))
				}
				<-release
			})
			if err != nil || n != metadataSize {
				t.Errorf("read batch: bytes=%d err=%v", n, err)
			}
		}()
		synctest.Wait()
		kernel, reader := q.snapshot(time.Now)
		if kernel.Depth != 2 || !kernel.CapacityUnavailable || reader.InFlight != 1 || reader.Depth != 0 || reader.DepthUnit != "batches" {
			t.Fatalf("kernel and reader work are not represented: kernel=%+v reader=%+v", kernel, reader)
		}
		time.Sleep(61 * time.Second)
		kernel, reader = q.snapshot(time.Now)
		if kernel.Reason != "consumer_stalled" || reader.Reason != "processing_lag" || reader.ProcessingSeconds != 61 {
			t.Fatalf("busy reader concealed stalled work: kernel=%+v reader=%+v", kernel, reader)
		}
		if err := q.close(); err != nil {
			t.Fatal(err)
		}
		kernel, reader = q.snapshot(time.Now)
		if kernel.Depth != 0 || kernel.DroppedTotal != 2 || !kernel.DroppedLowerBound || reader.InFlight != 1 || reader.DroppedTotal != 0 {
			t.Fatalf("close confused unread kernel records with owned reader work: kernel=%+v reader=%+v", kernel, reader)
		}
		releaseReader()
		<-done
		_, reader = q.snapshot(time.Now)
		if reader.InFlight != 0 || reader.Depth != 0 || reader.DroppedTotal != 0 || reader.Status != "ok" {
			t.Fatalf("completed reader batch did not recover: %+v", reader)
		}
	})
}

func TestNotificationQueueRejectsFailedMeasurements(t *testing.T) {
	for _, pending := range []int{4, -1} {
		now := time.Unix(1000, 0)
		clock := func() time.Time { return now }
		source := &notificationTestSource{pending: pending}
		if pending == 4 {
			source.err = unix.EIO
		}
		q := notificationQueueForTest(source)
		kernel, _ := q.snapshot(clock)
		if kernel.Status != "ok" || kernel.Reason != "" || !kernel.DepthUnavailable || kernel.LagBasis != "unavailable" {
			t.Fatalf("one failed measurement raised an alarm: %+v", kernel)
		}
		now = now.Add(queuehealth.MeasurementWindow)
		kernel, _ = q.snapshot(clock)
		if kernel.Reason != "measurement_unavailable" || !kernel.DepthUnavailable || kernel.LagBasis != "unavailable" || kernel.Status != "degraded" {
			t.Fatalf("sustained invalid measurement presented as a healthy empty queue: %+v", kernel)
		}
		source.err, source.pending = nil, 4
		now = now.Add(time.Second)
		kernel, _ = q.snapshot(clock)
		if kernel.Depth != 4 || kernel.DepthUnavailable || kernel.Status != "ok" || !kernel.CapacityUnavailable {
			t.Fatalf("valid sample did not recover: %+v", kernel)
		}
		source.err = unix.EIO
		if err := q.close(); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		kernel, _ = q.snapshot(clock)
		if kernel.Reason != "measurement_unavailable" || kernel.Status != "degraded" || !kernel.DroppedLowerBound {
			t.Fatalf("failed final sample was silently cleared: %+v", kernel)
		}
	}
}

func TestNotificationQueueReportsLossesOverMissingMeasurement(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	source := &notificationTestSource{pending: 4, err: unix.EIO}
	q := notificationQueueForTest(source)
	q.losses.Lose(now, 3)
	now = now.Add(queuehealth.MeasurementWindow)
	kernel, _ := q.snapshot(clock)
	if kernel.Status != "degraded" || kernel.Reason != "dropped_work" || kernel.DroppedTotal != 3 {
		t.Fatalf("confirmed kernel losses hidden behind an unreadable depth: %+v", kernel)
	}
}

func TestNotificationQueueNeverUsesClosedDescriptor(t *testing.T) {
	source := &notificationTestSource{pending: 4}
	q := notificationQueueForTest(source)
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 1000 {
				q.snapshot(time.Now)
			}
		})
	}
	if err := q.close(); err != nil {
		t.Fatal(err)
	}
	if err := q.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := q.read(make([]byte, metadataSize), func([]byte) { t.Error("closed reader delivered a batch") }); !errors.Is(err, unix.EBADF) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := q.write(make([]byte, responseSize)); !errors.Is(err, unix.EBADF) {
		t.Fatalf("write after close: %v", err)
	}
	readers.Wait()
	kernel, reader := q.snapshot(time.Now)
	if source.closes != 1 || kernel.Depth != 0 || kernel.DroppedTotal != 4 || kernel.RecentDrops != 4 || reader.DroppedTotal != 0 {
		t.Fatalf("descriptor shutdown lost or duplicated work: closes=%d kernel=%+v reader=%+v", source.closes, kernel, reader)
	}
}

func TestNotificationQueueCountsPanickingReaderBatch(t *testing.T) {
	q := notificationQueueForTest(&notificationTestSource{pending: 1})
	var caught any
	func() {
		defer func() { caught = recover() }()
		_, _ = q.read(make([]byte, metadataSize), func([]byte) { panic("reader failed") })
	}()
	kernel, reader := q.snapshot(time.Now)
	if caught != "reader failed" || kernel.Depth != 0 || kernel.DroppedTotal != 0 || reader.InFlight != 0 || reader.Depth != 0 || reader.DroppedTotal != 1 {
		t.Fatalf("reader panic escaped batch accounting: panic=%v kernel=%+v reader=%+v", caught, kernel, reader)
	}
}

func TestNotificationReplacementRetainsWorkWithoutOldDepth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := &SpoolWatcher{fd: -1}
		previous.initQueueHealth()
		previous.kernelQueue.source = &notificationTestSource{pending: 2}
		release, done := make(chan struct{}), make(chan struct{})
		releaseReader := sync.OnceFunc(func() { close(release) })
		defer releaseReader()
		go func() {
			defer close(done)
			_, err := previous.kernelQueue.read(make([]byte, metadataSize), func([]byte) { <-release })
			if err != nil {
				t.Errorf("read previous queue: %v", err)
			}
		}()
		synctest.Wait()
		previous.queueStatuses(time.Now())
		time.Sleep(61 * time.Second)
		if err := previous.kernelQueue.close(); err != nil {
			t.Fatal(err)
		}
		replacement := &SpoolWatcher{fd: -1}
		replacement.inheritQueueHealth(previous)
		replacement.kernelQueue.source = &notificationTestSource{pending: 3}
		states := replacement.queueStatuses(time.Now())
		kernel, reader := states["spool.kernel"], states["spool.reader"]
		if kernel.Depth != 3 || kernel.LagSeconds != 0 || kernel.Status != "ok" || kernel.DroppedTotal != 1 || reader.InFlight != 1 || reader.ProcessingSeconds != 61 {
			t.Fatalf("replacement lost retained work or inherited stale occupancy: kernel=%+v reader=%+v", kernel, reader)
		}
		time.Sleep(61 * time.Second)
		releaseReader()
		<-done
		previous.queueStatuses(time.Now())
		states = replacement.queueStatuses(time.Now())
		kernel, reader = states["spool.kernel"], states["spool.reader"]
		if kernel.Depth != 3 || kernel.LagSeconds != 61 || kernel.Reason != "consumer_stalled" || kernel.DroppedTotal != 1 || reader.InFlight != 0 || reader.DroppedTotal != 0 || reader.Status != "ok" {
			t.Fatalf("previous reader completion cleared replacement pressure: kernel=%+v reader=%+v", kernel, reader)
		}
	})
}

type delayedNotificationSource struct{ notificationTestSource }

func (s *delayedNotificationSource) Pending() (int, error) {
	time.Sleep(61 * time.Second)
	return s.notificationTestSource.Pending()
}

func TestNotificationSnapshotTimesCompletedMeasurement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := &delayedNotificationSource{notificationTestSource{pending: 1}}
		q := newNotificationQueue(source, queuehealth.New(0, time.Minute), queuehealth.New(1, time.Minute))
		if got, _ := q.snapshot(time.Now); got.Status != "ok" || got.Depth != 1 || got.LagSeconds != 0 {
			t.Fatalf("sampling delay counted as consumer stall: %+v", got)
		}
		kernel, _ := q.snapshot(time.Now)
		if kernel.Reason != "consumer_stalled" || kernel.LagSeconds != 61 {
			t.Fatalf("fresh measurement did not start the stall clock: %+v", kernel)
		}
	})
}
