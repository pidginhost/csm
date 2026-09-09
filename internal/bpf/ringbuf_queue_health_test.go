//go:build linux && bpf

package bpf

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/pidginhost/csm/internal/queuehealth"
)

type queuedRingReader struct {
	records   []ringbuf.Record
	position  int
	exhausted chan struct{}
	closed    chan struct{}
	idleOnce  sync.Once
	closeOnce sync.Once
}

func (r *queuedRingReader) Read() (ringbuf.Record, error) {
	if r.position < len(r.records) {
		record := r.records[r.position]
		r.position++
		return record, nil
	}
	r.idleOnce.Do(func() { close(r.exhausted) })
	<-r.closed
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *queuedRingReader) Close() error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

func TestReaderQueueHealthCountsConsumerAndDecoderLoss(t *testing.T) {
	rb := &queuedRingReader{exhausted: make(chan struct{}), closed: make(chan struct{})}
	for _, data := range [][]byte{{1}, {2}, {3}, {4}, nil, nil, nil} {
		rb.records = append(rb.records, ringbuf.Record{RawSample: data})
	}
	r := &Reader[int]{
		rb: rb, out: queuehealth.NewChannel[int](1, time.Minute), errs: make(chan error, 1),
		decode: func(data []byte) (int, error) {
			if len(data) == 0 {
				return 0, errors.New("invalid record")
			}
			return int(data[0]), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-rb.exhausted:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not consume the scripted records")
	}
	if r.EventCount() != 1 || r.DroppedCount() != 3 {
		t.Fatalf("script did not fill the consumer queue: delivered=%d dropped=%d", r.EventCount(), r.DroppedCount())
	}
	provider, ok := any(r).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("BPF consumer and decoder loss have no health evidence")
	}
	got := provider.QueueStatuses(time.Now())["output"]
	if got.Depth != 1 || got.InFlight != 0 || got.Capacity != 1 || got.DroppedTotal != 6 || got.RecentDrops != 6 || got.Reason != "dropped_work" {
		t.Fatalf("BPF loss accounting concealed rejected records: %+v", got)
	}
}

func TestReaderStopCountsUnconsumedOutput(t *testing.T) {
	rb := &queuedRingReader{
		exhausted: make(chan struct{}), closed: make(chan struct{}),
		records: []ringbuf.Record{{RawSample: []byte{1}}, {RawSample: []byte{2}}, {RawSample: []byte{3}}},
	}
	r := &Reader[int]{rb: rb, out: queuehealth.NewChannel[int](3, time.Minute), decode: func(data []byte) (int, error) { return int(data[0]), nil }}
	stop := r.Start(context.Background())
	t.Cleanup(stop)
	select {
	case <-rb.exhausted:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not publish the scripted records")
	}
	stop()
	stop()
	got := r.QueueStatuses(time.Now())["output"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Reason != "dropped_work" {
		t.Fatalf("stopped reader lost buffered output or counted it twice: %+v", got)
	}
	if _, ok := <-r.Events(); ok {
		t.Fatal("stop retained undeliverable output")
	}
}

func TestReaderQueueHealthRetainsBlockedConsumer(t *testing.T) {
	rb := &queuedRingReader{
		exhausted: make(chan struct{}), closed: make(chan struct{}),
		records: []ringbuf.Record{{RawSample: []byte{42}}},
	}
	r := &Reader[int]{rb: rb, out: queuehealth.NewChannel[int](1, time.Minute), decode: func(data []byte) (int, error) { return int(data[0]), nil }}
	stop := r.Start(context.Background())
	t.Cleanup(stop)
	var work queuehealth.Work[int]
	select {
	case work = <-r.Events():
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not publish its event")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		work.Process(func(value int) {
			if value != 42 {
				t.Errorf("processor received %d, want 42", value)
			}
			close(entered)
			<-release
		})
	}()
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		<-done
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("event did not reach the consumer")
	}
	got := r.QueueStatuses(time.Now().Add(61 * time.Second))["output"]
	if got.Depth != 0 || got.InFlight != 1 || got.ProcessingSeconds < 61 || got.Reason != "processing_lag" {
		t.Fatalf("empty delivery queue hid a blocked consumer: %+v", got)
	}
	close(release)
	released = true
	<-done
	stop()
	if got := r.QueueStatuses(time.Now())["output"]; got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
		t.Fatalf("completed delivery did not recover: %+v", got)
	}
}
