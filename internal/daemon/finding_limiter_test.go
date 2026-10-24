package daemon

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestFindingLimiterCountsOnlyDeliveredFindings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var limiter findingLimiter
		ch := make(chan alert.Finding, 1)
		ch <- alert.Finding{Check: "occupied"}
		emit := func() {
			limiter.emit(ch, "isolation", alert.Critical, time.Hour, "unavailable")
		}
		emit()
		if len(limiter.last) != 0 {
			t.Fatal("a rejected finding consumed the allowance")
		}
		<-ch
		emit()
		select {
		case f := <-ch:
			if f.Check != "isolation" || f.Severity != alert.Critical || !f.Timestamp.Equal(time.Now()) {
				t.Fatalf("delivered finding = %+v", f)
			}
		default:
			t.Fatal("rejected finding was not retried")
		}
		time.Sleep(time.Hour - time.Nanosecond)
		emit()
		if len(ch) != 0 {
			t.Fatal("finding repeated before the interval elapsed")
		}
		time.Sleep(time.Nanosecond)
		emit()
		if len(ch) != 1 {
			t.Fatal("finding did not repeat at the interval boundary")
		}
	})
}

func TestFindingLimiterSerializesConcurrentProducers(t *testing.T) {
	var limiter findingLimiter
	ch := make(chan alert.Finding, 32)
	var wg sync.WaitGroup
	for range cap(ch) {
		wg.Go(func() {
			limiter.emit(ch, "isolation", alert.Critical, time.Hour, "unavailable")
		})
	}
	wg.Wait()
	if len(ch) != 1 {
		t.Fatalf("concurrent producers delivered %d findings, want 1", len(ch))
	}
	limiter.emit(ch, "protocol", alert.Critical, time.Hour, "invalid reply")
	if len(ch) != 2 {
		t.Fatal("one condition consumed another condition's allowance")
	}
}
