package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func retryTestSpooler(t *testing.T, names []string, respond func(string) (int, string)) *Spooler {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var targets []Target
	for _, name := range names {
		targets = append(targets, Target{Name: name, URL: "https://collector.example/" + name,
			Transport: TransportEd25519, NodeID: "node", KeyID: "key", Ed25519Key: key})
	}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status, retry := respond(strings.TrimPrefix(r.URL.Path, "/"))
		return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": {retry}},
			Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	return NewSpooler(newSpool(t, 100), NewSender(client, time.Now), targets, time.Minute)
}

func TestSpoolerRetriesTargetsIndependently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := make(map[string]int)
		sp := retryTestSpooler(t, []string{"long", "short", "down", "healthy"}, func(name string) (int, string) {
			calls[name]++
			switch {
			case name == "long" && calls[name] == 1:
				return http.StatusTooManyRequests, "90"
			case name == "short" && calls[name] == 1:
				return http.StatusTooManyRequests, "2"
			case name == "down":
				return http.StatusServiceUnavailable, ""
			default:
				return http.StatusAccepted, ""
			}
		})
		if err := sp.Enqueue(Report{IP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
		for i, step := range []struct {
			elapsed time.Duration
			next    time.Duration
			counts  [4]int
		}{
			{0, 2 * time.Second, [4]int{1, 1, 1, 1}},
			{2 * time.Second, 58 * time.Second, [4]int{1, 2, 1, 1}},
			{58 * time.Second, 30 * time.Second, [4]int{1, 2, 2, 1}},
			{30 * time.Second, 30 * time.Second, [4]int{2, 2, 2, 1}},
		} {
			time.Sleep(step.elapsed)
			if got := sp.DrainOnce(context.Background()); got != step.next {
				t.Errorf("pass %d: next = %v, want %v", i, got, step.next)
			}
			got := [4]int{calls["long"], calls["short"], calls["down"], calls["healthy"]}
			if got != step.counts {
				t.Fatalf("pass %d: calls = %v, want %v", i, got, step.counts)
			}
		}
		if got := sp.spool.QueueStatuses(time.Now())["spool"]; got.Depth != 1 || got.DroppedTotal != 0 || got.Reason != "delivery_failed" {
			t.Fatalf("only the unavailable target should remain: %+v", got)
		}
	})
}

func TestSpoolerPersistentThrottleBacksOffAndLogs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		sp := retryTestSpooler(t, []string{"central"}, func(string) (int, string) {
			calls++
			return http.StatusTooManyRequests, "1"
		})
		var logs []string
		sp.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
		if err := sp.Enqueue(Report{IP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
		for i, seconds := range []int{1, 2, 4, 8, 16, 32, 60, 60} {
			want := time.Duration(seconds) * time.Second
			if got := sp.DrainOnce(context.Background()); got != want {
				t.Errorf("pass %d: retry = %v, want %v", i, got, want)
			}
			time.Sleep(want)
		}
		if calls != 8 || len(logs) != 3 {
			t.Fatalf("calls=%d logs=%v, want eight attempts and three bounded warnings", calls, logs)
		}
		for _, line := range logs {
			if !strings.Contains(line, "target central") || !strings.Contains(line, "429") {
				t.Errorf("throttle warning lacks target/status: %q", line)
			}
		}
		if got := sp.spool.QueueStatuses(time.Now())["spool"]; got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Reason != "delivery_failed" {
			t.Fatalf("throttled report was lost or stall hidden: %+v", got)
		}
	})
}

func TestSpoolerRetryDeadlineIncludesOtherDeliveryTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp := retryTestSpooler(t, []string{"throttled", "slow"}, func(name string) (int, string) {
			if name == "throttled" {
				return http.StatusTooManyRequests, "2"
			}
			time.Sleep(5 * time.Second)
			return http.StatusAccepted, ""
		})
		if err := sp.Enqueue(Report{IP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
		if got := sp.DrainOnce(context.Background()); got != 0 {
			t.Fatalf("retry deadline already elapsed, got additional wait %v", got)
		}
	})
}

func TestSpoolerProgressResetsThrottleBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		sp := retryTestSpooler(t, []string{"central"}, func(string) (int, string) {
			calls++
			if calls == 3 || calls >= 5 {
				return http.StatusAccepted, ""
			}
			return http.StatusTooManyRequests, "1"
		})
		var logs []string
		sp.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
		for range 2 {
			if err := sp.Enqueue(Report{IP: "192.0.2.1"}); err != nil {
				t.Fatal(err)
			}
		}
		for i, want := range []time.Duration{time.Second, 2 * time.Second, time.Second, time.Minute} {
			if got := sp.DrainOnce(context.Background()); got != want {
				t.Fatalf("pass %d: delay=%v want=%v", i, got, want)
			}
			time.Sleep(want)
		}
		if calls != 5 || len(logs) != 1 {
			t.Fatalf("calls=%d logs=%v, want five attempts and one stall warning", calls, logs)
		}
		if got := sp.spool.QueueStatuses(time.Now())["spool"]; got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
			t.Fatalf("delivery recovery did not clear the stall: %+v", got)
		}
	})
}

// A broken Retry-After must not park a collector until the daemon restarts.
func TestSpoolerCapsRequestedWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		sp := retryTestSpooler(t, []string{"central"}, func(string) (int, string) {
			calls++
			if calls == 1 {
				return http.StatusTooManyRequests, "99999999999999999999"
			}
			return http.StatusAccepted, ""
		})
		if err := sp.Enqueue(Report{IP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
		sp.DrainOnce(context.Background())
		time.Sleep(time.Hour - time.Second)
		sp.DrainOnce(context.Background())
		if calls != 1 {
			t.Fatalf("calls=%d before the capped wait, want 1", calls)
		}
		time.Sleep(time.Second)
		sp.DrainOnce(context.Background())
		if calls != 2 || sp.spool.Len() != 0 {
			t.Fatalf("calls=%d left=%d, want delivery once the capped wait ends", calls, sp.spool.Len())
		}
	})
}

func TestSpoolerConcurrentDrainsRespectRetryDeadline(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	calls := 0
	sp := retryTestSpooler(t, []string{"central"}, func(string) (int, string) {
		calls++
		if calls == 1 {
			close(entered)
			<-release
		}
		return http.StatusTooManyRequests, "60"
	})
	sp.now = fixedClock()
	if err := sp.Enqueue(Report{IP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() { sp.DrainOnce(context.Background()) })
	<-entered
	wg.Go(func() { sp.DrainOnce(context.Background()) })
	unblock()
	wg.Wait()
	if calls != 1 {
		t.Fatalf("concurrent drains made %d requests before the retry deadline", calls)
	}
	if got := sp.spool.QueueStatuses(time.Now())["spool"]; got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("concurrent drains changed pending work: %+v", got)
	}
}
