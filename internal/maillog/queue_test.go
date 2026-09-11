package maillog

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestMailQueueAccountsForCanceledReaderAndConsumer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		writer, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		queue := NewQueue()
		done := make(chan struct{})
		consumed := 0
		go func() {
			defer close(done)
			Supervise(ctx, func() (Reader, error) { return NewFileReader(path, queue), nil }, func(err error) {
				if err != nil {
					t.Errorf("reader attachment: %v", err)
				}
			}, func(Line) bool {
				consumed++
				<-ctx.Done()
				return false
			})
		}()
		synctest.Wait()
		appendMailAndPoll(t, writer, strings.Repeat("queued\n", 66))
		got := queue.QueueStatuses(time.Now())["delivery"]
		if consumed != 1 || got.Capacity != 64 || got.Depth != 65 || got.InFlight != 1 || got.DroppedTotal != 0 {
			t.Fatalf("waiting producer or consumer missing from pressure: consumed=%d status=%+v", consumed, got)
		}
		cancel()
		<-done
		got = queue.QueueStatuses(time.Now())["delivery"]
		if got.Status != "degraded" || got.Reason != "dropped_work" || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 66 || got.RecentDrops != 66 {
			t.Fatalf("canceled reader, waiting producer and rejected consumer were not counted exactly: %+v", got)
		}
		time.Sleep(time.Minute)
		got = queue.QueueStatuses(time.Now())["delivery"]
		if got.Status != "ok" || got.DroppedTotal != 66 || got.RecentDrops != 0 {
			t.Fatalf("loss window did not recover while retaining totals: %+v", got)
		}
	})
}

func TestMailQueueAccountsForConsumerPanicAndPendingLines(t *testing.T) {
	queue := NewQueue()
	reader := supervisorReaderFunc(func(context.Context) (<-chan Line, error) {
		out := queue.channel()
		for _, message := range []string{"one", "two", "three"} {
			if !queue.send(context.Background(), out, Line{Message: message}) {
				t.Fatal("unexpected admission failure")
			}
		}
		close(out)
		return out, nil
	})
	var caught any
	func() {
		defer func() { caught = recover() }()
		Supervise(context.Background(), func() (Reader, error) { return reader, nil }, func(error) {}, func(Line) bool { panic("consumer failed") })
	}()
	got := queue.QueueStatuses(time.Now())["delivery"]
	if caught != "consumer failed" || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Status != "degraded" {
		t.Fatalf("panic or pending work disappeared: panic=%v status=%+v", caught, got)
	}
}

func TestMailQueueRetainsLossAcrossReaderReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := NewQueue()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		starts := 0
		var messages []string
		go Supervise(ctx, func() (Reader, error) {
			starts++
			return supervisorReaderFunc(func(context.Context) (<-chan Line, error) {
				out := queue.channel()
				queue.lose()
				if !queue.send(ctx, out, Line{Message: "delivered"}) {
					t.Error("unexpected admission failure")
				}
				close(out)
				return out, nil
			}), nil
		}, func(error) {}, func(line Line) bool {
			messages = append(messages, line.Message)
			return true
		})
		time.Sleep(2 * time.Second)
		synctest.Wait()
		cancel()
		synctest.Wait()
		got := queue.QueueStatuses(time.Now())["delivery"]
		if starts != 3 || !slices.Equal(messages, []string{"delivered", "delivered", "delivered"}) || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Status != "degraded" {
			t.Fatalf("replacement cleared queue evidence: starts=%d messages=%q status=%+v", starts, messages, got)
		}
	})
}

func TestMailQueueAccountsForCancellationDuringAttachment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := NewQueue()
	reader := supervisorReaderFunc(func(context.Context) (<-chan Line, error) {
		out := queue.channel()
		for range 3 {
			if !queue.send(context.Background(), out, Line{Message: "queued"}) {
				t.Fatal("unexpected admission failure")
			}
		}
		close(out)
		cancel()
		return out, nil
	})
	Supervise(ctx, func() (Reader, error) { return reader, nil }, func(error) {
		t.Error("canceled attachment reported status")
	}, func(Line) bool {
		t.Error("canceled attachment delivered a line")
		return true
	})
	got := queue.QueueStatuses(time.Now())["delivery"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 {
		t.Fatalf("attachment cancellation abandoned queued records: %+v", got)
	}
}

func TestMailQueueCountsOversizedRecordOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		writer, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		queue := NewQueue()
		out, err := NewFileReader(path, queue).Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for range 3 {
			appendMailAndPoll(t, writer, strings.Repeat("A", maxLogLineBytes))
			if got := queue.QueueStatuses(time.Now())["delivery"]; got.DroppedTotal != 0 || got.Depth != 0 {
				t.Fatalf("incomplete fragments counted as whole lost records: %+v", got)
			}
		}
		appendMailAndPoll(t, writer, "\nvalid\n")
		line := <-out
		if !line.Process(func(line Line) bool { return line.Source == "file" && line.Message == "valid\n" }) {
			t.Fatalf("oversized record corrupted its successor: %+v", line)
		}
		cancel()
		for line := range out {
			t.Errorf("unexpected line: %+v", line)
		}
		got := queue.QueueStatuses(time.Now())["delivery"]
		if got.DroppedTotal != 1 || got.RecentDrops != 1 || got.Depth != 0 || got.InFlight != 0 {
			t.Fatalf("oversized record was not counted exactly once: %+v", got)
		}
	})
}

// The cursor exposes no unread count, so the row measures operations only.
func TestJournalSourceDoesNotClaimAMeasuredBacklog(t *testing.T) {
	q := NewQueue()
	q.journal.seen = true
	row, ok := q.QueueStatuses(time.Now())["journal_source"]
	if !ok {
		t.Fatal("journal source queue missing")
	}
	if row.LagBasis != "unavailable" || strings.Contains(row.Evidence(), "lag=0s") {
		t.Fatalf("a cursor with no backlog measurement reported an empty queue: %+v evidence=%q", row, row.Evidence())
	}
}
