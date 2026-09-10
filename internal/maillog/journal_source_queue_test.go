//go:build linux && journal

package maillog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/pidginhost/csm/internal/queuehealth"
)

type sourceQueueJournal struct {
	next  func() (uint64, error)
	entry func() (*sdjournal.JournalEntry, error)
	wait  func(time.Duration) int
	close func() error
}

func TestJournalSourceFailureClearsOnlyAfterReplacementAttaches(t *testing.T) {
	for _, phase := range []string{"wait", "close"} {
		t.Run(phase, func(t *testing.T) {
			q := NewQueue()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			journal := sourceQueueJournal{
				next: func() (uint64, error) { return 0, nil },
				wait: func(time.Duration) int {
					cancel()
					if phase == "wait" {
						return -1
					}
					return 0
				},
				close: func() error {
					if phase == "close" {
						return errors.New("synthetic close failure")
					}
					return nil
				},
			}
			out := q.channel()
			NewJournalReader(nil, q).loop(ctx, journal, out)
			row := journalSourceRow(t, q)
			if row.Reason != "source_io" || row.InFlight != 0 || !row.DroppedLowerBound || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 0 {
				t.Fatalf("%s failure was concealed or invented lost entries: %+v", phase, row)
			}
			path := filepath.Join(t.TempDir(), "replacement.log")
			fileCtx, stopFile := context.WithCancel(context.Background())
			defer stopFile()
			if failedOut, err := NewFileReader(path, q).Run(fileCtx); err == nil || failedOut != nil {
				t.Fatal("missing replacement unexpectedly attached")
			}
			if row = journalSourceRow(t, q); row.Reason != "source_io" {
				t.Fatalf("failed replacement concealed source outage: %+v", row)
			}
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			fileOut, err := NewFileReader(path, q).Run(fileCtx)
			if err != nil {
				t.Fatal(err)
			}
			stopFile()
			for line := range fileOut {
				line.reject()
				t.Error("empty replacement emitted work")
			}
			row = journalSourceRow(t, q)
			if row.Status != "ok" || row.InFlight != 0 || !row.DroppedLowerBound {
				t.Fatalf("healthy file replacement retained obsolete journal failure: %+v", row)
			}
		})
	}
}

func TestJournalSourceBlockedDeliveryCancellationCountsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		closed := false
		journal := sourceQueueJournal{
			next: func() (uint64, error) { calls++; return 1, nil },
			entry: func() (*sdjournal.JournalEntry, error) {
				return &sdjournal.JournalEntry{Fields: map[string]string{"MESSAGE": "queued"}}, nil
			},
			close: func() error { closed = true; return nil },
		}
		out := q.channel()
		done := make(chan struct{})
		go func() { defer close(done); NewJournalReader(nil, q).loop(ctx, journal, out) }()
		synctest.Wait()
		time.Sleep(time.Minute)
		row := journalSourceRow(t, q)
		delivery := q.QueueStatuses(time.Now())["delivery"]
		if calls != queueCapacity+1 || row.InFlight != 0 || row.Reason != "processing_lag" || row.DroppedTotal != 0 || delivery.Depth != queueCapacity+1 || delivery.InFlight != 0 || delivery.DroppedTotal != 0 {
			t.Errorf("blocked delivery lost source ownership or duplicated selected entry: calls=%d source=%+v delivery=%+v", calls, row, delivery)
		}
		cancel()
		<-done
		count := 0
		for line := range out {
			count++
			line.reject()
		}
		row = journalSourceRow(t, q)
		delivery = q.QueueStatuses(time.Now())["delivery"]
		if !closed || count != queueCapacity || row.InFlight != 0 || row.Status != "ok" || !row.DroppedLowerBound || delivery.Depth != 0 || delivery.InFlight != 0 || delivery.DroppedTotal != queueCapacity+1 {
			t.Fatalf("canceled delivery lost or double-counted entries: closed=%v drained=%d source=%+v delivery=%+v", closed, count, row, delivery)
		}
	})
}

func TestJournalSourceOwnsAbnormalExitThroughClose(t *testing.T) {
	for _, phase := range []string{"cursor", "entry", "wait", "close"} {
		for _, mode := range []string{"panic", "goexit"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					q := NewQueue()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					out := q.channel()
					entered, release := make(chan struct{}), make(chan struct{})
					exited := make(chan any, 1)
					var releaseOnce sync.Once
					unblock := func() { releaseOnce.Do(func() { close(release) }) }
					joined := false
					defer func() {
						unblock()
						if !joined {
							<-exited
						}
					}()
					interrupt := func() {
						if mode == "panic" {
							panic("journal source interruption")
						}
						runtime.Goexit()
					}
					journal := sourceQueueJournal{
						next: func() (uint64, error) {
							if phase == "cursor" {
								interrupt()
							}
							if phase == "entry" {
								return 1, nil
							}
							return 0, nil
						},
						entry: func() (*sdjournal.JournalEntry, error) { interrupt(); return nil, nil },
						wait: func(time.Duration) int {
							if phase == "wait" {
								interrupt()
							}
							cancel()
							return 0
						},
						close: func() error {
							defer func() { close(entered); <-release }()
							if phase == "close" {
								interrupt()
							}
							return nil
						},
					}
					returned := false
					go func() {
						defer func() { exited <- recover() }()
						NewJournalReader(nil, q).loop(ctx, journal, out)
						returned = true
					}()
					<-entered
					wantFlight := 0
					if phase == "entry" {
						wantFlight = 1
					}
					row := journalSourceRow(t, q)
					if row.InFlight != wantFlight || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 0 {
						t.Errorf("abnormal callback released work before actual close: %+v", row)
					}
					if phase != "close" && (row.Reason != "source_io" || !row.DroppedLowerBound) {
						t.Errorf("known abnormal read hidden during actual close: %+v", row)
					}
					unblock()
					caught := <-exited
					joined = true
					if returned || mode == "panic" && caught != "journal source interruption" || mode == "goexit" && caught != nil {
						t.Fatalf("original abnormal exit changed: returned=%v caught=%v", returned, caught)
					}
					row = journalSourceRow(t, q)
					delivery := q.QueueStatuses(time.Now())["delivery"]
					if row.InFlight != 0 || row.Reason != "source_io" || !row.DroppedLowerBound || delivery.Depth != 0 || delivery.InFlight != 0 || delivery.DroppedTotal != uint64(wantFlight) {
						t.Fatalf("abnormal source settlement lost or duplicated work: source=%+v delivery=%+v", row, delivery)
					}
					if _, ok := <-out; ok {
						t.Fatal("abnormal source emitted unexpected work")
					}
				})
			})
		}
	}
}

func (j sourceQueueJournal) Next() (uint64, error)                      { return j.next() }
func (j sourceQueueJournal) GetEntry() (*sdjournal.JournalEntry, error) { return j.entry() }
func (j sourceQueueJournal) Wait(d time.Duration) int                   { return j.wait(d) }
func (j sourceQueueJournal) Close() error                               { return j.close() }

func journalSourceRow(t *testing.T, q *Queue) queuehealth.Status {
	t.Helper()
	row, ok := q.QueueStatuses(time.Now())["journal_source"]
	if !ok {
		t.Fatal("journal source queue missing")
	}
	if !row.DepthUnavailable || !row.CapacityUnavailable || row.Depth != 0 {
		t.Fatalf("opaque journal backlog presented as an exact count: %+v", row)
	}
	return row
}

func TestJournalSourceTracksCursorEntryAndCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out := q.channel()
		calls := 0
		closed := false
		journal := sourceQueueJournal{
			next: func() (uint64, error) {
				calls++
				if calls == 2 {
					return 0, nil
				}
				time.Sleep(time.Minute)
				row := journalSourceRow(t, q)
				if row.InFlight != 0 || row.ProcessingSeconds != 60 || row.Reason != "processing_lag" || row.DroppedTotal != 0 {
					t.Errorf("blocked cursor invented an entry or hid its stall: %+v", row)
				}
				return 1, nil
			},
			entry: func() (*sdjournal.JournalEntry, error) {
				row := journalSourceRow(t, q)
				if row.InFlight != 1 || row.ProcessingSeconds != 0 || row.Status != "ok" {
					t.Errorf("selected entry missing or cursor progress ignored: %+v", row)
				}
				time.Sleep(time.Minute)
				row = journalSourceRow(t, q)
				if row.InFlight != 1 || row.Reason != "processing_lag" {
					t.Errorf("held entry was released early: %+v", row)
				}
				return &sdjournal.JournalEntry{Fields: map[string]string{"MESSAGE": "selected entry", "_SYSTEMD_UNIT": "postfix.service"}}, nil
			},
			wait: func(d time.Duration) int {
				row := journalSourceRow(t, q)
				delivery := q.QueueStatuses(time.Now())["delivery"]
				if d != 2*time.Second || row.InFlight != 0 || row.Status != "ok" || delivery.Depth != 1 || delivery.InFlight != 0 {
					t.Errorf("entry transfer or bounded idle wait changed: source=%+v delivery=%+v timeout=%v", row, delivery, d)
				}
				cancel()
				return 0
			},
			close: func() error {
				time.Sleep(time.Minute)
				row := journalSourceRow(t, q)
				if row.InFlight != 0 || row.Reason != "processing_lag" || row.ProcessingSeconds != 60 {
					t.Errorf("source close stopped being observable: %+v", row)
				}
				closed = true
				return nil
			},
		}
		NewJournalReader(nil, q).loop(ctx, journal, out)
		row := journalSourceRow(t, q)
		if !closed || calls != 2 || row.InFlight != 0 || row.ProcessingSeconds != 0 || row.Status != "ok" || !row.DroppedLowerBound {
			t.Fatalf("closed source retained active work or claimed exact unread shutdown: closed=%v calls=%d row=%+v", closed, calls, row)
		}
		line, ok := <-out
		if !ok || !line.Process(func(line Line) bool { return line.Message == "selected entry" && line.Unit == "postfix.service" }) {
			t.Fatal("selected entry was not delivered intact")
		}
		if _, ok = <-out; ok {
			t.Fatal("unexpected extra journal entry")
		}
		if delivery := q.QueueStatuses(time.Now())["delivery"]; delivery.Depth != 0 || delivery.InFlight != 0 || delivery.DroppedTotal != 0 {
			t.Fatalf("successful entry was counted as a loss: %+v", delivery)
		}
	})
}

func TestJournalSourceReadFailureRecoveryPreservesUncertainty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out := q.channel()
		calls := 0
		journal := sourceQueueJournal{
			next: func() (uint64, error) {
				calls++
				if calls == 1 {
					return 0, errors.New("synthetic cursor failure")
				}
				row := journalSourceRow(t, q)
				if calls == 2 && (row.Reason != "source_io" || !row.DroppedLowerBound || row.DroppedTotal != 0) {
					t.Errorf("cursor failure was hidden or invented a lost entry: %+v", row)
				}
				if calls <= 3 {
					return 1, nil
				}
				return 0, nil
			},
			entry: func() (*sdjournal.JournalEntry, error) {
				if calls == 2 {
					return nil, errors.New("synthetic entry failure")
				}
				row := journalSourceRow(t, q)
				if row.Reason != "source_io" || row.InFlight != 1 {
					t.Errorf("entry retry hid previous read failure: %+v", row)
				}
				return &sdjournal.JournalEntry{Fields: map[string]string{"MESSAGE": "recovered"}}, nil
			},
			wait: func(time.Duration) int {
				row := journalSourceRow(t, q)
				if row.Status != "ok" || !row.DroppedLowerBound || row.InFlight != 0 {
					t.Errorf("read recovery erased uncertainty or kept stale error: %+v", row)
				}
				cancel()
				return 0
			},
			close: func() error { return nil },
		}
		NewJournalReader(nil, q).loop(ctx, journal, out)
		if calls != 4 {
			t.Fatalf("cursor recovery calls=%d want4", calls)
		}
		line, ok := <-out
		if !ok || !line.Process(func(line Line) bool { return line.Message == "recovered" }) {
			t.Fatal("healthy successor was lost")
		}
		if _, ok = <-out; ok {
			t.Fatal("unexpected extra journal entry")
		}
		if delivery := q.QueueStatuses(time.Now())["delivery"]; delivery.Depth != 0 || delivery.InFlight != 0 || delivery.DroppedTotal != 1 {
			t.Fatalf("known unreadable entry loss changed: %+v", delivery)
		}
	})
}
