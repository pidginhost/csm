package maillog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

type supervisorReaderFunc func(context.Context) (<-chan Line, error)

func (f supervisorReaderFunc) Run(ctx context.Context) (<-chan Line, error) { return f(ctx) }

func TestSupervisorBackoffAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		start := time.Now()
		var attempts []time.Duration
		failures := 0
		done := make(chan struct{})
		go func() {
			defer close(done)
			Supervise(ctx, func() (Reader, error) {
				attempts = append(attempts, time.Since(start))
				if len(attempts)%2 == 1 {
					return nil, errors.New("unavailable")
				}
				return supervisorReaderFunc(func(context.Context) (<-chan Line, error) {
					return nil, errors.New("unavailable")
				}), nil
			}, func(err error) {
				if err == nil {
					t.Error("failed attachment reported healthy")
				}
				failures++
			}, func(Line) bool {
				t.Error("failed reader emitted a line")
				return false
			})
		}()
		time.Sleep(95 * time.Second)
		synctest.Wait()
		want := []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second, 15 * time.Second, 31 * time.Second, 61 * time.Second, 91 * time.Second}
		if !slices.Equal(attempts, want) || failures != 1 {
			t.Fatalf("attempts=%v, failures=%d; want %v and one outage notification", attempts, failures, want)
		}
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("cancellation did not interrupt backoff")
		}
	})
}

func TestSupervisorAutoRepicksAfterAttachmentFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		cfg := config.MailLogsConfig{Source: "auto", File: path, Units: []string{"postfix"}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var choices, messages []string
		var states []bool
		go Supervise(ctx, func() (Reader, error) {
			reader, err := New(cfg, "", NewQueue())
			if _, journal := reader.(*JournalReader); journal {
				choices = append(choices, "journal")
				return supervisorReaderFunc(func(context.Context) (<-chan Line, error) {
					return nil, errors.New("journal temporarily unavailable")
				}), nil
			}
			choices = append(choices, "file")
			return reader, err
		}, func(err error) { states = append(states, err == nil) }, func(line Line) bool {
			messages = append(messages, line.Message)
			return true
		})
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if err := os.WriteFile(path, []byte("historical\n"), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		w, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		appendMailAndPoll(t, w, "current\n")
		if !slices.Equal(choices, []string{"journal", "journal", "file"}) || !slices.Equal(states, []bool{false, true}) || !slices.Equal(messages, []string{"current\n"}) {
			t.Fatalf("choices=%v, states=%v, messages=%q", choices, states, messages)
		}
	})
}

func TestSupervisorSourceMigrationHonorsExplicitMode(t *testing.T) {
	for _, mode := range []string{"auto", "file", "journal"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "maillog")
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
				cfg := config.MailLogsConfig{Source: mode, File: path, Units: []string{"postfix"}}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var choices []string
				var states []bool
				activeJournals := 0
				go Supervise(ctx, func() (Reader, error) {
					reader, err := New(cfg, "", NewQueue())
					if file, ok := reader.(*FileReader); ok {
						choices = append(choices, "file")
						file.goneGrace = 2 * time.Second
					}
					if _, ok := reader.(*JournalReader); ok {
						choices = append(choices, "journal")
						return supervisorReaderFunc(func(ctx context.Context) (<-chan Line, error) {
							activeJournals++
							out := make(chan Line)
							go func() {
								<-ctx.Done()
								activeJournals--
								close(out)
							}()
							return out, nil
						}), nil
					}
					return reader, err
				}, func(err error) { states = append(states, err == nil) }, func(Line) bool { return true })
				synctest.Wait()
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				time.Sleep(10 * time.Second)
				synctest.Wait()
				switch mode {
				case "auto":
					if !slices.Equal(choices, []string{"file", "journal"}) || !slices.Equal(states, []bool{true, false, true}) || activeJournals != 1 {
						t.Fatalf("auto migration: choices=%v, states=%v, active journals=%d", choices, states, activeJournals)
					}
				case "file":
					if !slices.Equal(choices, []string{"file"}) || !slices.Equal(states, []bool{true, false, false}) || activeJournals != 0 {
						t.Fatalf("explicit file mode changed source or stayed healthy: choices=%v, states=%v", choices, states)
					}
				case "journal":
					if !slices.Equal(choices, []string{"journal"}) || !slices.Equal(states, []bool{true}) || activeJournals != 1 {
						t.Fatalf("explicit journal mode changed source: choices=%v, states=%v", choices, states)
					}
				}
				cancel()
				synctest.Wait()
				if activeJournals != 0 {
					t.Fatal("supervisor leaked its active journal reader")
				}
			})
		})
	}
}

func TestSupervisorWaitsForReaderShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stopped := false
		reader := supervisorReaderFunc(func(ctx context.Context) (<-chan Line, error) {
			out := make(chan Line, 1)
			out <- Line{Message: "stop"}
			go func() {
				<-ctx.Done()
				time.Sleep(time.Second)
				stopped = true
				close(out)
			}()
			return out, nil
		})
		ready, consumed := 0, 0
		Supervise(context.Background(), func() (Reader, error) { return reader, nil }, func(err error) {
			if err != nil {
				t.Errorf("normal consumer shutdown reported an outage: %v", err)
			}
			ready++
		}, func(line Line) bool {
			if line.Message != "stop" {
				t.Errorf("unexpected record %+v", line)
			}
			consumed++
			return false
		})
		if !stopped || ready != 1 || consumed != 1 {
			t.Fatalf("shutdown: stopped=%v, ready=%d, consumed=%d", stopped, ready, consumed)
		}
	})
}

func TestSupervisorReplacesStoppedReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		active, starts := 0, 0
		var states []bool
		go Supervise(ctx, func() (Reader, error) {
			return supervisorReaderFunc(func(ctx context.Context) (<-chan Line, error) {
				if active != 0 {
					t.Error("replacement started before the previous reader stopped")
				}
				active++
				starts++
				first := starts == 1
				out := make(chan Line)
				go func() {
					if first {
						time.Sleep(2 * time.Second)
					} else {
						<-ctx.Done()
					}
					active--
					close(out)
				}()
				return out, nil
			}), nil
		}, func(err error) { states = append(states, err == nil) }, func(Line) bool { return true })
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if starts != 2 || active != 1 || !slices.Equal(states, []bool{true, false, true}) {
			t.Fatalf("starts=%d, active=%d, states=%v", starts, active, states)
		}
		cancel()
		synctest.Wait()
		if active != 0 {
			t.Fatal("replacement survived supervisor shutdown")
		}
	})
}

func TestSupervisorReportsOutageWhileConsumerBusyAndDrainsQueuedLines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		release := make(chan struct{})
		releaseConsumer := sync.OnceFunc(func() { close(release) })
		defer releaseConsumer()
		var states []bool
		var messages []string
		queue := NewQueue()
		go Supervise(ctx, func() (Reader, error) {
			reader, err := New(config.MailLogsConfig{Source: "file", File: path}, "", queue)
			if file, ok := reader.(*FileReader); ok {
				file.goneGrace = 2 * time.Second
			}
			return reader, err
		}, func(err error) { states = append(states, err == nil) }, func(line Line) bool {
			messages = append(messages, line.Message)
			if len(messages) == 1 {
				<-release
			}
			return true
		})
		synctest.Wait()
		appendMailAndPoll(t, w, "one\ntwo\n")
		if !slices.Equal(messages, []string{"one\n"}) {
			t.Fatalf("consumer did not pause on the first record: %q", messages)
		}
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if !slices.Equal(states, []bool{true, false}) {
			t.Fatalf("outage hidden behind the busy consumer: %v", states)
		}
		releaseConsumer()
		synctest.Wait()
		if !slices.Equal(messages, []string{"one\n", "two\n"}) {
			t.Fatalf("queued records lost during source replacement: %q", messages)
		}
		if got := queue.QueueStatuses(time.Now())["delivery"]; got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("source migration left queued or lost work: %+v", got)
		}
	})
}
