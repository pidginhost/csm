package blockdigest

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func TestBlockDigestQueueInterruptedDelivery(t *testing.T) {
	for _, inLogger := range []bool{false, true} {
		phase := "sink"
		if inLogger {
			phase = "logger"
		}
		for _, goexit := range []bool{false, true} {
			kind := "panic"
			if goexit {
				kind = "goexit"
			}
			t.Run(phase+"/"+kind, func(t *testing.T) {
				sentinel := errors.New("fixture interrupted delivery")
				fail := true
				emailCalls, webhookCalls := 0, 0
				interrupt := func() {
					if goexit {
						runtime.Goexit()
					}
					panic(sentinel)
				}
				c := New(Options{Interval: time.Hour, SendOn: "any", MinBlock: 1,
					EmailSink: func(string, string) error {
						emailCalls++
						if fail {
							if !inLogger {
								interrupt()
							}
							return sentinel
						}
						return nil
					},
					WebhookSink: func(WebhookPayload) error { webhookCalls++; return nil },
					OnError: func(channel string, err error) {
						if channel != "email" || err != sentinel {
							t.Error("returned sink error changed")
						}
						interrupt()
					},
				})
				c.Observe("192.0.2.31", "fixture customer block", time.Now())
				done := make(chan struct{})
				var recovered any
				returned := false
				go func() {
					defer close(done)
					defer func() { recovered = recover() }()
					c.Flush()
					returned = true
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("interrupted flush did not join")
				}
				if returned || (!goexit && recovered != sentinel) || (goexit && recovered != nil) {
					t.Fatalf("interruption changed: returned=%v recovered=%v", returned, recovered)
				}
				rows := digestQueueStatuses(t, c, time.Now())
				email, webhook, records := rows["email"], rows["webhook"], rows["records"]
				wantLoss := uint64(0)
				if inLogger {
					wantLoss = 1
				}
				if email.Depth != 0 || email.InFlight != 0 || email.DroppedTotal != wantLoss || email.DroppedLowerBound == inLogger {
					t.Fatalf("first sink outcome: %+v", email)
				}
				if !inLogger && email.Reason != "delivery_uncertain" {
					t.Fatalf("unreturned sink hidden: %+v", email)
				}
				if webhook.Depth != 0 || webhook.InFlight != 0 || webhook.DroppedTotal != 1 || webhook.DroppedLowerBound || webhookCalls != 0 {
					t.Fatalf("unattempted second sink: calls=%d row=%+v", webhookCalls, webhook)
				}
				if records.Depth != 0 || records.InFlight != 0 || records.DroppedTotal != 0 {
					t.Fatalf("handed-off records counted again: %+v", records)
				}
				fail = false
				c.Observe("192.0.2.32", "fixture later block", time.Now())
				c.Flush()
				rows = digestQueueStatuses(t, c, time.Now().Add(2*time.Minute))
				if emailCalls != 2 || webhookCalls != 1 {
					t.Fatalf("retry policy changed: email=%d webhook=%d", emailCalls, webhookCalls)
				}
				if row := rows["email"]; row.Status != "ok" || row.DroppedTotal != wantLoss || row.DroppedLowerBound == inLogger || row.Depth != 0 || row.InFlight != 0 {
					t.Fatalf("recovery erased prior outcome: %+v", row)
				}
				if row := rows["webhook"]; row.Status != "ok" || row.DroppedTotal != 1 || row.Depth != 0 || row.InFlight != 0 {
					t.Fatalf("second sink recovery: %+v", row)
				}
			})
		}
	}
}

func TestBlockDigestQueueOwnsPreparation(t *testing.T) {
	for _, live := range []bool{false, true} {
		mode := "periodic"
		if live {
			mode = "live"
		}
		for _, outcome := range []string{"return", "panic", "goexit"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				var lookups atomic.Int32
				target := int32(3)
				if live {
					target = 2
				}
				calls := 0
				sentinel := errors.New("fixture interrupted preparation")
				c := New(Options{Interval: time.Hour, Live: live, SendOn: "any", MinBlock: 1,
					CountriesOf: func() []string {
						if lookups.Add(1) == target {
							close(entered)
							<-release
							switch outcome {
							case "panic":
								panic(sentinel)
							case "goexit":
								runtime.Goexit()
							}
						}
						return nil
					},
					EmailSink:   func(string, string) error { calls++; return nil },
					WebhookSink: func(WebhookPayload) error { calls++; return nil },
				})
				if !live {
					for range 2 {
						c.Observe("192.0.2.41", "fixture customer block", time.Now())
					}
				}
				t.Cleanup(func() {
					unblock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("preparation did not join")
					}
				})
				var recovered any
				returned := false
				go func() {
					defer close(done)
					defer func() { recovered = recover() }()
					if live {
						c.Observe("192.0.2.41", "fixture customer block", time.Now())
					} else {
						c.Flush()
					}
					returned = true
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("real country lookup not entered")
				}
				rows := digestQueueStatuses(t, c, time.Now().Add(2*time.Minute))
				if live {
					if row := rows["records"]; row.Depth != 1 || row.InFlight != 0 || row.DroppedTotal != 0 {
						t.Fatalf("live preparation removed periodic work: %+v", row)
					}
					for _, name := range []string{"email", "webhook"} {
						if row := rows[name]; row.Depth != 1 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Reason != "backlog_lag" {
							t.Fatalf("live %s preparation hidden: %+v", name, row)
						}
					}
				} else {
					if row := rows["records"]; row.Depth != 0 || row.InFlight != 2 || row.DroppedTotal != 0 || row.Reason != "processing_lag" {
						t.Fatalf("detached raw records hidden: %+v", row)
					}
					c.Observe("192.0.2.42", "fixture next window", time.Now())
					if row := digestQueueStatuses(t, c, time.Now())["records"]; row.Depth != 1 || row.InFlight != 2 {
						t.Fatalf("new window merged with detached batch: %+v", row)
					}
				}
				unblock()
				<-done
				if returned != (outcome == "return") || (outcome == "panic" && recovered != sentinel) || (outcome != "panic" && recovered != nil) {
					t.Fatalf("preparation interruption changed: returned=%v recovered=%v", returned, recovered)
				}
				rows = digestQueueStatuses(t, c, time.Now())
				wantRecordLoss, wantSinkLoss, wantCalls := uint64(0), uint64(0), 2
				if outcome != "return" {
					wantCalls = 0
					if live {
						wantSinkLoss = 1
					} else {
						wantRecordLoss = 2
					}
				}
				if row := rows["records"]; row.Depth != 1 || row.InFlight != 0 || row.DroppedTotal != wantRecordLoss || row.DroppedLowerBound {
					t.Fatalf("detached preparation outcome: %+v", row)
				}
				for _, name := range []string{"email", "webhook"} {
					if row := rows[name]; row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != wantSinkLoss || row.DroppedLowerBound {
						t.Fatalf("%s preparation outcome: %+v", name, row)
					}
				}
				if calls != wantCalls {
					t.Fatalf("sink calls=%d want=%d", calls, wantCalls)
				}
				digest := c.Drain()
				wantIP := "192.0.2.42"
				if live {
					wantIP = "192.0.2.41"
				}
				if digest.Total != 1 || len(digest.Records) != 1 || digest.Records[0].IP != wantIP {
					t.Fatalf("surviving periodic records changed: %+v", digest)
				}
			})
		}
	}
}

func TestBlockDigestQueueSnapshotAvoidsCollectorLock(t *testing.T) {
	c := New(Options{Interval: time.Hour})
	c.Observe("192.0.2.51", "fixture block", time.Now())
	c.mu.Lock()
	done := make(chan map[string]queuehealth.Status, 1)
	go func() { done <- c.QueueStatuses(time.Now()) }()
	select {
	case rows := <-done:
		c.mu.Unlock()
		if row := rows["records"]; row.Depth != 1 || row.InFlight != 0 || row.DroppedTotal != 0 {
			t.Fatalf("actual buffer not observed: %+v", row)
		}
	case <-time.After(5 * time.Second):
		c.mu.Unlock()
		<-done
		t.Fatal("health waits for collector state lock")
	}
}

func TestBlockDigestQueueCountsFailedHeartbeatDeliveries(t *testing.T) {
	emailCalls, webhookCalls := 0, 0
	fail := true
	sentinel := errors.New("fixture unavailable destination")
	c := New(Options{Interval: time.Hour, SendOn: "any", MinBlock: 0,
		EmailSink: func(string, string) error {
			emailCalls++
			if fail {
				return sentinel
			}
			return nil
		},
		WebhookSink: func(p WebhookPayload) error {
			webhookCalls++
			if p.CSM.Event != "block_digest" || p.CSM.Counts.Total != 0 || len(p.CSM.Blocks) != 0 {
				t.Error("empty heartbeat policy changed")
			}
			if fail {
				return sentinel
			}
			return nil
		},
	})
	for range 3 {
		c.Flush()
	}
	rows := digestQueueStatuses(t, c, time.Now())
	for _, name := range []string{"email", "webhook"} {
		if row := rows[name]; row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 3 || row.RecentDrops != 3 || row.DroppedLowerBound || row.Reason != "dropped_work" {
			t.Fatalf("%s failed notifications: %+v", name, row)
		}
	}
	if row := rows["records"]; row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Status != "ok" {
		t.Fatalf("heartbeat invented record loss: %+v", row)
	}
	fail = false
	c.Flush()
	rows = digestQueueStatuses(t, c, time.Now().Add(2*time.Minute))
	for _, name := range []string{"email", "webhook"} {
		if row := rows[name]; row.Status != "ok" || row.DroppedTotal != 3 || row.RecentDrops != 0 || row.Depth != 0 || row.InFlight != 0 {
			t.Fatalf("%s recovery: %+v", name, row)
		}
	}
	if emailCalls != 4 || webhookCalls != 4 {
		t.Fatalf("delivery attempts changed: email=%d webhook=%d", emailCalls, webhookCalls)
	}
}
