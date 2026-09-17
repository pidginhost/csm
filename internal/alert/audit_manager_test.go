package alert

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
)

type managedTestSink struct {
	name     string
	closed   atomic.Bool
	active   atomic.Int32
	badClose atomic.Bool
	events   atomic.Int32
	checks   []string
	failEmit bool
	entered  chan struct{}
	release  chan struct{}
}

func (s *managedTestSink) Name() string { return s.name }
func (s *managedTestSink) Emit(event AuditEvent) error {
	s.active.Add(1)
	defer s.active.Add(-1)
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	if s.closed.Load() {
		s.badClose.Store(true)
	}
	if s.failEmit {
		return errors.New("write failed")
	}
	s.checks = append(s.checks, event.Check)
	s.events.Add(1)
	return nil
}
func (s *managedTestSink) Close() error {
	if s.active.Load() > 0 {
		s.badClose.Store(true)
	}
	s.closed.Store(true)
	return nil
}

func isolateAuditManager(t *testing.T) {
	t.Helper()
	CloseAuditSinks()
	oldFile, oldSyslog, oldNow := openJSONLAuditSink, openSyslogAuditSink, auditNow
	t.Cleanup(func() {
		CloseAuditSinks()
		openJSONLAuditSink = oldFile
		openSyslogAuditSink = oldSyslog
		auditNow = oldNow
	})
}

func TestAuditManagerRecoveryMatrix(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		fileFails, syslogFails bool
	}{{"file healthy", false, true}, {"syslog healthy", true, false}, {"both fail", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAuditManager(t)
			now := time.Unix(100, 0)
			auditNow = func() time.Time { return now }
			failures := map[string]bool{"jsonl": tc.fileFails, "syslog": tc.syslogFails}
			attempts := map[string]int{}
			sinks := map[string]*managedTestSink{}
			open := func(name string) (AuditSink, error) {
				attempts[name]++
				if failures[name] {
					return nil, errors.New("unavailable")
				}
				s := &managedTestSink{name: name}
				sinks[name] = s
				return s, nil
			}
			openJSONLAuditSink = func(string) (AuditSink, error) { return open("jsonl") }
			openSyslogAuditSink = func(SyslogConfig) (AuditSink, error) { return open("syslog") }
			cfg := cfgWithJSONLAudit(t, "unused")
			cfg.Alerts.AuditLog.Syslog.Enabled = true
			event := []Finding{{Check: "one"}, {Check: "two"}}
			emitAudit(cfg, event)
			initial := map[string]*managedTestSink{"jsonl": sinks["jsonl"], "syslog": sinks["syslog"]}
			var scrape bytes.Buffer
			if err := metrics.WriteOpenMetrics(&scrape); err != nil {
				t.Fatal(err)
			}
			for name, failed := range failures {
				want := float64(0)
				if failed {
					want = 1
				}
				if got := auditSinkDegraded.With(name).Value(); got != want {
					t.Errorf("%s degraded=%g, want %g", name, got, want)
				}
				if failed && !strings.Contains(scrape.String(), `csm_audit_sink_degraded{sink="`+name+`"} 1`) {
					t.Errorf("scrape missing persistent degradation for %s", name)
				}
			}
			for range 20 {
				ensureAuditSinks(cfg)
			}
			if attempts["jsonl"] != 1 || attempts["syslog"] != 1 {
				t.Fatalf("retried without backoff: %v", attempts)
			}
			now = now.Add(time.Second)
			ensureAuditSinks(cfg)
			failures["jsonl"] = false
			failures["syslog"] = false
			now = now.Add(2 * time.Second)
			emitAudit(cfg, []Finding{{Check: "recovered"}})
			for name, was := range initial {
				wantEvents, wantOpens := int32(1), 3
				if was != nil {
					wantEvents, wantOpens = 3, 1
					if sinks[name] != was || was.closed.Load() {
						t.Errorf("healthy %s was replaced", name)
					}
				}
				if sinks[name].events.Load() != wantEvents || attempts[name] != wantOpens {
					t.Errorf("%s: events=%d opens=%d, want %d/%d", name, sinks[name].events.Load(), attempts[name], wantEvents, wantOpens)
				}
				wantChecks := []string{"recovered"}
				if was != nil {
					wantChecks = []string{"one", "two", "recovered"}
				}
				if !reflect.DeepEqual(sinks[name].checks, wantChecks) {
					t.Errorf("%s delivered checks=%v, want %v", name, sinks[name].checks, wantChecks)
				}
				if auditSinkDegraded.With(name).Value() != 0 {
					t.Errorf("%s still degraded after recovery", name)
				}
			}
			// A later write failure must close and retry only that destination.
			good := sinks["jsonl"]
			broken := sinks["syslog"]
			broken.failEmit = true
			dropped := auditEventsDropped.With("syslog").Value()
			emitAudit(cfg, []Finding{{Check: "write failure"}})
			if !broken.closed.Load() || auditSinkDegraded.With("syslog").Value() != 1 {
				t.Fatal("failed writer stayed active or healthy")
			}
			emitAudit(cfg, []Finding{{Check: "during backoff"}})
			if auditEventsDropped.With("syslog").Value() != dropped+2 {
				t.Fatal("missing dropped-event count during failed delivery and backoff")
			}
			now = now.Add(time.Second)
			emitAudit(cfg, []Finding{{Check: "recovered again"}})
			if sinks["syslog"] == broken || sinks["syslog"].events.Load() != 1 || sinks["jsonl"] != good {
				t.Fatal("recovery replaced a healthy sink or failed to deliver once")
			}
			ensureAuditSinks(&config.Config{})
			if !good.closed.Load() || !sinks["syslog"].closed.Load() {
				t.Fatal("disabled sink left open")
			}
			if auditSinkDegraded.With("syslog").Value() != 0 {
				t.Fatal("disabled sink reported degraded")
			}
		})
	}
}

func TestAuditRetryBackoffIsCapped(t *testing.T) {
	isolateAuditManager(t)
	start := time.Unix(100, 0)
	now := start
	auditNow = func() time.Time { return now }
	var attempts []time.Duration
	openJSONLAuditSink = func(string) (AuditSink, error) {
		attempts = append(attempts, now.Sub(start))
		return nil, errors.New("offline")
	}
	cfg := cfgWithJSONLAudit(t, "unused")
	ensureAuditSinks(cfg)
	for _, delay := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
		now = now.Add(delay*time.Second - time.Nanosecond)
		ensureAuditSinks(cfg)
		count := len(attempts)
		now = now.Add(time.Nanosecond)
		ensureAuditSinks(cfg)
		if len(attempts) != count+1 {
			t.Fatalf("retry not due after %s: %v", delay*time.Second, attempts)
		}
	}
	want := []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second, 15 * time.Second, 31 * time.Second, 63 * time.Second, 123 * time.Second, 183 * time.Second}
	if !reflect.DeepEqual(attempts, want) {
		t.Fatalf("attempt times=%v, want %v", attempts, want)
	}
}

func TestAuditCloseWaitsForEmission(t *testing.T) {
	isolateAuditManager(t)
	s := &managedTestSink{name: "jsonl", entered: make(chan struct{}), release: make(chan struct{})}
	openJSONLAuditSink = func(string) (AuditSink, error) { return s, nil }
	cfg := cfgWithJSONLAudit(t, "unused")
	emitted := make(chan struct{})
	go func() { emitAudit(cfg, []Finding{{Check: "held"}}); close(emitted) }()
	<-s.entered
	closeStarted, closed := make(chan struct{}), make(chan struct{})
	go func() { close(closeStarted); CloseAuditSinks(); close(closed) }()
	<-closeStarted
	select {
	case <-closed:
		close(s.release)
		<-emitted
		t.Fatal("sink closed while its event was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(s.release)
	<-emitted
	<-closed
	if s.badClose.Load() || !s.closed.Load() || s.events.Load() != 1 {
		t.Fatal("unsafe close or lost event")
	}
}

func TestAuditConcurrentReloadAndEmission(t *testing.T) {
	isolateAuditManager(t)
	var sinks []*managedTestSink
	openJSONLAuditSink = func(string) (AuditSink, error) {
		s := &managedTestSink{name: "jsonl"}
		sinks = append(sinks, s)
		return s, nil
	}
	cfgA, cfgB := cfgWithJSONLAudit(t, "a"), cfgWithJSONLAudit(t, "b")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			cfg := cfgA
			if i%2 == 0 {
				cfg = cfgB
			}
			for j := range 50 {
				if j%3 == 0 {
					ensureAuditSinks(cfg)
				}
				emitAudit(cfg, []Finding{{Check: fmt.Sprintf("%d/%d", i, j)}})
				if j%5 == 0 {
					CloseAuditSinks()
				}
			}
		})
	}
	wg.Wait()
	CloseAuditSinks()
	var total int32
	delivered := map[string]int{}
	for _, s := range sinks {
		if s.badClose.Load() || !s.closed.Load() {
			t.Fatal("reload closed an in-flight sink or leaked a sink")
		}
		total += s.events.Load()
		for _, check := range s.checks {
			delivered[check]++
		}
	}
	for i := range 8 {
		for j := range 50 {
			key := fmt.Sprintf("%d/%d", i, j)
			if delivered[key] != 1 {
				t.Errorf("event %s delivered %d times", key, delivered[key])
			}
		}
	}
	if total != 400 {
		t.Fatalf("delivered %d events, want exactly 400", total)
	}
}
