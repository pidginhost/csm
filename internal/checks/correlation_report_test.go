package checks

import (
	"sync"
	"testing"
)

type warnCall struct {
	msg  string
	args []any
}

type warnRecorder struct {
	mu    sync.Mutex
	calls []warnCall
}

func (w *warnRecorder) warn(msg string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, warnCall{msg: msg, args: append([]any(nil), args...)})
}

func (w *warnRecorder) snapshot() []warnCall {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]warnCall(nil), w.calls...)
}

func argValue(args []any, key string) any {
	for i := 0; i+1 < len(args); i += 2 {
		if args[i] == key {
			return args[i+1]
		}
	}
	return nil
}

func TestUnattributedReporterWarnsOncePerCheck(t *testing.T) {
	rec := &warnRecorder{}
	r := newUnattributedReporter(rec.warn)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Report(map[string]int{"db_rogue_admin": 3})
		}()
	}
	wg.Wait()
	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("racing callers produced %d warnings, want 1: %+v", len(calls), calls)
	}
	if argValue(calls[0].args, "check") != "db_rogue_admin" || argValue(calls[0].args, "rows") != 3 {
		t.Fatalf("warning args %+v", calls[0].args)
	}

	r.Report(map[string]int{"db_rogue_admin": 9})
	if len(rec.snapshot()) != 1 {
		t.Fatal("repeated snapshot for the same check warned again")
	}
	r.Report(map[string]int{"webshell": 1})
	if calls := rec.snapshot(); len(calls) != 2 || argValue(calls[1].args, "check") != "webshell" || argValue(calls[1].args, "rows") != 1 {
		t.Fatalf("different check not reported once: %+v", calls)
	}
	r.Report(map[string]int{"phishing_page": 0, "phishing_php": -2})
	r.Report(map[string]int{"not_registered": 5, "ip_reputation": 5, "coordinated_attack": 5})
	r.Report(nil)
	if len(rec.snapshot()) != 2 {
		t.Fatalf("zero, negative, unknown, ignored or derived input produced warnings: %+v", rec.snapshot())
	}
}

func TestUnattributedReporterIsSharedByAllCallers(t *testing.T) {
	// The three production consumers report through one process-wide
	// reporter, so suppression is shared rather than three separate sets.
	if defaultUnattributedReporter == nil || defaultUnattributedReporter.warn == nil {
		t.Fatal("default reporter not wired")
	}
	rec := &warnRecorder{}
	prev := defaultUnattributedReporter
	defaultUnattributedReporter = newUnattributedReporter(rec.warn)
	t.Cleanup(func() { defaultUnattributedReporter = prev })
	ReportUnattributedCorrelation(map[string]int{"suspicious_crontab": 2})
	ReportUnattributedCorrelation(map[string]int{"suspicious_crontab": 4})
	if len(rec.snapshot()) != 1 {
		t.Fatalf("exported helper does not share suppression: %+v", rec.snapshot())
	}
}
