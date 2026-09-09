package checks

import (
	"context"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
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

func TestUnattributedReporterIsSharedByScanAndLatestState(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	for _, scanFirst := range []bool{true, false} {
		rec := &warnRecorder{}
		prev := defaultUnattributedReporter
		defaultUnattributedReporter = newUnattributedReporter(rec.warn)
		t.Cleanup(func() { defaultUnattributedReporter = prev })
		st := newTestStore(t)
		batch := []alert.Finding{
			{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: alice)"},
			{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: bob)"},
		}
		scan := func() {
			rows, _ := runParallel(&config.Config{}, nil, []namedCheck{{name: "db_content", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
				return batch
			}}}, "test", true)
			if len(rows) != 2 {
				t.Fatalf("scan returned %d rows, want 2", len(rows))
			}
		}
		merge := func() { StoreLatestScanFindings(st, purgeNamesFor("db_content"), batch) }
		first, second := scan, merge
		if !scanFirst {
			first, second = merge, scan
		}
		first()
		if calls := rec.snapshot(); len(calls) != 1 || len(calls[0].args) != 4 || argValue(calls[0].args, "check") != "db_rogue_admin" || argValue(calls[0].args, "rows") != 2 {
			t.Fatalf("first caller (scan=%v) did not report its snapshot: %+v", scanFirst, calls)
		}
		second()
		ReportUnattributedCorrelation(map[string]int{"db_rogue_admin": 9})
		if len(rec.snapshot()) != 1 {
			t.Fatalf("scan, state and exported helper did not share suppression: %+v", rec.snapshot())
		}
	}
}
