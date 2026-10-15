package admissionowner

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// benchBounds is what an owner holds after a benchmark's turns: its
// outstanding and ready answers, its forecast blocks, the largest example
// batch it wrote, the examples its summary names and its comparison keys.
type benchBounds struct {
	pending, ready, entries, batch, named, keys int
}

func readBounds(b *testing.B, o *Owner, batch int) benchBounds {
	b.Helper()
	var got benchBounds
	if err := o.do(func() error {
		got = benchBounds{pending: len(o.verdicts.pending), ready: len(o.verdicts.ready), batch: batch}
		if o.shadow != nil {
			got.entries = len(o.shadow.entries)
		}
		if s := o.summary.pending; s != nil {
			got.named = len(s.examples)
		}
		o.compare.mu.Lock()
		defer o.compare.mu.Unlock()
		got.keys = len(o.compare.counts)
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	return got
}

// checkBounds fails b if the owner holds more than the design's bounds:
// 64 outstanding jobs, 128 ready answers, the forecast's modelling bound,
// 64 examples a write, 20 named examples, and the comparison's fixed
// keys for the turns' kinds and predictions.
func checkBounds(b *testing.B, got benchBounds) {
	b.Helper()
	if got.pending > verdictPending || got.ready > verdictReady || got.entries > forecastEntries ||
		got.batch > admission.MaxBatchMembers || got.named > summaryExamples || got.keys > int(admission.PredictionSlots) {
		b.Fatalf("bounds exceeded: %+v", got)
	}
}

// watchBatches records the largest example batch the owner writes.
func watchBatches(b *testing.B, o *Owner) *int {
	b.Helper()
	largest := new(int)
	write := recordExamples
	setOwnerHook(b, o, &recordExamples, func(db *store.DB, blocks []store.DryRunBlock) error {
		*largest = max(*largest, len(blocks))
		return write(db, blocks)
	})
	return largest
}

// Spec 6.5: one dry-run turn over a fixed queue of 64 block picks with
// the callback off: a selection, one admission snapshot and 64 endings.
// Each turn's picks are queued with the timer stopped. The forecast,
// examples, summary and comparison stay within their bounds, and the turn
// leaves no goroutine behind.
func BenchmarkForecastTurn(b *testing.B) {
	p := withTestRegistry(b)
	f := newOwnerFixture(b)
	blocks := newFakeBlocks()
	r := &policyReader{p: dryPolicy(1)}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	heldMono(b, o)
	largest := watchBatches(b, o)
	goroutines := runtime.NumGoroutine()
	next := 1
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		for range admission.MaxBatchMembers {
			queuedAt(b, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("2001:db8::%x", next))
			next++
		}
		b.StartTimer()
		turn(b, o)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*admission.MaxBatchMembers), "ns/pick")
	if n := len(queuedCandidates(b, o)); n != 0 {
		b.Fatalf("%d picks left after the turns", n)
	}
	got := readBounds(b, o, *largest)
	checkBounds(b, got)
	b.ReportMetric(float64(got.entries), "forecast-blocks")
	if n := runtime.NumGoroutine(); n > goroutines {
		b.Fatalf("%d goroutines after the turns, %d before", n, goroutines)
	}
}

// Spec 4.3, 6.5: turns over a fixed queue while the panel is saturated:
// 64 jobs wait on four held calls and 64 more picks are selected each
// turn, read once against the engine and left queued, unasked. No turn
// ends, asks or adds anything, and no goroutine is started per pick.
func BenchmarkTurnWithASaturatedPanel(b *testing.B) {
	for _, mode := range []string{"dry_run", "live"} {
		b.Run(mode, func(b *testing.B) {
			p := withTestRegistry(b)
			f := newOwnerFixture(b)
			blocks := newFakeBlocks()
			panel := newFakePanel("block")
			release := make(chan struct{})
			panel.hold = release
			b.Cleanup(func() { close(release) })
			policy := verdictPolicy(1, panel)
			policy.DryRun = mode == "dry_run"
			r := &policyReader{p: policy}
			opts := executeOptions(f, blocks)
			opts.Policy = r.read
			o := f.start(opts)
			heldMono(b, o)
			for i := range 2 * verdictPending {
				queuedAt(b, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("2001:db8::%x", i+1))
			}
			// The history budget can hold a live turn below 64 picks.
			for range 3 {
				turn(b, o)
			}
			if s := readBounds(b, o, 0); s.pending != verdictPending {
				b.Fatalf("fixture: %d jobs pending", s.pending)
			}
			queued := len(queuedCandidates(b, o))
			goroutines := runtime.NumGoroutine()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				turn(b, o)
			}
			b.StopTimer()
			if n := len(queuedCandidates(b, o)); n != queued {
				b.Fatalf("%d picks queued after the turns, %d before", n, queued)
			}
			got := readBounds(b, o, 0)
			checkBounds(b, got)
			if got.pending != verdictPending || got.ready != 0 || got.entries != 0 {
				b.Fatalf("a saturated stage changed: %+v", got)
			}
			asked, _, peak, _ := panel.state()
			if len(asked) != verdictWorkers || peak != verdictWorkers {
				b.Fatalf("%d calls, %d at once", len(asked), peak)
			}
			if n := runtime.NumGoroutine(); n > goroutines {
				b.Fatalf("%d goroutines after the turns, %d before", n, goroutines)
			}
		})
	}
}
