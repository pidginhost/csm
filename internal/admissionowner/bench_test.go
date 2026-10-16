package admissionowner

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/verdict"
)

// Benchmarks count snapshot work without retaining a copy of every turn.
type benchmarkBlocks struct {
	*fakeBlocks
	snapshots, members int
}

func (f *benchmarkBlocks) BlockAdmissionSnapshot(m []firewall.BlockMember, shadow []string) (firewall.BlockAdmission, error) {
	out, err := f.fakeBlocks.BlockAdmissionSnapshot(m, shadow)
	f.snapshots++
	f.members += len(m)
	f.set(func(b *fakeBlocks) { b.snapshots, b.shadows = nil, nil })
	return out, err
}

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
	blocks := &benchmarkBlocks{fakeBlocks: newFakeBlocks()}
	policy := dryPolicy(1)
	policy.Expiry = func(admission.Candidate) time.Duration { return time.Hour }
	r := &policyReader{p: policy}
	opts := executeOptions(f, blocks.fakeBlocks)
	opts.Blocks = func() BlockEngine { return blocks }
	opts.Policy = r.read
	o := f.start(opts)
	mono := heldMono(b, o)
	largest := watchBatches(b, o)
	goroutines := runtime.NumGoroutine()
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		b.StopTimer()
		// Reuse a fixed set of targets after their leases and charges
		// expire. Every measured turn must still admit the whole queue.
		f.host.advance(time.Hour)
		mono.advance(time.Hour)
		if err := o.do(o.tick); err != nil {
			b.Fatal(err)
		}
		for j := range admission.MaxBatchMembers {
			if err := submitObservationError(o, p, fmt.Sprintf("2001:db8::%x", j+1), fmt.Sprintf("turn=%d", i), f.host.now()); err != nil {
				b.Fatal(err)
			}
		}
		if err := o.do(func() error { o.maintainExamples(); return o.drain() }); err != nil {
			b.Fatal(err)
		}
		if n := len(queuedCandidates(b, o)); n != admission.MaxBatchMembers {
			b.Fatalf("fixture: %d queued picks", n)
		}
		b.StartTimer()
		turn(b, o)
		b.StopTimer()
		if err := o.do(func() error {
			if o.shadow.picks[admission.PredictCapacityAdmit] != uint64((i+1)*admission.MaxBatchMembers) ||
				len(o.shadow.entries) != admission.MaxBatchMembers || blocks.snapshots != i+1 || blocks.members != (i+1)*admission.MaxBatchMembers {
				return fmt.Errorf("turn %d did not forecast every pick: predictions %v, snapshots %d, members %d", i, o.shadow.picks, blocks.snapshots, blocks.members)
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
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
// 64 jobs wait on four held calls and up to 64 more picks are selected each
// turn, read once against the engine and left queued, unasked. No turn
// ends, asks or adds anything, and no goroutine is started per pick.
func BenchmarkTurnWithASaturatedPanel(b *testing.B) {
	for _, mode := range []string{"dry_run", "live"} {
		b.Run(mode, func(b *testing.B) {
			p := withTestRegistry(b)
			f := newOwnerFixture(b)
			blocks := &benchmarkBlocks{fakeBlocks: newFakeBlocks()}
			panel := newFakePanel("block")
			panel.hold = make(chan struct{})
			// Keep calls saturated for any benchtime, independently of
			// request deadlines. Teardown explicitly cancels this fixture.
			held, cancel := context.WithCancel(context.Background())
			defer cancel()
			policy := verdictPolicy(1, panel)
			policy.AskVerdict = func(_ context.Context, ip, reason string) (verdict.Response, error) {
				return panel.ask(held, ip, reason)
			}
			policy.DryRun = mode == "dry_run"
			r := &policyReader{p: policy}
			opts := executeOptions(f, blocks.fakeBlocks)
			opts.Blocks = func() BlockEngine { return blocks }
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
			eventually(b, "all panel workers", func() bool { _, active, _, _ := panel.state(); return active == verdictWorkers })
			// Live selection also observes the paced history budget. Pin
			// the amount of work in the warmed fixture before timing it.
			beforeMembers := blocks.members
			turn(b, o)
			membersPerTurn := blocks.members - beforeMembers
			if membersPerTurn <= 0 || membersPerTurn > admission.MaxBatchMembers || (policy.DryRun && membersPerTurn != admission.MaxBatchMembers) {
				b.Fatalf("fixture: %d selected members", membersPerTurn)
			}
			queued := len(queuedCandidates(b, o))
			beforeSnapshots := blocks.snapshots
			beforeMembers = blocks.members
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
			if blocks.snapshots-beforeSnapshots != b.N || blocks.members-beforeMembers != b.N*membersPerTurn {
				b.Fatalf("turns checked %d snapshots and %d members", blocks.snapshots-beforeSnapshots, blocks.members-beforeMembers)
			}
			b.ReportMetric(float64(membersPerTurn), "picks/turn")
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
			cancel()
			o.Stop()
			if _, active, _, _ := panel.state(); active != 0 {
				b.Fatalf("%d calls survived teardown", active)
			}
		})
	}
}
