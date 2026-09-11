// Command correlation-calibrate replays recorded finding streams through the
// production cross-account correlation.
//
//	go run ./scripts/correlation-calibrate --window 24h stream.jsonl.gz [more...]
//
// It reports what the coordinated-attack threshold would have done on real
// hosts: how often three or more accounts co-occur, how often account-and-check
// pairs repeat, and how per-batch derivation differs
// from the persisted active set. Streams are produced by scripts/finding-stream
// and are never committed; see docs/src/finding-streams.md.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "correlation-calibrate: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("correlation-calibrate", flag.ContinueOnError)
	fs.SetOutput(out)
	window := fs.Duration("window", time.Hour, "persisted correlation window to simulate; 0 reproduces unbounded correlation")
	gap := fs.Duration("batch-gap", time.Second, "arrival gap that separates two dispatch batches")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: correlation-calibrate [--window D] [--batch-gap D] STREAM [STREAM...]")
	}

	if *window < 0 || *gap < 0 {
		return fmt.Errorf("window and batch-gap must be nonnegative")
	}

	for _, path := range fs.Args() {
		events, skipped, err := readStream(path)
		if err != nil {
			return err
		}
		var rendered bytes.Buffer
		report(&rendered, path, events, skipped, *window, *gap)
		if _, err := io.Copy(out, &rendered); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	return nil
}

// readStream loads a recorded stream in arrival order. Rows with no timestamp
// are counted and skipped: they predate the fix that stamps every finding and
// would otherwise all land in one impossible batch at the zero time.
func readStream(path string) (events []Event, skipped int, err error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied recording path
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, gzErr := gzip.NewReader(f)
		if gzErr != nil {
			return nil, 0, fmt.Errorf("%s: %w", path, gzErr)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev alert.AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, 0, fmt.Errorf("%s: %w", path, err)
		}
		if ev.Timestamp.IsZero() {
			skipped++
			continue
		}
		events = append(events, Event{At: ev.Timestamp, Finding: findingOf(ev)})
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })
	return events, skipped, nil
}

// findingOf rebuilds the finding fields correlation reads. The recording keeps
// no other field that affects the result.
func findingOf(ev alert.AuditEvent) alert.Finding {
	return alert.Finding{
		Severity:  severityOf(ev.Severity),
		Check:     ev.Check,
		Message:   ev.Message,
		Details:   ev.Details,
		FilePath:  ev.FilePath,
		TenantID:  ev.TenantID,
		Timestamp: ev.Timestamp,
	}
}

func severityOf(s string) alert.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return alert.Critical
	case "HIGH":
		return alert.High
	default:
		return alert.Warning
	}
}

func report(out io.Writer, path string, events []Event, skipped int, window, gap time.Duration) {
	fmt.Fprintf(out, "== %s\n", path)
	if len(events) == 0 {
		fmt.Fprintf(out, "   no timestamped events\n")
		return
	}
	fmt.Fprintf(out, "   rows %d (%d without a timestamp, skipped), %s .. %s\n",
		len(events), skipped, events[0].At.Format(time.RFC3339), events[len(events)-1].At.Format(time.RFC3339))

	eligible, attributed := 0, 0
	unattributed := make(map[string]int)
	rowsByCheck := make(map[string]int)
	pairsByCheck := make(map[string]map[string]bool)
	correlator := recordingCorrelator(window)
	for _, e := range events {
		account, ok := correlator.InputOf(e.Finding)
		if !ok {
			continue
		}
		eligible++
		rowsByCheck[e.Finding.Check]++
		if account == "" {
			unattributed[e.Finding.Check]++
			continue
		}
		attributed++
		if pairsByCheck[e.Finding.Check] == nil {
			pairsByCheck[e.Finding.Check] = make(map[string]bool)
		}
		pairsByCheck[e.Finding.Check][account] = true
	}
	rows, pairs := Pairs(events)
	fmt.Fprintf(out, "   eligible %d (%.1f%%), attributed %d (%.1f%% of eligible)\n",
		eligible, pct(eligible, len(events)), attributed, pct(attributed, eligible))
	fmt.Fprintf(out, "   distinct account+check pairs %d from %d attributed rows (%.1f%% of rows repeat a pair)\n",
		pairs, rows, pct(rows-pairs, rows))

	fmt.Fprintf(out, "   checks producing the most eligible rows:\n")
	for _, line := range floodLines(rowsByCheck, pairsByCheck, 6) {
		fmt.Fprintf(out, "     %s\n", line)
	}

	batches := Batches(events, gap)
	batchFires, batchSpread := replayBatches(batches)
	fmt.Fprintf(out, "   per-batch derivation (%s gap): %d batches, %d coordinated_attack firings, max accounts in one batch %d\n",
		gap, len(batches), batchFires, batchSpread.Max())
	fmt.Fprintf(out, "     threshold sweep: %s\n", sweepLine(batchSpread))

	persistedFires, persistedSpread, latched := replayPersisted(events, window)
	label := "unbounded"
	if window > 0 {
		label = window.String()
	}
	fmt.Fprintf(out, "   persisted active set (%s): %d coordinated_attack firings, max accounts %d, raised for %.1f%% of the recording\n",
		label, persistedFires, persistedSpread.Max(), latched)
	fmt.Fprintf(out, "     threshold sweep: %s\n", sweepLine(persistedSpread))
	fmt.Fprintf(out, "\n")
}

// sweepLine renders how often each candidate threshold would have raised the
// aggregate over the same derivation points.
func sweepLine(s Spread) string {
	parts := make([]string, 0, 7)
	for n := 2; n <= 8; n++ {
		parts = append(parts, fmt.Sprintf("%d:%d", n, s.AtLeast(n)))
	}
	return fmt.Sprintf("accounts:points %s (of %d points)", strings.Join(parts, " "), s.Points())
}

func replayBatches(batches [][]Event) (fires int, spread Spread) {
	for _, batch := range batches {
		findings := make([]alert.Finding, 0, len(batch))
		for _, e := range batch {
			findings = append(findings, e.Finding)
		}
		raised, accounts := Derive(batch[len(batch)-1].At, findings, 0)
		spread.Observe(accounts)
		for _, f := range raised {
			if f.Check == "coordinated_attack" {
				fires++
			}
		}
	}
	return fires, spread
}

// replayPersisted merges every event into the modelled active set and derives
// after each one, which is what the latest-state merge does on every scan.
// latchedPct is how much of the recording the aggregate stayed raised for:
// an aggregate that never clears is a latch, not an alert.
func replayPersisted(events []Event, window time.Duration) (fires int, spread Spread, latchedPct float64) {
	// Keep the real store's unbounded source set; only correlation is
	// windowed. Retention would change which rows survive the store cap.
	set := NewActiveSet(0)
	raisedSpans := time.Duration(0)
	var raisedSince time.Time
	wasRaised := false
	for _, e := range events {
		set.Admit(e.Finding)
		// Ignored arrivals also advance the observation time and may expire
		// inputs, even when the persisted set did not evict anything.
		derived, accounts := Derive(e.At, set.Snapshot(), window)
		spread.Observe(accounts)
		isRaised := false
		for _, f := range derived {
			if f.Check == "coordinated_attack" {
				isRaised = true
			}
		}
		switch {
		case isRaised && !wasRaised:
			fires++
			raisedSince = e.At
		case !isRaised && wasRaised:
			raisedSpans += e.At.Sub(raisedSince)
		}
		wasRaised = isRaised
	}
	last := events[len(events)-1].At
	if wasRaised {
		raisedSpans += last.Sub(raisedSince)
	}
	total := last.Sub(events[0].At)
	if total > 0 {
		latchedPct = 100 * raisedSpans.Seconds() / total.Seconds()
	}
	return fires, spread, latchedPct
}

func floodLines(rowsByCheck map[string]int, pairsByCheck map[string]map[string]bool, limit int) []string {
	type row struct {
		check string
		rows  int
		pairs int
	}
	all := make([]row, 0, len(rowsByCheck))
	for check, n := range rowsByCheck {
		all = append(all, row{check: check, rows: n, pairs: len(pairsByCheck[check])})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].rows != all[j].rows {
			return all[i].rows > all[j].rows
		}
		return all[i].check < all[j].check
	})
	if len(all) > limit {
		all = all[:limit]
	}
	out := make([]string, 0, len(all))
	for _, r := range all {
		out = append(out, fmt.Sprintf("%-34s %6d rows over %3d account(s)", r.check, r.rows, r.pairs))
	}
	return out
}

func pct(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return 100 * float64(part) / float64(whole)
}
