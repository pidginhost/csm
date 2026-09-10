package emailav

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/obs"
)

// Orchestrator runs multiple scanners in parallel against extracted email parts.
type Orchestrator struct {
	scanners    []Scanner
	scanTimeout time.Duration
	health      *scanQueue
}

// NewOrchestrator creates an orchestrator with the given scanners and per-scan timeout.
func NewOrchestrator(scanners []Scanner, scanTimeout time.Duration) *Orchestrator {
	return &Orchestrator{
		scanners:    scanners,
		scanTimeout: scanTimeout,
		health:      newScanQueue(),
	}
}

// ScanParts scans all extracted parts with all available engines.
// Fail-open: unavailable engines, timeouts, and errors are recorded but do not
// mark the message as infected.
func (o *Orchestrator) ScanParts(messageID string, parts []emime.ExtractedPart, partial bool) *ScanResult {
	result := &ScanResult{
		MessageID:         messageID,
		ScannedAt:         time.Now(),
		PartialExtraction: partial,
	}

	// Determine which engines are available
	var available []Scanner
	for _, s := range o.scanners {
		if s.Available() {
			available = append(available, s)
			result.EnginesUsed = append(result.EnginesUsed, s.Name())
		} else {
			result.FailedEngines = append(result.FailedEngines, s.Name())
			fmt.Fprintf(os.Stderr, "[emailav] engine %s unavailable\n", s.Name())
		}
	}

	if len(available) == 0 {
		// fail-open: no engines available - rate-limit the warning
		result.AllEnginesDown = true
		return result
	}

	// Scan each part with all available engines
	for _, part := range parts {
		findings, timedOut, errored := o.scanPart(part, available)
		result.Findings = append(result.Findings, findings...)
		result.TimedOutEngines = append(result.TimedOutEngines, timedOut...)
		result.ErroredEngines = append(result.ErroredEngines, errored...)
	}

	result.Infected = len(result.Findings) > 0
	return result
}

// scanPart scans a single part with all available engines concurrently.
// Returns findings and lists of engine names that timed out or errored.
func (o *Orchestrator) scanPart(part emime.ExtractedPart, scanners []Scanner) ([]Finding, []string, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), o.scanTimeout)
	defer cancel()

	results := make(chan engineScanResult, len(scanners))
	var wg sync.WaitGroup
	work := make([]*scanWork, 0, len(scanners))
	defer func() {
		for _, w := range work {
			w.finishDelivery(false)
		}
	}()

	for _, s := range scanners {
		work = append(work, o.startScan(ctx, s, part.TempPath, results, &wg))
	}

	// Close results channel when all scans complete
	obs.SafeGo("emailav-drain", func() {
		wg.Wait()
		close(results)
	})

	var findings []Finding
	var timedOut []string
	var errored []string
	for r := range results {
		r.work.received()
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "[emailav] %s scan error on %s: %v\n", r.engine, part.Filename, r.err)
			if r.timedOut {
				timedOut = append(timedOut, r.engine)
			} else {
				errored = append(errored, r.engine)
			}
			r.work.finishDelivery(true)
			continue // fail-open
		}
		if r.verdict.Infected {
			f := Finding{
				Filename:  part.Filename,
				Engine:    r.engine,
				Signature: r.verdict.Signature,
				Severity:  r.verdict.Severity,
			}
			if part.Nested {
				f.Filename = part.ArchiveName + "/" + part.Filename
			}
			findings = append(findings, f)
		}
		r.work.finishDelivery(true)
	}

	return findings, timedOut, errored
}

type engineScanResult struct {
	engine   string
	verdict  Verdict
	err      error
	timedOut bool
	work     *scanWork
}

func (o *Orchestrator) startScan(ctx context.Context, scanner Scanner, path string, results chan<- engineScanResult, wg *sync.WaitGroup) *scanWork {
	deadline, _ := ctx.Deadline()
	w := o.health.begin(deadline)
	wg.Add(1)
	obs.SafeGo("emailav-scan", func() {
		defer wg.Done()
		published := false
		defer func() {
			if !published {
				w.finishDelivery(false)
			}
		}()
		done := make(chan engineScanResult, 1)
		obs.SafeGo("emailav-engine", func() {
			success := false
			defer func() { w.finishEngine(success) }()
			w.start()
			v, err := scanner.Scan(path)
			done <- engineScanResult{engine: scanner.Name(), verdict: v, err: err, work: w}
			success = err == nil
		})
		var r engineScanResult
		select {
		case r = <-done:
		case <-ctx.Done():
			r = engineScanResult{engine: scanner.Name(), err: fmt.Errorf("scan timeout"), timedOut: true, work: w}
		}
		w.publish(r.err != nil)
		results <- r
		published = true
	})
	return w
}
