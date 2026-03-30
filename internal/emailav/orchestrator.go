package emailav

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	emime "github.com/pidginhost/cpanel-security-monitor/internal/mime"
)

// Orchestrator runs multiple scanners in parallel against extracted email parts.
type Orchestrator struct {
	scanners        []Scanner
	scanTimeout     time.Duration
	lastDegradedLog time.Time // rate-limit degraded warnings to once per minute
	mu              sync.Mutex
}

// NewOrchestrator creates an orchestrator with the given scanners and per-scan timeout.
func NewOrchestrator(scanners []Scanner, scanTimeout time.Duration) *Orchestrator {
	return &Orchestrator{
		scanners:    scanners,
		scanTimeout: scanTimeout,
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
		// fail-open: no engines available — rate-limit the warning
		result.AllEnginesDown = true
		return result
	}

	// Scan each part with all available engines
	for _, part := range parts {
		findings, timedOut := o.scanPart(part, available)
		result.Findings = append(result.Findings, findings...)
		for _, eng := range timedOut {
			result.TimedOutEngines = append(result.TimedOutEngines, eng)
		}
	}

	result.Infected = len(result.Findings) > 0
	return result
}

// scanPart scans a single part with all available engines concurrently.
// Returns findings and a list of engine names that timed out.
func (o *Orchestrator) scanPart(part emime.ExtractedPart, scanners []Scanner) ([]Finding, []string) {
	type scanResult struct {
		engine   string
		verdict  Verdict
		err      error
		timedOut bool
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.scanTimeout)
	defer cancel()

	results := make(chan scanResult, len(scanners))
	var wg sync.WaitGroup

	for _, s := range scanners {
		wg.Add(1)
		go func(scanner Scanner) {
			defer wg.Done()
			done := make(chan scanResult, 1)
			go func() {
				v, err := scanner.Scan(part.TempPath)
				done <- scanResult{engine: scanner.Name(), verdict: v, err: err}
			}()
			select {
			case r := <-done:
				results <- r
			case <-ctx.Done():
				results <- scanResult{engine: scanner.Name(), err: fmt.Errorf("scan timeout"), timedOut: true}
			}
		}(s)
	}

	// Close results channel when all scans complete
	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	var timedOut []string
	for r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "[emailav] %s scan error on %s: %v\n", r.engine, part.Filename, r.err)
			if r.timedOut {
				timedOut = append(timedOut, r.engine)
			}
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
	}

	return findings, timedOut
}
