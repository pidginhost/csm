package checks

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/jstaint"
)

// jsTaintDeepCursorCheck is the host-scope scan-cursor key for the scheduled
// JS taint consumer of the shared deep-content walk.
const jsTaintDeepCursorCheck = logicalOwnerJSTaintDeep

// jsTaintDeepPerFileTimeout is the per-file safety net for one deep-scan
// analysis. The engine's node, depth, and fact caps bound normal work far
// below this; the deadline only stops an analyzer defect from eating the
// walk's soft-deadline margin on a single file.
const jsTaintDeepPerFileTimeout = 20 * time.Second

// maxJSTaintGapPaths bounds the exact paths one run retains for carry-forward,
// as maxPHPTaintGapPaths does for the PHP consumer. Past it the run keeps
// counting but reports its path set as incomplete, which suppresses the purge
// rather than carrying forward an arbitrary prefix.
const maxJSTaintGapPaths = 50_000

// Display bounds: the sanitized path in the finding message, the rendered
// evidence in its details, and diagnostic example paths (512, 2048
// and 256 bytes, markers included).
const (
	jsTaintMessageMaxBytes = 512
	jsTaintDetailsMaxBytes = 2048
	jsTaintExampleMaxBytes = 256
)

// sanitizeJSTaintDisplay renders untrusted path or evidence text for
// operator-facing fields: valid UTF-8, control and invalid bytes become '?',
// truncation happens at a rune boundary and the marker counts into the cap.
func sanitizeJSTaintDisplay(s string, maxBytes int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// jsTaintGapCollector aggregates per-path JS coverage gaps for one deep run:
// exact paths feed the carry-forward, counts and one example per status feed
// the js_taint_scan_incomplete diagnostic. Non-analyzed statuses are never
// counted as clean files.
type jsTaintGapCollector struct {
	gapPathSet
	recordCoverage func([]string)
}

func newJSTaintGapCollector() *jsTaintGapCollector {
	return &jsTaintGapCollector{gapPathSet: newGapPathSet(maxJSTaintGapPaths, jsTaintExampleMaxBytes, lexicalGapAliases)}
}

func (g *jsTaintGapCollector) record(path, status string) {
	if aliases := g.retain(path, status); len(aliases) > 0 && g.recordCoverage != nil {
		g.recordCoverage(aliases)
	}
}

func (g *jsTaintGapCollector) finding() alert.Finding {
	return g.incompleteFinding(alert.Warning, "js_taint_scan_incomplete",
		"JavaScript taint deep scan could not analyze %d file(s)",
		"JavaScript taint deep scan could not cover %d location(s)")
}

// carryForwardJSTaintFindings keeps at most one prior state finding for each
// path the current full cycle could not analyze.
func carryForwardJSTaintFindings(prior []alert.Finding, gaps *jsTaintGapCollector) []alert.Finding {
	return carryForwardLatestPerPath(prior, "js_keylogger_dataflow", &gaps.gapPathSet)
}

// analyzeJSTaintSnapshot runs the JS consumer on one complete in-memory
// snapshot and converts the result into at most one finding. A non-completed
// status is recorded as a known-path coverage gap, never as a clean file.
func analyzeJSTaintSnapshot(ctx context.Context, path, contentSHA256 string, data []byte, gaps *jsTaintGapCollector) []alert.Finding {
	fileCtx, cancel := context.WithTimeout(ctx, jsTaintDeepPerFileTimeout)
	report := runJSTaintAnalysis(fileCtx, data)
	cancel()
	switch report.Status {
	case jstaint.StatusAnalyzed:
		if len(report.Results) == 0 {
			return nil
		}
		return []alert.Finding{jsTaintDeepFinding(path, contentSHA256, report)}
	case jstaint.StatusNotCandidate:
		return nil
	default:
		gaps.record(path, report.Status.String())
		return nil
	}
}

// jsTaintDeepFinding renders the single finding for one analyzed file: the
// evidence flows the engine returned plus the count of endpoint flows beyond
// them, with every display field sanitized and bounded. The fingerprint is
// the hash of the exact analyzed bytes; FilePath keeps the exact live path
// for remediation while only its display copy is sanitized.
func jsTaintDeepFinding(path, contentSHA256 string, report jstaint.Report) alert.Finding {
	flows := make([]string, 0, len(report.Results))
	for _, res := range report.Results {
		segs := make([]string, 0, len(res.Via)+2)
		segs = append(segs, res.Source)
		segs = append(segs, res.Via...)
		segs = append(segs, res.Sink)
		flows = append(flows, strings.Join(segs, " -> "))
	}
	details := "Keystroke data reaches a network sink. Evidence: " + strings.Join(flows, "; ")
	if extra := report.TotalResults - len(report.Results); extra > 0 {
		details += fmt.Sprintf("; %d additional flow(s) beyond returned evidence", extra)
	}
	if report.EvidenceTruncated {
		details += " [evidence truncated]"
	}
	return alert.Finding{
		Severity:      alert.Critical,
		Check:         "js_keylogger_dataflow",
		Message:       "JavaScript keystroke exfiltration data flow: " + sanitizeJSTaintDisplay(path, jsTaintMessageMaxBytes),
		Details:       sanitizeJSTaintDisplay(details, jsTaintDetailsMaxBytes),
		FilePath:      path,
		ContentSHA256: contentSHA256,
		DetectLogic:   ContentDetectionVersion(),
		CoverageScope: deepFileCoverageScope(path),
	}
}
