package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/phptaint"
)

// phpTaintDeepCursorCheck is the host-scope scan-cursor key for the scheduled
// PHP taint consumer of the shared deep-content walk. It is distinct from the
// JS consumer's key so the two advance independently: they admit different
// files, so a shared cursor would let one consumer's progress hide the other's
// unscanned remainder.
const phpTaintDeepCursorCheck = logicalOwnerPHPTaintDeep

// phpTaintDeepPerFileTimeout bounds one file's analysis as seen by this
// consumer. The supervised worker applies its own, shorter deadline and kills
// the process when it expires; this outer bound only covers the case where the
// worker layer itself becomes unresponsive.
const phpTaintDeepPerFileTimeout = 30 * time.Second

// Display bounds mirror the JS consumer's: message, details, and diagnostic
// example paths.
// maxPHPTaintGapPaths bounds the exact paths one run retains for carry-forward.
//
// The bound matters here in a way it does not for the JS consumer. That
// analyzer runs in-process and answers StatusNotCandidate for non-JS content,
// so a gap needs a genuinely failing JS file. PHP analysis happens in a
// separate process, and its pre-filter lives THERE, so when the worker is
// unavailable every readable file on the host becomes a gap -- millions of
// retained path strings for the length of a scan. Past the bound the run stops
// enumerating and reports itself as unable to enumerate, which suppresses the
// purge wholesale rather than carrying forward an arbitrary prefix.
const maxPHPTaintGapPaths = 50_000

const (
	phpTaintMessageMaxBytes = 512
	phpTaintDetailsMaxBytes = 2048
	phpTaintExampleMaxBytes = 256
)

// phpTaintGapCollector aggregates per-path PHP coverage gaps for one deep run:
// exact paths feed the carry-forward, counts and one example per status feed
// the php_taint_scan_incomplete diagnostic. A non-completed status is never
// counted as a clean file.
type phpTaintGapCollector struct {
	paths    map[string]struct{}
	byStatus map[string]int
	example  map[string]string
	// unknown counts walk failures whose affected paths cannot be enumerated
	// (an unreadable directory, a failed Lstat that may hide one). They are
	// kept apart from paths because carry-forward needs exact paths, but they
	// must still reach the operator: without this the loss is recorded only in
	// a boolean that suppresses the purge, and a host running the PHP consumer
	// without the YARA one is told nothing at all.
	unknown        int
	unknownExample string
	// pathsTruncated records that the exact-path set hit its bound, so the
	// carry-forward can no longer be trusted to cover every gapped path.
	pathsTruncated bool
}

func newPHPTaintGapCollector() *phpTaintGapCollector {
	return &phpTaintGapCollector{
		paths:    map[string]struct{}{},
		byStatus: map[string]int{},
		example:  map[string]string{},
	}
}

func (g *phpTaintGapCollector) record(path, status string) {
	if _, retained := g.paths[path]; !retained {
		if len(g.paths) < maxPHPTaintGapPaths {
			g.paths[path] = struct{}{}
		} else {
			// Stop retaining paths, but never stop counting: the count is what
			// tells an operator how much of the host went unexamined.
			g.pathsTruncated = true
		}
	}
	g.byStatus[status]++
	if _, ok := g.example[status]; !ok {
		g.example[status] = sanitizeJSTaintDisplay(path, phpTaintExampleMaxBytes)
	}
}

// pathsIncomplete reports that this run could not enumerate every gapped path,
// either because retention hit its bound or because the walk lost an unknown
// range. Its carry-forward set is therefore not authoritative and the purge
// must be suppressed for the whole owner.
func (g *phpTaintGapCollector) pathsIncomplete() bool {
	return g.pathsTruncated || g.unknown > 0
}

// recordUnknownRange notes coverage lost over a range this walk cannot
// enumerate. It deliberately does not add to paths: claiming specific paths
// would be false, and the unknown range already forces a partial run, which
// suppresses the purge for every prior finding.
func (g *phpTaintGapCollector) recordUnknownRange(detail string) {
	g.unknown++
	if g.unknownExample == "" {
		g.unknownExample = sanitizeJSTaintDisplay(detail, phpTaintExampleMaxBytes)
	}
}

func (g *phpTaintGapCollector) empty() bool { return len(g.byStatus) == 0 && g.unknown == 0 }

func (g *phpTaintGapCollector) hasPath(path string) bool {
	_, ok := g.paths[path]
	return ok
}

func (g *phpTaintGapCollector) finding() alert.Finding {
	total := 0
	statuses := make([]string, 0, len(g.byStatus))
	for status, n := range g.byStatus {
		total += n
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		parts = append(parts, fmt.Sprintf("%s=%d (example: %s)", status, g.byStatus[status], g.example[status]))
	}
	if g.unknown > 0 {
		parts = append(parts, fmt.Sprintf("unreadable-range=%d (example: %s)", g.unknown, g.unknownExample))
	}
	if g.pathsTruncated {
		parts = append(parts, fmt.Sprintf("exact paths retained for only the first %d", maxPHPTaintGapPaths))
	}
	message := fmt.Sprintf("PHP taint deep scan could not analyze %d file(s)", total)
	if total == 0 {
		message = fmt.Sprintf("PHP taint deep scan could not cover %d location(s)", g.unknown)
	}
	return alert.Finding{
		Severity: alert.Warning,
		Check:    "php_taint_scan_incomplete",
		Message:  message,
		Details:  strings.Join(parts, "; "),
	}
}

// carryForwardPHPTaintFindings keeps at most one prior state finding for each
// path the current full cycle could not analyze, so a file that goes from
// analyzed to unexaminable does not silently lose its existing finding.
func carryForwardPHPTaintFindings(prior []alert.Finding, gaps *phpTaintGapCollector) []alert.Finding {
	byPath := make(map[string]alert.Finding)
	for _, finding := range prior {
		if finding.Check != "php_remote_taint" || !gaps.hasPath(finding.FilePath) {
			continue
		}
		current, exists := byPath[finding.FilePath]
		if !exists || finding.Timestamp.After(current.Timestamp) ||
			(finding.Timestamp.Equal(current.Timestamp) && finding.Key() < current.Key()) {
			byPath[finding.FilePath] = finding
		}
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	carried := make([]alert.Finding, 0, len(paths))
	for _, path := range paths {
		carried = append(carried, byPath[path])
	}
	return carried
}

// analyzePHPTaintSnapshot runs the PHP consumer on one complete in-memory
// snapshot and converts the result into at most one finding. Only StatusAnalyzed
// and StatusNotCandidate mean the file was examined; every other status is
// recorded as a known-path coverage gap.
func analyzePHPTaintSnapshot(ctx context.Context, path, contentSHA256 string, data []byte, gaps *phpTaintGapCollector) []alert.Finding {
	fileCtx, cancel := context.WithTimeout(ctx, phpTaintDeepPerFileTimeout)
	report := runPHPTaintAnalysis(fileCtx, data)
	cancel()
	switch report.Status {
	case phptaint.StatusAnalyzed:
		if len(report.Results) == 0 {
			return nil
		}
		return []alert.Finding{phpTaintDeepFinding(path, contentSHA256, report)}
	case phptaint.StatusNotCandidate:
		return nil
	default:
		gaps.record(path, report.Status.String())
		return nil
	}
}

// phpTaintDeepFinding renders the single finding for one analyzed file. Every
// display field is sanitized and bounded; FilePath keeps the exact live path
// for remediation while only its display copy is sanitized.
func phpTaintDeepFinding(path, contentSHA256 string, report phptaint.Report) alert.Finding {
	flows := make([]string, 0, len(report.Results))
	for _, res := range report.Results {
		flows = append(flows, fmt.Sprintf("%s -> %s (%s)", res.Source, res.Sink, phpTaintConfidence(res.Confidence)))
	}
	details := "Remotely fetched content reaches a code-execution construct. Evidence: " + strings.Join(flows, "; ")
	if extra := report.TotalResults - len(report.Results); extra > 0 {
		details += fmt.Sprintf("; %d additional flow(s) beyond returned evidence", extra)
	}
	if report.EvidenceTruncated {
		details += " [evidence truncated]"
	}
	if len(report.PrecisionLoss) > 0 {
		details += "; reduced precision: " + strings.Join(report.PrecisionLoss, ", ")
	}
	return alert.Finding{
		Severity:      alert.Critical,
		Check:         "php_remote_taint",
		Message:       "PHP remote-source code execution data flow: " + sanitizeJSTaintDisplay(path, phpTaintMessageMaxBytes),
		Details:       sanitizeJSTaintDisplay(details, phpTaintDetailsMaxBytes),
		FilePath:      path,
		ContentSHA256: contentSHA256,
		DetectLogic:   ContentDetectionVersion(),
	}
}

func phpTaintConfidence(c phptaint.Confidence) string {
	switch c {
	case phptaint.ConfidenceCertain:
		return "certain"
	case phptaint.ConfidenceHigh:
		return "high"
	default:
		return "low"
	}
}
